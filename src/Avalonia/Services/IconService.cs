using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Xml.Linq;
using Avalonia;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Microsoft.Win32;
using WindowsAppProtector.Models;
using WindowsAppProtector.Platform;

namespace WindowsAppProtector.Services;

public sealed class IconService : IDisposable
{
    private static readonly string[] ImageExtensions = [".png", ".jpg", ".jpeg", ".bmp", ".ico", ".webp"];
    private static readonly string[] LogoQualifierSuffixes =
    [
        ".targetsize-48_altform-unplated",
        ".targetsize-48",
        ".targetsize-32_altform-unplated",
        ".targetsize-32",
        ".scale-200",
        ".scale-150",
        ".scale-125",
        ".scale-100",
    ];

    private readonly ConcurrentDictionary<string, Bitmap?> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string?> _packageInstallLocationCache = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

    public Bitmap? GetIcon(string? path)
    {
        if (_disposed || string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var normalized = Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'));
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return null;
        }

        return _cache.GetOrAdd(normalized, LoadIconCore);
    }

    public Bitmap? GetPackagedAppIcon(string? installLocation, string? logoPath = null)
    {
        if (_disposed)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(logoPath))
        {
            var direct = ResolveLogoFile(installLocation, logoPath);
            if (!string.IsNullOrWhiteSpace(direct))
            {
                return GetIcon(direct);
            }
        }

        if (string.IsNullOrWhiteSpace(installLocation) || !Directory.Exists(installLocation))
        {
            return null;
        }

        var cacheKey = "pkg:" + installLocation.Trim();
        return _cache.GetOrAdd(cacheKey, _ => LoadPackagedLogoFromManifest(installLocation));
    }

    public Bitmap? GetAppIcon(PackagedAppInfo app)
    {
        if (app.IsPackaged)
        {
            RegisterPackagedInstallLocation(app.PackageFamilyName, app.InstallLocation);
            return GetPackagedAppIcon(app.InstallLocation);
        }

        return GetIcon(app.Path);
    }

    internal Bitmap? GetAppIcon(AppPolicy app, string? installLocation = null)
    {
        if (app.IsPackaged)
        {
            var resolved = string.IsNullOrWhiteSpace(installLocation)
                ? ResolvePackageInstallLocation(app.PackageFamilyName)
                : installLocation;
            return GetPackagedAppIcon(resolved);
        }

        return GetIcon(app.Path);
    }

    public Bitmap? GetProtectedAppIcon(bool isPackaged, string? rawPath, string? packageFamilyName)
    {
        if (_disposed)
        {
            return null;
        }

        if (isPackaged)
        {
            var installLocation = ResolvePackageInstallLocation(packageFamilyName);
            return GetPackagedAppIcon(installLocation);
        }

        return GetIcon(rawPath);
    }

    public void RegisterPackagedInstallLocation(string? packageFamilyName, string? installLocation)
    {
        if (_disposed || string.IsNullOrWhiteSpace(packageFamilyName) || string.IsNullOrWhiteSpace(installLocation))
        {
            return;
        }

        _packageInstallLocationCache[packageFamilyName.Trim()] = installLocation.Trim();
    }

    private string? ResolvePackageInstallLocation(string? packageFamilyName)
    {
        if (string.IsNullOrWhiteSpace(packageFamilyName))
        {
            return null;
        }

        var key = packageFamilyName.Trim();
        return _packageInstallLocationCache.GetOrAdd(key, LookupPackageInstallLocationFromRegistry);
    }

    private static string? LookupPackageInstallLocationFromRegistry(string packageFamilyName)
    {
        try
        {
            var separator = packageFamilyName.LastIndexOf('_');
            if (separator <= 0 || separator >= packageFamilyName.Length - 1)
            {
                return null;
            }

            var packageName = packageFamilyName[..separator];
            var publisherId = packageFamilyName[(separator + 1)..];
            var prefix = packageName + "_";
            var suffix = "_" + publisherId;

            const string repositorySubKey = @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";
            using var packagesKey = Registry.CurrentUser.OpenSubKey(repositorySubKey);
            if (packagesKey is null)
            {
                return null;
            }

            foreach (var fullName in packagesKey.GetSubKeyNames())
            {
                if (!fullName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
                    !fullName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                using var pkgKey = packagesKey.OpenSubKey(fullName);
                var rootFolder = pkgKey?.GetValue("PackageRootFolder") as string;
                if (!string.IsNullOrWhiteSpace(rootFolder) && Directory.Exists(rootFolder))
                {
                    return rootFolder;
                }
            }
        }
        catch
        {
        }

        return null;
    }

    public void ClearCache()
    {
        _packageInstallLocationCache.Clear();
        foreach (var entry in _cache)
        {
            if (_cache.TryRemove(entry.Key, out var bitmap))
            {
                bitmap?.Dispose();
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        ClearCache();
    }

    private static Bitmap? LoadIconCore(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            var extension = Path.GetExtension(path);
            if (IsImageFile(extension))
            {
                return LoadImageFile(path);
            }

            return ExtractExecutableIcon(path);
        }
        catch
        {
            return null;
        }
    }

    private static bool IsImageFile(string extension)
    {
        foreach (var candidate in ImageExtensions)
        {
            if (string.Equals(extension, candidate, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static Bitmap? LoadImageFile(string filePath)
    {
        try
        {
            using var stream = File.OpenRead(filePath);
            return new Bitmap(stream);
        }
        catch
        {
            return null;
        }
    }

    private static Bitmap? LoadPackagedLogoFromManifest(string installLocation)
    {
        try
        {
            var manifestPath = Path.Combine(installLocation, "AppxManifest.xml");
            if (!File.Exists(manifestPath))
            {
                return null;
            }

            var document = XDocument.Load(manifestPath);
            var candidateRelativePaths = new List<string>();

            foreach (var element in document.Descendants())
            {
                if (string.Equals(element.Name.LocalName, "VisualElements", StringComparison.OrdinalIgnoreCase))
                {
                    AddIfPresent(candidateRelativePaths, element.Attribute("Square44x44Logo")?.Value);
                    AddIfPresent(candidateRelativePaths, element.Attribute("Square150x150Logo")?.Value);
                }
                else if (string.Equals(element.Name.LocalName, "Logo", StringComparison.OrdinalIgnoreCase))
                {
                    AddIfPresent(candidateRelativePaths, element.Value);
                }
            }

            foreach (var relativePath in candidateRelativePaths)
            {
                var resolved = ResolveLogoFile(installLocation, relativePath);
                if (!string.IsNullOrWhiteSpace(resolved))
                {
                    var bitmap = LoadImageFile(resolved);
                    if (bitmap is not null)
                    {
                        return bitmap;
                    }
                }
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private static void AddIfPresent(List<string> list, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            list.Add(value.Trim());
        }
    }

    private static string? ResolveLogoFile(string? installLocation, string logoPath)
    {
        var trimmed = logoPath.Trim().Trim('"');
        if (Path.IsPathRooted(trimmed) && File.Exists(trimmed))
        {
            return trimmed;
        }

        if (string.IsNullOrWhiteSpace(installLocation))
        {
            return null;
        }

        var combined = Path.Combine(installLocation, trimmed.Replace('/', Path.DirectorySeparatorChar));
        if (File.Exists(combined))
        {
            return combined;
        }

        var directory = Path.GetDirectoryName(combined);
        var baseName = Path.GetFileNameWithoutExtension(combined);
        var extension = Path.GetExtension(combined);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory) || string.IsNullOrWhiteSpace(baseName))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(extension))
        {
            extension = ".png";
        }

        foreach (var suffix in LogoQualifierSuffixes)
        {
            var qualified = Path.Combine(directory, baseName + suffix + extension);
            if (File.Exists(qualified))
            {
                return qualified;
            }
        }

        var fallback = Directory
            .EnumerateFiles(directory, baseName + ".*" + extension)
            .OrderByDescending(static file => new FileInfo(file).Length)
            .FirstOrDefault();

        return fallback;
    }

    private static Bitmap? ExtractExecutableIcon(string exePath)
    {
        var hIcon = TryGetShellIcon(exePath);
        if (hIcon == IntPtr.Zero)
        {
            hIcon = TryExtractIconEx(exePath);
        }

        if (hIcon == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return ConvertHIconToPngBitmap(hIcon);
        }
        finally
        {
            _ = NativeMethods.DestroyIcon(hIcon);
        }
    }

    private static IntPtr TryGetShellIcon(string path)
    {
        var fileInfo = new NativeMethods.ShFileInfo();
        var result = NativeMethods.SHGetFileInfo(
            path,
            0,
            ref fileInfo,
            (uint)Marshal.SizeOf<NativeMethods.ShFileInfo>(),
            NativeMethods.ShgfiIcon | NativeMethods.ShgfiLargeIcon);

        return result != IntPtr.Zero ? fileInfo.hIcon : IntPtr.Zero;
    }

    private static IntPtr TryExtractIconEx(string path)
    {
        var largeIcons = new IntPtr[1];
        var extracted = NativeMethods.ExtractIconEx(path, 0, largeIcons, null, 1);
        return extracted > 0 ? largeIcons[0] : IntPtr.Zero;
    }

    private static Bitmap? ConvertHIconToPngBitmap(IntPtr hIcon)
    {
        if (!NativeMethods.GetIconInfo(hIcon, out var iconInfo))
        {
            return null;
        }

        try
        {
            var hasColor = iconInfo.hbmColor != IntPtr.Zero;
            var sourceBitmap = hasColor ? iconInfo.hbmColor : iconInfo.hbmMask;
            if (sourceBitmap == IntPtr.Zero)
            {
                return null;
            }

            if (NativeMethods.GetObject(sourceBitmap, Marshal.SizeOf<NativeMethods.GdiBitmap>(), out var gdiBitmap) == 0)
            {
                return null;
            }

            var width = gdiBitmap.bmWidth;
            var height = hasColor ? gdiBitmap.bmHeight : gdiBitmap.bmHeight / 2;
            if (width <= 0 || height <= 0)
            {
                return null;
            }

            var hdc = NativeMethods.CreateCompatibleDC(IntPtr.Zero);
            if (hdc == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                var bgra = ExtractBgraPixels(hdc, iconInfo, width, height, hasColor);
                if (bgra is null)
                {
                    return null;
                }

                return EncodeBgraToPngBitmap(bgra, width, height);
            }
            finally
            {
                _ = NativeMethods.DeleteDC(hdc);
            }
        }
        finally
        {
            if (iconInfo.hbmColor != IntPtr.Zero)
            {
                _ = NativeMethods.DeleteObject(iconInfo.hbmColor);
            }

            if (iconInfo.hbmMask != IntPtr.Zero)
            {
                _ = NativeMethods.DeleteObject(iconInfo.hbmMask);
            }
        }
    }

    private static byte[]? ExtractBgraPixels(
        IntPtr hdc,
        NativeMethods.IconInfo iconInfo,
        int width,
        int height,
        bool hasColor)
    {
        var pixelByteCount = checked(width * height * 4);

        if (hasColor)
        {
            var colorPixels = ReadDib32(hdc, iconInfo.hbmColor, width, height, pixelByteCount);
            if (colorPixels is null)
            {
                return null;
            }

            var hasAlpha = false;
            for (var i = 3; i < colorPixels.Length; i += 4)
            {
                if (colorPixels[i] != 0)
                {
                    hasAlpha = true;
                    break;
                }
            }

            if (!hasAlpha && iconInfo.hbmMask != IntPtr.Zero)
            {
                var maskPixels = ReadDib32(hdc, iconInfo.hbmMask, width, height, pixelByteCount);
                if (maskPixels is not null)
                {
                    for (var i = 0; i < colorPixels.Length; i += 4)
                    {
                        var isTransparent = maskPixels[i] != 0 || maskPixels[i + 1] != 0 || maskPixels[i + 2] != 0;
                        colorPixels[i + 3] = isTransparent ? (byte)0 : (byte)255;
                    }
                }
                else
                {
                    for (var i = 3; i < colorPixels.Length; i += 4)
                    {
                        colorPixels[i] = 255;
                    }
                }
            }

            return colorPixels;
        }

        // 흑백 아이콘: hbmMask 상반부는 AND 마스크, 하반부는 XOR 비트맵
        var fullMask = ReadDib32(hdc, iconInfo.hbmMask, width, height * 2, checked(pixelByteCount * 2));
        if (fullMask is null)
        {
            return null;
        }

        var pixels = new byte[pixelByteCount];
        for (var i = 0; i < pixelByteCount; i += 4)
        {
            var andMask = fullMask[i];
            var xorPixel = fullMask[pixelByteCount + i];
            var opaque = andMask == 0;
            pixels[i] = xorPixel;
            pixels[i + 1] = xorPixel;
            pixels[i + 2] = xorPixel;
            pixels[i + 3] = opaque ? (byte)255 : (byte)0;
        }

        return pixels;
    }

    private static byte[]? ReadDib32(IntPtr hdc, IntPtr hBitmap, int width, int height, int bufferSize)
    {
        var buffer = new byte[bufferSize];
        var header = new NativeMethods.BitmapInfoHeader
        {
            biSize = (uint)Marshal.SizeOf<NativeMethods.BitmapInfoHeader>(),
            biWidth = width,
            biHeight = -height, // top-down DIB
            biPlanes = 1,
            biBitCount = 32,
            biCompression = NativeMethods.BiRgb,
        };

        var lines = NativeMethods.GetDIBits(hdc, hBitmap, 0, (uint)height, buffer, ref header, NativeMethods.DibRgbColors);
        return lines > 0 ? buffer : null;
    }

    private static Bitmap EncodeBgraToPngBitmap(byte[] bgra, int width, int height)
    {
        using var writeable = new WriteableBitmap(
            new PixelSize(width, height),
            new Vector(96, 96),
            PixelFormat.Bgra8888,
            AlphaFormat.Unpremul);

        using (var frameBuffer = writeable.Lock())
        {
            var rowBytes = width * 4;
            if (frameBuffer.RowBytes == rowBytes)
            {
                Marshal.Copy(bgra, 0, frameBuffer.Address, bgra.Length);
            }
            else
            {
                for (var y = 0; y < height; y++)
                {
                    Marshal.Copy(bgra, y * rowBytes, IntPtr.Add(frameBuffer.Address, y * frameBuffer.RowBytes), rowBytes);
                }
            }
        }

        using var pngStream = new MemoryStream();
        writeable.Save(pngStream);
        pngStream.Position = 0;
        return new Bitmap(pngStream);
    }
}
