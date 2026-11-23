using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Avalonia.Threading;
using WindowsAppProtector.Platform;

namespace WindowsAppProtector;

public partial class App : Application
{
    private static readonly object ProtectionLogLock = new();
    private MainWindow? _mainWindow;

    internal const string BackgroundArgument = "--background";
    internal static bool VerifyInstallMode { get; set; }
    internal static bool StartInBackground { get; set; }

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
        ApplyHighContrastOverridesIfNeeded();
    }

    private void ApplyHighContrastOverridesIfNeeded()
    {
        if (!IsWindowsHighContrastEnabled())
        {
            return;
        }

        var windowColor = FromSysColor(NativeMethods.ColorWindow);
        var windowTextColor = FromSysColor(NativeMethods.ColorWindowText);
        var grayTextColor = FromSysColor(NativeMethods.ColorGrayText);
        var highlightColor = FromSysColor(NativeMethods.ColorHighlight);
        var highlightTextColor = FromSysColor(NativeMethods.ColorHighlightText);
        var btnFaceColor = FromSysColor(NativeMethods.ColorBtnFace);
        var btnShadowColor = FromSysColor(NativeMethods.ColorBtnShadow);

        SetSystemBrush("InkColor", "InkBrush", windowTextColor);
        SetSystemBrush("InkMutedColor", "InkMutedBrush", grayTextColor);
        SetSystemBrush("SurfaceColor", "SurfaceBrush", windowColor);
        SetSystemBrush("CanvasColor", "CanvasBrush", windowColor);
        SetSystemBrush("LatchColor", "LatchBrush", highlightColor);
        SetSystemBrush("LatchSubtleColor", "LatchSubtleBrush", btnFaceColor);
        SetSystemBrush("DangerColor", "DangerBrush", highlightColor);
        SetSystemBrush("DividerColor", "DividerBrush", btnShadowColor);

        Resources["InkOnAccentBrush"] = new SolidColorBrush(highlightTextColor);
        Resources["InkHoverBrush"] = new SolidColorBrush(highlightColor);
        Resources["InkPressedBrush"] = new SolidColorBrush(highlightColor);
        Resources["LatchOnFillBrush"] = new SolidColorBrush(highlightTextColor);
        Resources["LatchHoverBrush"] = new SolidColorBrush(highlightColor);
        Resources["LatchPressedBrush"] = new SolidColorBrush(highlightColor);
        Resources["SurfaceHoverBrush"] = new SolidColorBrush(btnFaceColor);
        Resources["SurfacePressedBrush"] = new SolidColorBrush(highlightColor);
        Resources["ControlNeutralBrush"] = new SolidColorBrush(btnShadowColor);
        Resources["ControlNeutralHoverBrush"] = new SolidColorBrush(highlightColor);
        Resources["ControlNeutralPressedBrush"] = new SolidColorBrush(highlightColor);
        Resources["ControlKnobOffBrush"] = new SolidColorBrush(windowTextColor);
        Resources["DangerSubtleBrush"] = new SolidColorBrush(btnFaceColor);
    }

    private void SetSystemBrush(string colorKey, string brushKey, Color color)
    {
        Resources[colorKey] = color;
        Resources[brushKey] = new SolidColorBrush(color);
    }

    private static bool IsWindowsHighContrastEnabled()
    {
        try
        {
            var info = new NativeMethods.HighContrastInfo
            {
                cbSize = (uint)Marshal.SizeOf<NativeMethods.HighContrastInfo>(),
            };
            return NativeMethods.SystemParametersInfo(NativeMethods.SpiGetHighContrast, info.cbSize, ref info, 0)
                && (info.dwFlags & NativeMethods.HcfHighContrastOn) != 0;
        }
        catch
        {
            return false;
        }
    }

    private static Color FromSysColor(int index)
    {
        var colorRef = NativeMethods.GetSysColor(index);
        var r = (byte)(colorRef & 0xFF);
        var g = (byte)((colorRef >> 8) & 0xFF);
        var b = (byte)((colorRef >> 16) & 0xFF);
        return new Color(255, r, g, b);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        Dispatcher.UIThread.UnhandledException += (_, e) =>
        {
            WriteCrashLog(e.Exception);
            e.Handled = true;
        };

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;

            if (VerifyInstallMode)
            {
                if (!this.TryFindResource("AppFontFamily", out _))
                {
                    throw new InvalidOperationException("AppFontFamily resource not found.");
                }

                _ = new Grid
                {
                    Children = { new TextBlock { Text = ProductBrand.Name } }
                };
                base.OnFrameworkInitializationCompleted();
                return;
            }

            _mainWindow = new MainWindow(StartInBackground);
            if (!StartInBackground)
            {
                desktop.MainWindow = _mainWindow;
            }
        }

        base.OnFrameworkInitializationCompleted();
    }

    internal static void WriteCrashLog(Exception exception)
    {
        try
        {
            var logDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Windows App Protector",
                "Logs");
            Directory.CreateDirectory(logDirectory);
            var logPath = Path.Combine(logDirectory, "winui-crash.log");
            File.AppendAllText(
                logPath,
                $"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}] {exception}\r\n\r\n");
        }
        catch
        {
        }
    }

    internal static void WriteProtectionLog(string eventName)
    {
        lock (ProtectionLogLock)
        {
            try
            {
                var directory = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Windows App Protector",
                    "Logs");
                Directory.CreateDirectory(directory);
                var path = Path.Combine(directory, "protection.log");
                var log = new FileInfo(path);
                if (log.Exists && log.Length >= 256 * 1024)
                {
                    File.Move(path, path + ".previous", overwrite: true);
                }

                File.AppendAllText(path, $"[{DateTimeOffset.Now:O}] {eventName}{Environment.NewLine}");
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
