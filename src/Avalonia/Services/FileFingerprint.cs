using System.Security.Cryptography;
using System.Text;

namespace WindowsAppProtector.Services;

/// <summary>
/// Size and SHA-256 of a protected executable. The service uses them to recognise a renamed or copied
/// binary. Files above the limit get a size but no hash, and the service falls back to path matching.
/// </summary>
internal static class FileFingerprint
{
    public const long MaxHashBytes = 64L * 1024 * 1024;

    public static Task<(long Size, string Sha256)> ComputeAsync(string path) => Task.Run(() => Compute(path));

    public static (long Size, string Sha256) Compute(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return (0, string.Empty);
            }

            if (info.Length > MaxHashBytes)
            {
                return (info.Length, string.Empty);
            }

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var hash = SHA256.HashData(stream);
            var text = new StringBuilder(hash.Length * 2);
            foreach (var value in hash)
            {
                text.Append(value.ToString("x2"));
            }

            return (info.Length, text.ToString());
        }
        catch (IOException)
        {
            return (0, string.Empty);
        }
        catch (UnauthorizedAccessException)
        {
            return (0, string.Empty);
        }
    }
}
