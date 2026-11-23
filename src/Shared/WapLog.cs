using System;
using System.Globalization;
using System.IO;
using System.Text;

// One-line-per-event UTF-8 log shared by every component.
// Format: 2026-11-23T14:03:12.481+09:00 INFO  service  rule.applied app=kakaotalk.exe mode=blocked
internal static class WapLog
{
    private const long MaxBytes = 1024 * 1024;
    private const int Generations = 3;
    private static readonly object Sync = new object();
    private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);

    internal static void Info(string component, string logPath, string eventKey, params string[] fields)
    {
        Write("INFO ", component, logPath, eventKey, fields);
    }

    internal static void Warn(string component, string logPath, string eventKey, params string[] fields)
    {
        Write("WARN ", component, logPath, eventKey, fields);
    }

    internal static void Error(string component, string logPath, string eventKey, params string[] fields)
    {
        Write("ERROR", component, logPath, eventKey, fields);
    }

    internal static void Fatal(string component, string logPath, string eventKey, params string[] fields)
    {
        Write("FATAL", component, logPath, eventKey, fields);
    }

    internal static void Exception(string component, string logPath, string eventKey, Exception ex)
    {
        Write("ERROR", component, logPath, eventKey, Describe(ex));
    }

    internal static void FatalException(string component, string logPath, string eventKey, Exception ex)
    {
        Write("FATAL", component, logPath, eventKey, Describe(ex));
    }

    // Exception text: type name, native error code / HResult, message, in that order.
    internal static string[] Describe(Exception ex)
    {
        if (ex == null) return new string[0];
        string native = string.Empty;
        var win32 = ex as System.ComponentModel.Win32Exception;
        if (win32 != null) native = win32.NativeErrorCode.ToString(CultureInfo.InvariantCulture);
        return new[]
        {
            "type=" + ex.GetType().Name,
            "code=" + (native.Length > 0 ? native : "0x" + ex.HResult.ToString("X8", CultureInfo.InvariantCulture)),
            "message=" + ex.Message,
        };
    }

    private static void Write(string level, string component, string logPath, string eventKey, string[] fields)
    {
        try
        {
            var line = new StringBuilder();
            line.Append(DateTimeOffset.Now.ToString("yyyy-MM-dd'T'HH:mm:ss.fffzzz", CultureInfo.InvariantCulture));
            line.Append(' ').Append(level).Append(' ');
            line.Append((component ?? string.Empty).PadRight(8)).Append(' ').Append(eventKey);
            if (fields != null)
            {
                foreach (string field in fields)
                {
                    if (string.IsNullOrEmpty(field)) continue;
                    line.Append(' ').Append(Quote(field));
                }
            }
            line.Append("\r\n");

            lock (Sync)
            {
                string directory = Path.GetDirectoryName(logPath);
                if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
                Rotate(logPath);
                using (var stream = new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                {
                    byte[] bytes = Utf8.GetBytes(line.ToString());
                    stream.Write(bytes, 0, bytes.Length);
                }
            }
        }
        catch (Exception)
        {
            // Logging must never take a component down.
        }
    }

    // key=value pairs whose value contains whitespace are written as key="value with spaces".
    private static string Quote(string field)
    {
        int equals = field.IndexOf('=');
        if (equals <= 0) return field.IndexOfAny(new[] { ' ', '\t', '\r', '\n' }) >= 0 ? "\"" + Flatten(field) + "\"" : field;
        string key = field.Substring(0, equals + 1);
        string value = field.Substring(equals + 1);
        if (value.IndexOfAny(new[] { ' ', '\t', '\r', '\n', '"' }) < 0) return field;
        return key + "\"" + Flatten(value).Replace("\"", "'") + "\"";
    }

    private static string Flatten(string value)
    {
        return value.Replace("\r", " ").Replace("\n", " ");
    }

    private static void Rotate(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length < MaxBytes) return;
        for (int index = Generations; index >= 1; index--)
        {
            string target = path + "." + index.ToString(CultureInfo.InvariantCulture);
            string source = index == 1 ? path : path + "." + (index - 1).ToString(CultureInfo.InvariantCulture);
            if (!File.Exists(source)) continue;
            if (File.Exists(target)) File.Delete(target);
            File.Move(source, target);
        }
    }
}
