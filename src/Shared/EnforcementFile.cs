using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

// Runtime\enforcement.txt: what the session agent must hide, close or leave alone.
//   WAP-ENF 1
//   rev=<policy revision>
//   W:<base64 path>                      hide windows of this executable
//   F:<base64 package family>            hide windows of this package
//   L:<base64 path>|<lockedAtUtc ticks>  hide windows of processes of this executable that started before the ticks
//   C:<base64 path or family>            send WM_CLOSE once for this revision
//   G:<pid>|<startTimeUtc ticks>         approved process: never hide
internal sealed class EnforcementData
{
    internal const string Magic = "WAP-ENF 1";
    private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);

    internal long Revision;
    internal readonly List<string> HidePaths = new List<string>();
    internal readonly List<string> HidePackages = new List<string>();
    internal readonly List<KeyValuePair<string, long>> HideBefore = new List<KeyValuePair<string, long>>();
    internal readonly List<string> Close = new List<string>();
    internal readonly List<KeyValuePair<int, long>> Granted = new List<KeyValuePair<int, long>>();

    internal string Serialize()
    {
        var text = new StringBuilder();
        text.Append(Magic).Append('\n');
        text.Append("rev=").Append(Revision.ToString(CultureInfo.InvariantCulture)).Append('\n');
        foreach (string path in HidePaths) text.Append("W:").Append(Encode(path)).Append('\n');
        foreach (string family in HidePackages) text.Append("F:").Append(Encode(family)).Append('\n');
        foreach (var entry in HideBefore)
            text.Append("L:").Append(Encode(entry.Key)).Append('|')
                .Append(entry.Value.ToString(CultureInfo.InvariantCulture)).Append('\n');
        foreach (string target in Close) text.Append("C:").Append(Encode(target)).Append('\n');
        foreach (var entry in Granted)
            text.Append("G:").Append(entry.Key.ToString(CultureInfo.InvariantCulture)).Append('|')
                .Append(entry.Value.ToString(CultureInfo.InvariantCulture)).Append('\n');
        return text.ToString();
    }

    // Throws FormatException for malformed content: the agent then keeps its previous enforcement.
    internal static EnforcementData Parse(string text)
    {
        string[] lines = text.Replace("\r", string.Empty).Split('\n');
        if (lines.Length == 0 || lines[0] != Magic) throw new FormatException("Invalid enforcement header.");
        var data = new EnforcementData();
        bool hasRevision = false;
        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i];
            if (line.Length == 0) continue;
            if (line.StartsWith("rev=", StringComparison.Ordinal))
            {
                if (!long.TryParse(line.Substring(4), NumberStyles.None, CultureInfo.InvariantCulture, out data.Revision))
                    throw new FormatException("Invalid enforcement revision.");
                hasRevision = true;
                continue;
            }
            if (line.Length < 3 || line[1] != ':') throw new FormatException("Invalid enforcement rule.");
            string body = line.Substring(2);
            switch (line[0])
            {
                case 'W': data.HidePaths.Add(Decode(body)); break;
                case 'F': data.HidePackages.Add(Decode(body)); break;
                case 'C': data.Close.Add(Decode(body)); break;
                case 'L':
                {
                    int bar = body.LastIndexOf('|');
                    long ticks;
                    if (bar <= 0 || !long.TryParse(body.Substring(bar + 1), NumberStyles.None, CultureInfo.InvariantCulture, out ticks))
                        throw new FormatException("Invalid enforcement rule.");
                    data.HideBefore.Add(new KeyValuePair<string, long>(Decode(body.Substring(0, bar)), ticks));
                    break;
                }
                case 'G':
                {
                    int bar = body.IndexOf('|');
                    int pid;
                    long ticks;
                    if (bar <= 0 || !int.TryParse(body.Substring(0, bar), NumberStyles.None, CultureInfo.InvariantCulture, out pid) ||
                        !long.TryParse(body.Substring(bar + 1), NumberStyles.None, CultureInfo.InvariantCulture, out ticks))
                        throw new FormatException("Invalid enforcement rule.");
                    data.Granted.Add(new KeyValuePair<int, long>(pid, ticks));
                    break;
                }
                default:
                    throw new FormatException("Unknown enforcement rule.");
            }
        }
        if (!hasRevision) throw new FormatException("Missing enforcement revision.");
        return data;
    }

    private static string Encode(string value)
    {
        return Convert.ToBase64String(Utf8.GetBytes(value ?? string.Empty));
    }

    private static string Decode(string value)
    {
        return Utf8.GetString(Convert.FromBase64String(value));
    }
}
