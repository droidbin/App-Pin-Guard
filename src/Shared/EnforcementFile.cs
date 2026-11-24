using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

// Runtime\enforcement.txt: what the session agent and Gate must hide, close or leave alone.
//   WAP-ENF 2
//   rev=<policy revision>
//   A:<appId>|<kind>|<base64 match>|<lockedAtUtc ticks or 0>[|<base64 name>]   a locked app (kind W, P or L)
//   U:<sessionId>|<base64 userSid>|<appId>                      the app is unlocked for this user session
//   R:<sessionId>|<base64 userSid>|<appId>                      the app was unlocked here before and is running locked
//                                                               again: one PIN may reopen all R apps of the session
//   C:<base64 path or family>                                   send WM_CLOSE once for this revision
// Kinds: W window-mode Win32 app (match = path), P packaged app (match = package family),
//        L launch-mode app (match = path; only processes started before lockedAt are hidden).
internal sealed class EnforcementApp
{
    internal const string KindWindow = "W";
    internal const string KindPackage = "P";
    internal const string KindLaunch = "L";

    internal string Id = string.Empty;
    internal string Kind = KindWindow;
    internal string Match = string.Empty;
    internal long LockedAtTicks;
    // Display name for the grouped PIN prompt (empty when unknown).
    internal string Name = string.Empty;
}

internal sealed class EnforcementUnlock
{
    internal int Session;
    internal string Sid = string.Empty;
    internal string AppId = string.Empty;
}

internal sealed class EnforcementData
{
    internal const string Magic = "WAP-ENF 2";
    private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);

    internal long Revision;
    internal readonly List<EnforcementApp> Apps = new List<EnforcementApp>();
    internal readonly List<EnforcementUnlock> Unlocks = new List<EnforcementUnlock>();
    internal readonly List<EnforcementUnlock> Relocked = new List<EnforcementUnlock>();
    internal readonly List<string> Close = new List<string>();

    // The apps of this user session that were unlocked before and are locked again, in file order.
    internal List<string> RelockedApps(int session, string sid)
    {
        var ids = new List<string>();
        foreach (EnforcementUnlock entry in Relocked)
            if (entry.Session == session && string.Equals(entry.Sid, sid, StringComparison.OrdinalIgnoreCase) &&
                !ids.Contains(entry.AppId)) ids.Add(entry.AppId);
        return ids;
    }

    // True when the app is unlocked for exactly this user in this session.
    internal bool IsUnlocked(int session, string sid, string appId)
    {
        foreach (EnforcementUnlock unlock in Unlocks)
            if (unlock.Session == session && string.Equals(unlock.AppId, appId, StringComparison.Ordinal) &&
                string.Equals(unlock.Sid, sid, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    internal EnforcementApp FindApp(string appId)
    {
        foreach (EnforcementApp app in Apps)
            if (string.Equals(app.Id, appId, StringComparison.Ordinal)) return app;
        return null;
    }

    internal string Serialize()
    {
        var text = new StringBuilder();
        text.Append(Magic).Append('\n');
        text.Append("rev=").Append(Revision.ToString(CultureInfo.InvariantCulture)).Append('\n');
        foreach (EnforcementApp app in Apps)
            text.Append("A:").Append(app.Id).Append('|').Append(app.Kind).Append('|').Append(Encode(app.Match)).Append('|')
                .Append(app.LockedAtTicks.ToString(CultureInfo.InvariantCulture))
                .Append(string.IsNullOrEmpty(app.Name) ? string.Empty : "|" + Encode(app.Name)).Append('\n');
        foreach (EnforcementUnlock unlock in Unlocks)
            text.Append("U:").Append(unlock.Session.ToString(CultureInfo.InvariantCulture)).Append('|')
                .Append(Encode(unlock.Sid)).Append('|').Append(unlock.AppId).Append('\n');
        foreach (EnforcementUnlock entry in Relocked)
            text.Append("R:").Append(entry.Session.ToString(CultureInfo.InvariantCulture)).Append('|')
                .Append(Encode(entry.Sid)).Append('|').Append(entry.AppId).Append('\n');
        foreach (string target in Close) text.Append("C:").Append(Encode(target)).Append('\n');
        return text.ToString();
    }

    // Throws FormatException for malformed content: the reader then keeps its previous enforcement.
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
            string[] fields = body.Split('|');
            switch (line[0])
            {
                case 'A':
                {
                    long lockedAt;
                    if ((fields.Length != 4 && fields.Length != 5) || fields[0].Length == 0 || !IsKind(fields[1]) ||
                        !long.TryParse(fields[3], NumberStyles.None, CultureInfo.InvariantCulture, out lockedAt))
                        throw new FormatException("Invalid enforcement app.");
                    data.Apps.Add(new EnforcementApp
                    {
                        Id = fields[0],
                        Kind = fields[1],
                        Match = Decode(fields[2]),
                        LockedAtTicks = lockedAt,
                        Name = fields.Length == 5 ? Decode(fields[4]) : string.Empty,
                    });
                    break;
                }
                case 'U':
                case 'R':
                {
                    int session;
                    if (fields.Length != 3 || fields[2].Length == 0 ||
                        !int.TryParse(fields[0], NumberStyles.None, CultureInfo.InvariantCulture, out session))
                        throw new FormatException("Invalid enforcement unlock.");
                    var entry = new EnforcementUnlock { Session = session, Sid = Decode(fields[1]), AppId = fields[2] };
                    if (line[0] == 'U') data.Unlocks.Add(entry);
                    else data.Relocked.Add(entry);
                    break;
                }
                case 'C':
                    data.Close.Add(Decode(body));
                    break;
                default:
                    throw new FormatException("Unknown enforcement rule.");
            }
        }
        if (!hasRevision) throw new FormatException("Missing enforcement revision.");
        return data;
    }

    private static bool IsKind(string kind)
    {
        return kind == EnforcementApp.KindWindow || kind == EnforcementApp.KindPackage || kind == EnforcementApp.KindLaunch;
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

// Which locked app an executable path or package family belongs to. Service, agent and Gate share these rules.
internal static class AppMatcher
{
    // A packaged app is identified by its package family, everything else by its executable path.
    internal static bool Matches(bool packaged, string match, string imagePath, string packageFamily)
    {
        if (string.IsNullOrEmpty(match)) return false;
        if (packaged) return !string.IsNullOrEmpty(packageFamily) && string.Equals(packageFamily, match, StringComparison.OrdinalIgnoreCase);
        return PathEquals(imagePath, match);
    }

    internal static EnforcementApp Match(IEnumerable<EnforcementApp> apps, string imagePath, string packageFamily)
    {
        // Package family first (spec 4.1 step 1), then executable path (step 2), whatever the list order.
        EnforcementApp byPath = null;
        foreach (EnforcementApp app in apps)
        {
            bool packaged = app.Kind == EnforcementApp.KindPackage;
            if (!Matches(packaged, app.Match, imagePath, packageFamily)) continue;
            if (packaged) return app;
            if (byPath == null) byPath = app;
        }
        return byPath;
    }

    internal static bool PathEquals(string left, string right)
    {
        string a = Normalize(left);
        string b = Normalize(right);
        return a.Length > 0 && string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path)) return string.Empty;
        try { return Path.GetFullPath(path); }
        catch (ArgumentException) { return string.Empty; }
        catch (NotSupportedException) { return string.Empty; }
        catch (PathTooLongException) { return string.Empty; }
    }
}
