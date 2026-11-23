using System;
using System.Collections.Generic;
using System.IO;

// Rules every component must agree on: which apps are window-only, IFEO rule names, lock hours.
internal static class PolicyRules
{
    internal const string ModeLaunch = "launch";
    internal const string ModeWindow = "window";

    // Browsers (and packaged apps) are not blocked at launch; their windows are hidden by the session agent.
    internal static readonly HashSet<string> WindowOnlyExecutableNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "arc.exe",
        "brave.exe",
        "chrome.exe",
        "firefox.exe",
        "iexplore.exe",
        "msedge.exe",
        "opera.exe",
        "opera_gx.exe",
        "samsunginternet.exe",
        "vivaldi.exe",
        "whale.exe",
    };

    internal static string GetRuleName(AppPolicy app)
    {
        if (app == null) return string.Empty;
        if (!string.IsNullOrWhiteSpace(app.ExecutableName)) return app.ExecutableName;
        if (string.IsNullOrWhiteSpace(app.Path)) return string.Empty;
        return Path.GetFileName(app.Path);
    }

    internal static string GetMode(AppPolicy app)
    {
        if (app == null) return ModeWindow;
        if (app.IsPackaged) return ModeWindow;
        string name = GetRuleName(app);
        return !string.IsNullOrWhiteSpace(name) && WindowOnlyExecutableNames.Contains(name) ? ModeWindow : ModeLaunch;
    }

    internal static bool IsWindowMode(AppPolicy app)
    {
        return GetMode(app) == ModeWindow;
    }

    // A launch-mode app can use the PIN gate only when it is a plain, rooted .exe.
    internal static bool CanUseGate(AppPolicy app)
    {
        return app != null && !IsWindowMode(app) && !string.IsNullOrWhiteSpace(app.Path) &&
            Path.IsPathRooted(app.Path) &&
            string.Equals(Path.GetExtension(app.Path), ".exe", StringComparison.OrdinalIgnoreCase);
    }

    internal static bool IsWithinLockHours(LaunchPolicy launch, DateTime localTime)
    {
        if (launch == null) return true;
        int? start = launch.LockStartMinute;
        int? end = launch.LockEndMinute;
        if (!start.HasValue || !end.HasValue || start < 0 || end < 0 || start >= 1440 || end >= 1440 || start == end)
            return true;
        int minute = localTime.Hour * 60 + localTime.Minute;
        return start < end ? minute >= start && minute < end : minute >= start || minute < end;
    }

    internal static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path)) return string.Empty;
        try { return Path.GetFullPath(path); }
        catch (ArgumentException) { return string.Empty; }
        catch (NotSupportedException) { return string.Empty; }
        catch (PathTooLongException) { return string.Empty; }
    }

    internal static bool PathsEqual(string left, string right)
    {
        string a = NormalizePath(left);
        string b = NormalizePath(right);
        return a.Length > 0 && string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    }

    internal static DateTime ParseUtc(string text)
    {
        DateTime value;
        if (!string.IsNullOrEmpty(text) && DateTime.TryParse(text, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out value))
            return value;
        return DateTime.MinValue;
    }

    internal static AppPolicy FindById(PolicyDocument policy, string id)
    {
        if (policy == null || policy.Apps == null || string.IsNullOrEmpty(id)) return null;
        foreach (AppPolicy app in policy.Apps)
            if (app != null && string.Equals(app.Id, id, StringComparison.Ordinal)) return app;
        return null;
    }

    // The launch-mode app, if any, that is registered for this exact executable path.
    internal static AppPolicy FindLaunchAppByPath(PolicyDocument policy, string path)
    {
        if (policy == null || policy.Apps == null) return null;
        foreach (AppPolicy app in policy.Apps)
        {
            if (app == null || !CanUseGate(app)) continue;
            if (PathsEqual(app.Path, path)) return app;
        }
        return null;
    }
}
