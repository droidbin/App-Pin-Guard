using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

internal static class ServiceLog
{
    internal static string Path
    {
        get { return System.IO.Path.Combine(WapPaths.LogsDir, "service.log"); }
    }

    internal static void Info(string key, params string[] fields) { WapLog.Info("service", Path, key, fields); }
    internal static void Warn(string key, params string[] fields) { WapLog.Warn("service", Path, key, fields); }
    internal static void Error(string key, params string[] fields) { WapLog.Error("service", Path, key, fields); }
    internal static void Exception(string key, Exception ex) { WapLog.Exception("service", Path, key, ex); }

    // Event Log carries service start/stop and FATAL only.
    internal static void EventLogEntry(string message, EventLogEntryType type)
    {
        try { EventLog.WriteEntry(ProductBrand.Name, message, type); }
        catch (Exception) { }
    }
}

// Owns Runtime\status.json. Components update it through Update(); it is flushed at most every 500 ms
// from the worker heartbeat or immediately via Flush().
internal sealed class StatusWriter
{
    private const int MaxTamperEvents = 20;
    private readonly object sync = new object();
    private readonly StatusDocument document = new StatusDocument();

    internal StatusWriter()
    {
        document.ServiceVersion = GetVersion();
        document.StartedAtUtc = DateTime.UtcNow.ToString("o");
    }

    internal void Update(Action<StatusDocument> change)
    {
        lock (sync) change(document);
    }

    internal void AddTamper(string detail)
    {
        lock (sync)
        {
            document.TamperEvents.Insert(0, new TamperEvent { AtUtc = DateTime.UtcNow.ToString("o"), Detail = detail });
            while (document.TamperEvents.Count > MaxTamperEvents)
                document.TamperEvents.RemoveAt(document.TamperEvents.Count - 1);
        }
        ServiceLog.Warn("tamper.detected", "detail=" + detail);
    }

    internal void MarkBlocked(string appId, DateTime utc)
    {
        lock (sync)
        {
            foreach (AppStatus app in document.Apps)
                if (app.Id == appId) app.LastBlockedUtc = utc.ToString("o");
            pendingBlocked[appId] = utc.ToString("o");
        }
    }

    // Blocked timestamps survive the Apps list being rebuilt on every policy apply.
    private readonly Dictionary<string, string> pendingBlocked = new Dictionary<string, string>();

    internal void SetApps(List<AppStatus> apps)
    {
        lock (sync)
        {
            foreach (AppStatus app in apps)
            {
                string blocked;
                if (pendingBlocked.TryGetValue(app.Id, out blocked)) app.LastBlockedUtc = blocked;
            }
            document.Apps = apps;
        }
    }

    internal void Flush()
    {
        try
        {
            lock (sync)
            {
                document.UpdatedAtUtc = DateTime.UtcNow.ToString("o");
                PolicyStore.WriteAtomic(WapPaths.StatusFile, document);
                SecureLayout.ShareRuntimeFile(WapPaths.StatusFile);
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Exception("status.write.failed", ex);
        }
    }

    // The UI executable ships in the same folder and carries the product version.
    private static string GetVersion()
    {
        try
        {
            string ui = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, WapPaths.UiExeName);
            if (!File.Exists(ui)) return "unknown";
            return FileVersionInfo.GetVersionInfo(ui).ProductVersion ?? "unknown";
        }
        catch (Exception)
        {
            return "unknown";
        }
    }
}
