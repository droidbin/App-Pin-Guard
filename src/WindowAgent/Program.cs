using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using System.Threading;

internal static class AgentLog
{
    internal static string Path
    {
        get { return System.IO.Path.Combine(WapPaths.UserLogsDir, "agent.log"); }
    }

    internal static void Info(string key, params string[] fields) { WapLog.Info("agent", Path, key, fields); }
    internal static void Warn(string key, params string[] fields) { WapLog.Warn("agent", Path, key, fields); }
    internal static void Exception(string key, Exception ex) { WapLog.Exception("agent", Path, key, ex); }
}

// Hides (and optionally closes) windows of locked apps in this user session.
// Policy comes from Runtime\enforcement.txt, written by the service. Exit codes:
// 0 = stop event, 1 = exception, 2 = another agent runs in this session, 3 = no enforcement file for 30 s.
internal sealed class WindowAgent
{
    private const uint WmClose = 0x0010;
    private static readonly StringComparer Names = StringComparer.OrdinalIgnoreCase;

    private readonly HashSet<string> hidePaths = new HashSet<string>(Names);
    private readonly HashSet<string> hidePackages = new HashSet<string>(Names);
    private readonly Dictionary<string, long> hideBefore = new Dictionary<string, long>(Names);
    private readonly HashSet<string> closeTargets = new HashSet<string>(Names);
    private readonly Dictionary<int, long> granted = new Dictionary<int, long>();
    private readonly Dictionary<IntPtr, WindowIdentity> hidden = new Dictionary<IntPtr, WindowIdentity>();
    private readonly Dictionary<uint, ProcessInfo> processes = new Dictionary<uint, ProcessInfo>();
    private readonly string journal;
    private bool policyReady;
    private long policyRevision = -1;
    private long closedRevision = -1;
    private string lastPolicyText;
    private int hiddenSinceSummary, restoredSinceSummary;
    private DateTime nextSummary = DateTime.UtcNow.AddMinutes(1);

    private struct ProcessInfo
    {
        internal string Path;
        internal string Family;
        internal long StartTicks;
        internal bool Matches;
    }

    internal WindowAgent(string journal)
    {
        this.journal = journal;
        if (!File.Exists(journal)) return;
        foreach (string line in File.ReadLines(journal).Take(8192))
        {
            string[] fields = line.Split(',');
            long handle, started;
            uint pid, thread;
            if (fields.Length == 4 && long.TryParse(fields[0], out handle) && uint.TryParse(fields[1], out pid) &&
                uint.TryParse(fields[2], out thread) && long.TryParse(fields[3], out started))
                hidden[new IntPtr(handle)] = new WindowIdentity(pid, thread, started);
        }
    }

    private static int Main(string[] args)
    {
        try
        {
            using (var mutex = new Mutex(false, @"Local\WindowsAppProtector.WindowAgent"))
            using (var self = Process.GetCurrentProcess())
            {
                try { if (!mutex.WaitOne(0)) return 2; }
                catch (AbandonedMutexException) { }
                try
                {
                    string journal = Path.Combine(WapPaths.UserDataDir, "window-agent-" + self.SessionId + ".state");
                    AgentLog.Info("agent.started", "session=" + self.SessionId, "pid=" + self.Id);
                    int code = new WindowAgent(journal).Run();
                    AgentLog.Info("agent.exit", "code=" + code);
                    return code;
                }
                finally { mutex.ReleaseMutex(); }
            }
        }
        catch (Exception ex)
        {
            AgentLog.Exception("agent.crashed", ex);
            // Windows that are hidden stay hidden: the service starts a new agent that picks the journal up.
            return 1;
        }
    }

    private int Run()
    {
        using (EventWaitHandle stop = OpenEvent(WapPaths.AgentStopEvent) ?? new ManualResetEvent(false))
        using (EventWaitHandle changed = OpenEvent(WapPaths.EnforcementChangedEvent) ?? new ManualResetEvent(false))
        {
            var started = DateTime.UtcNow;
            var nextPolicy = DateTime.MinValue;
            while (!stop.WaitOne(0))
            {
                var now = DateTime.UtcNow;
                if (now >= nextPolicy)
                {
                    nextPolicy = now.AddSeconds(2);
                    RefreshPolicy();
                }
                if (!policyReady && now - started > TimeSpan.FromSeconds(30))
                {
                    AgentLog.Warn("agent.nopolicy", "seconds=30");
                    return 3;
                }
                if (stop.WaitOne(0)) break;
                if (policyReady)
                {
                    try { Scan(); }
                    catch (Exception ex) { AgentLog.Exception("agent.scan.failed", ex); }
                }
                LogSummaryIfDue();
                // Wakes early when the service reports a change; otherwise rescans after 350 ms.
                int signalled = WaitHandle.WaitAny(new WaitHandle[] { stop, changed }, 350);
                if (signalled == 0) break;
                if (signalled == 1)
                {
                    nextPolicy = DateTime.MinValue;
                    Thread.Sleep(100);
                }
            }
            // Stop event: hidden windows are deliberately left hidden. The next agent (or the uninstall
            // procedure, which clears the policy first) decides whether to restore them.
            return 0;
        }
    }

    private static EventWaitHandle OpenEvent(string name)
    {
        try { return EventWaitHandle.OpenExisting(name, EventWaitHandleRights.Synchronize); }
        catch (WaitHandleCannotBeOpenedException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    // ---- policy ------------------------------------------------------------------------------------

    private void RefreshPolicy()
    {
        try
        {
            string file = WapPaths.EnforcementFile;
            if (!File.Exists(file)) return;
            // Only a file written by the service (SYSTEM or Administrators) is trusted.
            if (!WapSecurity.IsOwnedByServiceAccount(file)) { AgentLog.Warn("agent.policy.untrusted"); return; }
            string text = File.ReadAllText(file, Encoding.UTF8);
            if (text == lastPolicyText) return;
            Apply(EnforcementData.Parse(text));
            lastPolicyText = text;
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        catch (FormatException ex) { AgentLog.Exception("agent.policy.invalid", ex); }
    }

    private void Apply(EnforcementData data)
    {
        hidePaths.Clear();
        hidePackages.Clear();
        hideBefore.Clear();
        closeTargets.Clear();
        granted.Clear();
        foreach (string path in data.HidePaths) hidePaths.Add(path);
        foreach (string family in data.HidePackages) hidePackages.Add(family);
        foreach (var entry in data.HideBefore) hideBefore[entry.Key] = entry.Value;
        foreach (string target in data.Close) closeTargets.Add(target);
        foreach (var entry in data.Granted) granted[entry.Key] = entry.Value;
        policyReady = true;

        if (data.Revision != policyRevision)
        {
            AgentLog.Info("agent.policy.applied", "rev=" + data.Revision, "hide=" + (hidePaths.Count + hidePackages.Count),
                "before=" + hideBefore.Count, "close=" + closeTargets.Count);
            policyRevision = data.Revision;
        }
        // WM_CLOSE goes out once per revision, so a persistent C: line never closes the app again.
        if (closeTargets.Count > 0 && closedRevision != data.Revision)
        {
            closedRevision = data.Revision;
            CloseWindows();
        }
    }

    // ---- windows -----------------------------------------------------------------------------------

    internal void Scan()
    {
        processes.Clear();
        RestoreWindows(false);
        if (hidePaths.Count == 0 && hidePackages.Count == 0 && hideBefore.Count == 0) return;
        EnumWindows((window, ignored) =>
        {
            try
            {
                if (!IsWindowVisible(window) || !MatchesWindow(window)) return true;
                WindowIdentity identity;
                if (!TryIdentify(window, out identity)) return true;
                if (!hidden.ContainsKey(window) || !hidden[window].Equals(identity))
                {
                    if (hidden.Count >= 8192) return true;
                    hidden[window] = identity;
                    // Journal before hiding so a crash cannot strand a new window.
                    try { SaveJournal(); }
                    catch (IOException) { hidden.Remove(window); return true; }
                    catch (UnauthorizedAccessException) { hidden.Remove(window); return true; }
                    hiddenSinceSummary++;
                }
                ShowWindowAsync(window, 0);
            }
            catch (Exception) { /* The window or process may disappear while enumerating. */ }
            return true;
        }, IntPtr.Zero);
    }

    // Restores windows whose process no longer needs hiding (the app was unlocked or the policy changed).
    private void RestoreWindows(bool all)
    {
        bool changed = false;
        foreach (var entry in hidden.ToArray())
        {
            WindowIdentity identity;
            if (TryIdentify(entry.Key, out identity) && identity.Equals(entry.Value))
            {
                if (!all && MatchesWindow(entry.Key)) continue;
                if (!IsWindowVisible(entry.Key))
                {
                    ShowWindowAsync(entry.Key, 8);
                    restoredSinceSummary++;
                    continue;
                }
            }
            hidden.Remove(entry.Key);
            changed = true;
        }
        if (changed)
        {
            try { SaveJournal(); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private void CloseWindows()
    {
        processes.Clear();
        EnumWindows((window, ignored) =>
        {
            try
            {
                if (!IsWindowVisible(window)) return true;
                uint pid;
                GetWindowThreadProcessId(window, out pid);
                ProcessInfo info = Describe(pid);
                if (closeTargets.Contains(info.Path ?? string.Empty) || closeTargets.Contains(info.Family ?? string.Empty))
                    PostMessage(window, WmClose, IntPtr.Zero, IntPtr.Zero);
            }
            catch (Exception) { }
            return true;
        }, IntPtr.Zero);
    }

    private void SaveJournal()
    {
        if (hidden.Count == 0) { File.Delete(journal); return; }
        Directory.CreateDirectory(Path.GetDirectoryName(journal));
        string temp = journal + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllLines(temp, hidden.Select(entry => string.Format(CultureInfo.InvariantCulture, "{0},{1},{2},{3}",
                entry.Key.ToInt64(), entry.Value.Pid, entry.Value.Thread, entry.Value.Started)));
            if (File.Exists(journal)) File.Replace(temp, journal, null);
            else File.Move(temp, journal);
        }
        finally { File.Delete(temp); }
    }

    private void LogSummaryIfDue()
    {
        if (DateTime.UtcNow < nextSummary) return;
        nextSummary = DateTime.UtcNow.AddMinutes(1);
        if (hiddenSinceSummary == 0 && restoredSinceSummary == 0) return;
        AgentLog.Info("agent.windows", "hidden=" + hiddenSinceSummary, "restored=" + restoredSinceSummary,
            "tracked=" + hidden.Count);
        hiddenSinceSummary = 0;
        restoredSinceSummary = 0;
    }

    // ---- matching ----------------------------------------------------------------------------------

    private bool MatchesWindow(IntPtr window)
    {
        uint owner;
        GetWindowThreadProcessId(window, out owner);
        if (Describe(owner).Matches) return true;
        if (hidePackages.Count == 0) return false;
        // A packaged app's frame is owned by ApplicationFrameHost; the app's own process owns a child window.
        bool match = false;
        EnumChildWindows(window, (child, ignored) =>
        {
            uint pid;
            GetWindowThreadProcessId(child, out pid);
            match = pid != owner && Describe(pid).Matches;
            return !match;
        }, IntPtr.Zero);
        return match;
    }

    private ProcessInfo Describe(uint pid)
    {
        ProcessInfo info;
        if (pid == 0) return default(ProcessInfo);
        if (processes.TryGetValue(pid, out info)) return info;
        var handle = OpenProcess(0x1000, false, pid);
        if (handle != IntPtr.Zero)
        {
            try
            {
                var image = new StringBuilder(32768);
                int length = image.Capacity;
                if (QueryFullProcessImageName(handle, 0, image, ref length)) info.Path = image.ToString();
                long created, exited, kernel, user;
                if (GetProcessTimes(handle, out created, out exited, out kernel, out user) && created > 0)
                    info.StartTicks = DateTime.FromFileTimeUtc(created).Ticks;
                if (hidePackages.Count > 0)
                {
                    int count = 0;
                    if (GetPackageFamilyName(handle, ref count, null) == 122 && count > 0 && count < 512)
                    {
                        var family = new StringBuilder(count);
                        if (GetPackageFamilyName(handle, ref count, family) == 0) info.Family = family.ToString();
                    }
                }
            }
            finally { CloseHandle(handle); }
        }
        info.Matches = ShouldHide(pid, info);
        processes[pid] = info;
        return info;
    }

    private bool ShouldHide(uint pid, ProcessInfo info)
    {
        long approvedStart;
        // Approved launches are never hidden.
        if (granted.TryGetValue((int)pid, out approvedStart) && approvedStart == info.StartTicks) return false;
        if (info.Path != null)
        {
            if (hidePaths.Contains(info.Path)) return true;
            long lockedAt;
            if (hideBefore.TryGetValue(info.Path, out lockedAt) && info.StartTicks > 0 && info.StartTicks < lockedAt) return true;
        }
        return info.Family != null && hidePackages.Contains(info.Family);
    }

    private static bool TryIdentify(IntPtr window, out WindowIdentity identity)
    {
        identity = default(WindowIdentity);
        uint pid;
        uint thread = GetWindowThreadProcessId(window, out pid);
        if (thread == 0 || pid == 0 || pid > int.MaxValue) return false;
        try
        {
            using (var process = Process.GetProcessById((int)pid))
                identity = new WindowIdentity(pid, thread, process.StartTime.ToUniversalTime().Ticks);
            return true;
        }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
        catch (System.ComponentModel.Win32Exception) { return false; }
    }

    private struct WindowIdentity
    {
        internal readonly uint Pid, Thread;
        internal readonly long Started;
        internal WindowIdentity(uint pid, uint thread, long started) { Pid = pid; Thread = thread; Started = started; }
    }

    private delegate bool EnumProc(IntPtr window, IntPtr state);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc callback, IntPtr state);
    [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr window, EnumProc callback, IntPtr state);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] private static extern bool ShowWindowAsync(IntPtr window, int command);
    [DllImport("user32.dll")] private static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("kernel32.dll")] private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder image, ref int size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackageFamilyName(IntPtr process, ref int length, StringBuilder name);
}
