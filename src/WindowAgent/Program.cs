using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
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
    private static readonly TimeSpan PromptInterval = TimeSpan.FromSeconds(5);

    private readonly Dictionary<IntPtr, WindowIdentity> hidden = new Dictionary<IntPtr, WindowIdentity>();
    private readonly WindowResolver resolver = new WindowResolver();
    private readonly HashSet<string> closeTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Process> prompts = new Dictionary<string, Process>(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTime> nextPrompt = new Dictionary<string, DateTime>(StringComparer.Ordinal);
    private readonly HashSet<string> promptedSinceStart = new HashSet<string>(StringComparer.Ordinal);
    private readonly string journal;
    private readonly int session;
    private readonly string sid;
    private EnforcementData current = new EnforcementData();
    private bool policyReady;
    private long policyRevision = -1;
    private long closedRevision = -1;
    private string lastPolicyText;
    private string lastUnlockState = string.Empty;
    private int hiddenSinceSummary, restoredSinceSummary;
    private DateTime nextSummary = DateTime.UtcNow.AddMinutes(1);

    internal WindowAgent(string journal, int session, string sid)
    {
        this.journal = journal;
        this.session = session;
        this.sid = sid ?? string.Empty;
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
                    string userSid;
                    using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) userSid = identity.User == null ? string.Empty : identity.User.Value;
                    int code = new WindowAgent(journal, self.SessionId, userSid).Run();
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
                // The file is replaced atomically, so it can be read right away.
                if (signalled == 1) nextPolicy = DateTime.MinValue;
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

    internal void Apply(EnforcementData data)
    {
        current = data;
        resolver.SetApps(data.Apps);
        closeTargets.Clear();
        foreach (string target in data.Close) closeTargets.Add(target);
        policyReady = true;

        // An app that is unlocked again may get a fresh prompt the next time it is locked.
        foreach (EnforcementApp app in data.Apps)
            if (data.IsUnlocked(session, sid, app.Id)) promptedSinceStart.Remove(app.Id);

        string unlockState = string.Join(",", data.Unlocks
            .Where(u => u.Session == session && string.Equals(u.Sid, sid, StringComparison.OrdinalIgnoreCase))
            .Select(u => u.AppId).OrderBy(id => id, StringComparer.Ordinal).ToArray());
        if (unlockState != lastUnlockState)
        {
            AgentLog.Info("agent.unlock.state", "unlocked=" + (unlockState.Length == 0 ? 0 : unlockState.Split(',').Length));
            lastUnlockState = unlockState;
        }
        if (data.Revision != policyRevision)
        {
            AgentLog.Info("agent.policy.applied", "rev=" + data.Revision, "apps=" + data.Apps.Count);
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
        resolver.Reset();
        RestoreWindows(false);
        if (current.Apps.Count == 0) return;
        EnumWindows((window, ignored) =>
        {
            try
            {
                if (!IsWindowVisible(window)) return true;
                WindowResolver.Resolution resolution;
                if (!resolver.Resolve(window, out resolution) || !ShouldHide(resolution)) return true;
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
                    PromptUnlock(resolution);
                }
                ShowWindowAsync(window, 0);
            }
            catch (Exception) { /* The window or process may disappear while enumerating. */ }
            return true;
        }, IntPtr.Zero);
    }

    // The window belongs to a locked app that is not unlocked in this session. Launch-mode apps are only
    // hidden for processes that were already running when the app was locked.
    private bool ShouldHide(WindowResolver.Resolution resolution)
    {
        if (current.IsUnlocked(session, sid, resolution.App.Id)) return false;
        if (resolution.App.Kind == EnforcementApp.KindLaunch)
            return resolution.StartTicks > 0 && resolution.StartTicks < resolution.App.LockedAtTicks;
        return true;
    }

    // A newly hidden window of a locked app: ask for the PIN through Gate. Gate itself keeps the prompt single
    // per app and session (named mutex), so a restarted agent cannot create a second one.
    private void PromptUnlock(WindowResolver.Resolution resolution)
    {
        string appId = resolution.App.Id;
        promptedSinceStart.Add(appId);
        try
        {
            Process running;
            if (prompts.TryGetValue(appId, out running))
            {
                bool alive = !running.HasExited;
                if (alive) return;
                running.Dispose();
                prompts.Remove(appId);
            }
            DateTime due;
            if (nextPrompt.TryGetValue(appId, out due) && DateTime.UtcNow < due) return;
            string gate = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, WapPaths.GateExeName);
            string exePath = !string.IsNullOrEmpty(resolution.Path)
                ? resolution.Path
                : (resolution.App.Kind == EnforcementApp.KindPackage ? null : resolution.App.Match);
            if (!File.Exists(gate) || string.IsNullOrEmpty(exePath)) return;
            nextPrompt[appId] = DateTime.UtcNow.Add(PromptInterval);
            prompts[appId] = Process.Start(new ProcessStartInfo(gate,
                "--unlock " + appId + " \"" + exePath + "\"") { UseShellExecute = false });
            AgentLog.Info("agent.unlock.prompt", "app=" + Path.GetFileName(exePath), "id=" + appId);
        }
        catch (System.ComponentModel.Win32Exception ex) { AgentLog.Exception("agent.unlock.failed", ex); }
        catch (InvalidOperationException ex) { AgentLog.Exception("agent.unlock.failed", ex); }
    }

    // Restores windows whose app is unlocked or no longer locked.
    private void RestoreWindows(bool all)
    {
        bool changed = false;
        Dictionary<string, int> restored = null;
        foreach (var entry in hidden.ToArray())
        {
            WindowIdentity identity;
            if (TryIdentify(entry.Key, out identity) && identity.Equals(entry.Value))
            {
                WindowResolver.Resolution resolution;
                bool resolved = resolver.Resolve(entry.Key, out resolution);
                if (!all && resolved && ShouldHide(resolution))
                {
                    // A window an earlier agent hid: the PIN prompt it had open is gone, so ask once after a restart.
                    if (!promptedSinceStart.Contains(resolution.App.Id)) PromptUnlock(resolution);
                    continue;
                }
                if (!IsWindowVisible(entry.Key))
                {
                    ShowWindowAsync(entry.Key, 8);
                    restoredSinceSummary++;
                    if (restored == null) restored = new Dictionary<string, int>(StringComparer.Ordinal);
                    string id = resolved ? resolution.App.Id : "unknown";
                    int count;
                    restored.TryGetValue(id, out count);
                    restored[id] = count + 1;
                    continue;
                }
            }
            hidden.Remove(entry.Key);
            changed = true;
        }
        if (restored != null)
            foreach (var pair in restored) AgentLog.Info("agent.restore", "app=" + pair.Key, "count=" + pair.Value);
        if (changed)
        {
            try { SaveJournal(); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private void CloseWindows()
    {
        resolver.Reset();
        EnumWindows((window, ignored) =>
        {
            try
            {
                if (!IsWindowVisible(window)) return true;
                uint pid;
                GetWindowThreadProcessId(window, out pid);
                string path, family;
                resolver.DescribeProcess(pid, out path, out family);
                if (closeTargets.Contains(path ?? string.Empty) || closeTargets.Contains(family ?? string.Empty))
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

    // ---- window identity ---------------------------------------------------------------------------

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
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] private static extern bool ShowWindowAsync(IntPtr window, int command);
    [DllImport("user32.dll")] private static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
}
