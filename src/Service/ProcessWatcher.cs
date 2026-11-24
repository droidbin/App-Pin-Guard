using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

// Terminates locked launch-mode apps that were started without going through the PIN gate: renamed or copied
// executables, or launches that skip IFEO (design section 7.1).
internal sealed class ProcessWatcher : IDisposable
{
    private const long MaxHashBytes = 64L * 1024 * 1024;
    private static readonly TimeSpan NoticeInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan CloseGrace = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan CloseVisible = TimeSpan.FromSeconds(10);

    private readonly PolicyHost host;
    private readonly UnlockTable unlocks;
    private readonly StatusWriter status;
    // pid -> which locked app (if any) the process belongs to; refilled whenever the policy revision changes.
    private readonly Dictionary<int, CountedProcess> counted = new Dictionary<int, CountedProcess>();
    private long countedRevision = -1;
    private readonly string gatePath;
    private readonly object evalLock = new object();
    private readonly HashSet<string> handled = new HashSet<string>(StringComparer.Ordinal);
    private readonly Dictionary<int, long> known = new Dictionary<int, long>();
    private readonly Dictionary<string, DateTime> lastNotice = new Dictionary<string, DateTime>(StringComparer.Ordinal);
    private readonly Dictionary<string, string> hashCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    private readonly List<CloseRequest> closeRequests = new List<CloseRequest>();
    private readonly HashSet<string> loggedSkips = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private ManagementEventWatcher wmi;
    private Timer sweep;
    private Timer closer;
    private bool primed;

    private sealed class CloseRequest
    {
        internal string AppId;
        internal string AppName;
        internal string Target;
        internal bool Packaged;
        internal DateTime CreatedUtc;
        internal bool Killed;
    }

    private sealed class CountedProcess
    {
        internal long StartTicks;
        internal int Session;
        internal string AppId;
        internal string Sid;
    }

    // An app that has at least one process in a user session (from the last one-second snapshot).
    internal struct RunningApp
    {
        internal string Sid;
        internal int Session;
        internal string AppId;
    }

    private List<RunningApp> lastRunning = new List<RunningApp>();

    // Which apps are open in which user session right now, whether locked or not.
    internal List<RunningApp> RunningApps()
    {
        lock (counted) return new List<RunningApp>(lastRunning);
    }

    internal ProcessWatcher(PolicyHost host, UnlockTable unlocks, StatusWriter status, string gatePath)
    {
        this.host = host;
        this.unlocks = unlocks;
        this.status = status;
        this.gatePath = gatePath;
        Mode = "polling";
    }

    // "wmi" when process-start events are delivered, "polling" when only the 1 s sweep runs.
    internal string Mode { get; private set; }

    internal void Start()
    {
        Sweep();
        primed = true;
        try
        {
            wmi = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            wmi.EventArrived += OnProcessStarted;
            wmi.Start();
            Mode = "wmi";
        }
        catch (Exception ex)
        {
            Mode = "polling";
            ServiceLog.Warn("watcher.wmi.unavailable", "fallback=polling");
            ServiceLog.Exception("watcher.wmi.error", ex);
            if (wmi != null)
            {
                try { wmi.Dispose(); } catch (Exception) { }
                wmi = null;
            }
        }
        sweep = new Timer(delegate { Sweep(); }, null, 1000, 1000);
        closer = new Timer(delegate { KillExpiredCloseRequests(); }, null, 1000, 1000);
        ServiceLog.Info("watcher.started", "mode=" + Mode);
    }

    public void Dispose()
    {
        if (sweep != null) { sweep.Dispose(); sweep = null; }
        if (closer != null) { closer.Dispose(); closer = null; }
        if (wmi != null)
        {
            try { wmi.Stop(); wmi.Dispose(); } catch (Exception) { }
            wmi = null;
        }
    }

    // ---- event sources -----------------------------------------------------------------------------

    private void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            int pid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);
            int parent = Convert.ToInt32(e.NewEvent.Properties["ParentProcessID"].Value);
            int session = Convert.ToInt32(e.NewEvent.Properties["SessionID"].Value);
            Evaluate(pid, parent, session);
        }
        catch (Exception ex)
        {
            ServiceLog.Exception("watcher.event.failed", ex);
        }
    }

    // Backstop: WMI can drop events or restart its provider, so every second the process list is compared.
    private void Sweep()
    {
        try
        {
            List<NativeApi.ProcessEntry> processes = NativeApi.SnapshotProcesses();
            var current = new Dictionary<int, long>(processes.Count);
            var fresh = new List<NativeApi.ProcessEntry>();
            lock (evalLock)
            {
                foreach (NativeApi.ProcessEntry entry in processes)
                {
                    if (entry.Pid <= 4) continue;
                    long start;
                    if (!known.TryGetValue(entry.Pid, out start))
                    {
                        fresh.Add(entry);
                        start = 0;
                    }
                    current[entry.Pid] = start;
                }
                known.Clear();
                foreach (var pair in current) known[pair.Key] = pair.Value;
            }
            if (!primed) return;
            foreach (NativeApi.ProcessEntry entry in fresh)
                Evaluate(entry.Pid, entry.ParentPid, NativeApi.GetSessionId(entry.Pid));
            ObserveUnlocks(processes);
        }
        catch (Exception ex)
        {
            ServiceLog.Exception("watcher.sweep.failed", ex);
        }
    }

    // Tells the unlock table which locked apps are running in which session, so it can end unlocks of closed apps.
    private void ObserveUnlocks(List<NativeApi.ProcessEntry> processes)
    {
        lock (counted) ObserveUnlocksLocked(processes);
    }

    private void ObserveUnlocksLocked(List<NativeApi.ProcessEntry> processes)
    {
        PolicyState state = host.Current;
        if (state == null) return;
        bool anyPackaged = state.Policy.Apps.Any(a => a.IsPackaged);
        if (countedRevision != state.Policy.Revision)
        {
            counted.Clear();
            countedRevision = state.Policy.Revision;
        }

        var running = new Dictionary<string, int>(StringComparer.Ordinal);
        var present = new HashSet<int>();
        foreach (NativeApi.ProcessEntry entry in processes)
        {
            if (entry.Pid <= 4) continue;
            present.Add(entry.Pid);
            CountedProcess known;
            if (counted.TryGetValue(entry.Pid, out known))
            {
                // A reused pid must not inherit the previous owner's app.
                if (known.AppId == null || NativeApi.GetStartTicks(entry.Pid) == known.StartTicks)
                {
                    Count(running, known);
                    continue;
                }
                counted.Remove(entry.Pid);
            }

            long start = NativeApi.GetStartTicks(entry.Pid);
            string image = start == 0 ? null : NativeApi.GetImagePath(entry.Pid);
            var created = new CountedProcess { StartTicks = start, Session = NativeApi.GetSessionId(entry.Pid) };
            if (image != null && created.Session > 0)
            {
                string family = anyPackaged ? NativeApi.GetPackageFamilyName(entry.Pid) : null;
                // Unlocked apps are counted too: the relock group needs to know which ones are still open.
                AppPolicy app = PolicyRules.MatchApp(state.Policy, image, family, false);
                if (app != null)
                {
                    created.AppId = app.Id;
                    created.Sid = NativeApi.GetUserSid(entry.Pid);
                }
            }
            counted[entry.Pid] = created;
            Count(running, created);
        }
        foreach (int pid in counted.Keys.ToArray())
            if (!present.Contains(pid)) counted.Remove(pid);
        lastRunning = counted.Values.Where(c => c.AppId != null && c.Sid != null)
            .Select(c => new RunningApp { Sid = c.Sid, Session = c.Session, AppId = c.AppId })
            .Distinct().ToList();

        if (unlocks.Observe(running, DateTime.UtcNow))
        {
            ServiceLog.Info("unlock.ended");
            host.RequestApply();
        }
    }

    private static void Count(Dictionary<string, int> running, CountedProcess process)
    {
        if (process.AppId == null) return;
        string key = process.Session.ToString(System.Globalization.CultureInfo.InvariantCulture) + "|" + process.AppId;
        int count;
        running.TryGetValue(key, out count);
        running[key] = count + 1;
    }

    // ---- decision ----------------------------------------------------------------------------------

    private void Evaluate(int pid, int parentPid, int session)
    {
        if (session <= 0 || pid <= 4) return;
        PolicyState state = host.Current;
        if (state == null || state.Policy.Apps.Count == 0) return;

        lock (evalLock)
        {
            string image = NativeApi.GetImagePath(pid);
            long start = NativeApi.GetStartTicks(pid);
            if (image == null || start == 0) return;
            if (!handled.Add(pid.ToString() + ":" + start.ToString())) return;
            if (handled.Count > 20000) handled.Clear();

            AppPolicy app = MatchApp(state.Policy, image);
            if (app == null) return;

            DateTime now = DateTime.UtcNow;
            if (!PolicyRules.IsWithinLockHours(app.Launch, DateTime.Now)) return;
            // Unlocked means the app, not one process: Gate creates the record before it starts the app, and every
            // helper or restarted process of the app passes the same check.
            string sid = NativeApi.GetUserSid(pid);
            if (sid != null && unlocks.IsUnlocked(sid, session, app.Id, now)) return;

            bool terminated = NativeApi.Terminate(pid);
            status.MarkBlocked(app.Id, now);
            ServiceLog.Warn("watcher.blocked", "app=" + app.Name, "pid=" + pid, "session=" + session,
                "image=" + image, "terminated=" + terminated);
            ShowNotice(app, session, state.Policy, now);
        }
    }

    private AppPolicy MatchApp(PolicyDocument policy, string image)
    {
        AppPolicy byPath = null;
        List<AppPolicy> candidates = null;
        foreach (AppPolicy app in policy.Apps)
        {
            if (!app.Locked || !PolicyRules.CanUseGate(app)) continue;
            if (PolicyRules.PathsEqual(app.Path, image)) { byPath = app; break; }
            if (app.FileSize > 0 && !string.IsNullOrEmpty(app.Sha256))
            {
                if (candidates == null) candidates = new List<AppPolicy>();
                candidates.Add(app);
            }
        }
        if (byPath != null) return byPath;
        if (candidates == null) return null;

        // Renamed or copied executable: same size first, and the hash only when the size matches.
        FileInfo info;
        try
        {
            info = new FileInfo(image);
            if (!info.Exists) return null;
        }
        catch (Exception) { return null; }
        AppPolicy sameSize = candidates.FirstOrDefault(a => a.FileSize == info.Length);
        if (sameSize == null) return null;
        if (info.Length > MaxHashBytes)
        {
            if (loggedSkips.Add(image)) ServiceLog.Info("watcher.hash.skipped", "reason=too-large", "image=" + image);
            return null;
        }
        string hash = HashOf(info);
        if (hash == null) return null;
        AppPolicy match = candidates.FirstOrDefault(a => a.FileSize == info.Length &&
            string.Equals(a.Sha256, hash, StringComparison.OrdinalIgnoreCase));
        if (match != null) ServiceLog.Warn("watcher.copy.detected", "app=" + match.Name, "image=" + image);
        return match;
    }

    private string HashOf(FileInfo info)
    {
        string key = info.FullName + "|" + info.Length + "|" + info.LastWriteTimeUtc.Ticks;
        string cached;
        if (hashCache.TryGetValue(key, out cached)) return cached;
        try
        {
            using (var stream = new FileStream(info.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(stream);
                var text = new StringBuilder(hash.Length * 2);
                foreach (byte value in hash) text.Append(value.ToString("x2"));
                if (hashCache.Count > 512) hashCache.Clear();
                return hashCache[key] = text.ToString();
            }
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    private void ShowNotice(AppPolicy app, int session, PolicyDocument policy, DateTime now)
    {
        DateTime last;
        if (lastNotice.TryGetValue(app.Id, out last) && now - last < NoticeInterval) return;
        lastNotice[app.Id] = now;
        try
        {
            string verb = policy.EnableLaunchGate && PolicyRules.CanUseGate(app) ? "--launch" : "--notice-blocked";
            SessionLauncher.Launched process = SessionLauncher.Start(session, gatePath,
                verb + " " + SessionLauncher.Quote(app.Path), true);
            NativeApi.CloseHandle(process.Process);
        }
        catch (Exception ex)
        {
            ServiceLog.Exception("watcher.notice.failed", ex);
        }
    }

    // ---- lock transitions --------------------------------------------------------------------------

    // Apps whose Locked flag just changed to true. With CloseAppsOnLock the agent first asks their windows to
    // close; anything still running 5 seconds later is terminated here.
    internal void OnPolicyChanged(PolicyDocument policy, List<AppPolicy> newlyLocked)
    {
        if (!policy.CloseAppsOnLock || newlyLocked == null || newlyLocked.Count == 0) return;
        lock (closeRequests)
        {
            foreach (AppPolicy app in newlyLocked)
            {
                closeRequests.RemoveAll(r => r.AppId == app.Id);
                string target = app.IsPackaged ? app.PackageFamilyName : PolicyRules.NormalizePath(app.Path);
                if (string.IsNullOrEmpty(target)) continue;
                closeRequests.Add(new CloseRequest
                {
                    AppId = app.Id,
                    AppName = app.Name,
                    Target = target,
                    Packaged = app.IsPackaged,
                    CreatedUtc = DateTime.UtcNow,
                });
            }
        }
    }

    // Targets the agent should send WM_CLOSE to while the close request is fresh.
    internal List<string> CloseTargets(DateTime utcNow)
    {
        lock (closeRequests)
        {
            closeRequests.RemoveAll(r => utcNow - r.CreatedUtc > CloseVisible && r.Killed);
            return closeRequests.Where(r => utcNow - r.CreatedUtc <= CloseVisible).Select(r => r.Target).Distinct().ToList();
        }
    }

    private void KillExpiredCloseRequests()
    {
        try
        {
            List<CloseRequest> due;
            lock (closeRequests)
            {
                DateTime now = DateTime.UtcNow;
                due = closeRequests.Where(r => !r.Killed && now - r.CreatedUtc >= CloseGrace).ToList();
                foreach (CloseRequest request in due) request.Killed = true;
            }
            if (due.Count == 0) return;

            List<NativeApi.ProcessEntry> processes = NativeApi.SnapshotProcesses();
            foreach (CloseRequest request in due)
            {
                int killed = 0;
                foreach (NativeApi.ProcessEntry entry in processes)
                {
                    if (entry.Pid <= 4) continue;
                    bool match = request.Packaged
                        ? string.Equals(NativeApi.GetPackageFamilyName(entry.Pid), request.Target, StringComparison.OrdinalIgnoreCase)
                        : PolicyRules.PathsEqual(NativeApi.GetImagePath(entry.Pid), request.Target);
                    if (match && NativeApi.Terminate(entry.Pid)) killed++;
                }
                ServiceLog.Info("lock.close", "app=" + request.AppName, "terminated=" + killed);
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Exception("watcher.close.failed", ex);
        }
    }
}
