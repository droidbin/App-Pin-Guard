using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading;

internal sealed class PolicyState
{
    internal PolicyDocument Policy;
    internal SecretsDocument Secrets;
}

// Loads the policy, remembers the last good one, and applies it everywhere. Three triggers (the UI's kernel
// event, a file watcher and a 5 second timer) funnel into one serialized, debounced Apply().
internal sealed class PolicyHost : IDisposable
{
    private readonly StatusWriter status;
    private readonly object applyLock = new object();
    private readonly object stateLock = new object();
    private EventWaitHandle policyChanged;
    private EventWaitHandle enforcementChanged;
    private RegisteredWaitHandle policyWait;
    private FileSystemWatcher watcher;
    private Timer tick;
    private Timer debounce;
    private Timer enforcementReset;
    private string lastEnforcement = string.Empty;
    private string lastError;
    private PolicyState current;
    private volatile bool stopping;

    internal RuleEngine Rules;
    internal GrantTable Grants;
    internal ProcessWatcher Watcher;

    internal PolicyHost(StatusWriter status)
    {
        this.status = status;
    }

    // Last policy that loaded cleanly; null until the first successful load.
    internal PolicyState Current
    {
        get { lock (stateLock) return current; }
    }

    internal void Start()
    {
        policyChanged = CreateEvent(WapPaths.PolicyChangedEvent, EventResetMode.AutoReset,
            WapSecurity.AdminsSid, EventWaitHandleRights.Modify | EventWaitHandleRights.Synchronize);
        enforcementChanged = CreateEvent(WapPaths.EnforcementChangedEvent, EventResetMode.ManualReset,
            WapSecurity.UsersSid, EventWaitHandleRights.Synchronize);
        policyWait = ThreadPool.RegisterWaitForSingleObject(policyChanged,
            delegate(object state, bool timedOut) { RequestApply(); }, null, Timeout.Infinite, false);

        try
        {
            watcher = new FileSystemWatcher(WapPaths.Root);
            watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size;
            watcher.Created += OnFileEvent;
            watcher.Changed += OnFileEvent;
            watcher.Renamed += OnFileEvent;
            watcher.EnableRaisingEvents = true;
        }
        catch (Exception ex)
        {
            // The 5 second timer still picks changes up.
            ServiceLog.Exception("policy.watcher.failed", ex);
        }

        debounce = new Timer(delegate { ApplySafely(); }, null, Timeout.Infinite, Timeout.Infinite);
        enforcementReset = new Timer(delegate { ResetEnforcementEvent(); }, null, Timeout.Infinite, Timeout.Infinite);
        ApplySafely();
        tick = new Timer(delegate { ApplySafely(); }, null, 5000, 5000);
    }

    public void Dispose()
    {
        stopping = true;
        if (tick != null) { tick.Dispose(); tick = null; }
        if (debounce != null) { debounce.Dispose(); debounce = null; }
        if (enforcementReset != null) { enforcementReset.Dispose(); enforcementReset = null; }
        if (watcher != null) { watcher.Dispose(); watcher = null; }
        if (policyWait != null) { policyWait.Unregister(null); policyWait = null; }
        if (policyChanged != null) { policyChanged.Dispose(); policyChanged = null; }
        if (enforcementChanged != null) { enforcementChanged.Dispose(); enforcementChanged = null; }
    }

    private void OnFileEvent(object sender, FileSystemEventArgs e)
    {
        string name = e.Name ?? string.Empty;
        if (name.StartsWith("policy.json", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("secrets.json", StringComparison.OrdinalIgnoreCase)) RequestApply();
    }

    // Any number of triggers inside 100 ms produce a single Apply().
    internal void RequestApply()
    {
        Timer timer = debounce;
        if (stopping || timer == null) return;
        try { timer.Change(100, Timeout.Infinite); }
        catch (ObjectDisposedException) { }
    }

    private void ApplySafely()
    {
        if (stopping) return;
        try { Apply(); }
        catch (Exception ex)
        {
            ServiceLog.Exception("policy.apply.failed", ex);
        }
    }

    // ---- apply -------------------------------------------------------------------------------------

    internal void Apply()
    {
        lock (applyLock)
        {
            PolicyDocument policy = null;
            SecretsDocument secrets = null;
            string error = null;
            try
            {
                LegacyMigration.Run();
                policy = PolicyStore.LoadPolicy();
                secrets = PolicyStore.LoadSecrets();
            }
            catch (Exception ex)
            {
                error = ex.Message;
                if (error != lastError) ServiceLog.Exception("policy.load.failed", ex);
            }

            PolicyState previous = Current;
            if (error == null && policy == null && previous != null)
            {
                error = "policy.json is missing";
                if (error != lastError) ServiceLog.Error("policy.load.failed", "message=" + error);
            }
            lastError = error;

            if (error != null)
            {
                // Keep enforcing the last good policy; report why a newer one was not applied.
                status.Update(delegate(StatusDocument doc)
                {
                    doc.PolicyError = error;
                    doc.Healthy = false;
                });
                if (previous != null) WriteEnforcement(previous.Policy);
                status.Flush();
                return;
            }

            if (policy == null) policy = new PolicyDocument();
            if (secrets == null) secrets = new SecretsDocument();
            var state = new PolicyState { Policy = policy, Secrets = secrets };
            lock (stateLock) current = state;

            List<AppPolicy> newlyLocked = FindNewlyLocked(previous == null ? null : previous.Policy, policy);
            Dictionary<string, string> rules = Rules.Sync(policy);
            Grants.Prune(policy, secrets);
            Watcher.OnPolicyChanged(policy, newlyLocked);
            WriteEnforcement(policy);

            bool gateAvailable = Rules.GateAvailable;
            List<AppStatus> apps = policy.Apps.Select(app => new AppStatus
            {
                Id = app.Id,
                Name = app.Name,
                Mode = PolicyRules.GetMode(app),
                Rule = rules.ContainsKey(app.Id) ? rules[app.Id] : StatusDocument.RuleNone,
            }).ToList();
            status.SetApps(apps);
            status.Update(delegate(StatusDocument doc)
            {
                doc.AppliedRevision = policy.Revision;
                doc.PolicyError = null;
                doc.Watcher = Watcher.Mode;
                doc.Healthy = gateAvailable && !apps.Any(a => a.Rule != null && a.Rule.StartsWith("error:", StringComparison.Ordinal));
            });
            if (!gateAvailable) ServiceLog.Error("gate.missing");
            status.Flush();
        }
    }

    private static List<AppPolicy> FindNewlyLocked(PolicyDocument previous, PolicyDocument next)
    {
        var result = new List<AppPolicy>();
        if (previous == null) return result;
        foreach (AppPolicy app in next.Apps)
        {
            if (!app.Locked) continue;
            AppPolicy before = PolicyRules.FindById(previous, app.Id);
            if (before == null || !before.Locked) result.Add(app);
        }
        return result;
    }

    // ---- enforcement.txt ---------------------------------------------------------------------------

    private void WriteEnforcement(PolicyDocument policy)
    {
        var data = new EnforcementData { Revision = policy.Revision };
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var families = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var before = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        DateTime localNow = DateTime.Now;

        foreach (AppPolicy app in policy.Apps)
        {
            if (!app.Locked) continue;
            if (PolicyRules.IsWindowMode(app))
            {
                if (app.IsPackaged)
                {
                    if (!string.IsNullOrWhiteSpace(app.PackageFamilyName) && families.Add(app.PackageFamilyName))
                        data.HidePackages.Add(app.PackageFamilyName);
                }
                else
                {
                    string path = PolicyRules.NormalizePath(app.Path);
                    if (path.Length > 0 && paths.Add(path)) data.HidePaths.Add(path);
                }
                continue;
            }

            // Launch-mode app: windows of processes that were already running when it was locked are hidden.
            // Outside the configured lock hours the app is open, so nothing is hidden.
            if (!PolicyRules.IsWithinLockHours(app.Launch, localNow)) continue;
            string launchPath = PolicyRules.NormalizePath(app.Path);
            DateTime lockedAt = PolicyRules.ParseUtc(app.LockedAtUtc);
            if (launchPath.Length == 0 || lockedAt == DateTime.MinValue || !before.Add(launchPath)) continue;
            data.HideBefore.Add(new KeyValuePair<string, long>(launchPath, lockedAt.Ticks));
        }

        data.Close.AddRange(Watcher.CloseTargets(DateTime.UtcNow));
        data.Granted.AddRange(Grants.GrantedProcesses());

        string text = data.Serialize();
        if (text == lastEnforcement && File.Exists(WapPaths.EnforcementFile)) return;
        try
        {
            string temporary = WapPaths.EnforcementFile + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                File.WriteAllText(temporary, text, new UTF8Encoding(false));
                if (File.Exists(WapPaths.EnforcementFile)) File.Replace(temporary, WapPaths.EnforcementFile, null);
                else File.Move(temporary, WapPaths.EnforcementFile);
                SecureLayout.ShareRuntimeFile(WapPaths.EnforcementFile);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
            lastEnforcement = text;
            SignalEnforcement();
        }
        catch (Exception ex)
        {
            ServiceLog.Exception("enforcement.write.failed", ex);
        }
    }

    // A manual-reset event wakes every session's agent; it is reset shortly after so the next change wakes them again.
    private void SignalEnforcement()
    {
        EventWaitHandle handle = enforcementChanged;
        Timer reset = enforcementReset;
        if (handle == null || reset == null) return;
        try
        {
            handle.Set();
            reset.Change(300, Timeout.Infinite);
        }
        catch (ObjectDisposedException) { }
    }

    private void ResetEnforcementEvent()
    {
        EventWaitHandle handle = enforcementChanged;
        if (handle == null) return;
        try { handle.Reset(); }
        catch (ObjectDisposedException) { }
    }

    private static EventWaitHandle CreateEvent(string name, EventResetMode mode, System.Security.Principal.SecurityIdentifier sid,
        EventWaitHandleRights rights)
    {
        var security = new EventWaitHandleSecurity();
        security.AddAccessRule(new EventWaitHandleAccessRule(WapSecurity.SystemSid, EventWaitHandleRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new EventWaitHandleAccessRule(WapSecurity.AdminsSid,
            EventWaitHandleRights.Modify | EventWaitHandleRights.Synchronize | EventWaitHandleRights.ReadPermissions, AccessControlType.Allow));
        if (!sid.Equals(WapSecurity.AdminsSid))
            security.AddAccessRule(new EventWaitHandleAccessRule(sid, rights, AccessControlType.Allow));
        bool created;
        var handle = new EventWaitHandle(false, mode, name, out created, security);
        if (!created) AgentSupervisor.CheckExistingObjectOwner(handle, name);
        return handle;
    }
}
