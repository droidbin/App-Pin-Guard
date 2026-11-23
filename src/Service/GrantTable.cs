using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;

internal enum AuthResult
{
    Approved,
    Denied,
    Prompt,
    RateLimited,
}

[DataContract]
internal sealed class LaunchAttemptState
{
    [DataMember] public int Failed { get; set; }
    [DataMember] public long DeadlineUtcTicks { get; set; }
}

// In-memory record of what the user has been allowed to start (design section 7.2).
// Keys use AppId and the PIN record version, never a hash or a path.
internal sealed class GrantTable
{
    private const int MaxEntries = 1024;
    private static readonly TimeSpan ApprovalWindow = TimeSpan.FromSeconds(5);

    private readonly object sync = new object();
    private readonly Dictionary<string, LaunchGrant> grants = new Dictionary<string, LaunchGrant>(StringComparer.Ordinal);
    private readonly Dictionary<int, PendingLaunch> pending = new Dictionary<int, PendingLaunch>();
    private readonly List<GateApproval> approvals = new List<GateApproval>();
    private readonly Dictionary<int, ProcessGrant> processes = new Dictionary<int, ProcessGrant>();

    private sealed class LaunchGrant
    {
        internal string AppId;
        internal long PinVersion;
        internal string Settings;
        internal DateTime Expires;
        internal readonly Dictionary<int, long> Processes = new Dictionary<int, long>();
    }

    private sealed class PendingLaunch
    {
        internal string Key;
        internal LaunchGrant Grant;
        internal DateTime Started, TrackBefore;
    }

    // A Gate process that was just approved for an app: its direct children are legitimate.
    private sealed class GateApproval
    {
        internal int GatePid;
        internal long GateStartTicks;
        internal string AppId;
        internal DateTime Expires;
    }

    private sealed class ProcessGrant
    {
        internal long StartTicks;
        internal string AppId;
    }

    internal AuthResult Authorize(PolicyDocument policy, SecretsDocument secrets, AppPolicy app, string sid,
        int sessionId, int gatePid, string pin, DateTime utcNow, out int retryAfterSeconds)
    {
        retryAfterSeconds = 0;
        lock (sync)
        {
            ExpireLocked(utcNow);
            if (!policy.EnableLaunchGate || app == null || !app.Locked ||
                !(PolicyRules.CanUseGate(app) || PolicyRules.CanUseWindowUnlock(app))) return AuthResult.Denied;

            PinRecord record = DefaultOrOwnPin(secrets, app);
            int minutes = Math.Max(0, Math.Min(app.Launch.AllowedMinutes, 1440));
            string settings = SettingsKey(app, minutes);
            string key = sid + "|" + sessionId.ToString(CultureInfo.InvariantCulture) + "|" + app.Id + "|" +
                record.Version.ToString(CultureInfo.InvariantCulture) + "|" + settings;

            // Outside the configured lock hours the app is not gated.
            if (!PolicyRules.IsWithinLockHours(app.Launch, DateTime.Now))
            {
                RecordApproval(gatePid, app.Id, utcNow);
                return AuthResult.Approved;
            }

            LaunchGrant active;
            if (minutes > 0 && grants.TryGetValue(key, out active))
            {
                if (!app.Launch.RelockOnExit || HasRunningLaunch(active))
                {
                    if (app.Launch.RelockOnExit) AllowTracking(gatePid, key, active, utcNow);
                    RecordApproval(gatePid, app.Id, utcNow);
                    return AuthResult.Approved;
                }
                grants.Remove(key);
            }

            string statePath = Path.Combine(WapPaths.AttemptsDir, sid + ".json");
            LaunchAttemptState state = LoadAttempts(statePath);
            if (state.DeadlineUtcTicks > utcNow.Ticks)
            {
                retryAfterSeconds = (int)Math.Max(1, Math.Ceiling(new TimeSpan(state.DeadlineUtcTicks - utcNow.Ticks).TotalSeconds));
                return AuthResult.RateLimited;
            }
            if (string.IsNullOrEmpty(pin)) return AuthResult.Prompt;

            if (PinHash.Verify(pin, record))
            {
                SaveAttempts(statePath, new LaunchAttemptState());
                if (minutes > 0 && grants.Count < MaxEntries)
                {
                    var grant = new LaunchGrant
                    {
                        AppId = app.Id,
                        PinVersion = record.Version,
                        Settings = settings,
                        Expires = utcNow.AddMinutes(minutes),
                    };
                    if (app.Launch.RelockOnExit) AllowTracking(gatePid, key, grant, utcNow);
                    else grants[key] = grant;
                }
                RecordApproval(gatePid, app.Id, utcNow);
                return AuthResult.Approved;
            }

            state.Failed = Math.Min(state.Failed + 1, 15);
            if (state.Failed >= 5)
                state.DeadlineUtcTicks = utcNow.AddSeconds(Math.Min(900, 30 * (1 << (state.Failed - 5)))).Ticks;
            SaveAttempts(statePath, state);
            if (state.DeadlineUtcTicks > utcNow.Ticks)
            {
                retryAfterSeconds = (int)Math.Max(1, Math.Ceiling(new TimeSpan(state.DeadlineUtcTicks - utcNow.Ticks).TotalSeconds));
                return AuthResult.RateLimited;
            }
            return AuthResult.Denied;
        }
    }

    // Gate reports the process it started. Only a child of the approved Gate that runs the app's executable counts.
    internal bool Track(AppPolicy app, string sid, int sessionId, int gatePid, int childPid, DateTime utcNow)
    {
        lock (sync)
        {
            ExpireLocked(utcNow);
            if (app == null) return false;
            long childStart = NativeApi.GetStartTicks(childPid);
            string image = NativeApi.GetImagePath(childPid);
            if (childStart == 0 || image == null || NativeApi.GetSessionId(childPid) != sessionId ||
                !PolicyRules.PathsEqual(image, app.Path)) return false;

            GateApproval approval = approvals.FirstOrDefault(a => a.GatePid == gatePid && a.AppId == app.Id);
            if (approval == null && !pending.ContainsKey(gatePid)) return false;
            if (!IsStartedAfter(childStart, approval, pending.ContainsKey(gatePid) ? pending[gatePid].Started : (DateTime?)null))
                return false;

            PendingLaunch launch;
            if (pending.TryGetValue(gatePid, out launch))
            {
                pending.Remove(gatePid);
                launch.Grant.Processes[childPid] = childStart;
                if (grants.Count < MaxEntries || grants.ContainsKey(launch.Key)) grants[launch.Key] = launch.Grant;
            }
            RegisterProcessLocked(childPid, childStart, app.Id);
            return true;
        }
    }

    // True when an approved Gate (started just before) is the parent of a process of this app.
    internal bool IsApprovedGateChild(int parentPid, string appId, DateTime utcNow)
    {
        lock (sync)
        {
            ExpireLocked(utcNow);
            // Gate may already have exited by the time the watcher looks; the 5 s approval window still covers it.
            return approvals.Any(a => a.GatePid == parentPid && a.AppId == appId);
        }
    }

    internal bool IsProcessGranted(int pid, long startTicks, string appId)
    {
        lock (sync)
        {
            ProcessGrant grant;
            return processes.TryGetValue(pid, out grant) && grant.StartTicks == startTicks && grant.AppId == appId;
        }
    }

    internal void RegisterProcess(int pid, long startTicks, string appId)
    {
        lock (sync) RegisterProcessLocked(pid, startTicks, appId);
    }

    // Processes that must not be hidden by the agent.
    internal List<KeyValuePair<int, long>> GrantedProcesses()
    {
        lock (sync)
        {
            foreach (int pid in processes.Keys.ToArray())
                if (!NativeApi.IsRunning(pid, processes[pid].StartTicks)) processes.Remove(pid);
            return processes.Select(p => new KeyValuePair<int, long>(p.Key, p.Value.StartTicks)).ToList();
        }
    }

    // Drops grants for apps that were unlocked or deleted, or whose PIN or launch policy changed.
    internal void Prune(PolicyDocument policy, SecretsDocument secrets)
    {
        lock (sync)
        {
            foreach (string key in grants.Keys.ToArray())
            {
                LaunchGrant grant = grants[key];
                AppPolicy app = PolicyRules.FindById(policy, grant.AppId);
                if (app == null || !app.Locked || !IsCurrent(app, secrets, grant.PinVersion, grant.Settings))
                    grants.Remove(key);
            }
            foreach (int pid in pending.Keys.ToArray())
                if (!grants.ContainsKey(pending[pid].Key) && PolicyRules.FindById(policy, pending[pid].Grant.AppId) == null)
                    pending.Remove(pid);
            foreach (int pid in processes.Keys.ToArray())
            {
                AppPolicy app = PolicyRules.FindById(policy, processes[pid].AppId);
                if (app == null || !app.Locked) processes.Remove(pid);
            }
            approvals.RemoveAll(a => PolicyRules.FindById(policy, a.AppId) == null);
        }
    }

    internal void RevokeAll()
    {
        lock (sync)
        {
            grants.Clear();
            pending.Clear();
            approvals.Clear();
        }
    }

    // ---- helpers -----------------------------------------------------------------------------------

    private static PinRecord DefaultOrOwnPin(SecretsDocument secrets, AppPolicy app)
    {
        PinRecord own = secrets.FindAppPin(app.Id);
        return own != null && own.IsSet ? own : secrets.AppPin;
    }

    private static string SettingsKey(AppPolicy app, int minutes)
    {
        return minutes.ToString(CultureInfo.InvariantCulture) + "|" + app.Launch.LockStartMinute + "|" +
            app.Launch.LockEndMinute + "|" + app.Launch.RelockOnExit;
    }

    private static bool IsCurrent(AppPolicy app, SecretsDocument secrets, long pinVersion, string settings)
    {
        int minutes = Math.Max(0, Math.Min(app.Launch.AllowedMinutes, 1440));
        return DefaultOrOwnPin(secrets, app).Version == pinVersion && SettingsKey(app, minutes) == settings;
    }

    private void ExpireLocked(DateTime utcNow)
    {
        foreach (string key in grants.Keys.ToArray())
            if (grants[key].Expires <= utcNow) grants.Remove(key);
        foreach (int pid in pending.Keys.ToArray())
            if (pending[pid].TrackBefore <= utcNow) pending.Remove(pid);
        approvals.RemoveAll(a => a.Expires <= utcNow);
    }

    private void AllowTracking(int gatePid, string key, LaunchGrant grant, DateTime utcNow)
    {
        if (pending.Count < MaxEntries)
            pending[gatePid] = new PendingLaunch { Key = key, Grant = grant, Started = utcNow, TrackBefore = utcNow.Add(ApprovalWindow) };
    }

    private void RecordApproval(int gatePid, string appId, DateTime utcNow)
    {
        if (approvals.Count >= MaxEntries) approvals.RemoveAt(0);
        approvals.Add(new GateApproval
        {
            GatePid = gatePid,
            GateStartTicks = NativeApi.GetStartTicks(gatePid),
            AppId = appId,
            Expires = utcNow.Add(ApprovalWindow),
        });
    }

    private void RegisterProcessLocked(int pid, long startTicks, string appId)
    {
        if (processes.Count >= 4096 && !processes.ContainsKey(pid)) return;
        processes[pid] = new ProcessGrant { StartTicks = startTicks, AppId = appId };
    }

    private static bool IsStartedAfter(long childStartTicks, GateApproval approval, DateTime? pendingStart)
    {
        // The child must not predate the approval that allowed it (allow a little clock granularity).
        DateTime child = new DateTime(childStartTicks, DateTimeKind.Utc);
        DateTime earliest = DateTime.MaxValue;
        if (approval != null) earliest = approval.Expires - ApprovalWindow;
        if (pendingStart.HasValue && pendingStart.Value < earliest) earliest = pendingStart.Value;
        return earliest == DateTime.MaxValue || child >= earliest.AddSeconds(-1);
    }

    private static bool HasRunningLaunch(LaunchGrant grant)
    {
        foreach (var started in grant.Processes.ToArray())
            if (!NativeApi.IsRunning(started.Key, started.Value)) grant.Processes.Remove(started.Key);
        return grant.Processes.Count != 0;
    }

    private static LaunchAttemptState LoadAttempts(string path)
    {
        try { return PolicyStore.Read<LaunchAttemptState>(path) ?? new LaunchAttemptState(); }
        catch (InvalidDataException) { return new LaunchAttemptState(); }
        catch (IOException) { return new LaunchAttemptState(); }
    }

    private static void SaveAttempts(string path, LaunchAttemptState state)
    {
        try { PolicyStore.WriteAtomic(path, state); }
        catch (IOException ex) { ServiceLog.Exception("attempts.save.failed", ex); }
        catch (UnauthorizedAccessException ex) { ServiceLog.Exception("attempts.save.failed", ex); }
    }
}
