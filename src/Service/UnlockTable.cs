using System;
using System.Collections.Generic;
using System.Globalization;
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

// The one place that knows which apps are unlocked (docs/DESIGN-app-lock-redesign.md section 4).
// A record belongs to (user, session, app): every process and window of that app is open while it exists.
internal sealed class UnlockTable
{
    private const int MaxEntries = 1024;
    private static readonly TimeSpan ExitGrace = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan StartGrace = TimeSpan.FromSeconds(30);

    private readonly object sync = new object();
    private readonly Dictionary<string, AppUnlock> records = new Dictionary<string, AppUnlock>(StringComparer.Ordinal);
    private readonly Dictionary<string, LaunchAttemptState> memoryAttempts = new Dictionary<string, LaunchAttemptState>(StringComparer.Ordinal);

    // The service replaces these with file-backed storage (Attempts\<sid>.json); tests use the in-memory default.
    internal Func<string, LaunchAttemptState> LoadAttempts;
    internal Action<string, LaunchAttemptState> SaveAttempts;

    // An app that was unlocked here, got locked again while it kept running (screen lock, "lock all") and is therefore
    // offered together with its siblings in one PIN prompt.
    private sealed class RelockedApp
    {
        internal string UserSid;
        internal int SessionId;
        internal string AppId;
        internal DateTime AddedUtc;
        internal DateTime LastSeenRunningUtc;
    }

    private static readonly TimeSpan RelockedMaxAge = TimeSpan.FromHours(12);
    private readonly List<RelockedApp> relocked = new List<RelockedApp>();

    private sealed class AppUnlock
    {
        internal string UserSid;
        internal int SessionId;
        internal string AppId;
        internal long PinVersion;
        internal string Settings;
        internal DateTime UnlockedUtc;
        internal DateTime? ExpiresUtc;
        // False when AllowedMinutes > 0 and RelockOnExit is off: the app may be closed and reopened within the time.
        internal bool EndsOnExit;
        internal bool SeenRunning;
        internal DateTime LastSeenRunningUtc;
    }

    private static string KeyOf(string sid, int session, string appId)
    {
        return (sid ?? string.Empty).ToUpperInvariant() + "|" + session.ToString(CultureInfo.InvariantCulture) + "|" + appId;
    }

    internal AuthResult Authorize(PolicyDocument policy, SecretsDocument secrets, AppPolicy app, string sid,
        int sessionId, string pin, DateTime utcNow, out int retryAfterSeconds)
    {
        return Authorize(policy, secrets, app, sid, sessionId, pin, utcNow, null, out retryAfterSeconds);
    }

    // groupIds: other apps the user asked to unlock with the same PIN. Only apps in this user's relocked group are
    // taken, and only those whose own PIN matches; a mismatch there never counts as a failed attempt.
    internal AuthResult Authorize(PolicyDocument policy, SecretsDocument secrets, AppPolicy app, string sid,
        int sessionId, string pin, DateTime utcNow, IEnumerable<string> groupIds, out int retryAfterSeconds)
    {
        retryAfterSeconds = 0;
        lock (sync)
        {
            RemoveExpired(utcNow);
            if (!policy.EnableLaunchGate || app == null || !app.Locked ||
                !(PolicyRules.CanUseGate(app) || PolicyRules.CanUseWindowUnlock(app))) return AuthResult.Denied;

            // Outside the configured lock hours the app is not gated.
            if (!PolicyRules.IsWithinLockHours(app.Launch, DateTime.Now)) return AuthResult.Approved;

            PinRecord record = DefaultOrOwnPin(secrets, app);
            string settings = PolicyRules.SettingsKey(app);
            AppUnlock active;
            if (records.TryGetValue(KeyOf(sid, sessionId, app.Id), out active) && active.PinVersion == record.Version &&
                active.Settings == settings) return AuthResult.Approved;

            LaunchAttemptState state = ReadAttempts(sid);
            if (state.DeadlineUtcTicks > utcNow.Ticks)
            {
                retryAfterSeconds = SecondsUntil(state.DeadlineUtcTicks, utcNow);
                return AuthResult.RateLimited;
            }
            if (string.IsNullOrEmpty(pin)) return AuthResult.Prompt;

            if (PinHash.Verify(pin, record))
            {
                WriteAttempts(sid, new LaunchAttemptState());
                if (records.Count >= MaxEntries) return AuthResult.Denied;
                CreateRecord(app, sid, sessionId, record, utcNow);
                if (groupIds != null)
                {
                    foreach (string id in groupIds)
                    {
                        if (id == app.Id || !IsRelocked(sid, sessionId, id)) continue;
                        AppPolicy other = PolicyRules.FindById(policy, id);
                        if (other == null || !other.Locked || !(PolicyRules.CanUseGate(other) || PolicyRules.CanUseWindowUnlock(other)) ||
                            !PolicyRules.IsWithinLockHours(other.Launch, DateTime.Now) || records.Count >= MaxEntries) continue;
                        PinRecord otherPin = DefaultOrOwnPin(secrets, other);
                        if (PinHash.Verify(pin, otherPin)) CreateRecord(other, sid, sessionId, otherPin, utcNow);
                    }
                }
                return AuthResult.Approved;
            }

            state.Failed = Math.Min(state.Failed + 1, 15);
            if (state.Failed >= 5)
                state.DeadlineUtcTicks = utcNow.AddSeconds(Math.Min(900, 30 * (1 << (state.Failed - 5)))).Ticks;
            WriteAttempts(sid, state);
            if (state.DeadlineUtcTicks > utcNow.Ticks)
            {
                retryAfterSeconds = SecondsUntil(state.DeadlineUtcTicks, utcNow);
                return AuthResult.RateLimited;
            }
            return AuthResult.Denied;
        }
    }

    private void CreateRecord(AppPolicy app, string sid, int sessionId, PinRecord pin, DateTime utcNow)
    {
        int minutes = Math.Max(0, Math.Min(app.Launch.AllowedMinutes, 1440));
        records[KeyOf(sid, sessionId, app.Id)] = new AppUnlock
        {
            UserSid = sid,
            SessionId = sessionId,
            AppId = app.Id,
            PinVersion = pin.Version,
            Settings = PolicyRules.SettingsKey(app),
            UnlockedUtc = utcNow,
            ExpiresUtc = minutes > 0 ? (DateTime?)utcNow.AddMinutes(minutes) : null,
            EndsOnExit = !(minutes > 0 && !app.Launch.RelockOnExit),
        };
        relocked.RemoveAll(r => r.AppId == app.Id && r.SessionId == sessionId &&
            string.Equals(r.UserSid, sid, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsRelocked(string sid, int sessionId, string appId)
    {
        return relocked.Any(r => r.AppId == appId && r.SessionId == sessionId &&
            string.Equals(r.UserSid, sid, StringComparison.OrdinalIgnoreCase));
    }

    private void AddRelocked(AppUnlock record, DateTime utcNow)
    {
        // Only an app that is open right now is worth a grouped prompt.
        if (!record.SeenRunning || IsRelocked(record.UserSid, record.SessionId, record.AppId)) return;
        relocked.Add(new RelockedApp
        {
            UserSid = record.UserSid,
            SessionId = record.SessionId,
            AppId = record.AppId,
            // The last time the app was seen running is on the same clock as Observe(); it is at most a second old.
            AddedUtc = record.LastSeenRunningUtc,
            LastSeenRunningUtc = record.LastSeenRunningUtc,
        });
    }

    // An app that was open and has just been locked ("lock all") while it runs joins the group too: the user has to
    // enter the PIN for it anyway, and should do so once for all of them.
    internal bool AddRelockedRunning(AppPolicy app, string sid, int sessionId, DateTime utcNow)
    {
        lock (sync)
        {
            if (app == null || !app.Locked || IsRelocked(sid, sessionId, app.Id) ||
                records.ContainsKey(KeyOf(sid, sessionId, app.Id))) return false;
            relocked.Add(new RelockedApp { UserSid = sid, SessionId = sessionId, AppId = app.Id, AddedUtc = utcNow, LastSeenRunningUtc = utcNow });
            return true;
        }
    }

    internal bool IsUnlocked(string sid, int sessionId, string appId, DateTime utcNow)
    {
        lock (sync)
        {
            AppUnlock record;
            if (!records.TryGetValue(KeyOf(sid, sessionId, appId), out record)) return false;
            return !record.ExpiresUtc.HasValue || record.ExpiresUtc.Value > utcNow;
        }
    }

    // running: "<session>|<appId>" -> number of processes of that app in that session, taken from one process snapshot.
    // Returns true when a record ended (the enforcement file must be rewritten).
    internal bool Observe(IDictionary<string, int> running, DateTime utcNow)
    {
        lock (sync)
        {
            bool changed = false;
            foreach (string key in records.Keys.ToArray())
            {
                AppUnlock record = records[key];
                int count;
                running.TryGetValue(record.SessionId.ToString(CultureInfo.InvariantCulture) + "|" + record.AppId, out count);
                bool end = false;
                if (record.ExpiresUtc.HasValue && record.ExpiresUtc.Value <= utcNow) end = true;
                else if (count > 0)
                {
                    record.SeenRunning = true;
                    record.LastSeenRunningUtc = utcNow;
                }
                else if (record.SeenRunning)
                {
                    if (record.EndsOnExit && utcNow - record.LastSeenRunningUtc >= ExitGrace) end = true;
                }
                else if (utcNow - record.UnlockedUtc >= StartGrace) end = true;
                if (end)
                {
                    records.Remove(key);
                    changed = true;
                }
            }

            // A relocked app stays in the group while it runs; once it has been gone for the grace period it leaves.
            foreach (RelockedApp entry in relocked.ToArray())
            {
                int count;
                running.TryGetValue(entry.SessionId.ToString(CultureInfo.InvariantCulture) + "|" + entry.AppId, out count);
                if (count > 0) entry.LastSeenRunningUtc = utcNow;
                if (count == 0 && utcNow - entry.LastSeenRunningUtc >= ExitGrace || utcNow - entry.AddedUtc > RelockedMaxAge)
                {
                    relocked.Remove(entry);
                    changed = true;
                }
            }
            return changed;
        }
    }

    // Drops records for apps that were unlocked or deleted, or whose PIN or settings changed.
    internal bool Prune(PolicyDocument policy, SecretsDocument secrets)
    {
        lock (sync)
        {
            DateTime utcNow = DateTime.UtcNow;
            bool changed = false;
            foreach (string key in records.Keys.ToArray())
            {
                AppUnlock record = records[key];
                AppPolicy app = PolicyRules.FindById(policy, record.AppId);
                if (app == null || !app.Locked || DefaultOrOwnPin(secrets, app).Version != record.PinVersion ||
                    PolicyRules.SettingsKey(app) != record.Settings)
                {
                    // The app was opened for good ("unlock all") but may be locked again: remember it as a group member.
                    if (app != null && !app.Locked) AddRelocked(record, utcNow);
                    records.Remove(key);
                    changed = true;
                }
            }
            if (relocked.RemoveAll(r => PolicyRules.FindById(policy, r.AppId) == null) > 0) changed = true;
            return changed;
        }
    }

    internal void RevokeAll()
    {
        lock (sync)
        {
            DateTime utcNow = DateTime.UtcNow;
            foreach (AppUnlock record in records.Values) AddRelocked(record, utcNow);
            records.Clear();
        }
    }

    internal bool RevokeSession(int sessionId)
    {
        lock (sync)
        {
            DateTime utcNow = DateTime.UtcNow;
            string[] doomed = records.Where(pair => pair.Value.SessionId == sessionId).Select(pair => pair.Key).ToArray();
            foreach (string key in doomed)
            {
                AddRelocked(records[key], utcNow);
                records.Remove(key);
            }
            return doomed.Length > 0;
        }
    }

    internal List<EnforcementUnlock> RelockedSnapshot()
    {
        lock (sync)
        {
            return relocked.OrderBy(r => r.SessionId).ThenBy(r => r.AppId, StringComparer.Ordinal)
                .Select(r => new EnforcementUnlock { Session = r.SessionId, Sid = r.UserSid, AppId = r.AppId }).ToList();
        }
    }

    internal List<EnforcementUnlock> Snapshot(DateTime utcNow)
    {
        lock (sync)
        {
            return records.Values
                .Where(r => !r.ExpiresUtc.HasValue || r.ExpiresUtc.Value > utcNow)
                .OrderBy(r => r.SessionId).ThenBy(r => r.AppId, StringComparer.Ordinal)
                .Select(r => new EnforcementUnlock { Session = r.SessionId, Sid = r.UserSid, AppId = r.AppId }).ToList();
        }
    }

    internal int CountSessions(string appId)
    {
        lock (sync) return records.Values.Count(r => r.AppId == appId);
    }

    private void RemoveExpired(DateTime utcNow)
    {
        foreach (string key in records.Keys.ToArray())
        {
            AppUnlock record = records[key];
            if (record.ExpiresUtc.HasValue && record.ExpiresUtc.Value <= utcNow) records.Remove(key);
        }
    }

    private static PinRecord DefaultOrOwnPin(SecretsDocument secrets, AppPolicy app)
    {
        PinRecord own = secrets.FindAppPin(app.Id);
        return own != null && own.IsSet ? own : secrets.AppPin;
    }

    private static int SecondsUntil(long deadlineTicks, DateTime utcNow)
    {
        return (int)Math.Max(1, Math.Ceiling(new TimeSpan(deadlineTicks - utcNow.Ticks).TotalSeconds));
    }

    private LaunchAttemptState ReadAttempts(string sid)
    {
        if (LoadAttempts != null) return LoadAttempts(sid) ?? new LaunchAttemptState();
        LaunchAttemptState state;
        return memoryAttempts.TryGetValue(sid, out state) ? state : new LaunchAttemptState();
    }

    private void WriteAttempts(string sid, LaunchAttemptState state)
    {
        if (SaveAttempts != null) SaveAttempts(sid, state);
        else memoryAttempts[sid] = state;
    }
}
