using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

// Keeps one WindowAgent running per interactive session (design section 7.3).
// The agent is owned by SYSTEM, restarted the moment it exits, and survives service restarts: a new service
// adopts the running agents instead of stopping them.
internal sealed class AgentSupervisor : IDisposable
{
    private const uint WtsActive = 0;
    private const int MaxRestartsPerMinute = 5;
    private static readonly TimeSpan RestartWindow = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan Backoff = TimeSpan.FromSeconds(30);

    private readonly string agentPath;
    private readonly StatusWriter status;
    private readonly object sync = new object();
    private readonly Dictionary<int, AgentInfo> agents = new Dictionary<int, AgentInfo>();
    private bool stopped;
    private EventWaitHandle stopEvent;

    private sealed class AgentInfo
    {
        internal int Session;
        internal IntPtr Process;
        internal int ProcessId;
        internal RegisteredWaitHandle Wait;
        internal readonly List<DateTime> Starts = new List<DateTime>();
        internal DateTime BackoffUntil = DateTime.MinValue;
        internal int Restarts;
        internal string State = "restarting";
    }

    internal AgentSupervisor(string agentPath, StatusWriter status)
    {
        this.agentPath = agentPath;
        this.status = status;
    }

    internal void Start()
    {
        CreateStopEvent();
        AdoptExisting();
        Reconcile();
    }

    // Created with only SYNCHRONIZE for users: they can wait on it but never signal it.
    // The service itself does not set it; only the uninstall helper does, after the policy has been cleared.
    private void CreateStopEvent()
    {
        try
        {
            var security = new EventWaitHandleSecurity();
            security.AddAccessRule(new EventWaitHandleAccessRule(WapSecurity.SystemSid, EventWaitHandleRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new EventWaitHandleAccessRule(WapSecurity.AdminsSid,
                EventWaitHandleRights.Modify | EventWaitHandleRights.Synchronize | EventWaitHandleRights.ReadPermissions, AccessControlType.Allow));
            security.AddAccessRule(new EventWaitHandleAccessRule(WapSecurity.UsersSid, EventWaitHandleRights.Synchronize, AccessControlType.Allow));
            bool created;
            stopEvent = new EventWaitHandle(false, EventResetMode.ManualReset, WapPaths.AgentStopEvent, out created, security);
            if (!created) CheckExistingObjectOwner(stopEvent, WapPaths.AgentStopEvent);
        }
        catch (Exception ex)
        {
            ServiceLog.Exception("agent.stopevent.failed", ex);
        }
    }

    internal static void CheckExistingObjectOwner(EventWaitHandle handle, string name)
    {
        try
        {
            var owner = handle.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner != null && !owner.Equals(WapSecurity.SystemSid) && !owner.Equals(WapSecurity.AdminsSid))
                ServiceLog.Error("event.owner.untrusted", "name=" + name, "owner=" + owner.Value);
        }
        catch (Exception) { }
    }

    // ---- adoption ----------------------------------------------------------------------------------

    private void AdoptExisting()
    {
        string exeName = Path.GetFileName(agentPath);
        foreach (NativeApi.ProcessEntry entry in NativeApi.SnapshotProcesses())
        {
            if (!string.Equals(entry.ExeFile, exeName, StringComparison.OrdinalIgnoreCase)) continue;
            IntPtr handle = NativeApi.OpenProcess(
                NativeApi.ProcessTerminate | NativeApi.ProcessQueryLimitedInformation | NativeApi.Synchronize | NativeApi.ReadControl,
                false, (uint)entry.Pid);
            if (handle == IntPtr.Zero) continue;

            bool adopted = false;
            try
            {
                int session = NativeApi.GetSessionId(entry.Pid);
                string image = NativeApi.GetImagePath(handle);
                SecurityIdentifier owner = NativeApi.GetKernelObjectOwner(handle);
                bool current = session > 0 && image != null &&
                    string.Equals(image, agentPath, StringComparison.OrdinalIgnoreCase) &&
                    owner != null && owner.Equals(WapSecurity.SystemSid);
                lock (sync)
                {
                    if (current && !agents.ContainsKey(session))
                    {
                        var info = new AgentInfo { Session = session, Process = handle, ProcessId = entry.Pid, State = "running" };
                        agents[session] = info;
                        Watch(info);
                        adopted = true;
                        ServiceLog.Info("agent.adopted", "session=" + session, "pid=" + entry.Pid);
                    }
                }
                if (!adopted)
                {
                    // An agent from an older build (user-owned, or running a replaced binary) is replaced.
                    NativeApi.Terminate(entry.Pid);
                    ServiceLog.Info("agent.replaced", "pid=" + entry.Pid, "session=" + session);
                }
            }
            finally
            {
                if (!adopted) NativeApi.CloseHandle(handle);
            }
        }
    }

    // ---- reconcile ---------------------------------------------------------------------------------

    internal void Reconcile()
    {
        lock (sync)
        {
            if (stopped || !File.Exists(agentPath)) return;
            foreach (int session in ActiveSessions())
            {
                AgentInfo info;
                if (!agents.TryGetValue(session, out info))
                {
                    info = new AgentInfo { Session = session };
                    agents[session] = info;
                }
                if (info.Process != IntPtr.Zero) continue;
                StartAgent(info);
            }
            PublishStatus();
        }
    }

    private void StartAgent(AgentInfo info)
    {
        DateTime now = DateTime.UtcNow;
        if (now < info.BackoffUntil) return;
        info.Starts.RemoveAll(t => now - t > RestartWindow);
        if (info.Starts.Count >= MaxRestartsPerMinute)
        {
            info.BackoffUntil = now.Add(Backoff);
            info.Starts.Clear();
            info.State = "failed";
            ServiceLog.Error("agent.backoff", "session=" + info.Session, "seconds=" + (int)Backoff.TotalSeconds);
            ScheduleReconcile(Backoff);
            return;
        }

        try
        {
            SessionLauncher.Launched launched = SessionLauncher.Start(info.Session, agentPath, null, false);
            try { NativeApi.ProtectProcess(launched.Process); }
            catch (Exception ex) { ServiceLog.Exception("agent.protect.failed", ex); }
            info.Process = launched.Process;
            info.ProcessId = launched.ProcessId;
            info.Starts.Add(now);
            info.Restarts++;
            info.State = "running";
            Watch(info);
            ServiceLog.Info("agent.started", "session=" + info.Session, "pid=" + info.ProcessId);
        }
        catch (Win32Exception ex)
        {
            info.State = "restarting";
            ServiceLog.Exception("agent.start.failed", ex);
            ScheduleReconcile(TimeSpan.FromSeconds(5));
        }
    }

    // Exit is noticed through the process handle, not a poll, and the agent is started again immediately.
    private void Watch(AgentInfo info)
    {
        AgentInfo target = info;
        info.Wait = ThreadPool.RegisterWaitForSingleObject(
            new ProcessWaitHandle(info.Process), delegate(object state, bool timedOut) { OnExited(target); },
            null, Timeout.Infinite, true);
    }

    private void OnExited(AgentInfo info)
    {
        lock (sync)
        {
            if (stopped || info.Process == IntPtr.Zero) return;
            uint code;
            GetExitCodeProcess(info.Process, out code);
            ServiceLog.Warn("agent.exited", "session=" + info.Session, "pid=" + info.ProcessId, "code=" + code);
            NativeApi.CloseHandle(info.Process);
            info.Process = IntPtr.Zero;
            info.ProcessId = 0;
            info.State = "restarting";
            // Exit code 2 means another agent already runs in the session; nothing to start.
            if (code == 2) { info.State = "running"; return; }
            // Session gone: forget it.
            try
            {
                if (!ActiveSessions().Contains(info.Session)) { agents.Remove(info.Session); PublishStatus(); return; }
            }
            catch (Win32Exception) { }
        }
        try { Reconcile(); }
        catch (Exception ex) { ServiceLog.Exception("agent.reconcile.failed", ex); }
    }

    private void ScheduleReconcile(TimeSpan delay)
    {
        Timer timer = null;
        timer = new Timer(delegate
        {
            try { Reconcile(); }
            catch (Exception ex) { ServiceLog.Exception("agent.reconcile.failed", ex); }
            finally { if (timer != null) timer.Dispose(); }
        }, null, delay, TimeSpan.FromMilliseconds(-1));
    }

    private void PublishStatus()
    {
        List<AgentStatus> list = agents.Values
            .Select(a => new AgentStatus { Session = a.Session, State = a.State, Restarts = Math.Max(0, a.Restarts - 1) })
            .OrderBy(a => a.Session).ToList();
        status.Update(doc => doc.Agents = list);
    }

    private static List<int> ActiveSessions()
    {
        var result = new List<int>();
        IntPtr buffer;
        int count;
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out buffer, out count)) throw new Win32Exception();
        try
        {
            int size = Marshal.SizeOf(typeof(SessionInfo));
            for (int index = 0; index < count; index++)
            {
                var item = (SessionInfo)Marshal.PtrToStructure(IntPtr.Add(buffer, size * index), typeof(SessionInfo));
                if (item.Id > 0 && (uint)item.State == WtsActive) result.Add(item.Id);
            }
        }
        finally { WTSFreeMemory(buffer); }
        return result;
    }

    // The service is stopping. Agents deliberately keep running so protection holds while it is down.
    public void Dispose()
    {
        lock (sync)
        {
            stopped = true;
            foreach (AgentInfo info in agents.Values)
            {
                if (info.Wait != null) info.Wait.Unregister(null);
                if (info.Process != IntPtr.Zero) NativeApi.CloseHandle(info.Process);
                info.Process = IntPtr.Zero;
            }
            agents.Clear();
        }
        if (stopEvent != null) { stopEvent.Dispose(); stopEvent = null; }
    }

    private sealed class ProcessWaitHandle : WaitHandle
    {
        internal ProcessWaitHandle(IntPtr handle)
        {
            SafeWaitHandle = new Microsoft.Win32.SafeHandles.SafeWaitHandle(handle, false);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SessionInfo
    {
        internal int Id;
        internal IntPtr Name;
        internal int State;
    }

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
    [DllImport("kernel32.dll")]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
}
