using System;
using System.IO;
using System.Security.Principal;
using System.Threading;

// Assembles the service components, starts them in dependency order and stops them in reverse.
internal sealed class ProtectionWorker : IDisposable
{
    private readonly string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
    private readonly object sync = new object();
    private StatusWriter status;
    private UnlockTable unlocks;
    private PolicyHost policyHost;
    private RuleEngine rules;
    private ProcessWatcher watcher;
    private GateSpoolServer spool;
    private AgentSupervisor agents;
    private Timer heartbeat;
    private bool running;

    internal void Start()
    {
        lock (sync)
        {
            if (running) return;
            string gatePath = Path.Combine(baseDirectory, WapPaths.GateExeName);
            string agentPath = Path.Combine(baseDirectory, WapPaths.AgentExeName);
            ServiceLog.Info("service.starting", "gate=" + File.Exists(gatePath), "agent=" + File.Exists(agentPath));

            SecureLayout.Ensure();
            try { LegacyMigration.Run(); }
            catch (Exception ex) { ServiceLog.Exception("migration.failed", ex); }

            status = new StatusWriter();
            unlocks = new UnlockTable { LoadAttempts = LoadAttempts, SaveAttempts = SaveAttempts };
            policyHost = new PolicyHost(status);
            rules = new RuleEngine(gatePath, status, policyHost.RequestApply);
            watcher = new ProcessWatcher(policyHost, unlocks, status, gatePath);
            spool = new GateSpoolServer(policyHost, unlocks, gatePath);
            policyHost.Rules = rules;
            policyHost.Unlocks = unlocks;
            policyHost.Watcher = watcher;

            bool isSystem;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) isSystem = identity.IsSystem;
            if (isSystem)
            {
                agents = new AgentSupervisor(agentPath, status);
                try { agents.Start(); }
                catch (Exception ex) { ServiceLog.Exception("agent.supervisor.failed", ex); }
            }

            watcher.Start();
            spool.Start();
            rules.StartWatching();
            policyHost.Start();
            status.Update(delegate(StatusDocument doc) { doc.Watcher = watcher.Mode; });
            status.Flush();
            heartbeat = new Timer(delegate { Heartbeat(); }, null, 5000, 5000);
            running = true;
            ServiceLog.Info("service.started");
            ServiceLog.EventLogEntry("Service started.", System.Diagnostics.EventLogEntryType.Information);
        }
    }

    // Stops the service's own components. IFEO rules stay in place and the session agents keep running, so
    // protection holds while the service is down; rules are removed only by uninstall.
    internal void Stop()
    {
        lock (sync)
        {
            if (!running) return;
            running = false;
            if (heartbeat != null) { heartbeat.Dispose(); heartbeat = null; }
            Quiet(policyHost);
            Quiet(spool);
            Quiet(rules);
            Quiet(watcher);
            Quiet(agents);
            if (unlocks != null) unlocks.RevokeAll();
            ServiceLog.Info("service.stopped");
            ServiceLog.EventLogEntry("Service stopped.", System.Diagnostics.EventLogEntryType.Information);
        }
    }

    public void Dispose()
    {
        Stop();
    }

    // Screen lock, disconnect, logoff, suspend: every unlock ends and the agents hide the apps again.
    internal void RevokeLaunchGrants()
    {
        UnlockTable table = unlocks;
        PolicyHost host = policyHost;
        if (table == null) return;
        table.RevokeAll();
        if (host != null) host.RequestApply();
    }

    // A logoff ends only the unlocks of that session; other sessions keep theirs.
    internal void RevokeSession(int sessionId)
    {
        UnlockTable table = unlocks;
        PolicyHost host = policyHost;
        if (table == null) return;
        if (table.RevokeSession(sessionId))
        {
            ServiceLog.Info("unlock.session.revoked", "session=" + sessionId);
            if (host != null) host.RequestApply();
        }
    }

    private static LaunchAttemptState LoadAttempts(string sid)
    {
        try { return PolicyStore.Read<LaunchAttemptState>(System.IO.Path.Combine(WapPaths.AttemptsDir, sid + ".json")) ?? new LaunchAttemptState(); }
        catch (InvalidDataException) { return new LaunchAttemptState(); }
        catch (IOException) { return new LaunchAttemptState(); }
    }

    private static void SaveAttempts(string sid, LaunchAttemptState state)
    {
        try { PolicyStore.WriteAtomic(System.IO.Path.Combine(WapPaths.AttemptsDir, sid + ".json"), state); }
        catch (IOException ex) { ServiceLog.Exception("attempts.save.failed", ex); }
        catch (UnauthorizedAccessException ex) { ServiceLog.Exception("attempts.save.failed", ex); }
    }

    internal void ReconcileAgents()
    {
        AgentSupervisor supervisor = agents;
        if (supervisor == null) return;
        try { supervisor.Reconcile(); }
        catch (Exception ex) { ServiceLog.Exception("agent.reconcile.failed", ex); }
    }

    private void Heartbeat()
    {
        ReconcileAgents();
    }

    private static void Quiet(IDisposable component)
    {
        if (component == null) return;
        try { component.Dispose(); }
        catch (Exception ex) { ServiceLog.Exception("service.stop.component.failed", ex); }
    }
}
