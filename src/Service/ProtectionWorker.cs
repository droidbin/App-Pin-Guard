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
    private GrantTable grants;
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
            grants = new GrantTable();
            policyHost = new PolicyHost(status);
            rules = new RuleEngine(gatePath, status, policyHost.RequestApply);
            watcher = new ProcessWatcher(policyHost, grants, status, gatePath);
            spool = new GateSpoolServer(policyHost, grants, gatePath);
            policyHost.Rules = rules;
            policyHost.Grants = grants;
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
            if (grants != null) grants.RevokeAll();
            ServiceLog.Info("service.stopped");
            ServiceLog.EventLogEntry("Service stopped.", System.Diagnostics.EventLogEntryType.Information);
        }
    }

    public void Dispose()
    {
        Stop();
    }

    internal void RevokeLaunchGrants()
    {
        GrantTable table = grants;
        if (table != null) table.RevokeAll();
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
