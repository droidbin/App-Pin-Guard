using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Threading;

internal static class Program
{
    private static int Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += delegate(object sender, UnhandledExceptionEventArgs e)
        {
            Exception ex = e.ExceptionObject as Exception;
            if (ex != null) WapLog.FatalException("service", ServiceLog.Path, "service.fatal", ex);
            ServiceLog.EventLogEntry("Unhandled exception: " + (ex == null ? "unknown" : ex.ToString()), EventLogEntryType.Error);
        };

        if (args.Any(arg => string.Equals(arg, "--console", StringComparison.OrdinalIgnoreCase)))
        {
            using (var worker = new ProtectionWorker())
            {
                worker.Start();
                Console.WriteLine(ProductBrand.Name + " service worker is running. Press Enter to stop.");
                Console.ReadLine();
                worker.Stop();
            }
            return 0;
        }

        // Run by Uninstall.bat before the service is stopped: unlock everything so the agent restores hidden
        // windows, wait until the service has applied it, then tell the agents to exit.
        if (args.Any(arg => string.Equals(arg, "--uninstall-prepare", StringComparison.OrdinalIgnoreCase)))
            return UninstallPrepare.Run();

        ServiceBase.Run(new ProtectorService());
        return 0;
    }

    private sealed class ProtectorService : ServiceBase
    {
        private readonly ProtectionWorker worker = new ProtectionWorker();

        public ProtectorService()
        {
            ServiceName = WapPaths.ServiceName;
            CanStop = true;
            CanShutdown = true;
            CanHandleSessionChangeEvent = true;
            CanHandlePowerEvent = true;
        }

        protected override void OnStart(string[] args)
        {
            try { worker.Start(); }
            catch (Exception ex)
            {
                WapLog.FatalException("service", ServiceLog.Path, "service.start.failed", ex);
                ServiceLog.EventLogEntry("Service failed to start: " + ex, EventLogEntryType.Error);
                throw;
            }
        }

        protected override void OnStop() { worker.Stop(); }

        protected override void OnShutdown() { worker.Stop(); }

        protected override void OnSessionChange(SessionChangeDescription change)
        {
            switch (change.Reason)
            {
                case SessionChangeReason.SessionLock:
                case SessionChangeReason.ConsoleDisconnect:
                case SessionChangeReason.RemoteDisconnect:
                    worker.RevokeLaunchGrants();
                    break;
                case SessionChangeReason.SessionLogoff:
                    worker.RevokeSession(change.SessionId);
                    break;
                case SessionChangeReason.SessionLogon:
                case SessionChangeReason.SessionUnlock:
                case SessionChangeReason.ConsoleConnect:
                case SessionChangeReason.RemoteConnect:
                    worker.ReconcileAgents();
                    break;
            }
        }

        protected override bool OnPowerEvent(PowerBroadcastStatus status)
        {
            if (status == PowerBroadcastStatus.Suspend || status == PowerBroadcastStatus.ResumeAutomatic)
                worker.RevokeLaunchGrants();
            return true;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) worker.Dispose();
            base.Dispose(disposing);
        }
    }
}

internal static class UninstallPrepare
{
    internal static int Run()
    {
        try
        {
            PolicyDocument policy = PolicyStore.LoadPolicy();
            if (policy != null)
            {
                foreach (AppPolicy app in policy.Apps) app.Locked = false;
                long revision = PolicyStore.SavePolicy(policy);
                Signal(WapPaths.PolicyChangedEvent);
                if (!WaitForApplied(revision, TimeSpan.FromSeconds(5)))
                    Console.Error.WriteLine("The service did not confirm the unlock in time; continuing.");
                // Give the agents a moment to read the cleared enforcement file and restore their windows:
                // an agent that gets the stop event leaves hidden windows hidden.
                Thread.Sleep(2000);
            }
            Signal(WapPaths.AgentStopEvent);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Uninstall preparation failed: " + ex.Message);
            return 1;
        }
    }

    private static void Signal(string name)
    {
        try
        {
            using (EventWaitHandle handle = EventWaitHandle.OpenExisting(name, System.Security.AccessControl.EventWaitHandleRights.Modify))
                handle.Set();
        }
        catch (WaitHandleCannotBeOpenedException) { }
    }

    private static bool WaitForApplied(long revision, TimeSpan timeout)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                StatusDocument status = PolicyStore.Read<StatusDocument>(WapPaths.StatusFile);
                if (status != null && status.AppliedRevision >= revision) return true;
            }
            catch (Exception) { }
            Thread.Sleep(100);
        }
        return false;
    }
}
