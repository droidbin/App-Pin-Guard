using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;

internal static class WindowAgentSmoke
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--fixture")
        {
            Application.Run(new Form { Text = "Disposable App PIN Guard window fixture" });
            return 0;
        }

        string source = Assembly.GetExecutingAssembly().Location;
        string root = Path.Combine(Path.GetDirectoryName(source), "fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string copy = Path.Combine(root, Path.GetFileName(source));
        string journal = Path.Combine(root, "windows.state");
        File.Copy(source, copy);
        Process protectedChild = null, otherChild = null;
        try
        {
            protectedChild = Process.Start(source, "--fixture");
            otherChild = Process.Start(copy, "--fixture");
            IntPtr protectedWindow = WaitForWindow(protectedChild);
            IntPtr otherWindow = WaitForWindow(otherChild);

            int session;
            using (Process self = Process.GetCurrentProcess()) session = self.SessionId;
            string sid;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                sid = identity.User == null ? string.Empty : identity.User.Value;
            string appId = Guid.NewGuid().ToString("N");

            var lockedData = new EnforcementData { Revision = 1 };
            lockedData.Apps.Add(new EnforcementApp
            {
                Id = appId,
                Kind = EnforcementApp.KindWindow,
                Match = source,
                Name = "Fixture",
            });
            string lockedText = lockedData.Serialize();

            var guard = new WindowAgent(journal, session, sid);
            guard.Apply(EnforcementData.Parse(lockedText));
            WaitUntil(() => { guard.Scan(); return !IsWindowVisible(protectedWindow); }, "Protected window did not hide.");
            if (!File.Exists(journal) || !IsWindowVisible(otherWindow))
                throw new InvalidOperationException("Missing journal or matched a different path with the same name.");

            var restarted = new WindowAgent(journal, session, sid);
            restarted.Apply(EnforcementData.Parse(lockedText));
            restarted.Scan();
            if (IsWindowVisible(protectedWindow)) throw new InvalidOperationException("Restart released locked window.");

            // Reject malformed enforcement format (non-v2).
            bool rejected = false;
            try { EnforcementData.Parse("WAP-ENF 1\nrev=1\n"); }
            catch (FormatException) { rejected = true; }
            if (!rejected) throw new InvalidOperationException("Non-v2 enforcement header was accepted.");

            // Unlock entry for a different SID or different session must not restore this window.
            var otherUserData = EnforcementData.Parse(lockedText);
            otherUserData.Unlocks.Add(new EnforcementUnlock { Session = session, Sid = "S-1-5-21-0-0-0-9999", AppId = appId });
            otherUserData.Unlocks.Add(new EnforcementUnlock { Session = session + 1, Sid = sid, AppId = appId });
            restarted.Apply(EnforcementData.Parse(otherUserData.Serialize()));
            restarted.Scan();
            if (IsWindowVisible(protectedWindow))
                throw new InvalidOperationException("Unlock for another user or session released the window.");

            // Unlock entry matching both session and SID restores the window and retires the journal.
            var unlockedData = EnforcementData.Parse(lockedText);
            unlockedData.Unlocks.Add(new EnforcementUnlock { Session = session, Sid = sid, AppId = appId });
            restarted.Apply(EnforcementData.Parse(unlockedData.Serialize()));
            WaitUntil(() => { restarted.Scan(); return IsWindowVisible(protectedWindow) && !File.Exists(journal); },
                "Unlock did not restore the window and retire the journal entry.");
            Console.WriteLine("PASS: v2 enforcement hide, exact-path isolation, journal adoption, session/SID scoping, and unlock restore.");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
        finally
        {
            Stop(protectedChild);
            Stop(otherChild);
            if (File.Exists(journal)) File.Delete(journal);
            if (File.Exists(copy)) File.Delete(copy);
            if (Directory.Exists(root)) Directory.Delete(root);
        }
    }

    private static IntPtr WaitForWindow(Process process)
    {
        IntPtr found = IntPtr.Zero;
        WaitUntil(() =>
        {
            EnumWindows((window, state) =>
            {
                uint pid;
                GetWindowThreadProcessId(window, out pid);
                if (pid == process.Id && IsWindowVisible(window)) found = window;
                return found == IntPtr.Zero;
            }, IntPtr.Zero);
            return found != IntPtr.Zero;
        }, "Desktop fixture did not show a window.");
        return found;
    }

    private static void WaitUntil(Func<bool> ready, string error)
    {
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < TimeSpan.FromSeconds(8))
        {
            if (ready()) return;
            Thread.Sleep(80);
        }
        throw new InvalidOperationException(error);
    }

    private static void Stop(Process process)
    {
        if (process == null) return;
        using (process)
        {
            if (!process.HasExited)
            {
                process.Kill();
                process.WaitForExit(5000);
            }
        }
    }

    private delegate bool EnumProc(IntPtr window, IntPtr state);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc callback, IntPtr state);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
}
