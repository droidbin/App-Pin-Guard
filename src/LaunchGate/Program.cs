using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

internal static class GateLog
{
    internal static string Path
    {
        get { return System.IO.Path.Combine(WapPaths.UserLogsDir, "gate.log"); }
    }

    internal static void Info(string key, params string[] fields) { WapLog.Info("gate", Path, key, fields); }
    internal static void Warn(string key, params string[] fields) { WapLog.Warn("gate", Path, key, fields); }
    internal static void Exception(string key, Exception ex) { WapLog.Exception("gate", Path, key, ex); }
}

internal static class Gate
{
    private const int PromptWaitSeconds = 120;
    private const int WindowWaitMilliseconds = 3000;
    private const int LaunchWindowWaitMilliseconds = 5000;

    private enum PromptOutcome
    {
        // PIN was verified and approved; the app window was already activated before the prompt closed.
        Approved,
        // PIN was rejected (or the service was unavailable / rate-limited) or launch failed.
        Failed,
        Cancelled,
        // The app was unlocked (or stopped being locked) while the prompt was open: it closed itself.
        Released,
        // Another Gate already shows the prompt of this app in this session.
        Busy,
    }

    private sealed class SubmitResult
    {
        internal GateResponse Response;
        internal Exception Error;
        internal bool Approved;
        internal IntPtr WindowToActivate;
        internal string FocusReason;
    }

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length >= 1 && args[0] == "--blocked")
        {
            // IFEO fallback rule: this exe runs without elevation, so the block message always shows.
            GateLog.Info("gate.blocked");
            ShowError("보호 정책에 따라 이 앱의 실행이 차단되었습니다.");
            return 1;
        }

        if (args.Length >= 1 && args[0] == "--notice-blocked")
        {
            // Shown by the service after the process watcher ended a launch that bypassed the gate.
            GateLog.Info("gate.notice", "app=" + (args.Length > 1 ? System.IO.Path.GetFileName(args[1]) : string.Empty));
            ShowError("PIN Guard가 잠긴 앱의 실행을 막았습니다.");
            return 1;
        }

        // Started by the window agent when it hid a window of a locked app: ask for the PIN and unlock the whole app.
        if (args.Length >= 3 && args[0] == "--unlock") return Unlock(args[1], args[2]);

        if (args.Length < 2 || args[0] != "--launch") return 1;
        try
        {
            if (!Path.IsPathRooted(args[1])) throw new InvalidDataException("보호 앱의 전체 경로가 필요합니다.");
            string path = Path.GetFullPath(args[1]);
            if (!File.Exists(path)) throw new FileNotFoundException("보호 앱을 찾을 수 없습니다.");
            string[] launchArgs = args.Skip(2).ToArray();
            GateLog.Info("gate.launch.requested", "app=" + System.IO.Path.GetFileName(path));
            GateResponse response = AuthorizeByPath(path, string.Empty);

            if (response.Result == GateSpool.ResultPrompt)
            {
                string promptId = string.IsNullOrEmpty(response.AppId) ? "unknown" : response.AppId;
                GateResponse submitResponse;
                Exception submitError;
                PromptOutcome outcome = RunPrompt(path, null, new[] { promptId }, false,
                    delegate(string pin) { return HandleLaunchSubmit(path, launchArgs, promptId, pin); },
                    out submitResponse, out submitError);

                if (outcome == PromptOutcome.Approved) return 0;
                if (outcome == PromptOutcome.Cancelled) return 1;
                if (outcome == PromptOutcome.Failed)
                {
                    if (submitError != null) throw submitError;
                    GateLog.Info("gate.launch.refused", "result=" + (submitResponse == null ? "unknown" : submitResponse.Result));
                    ShowError(DescribeRefusal(submitResponse));
                    return 1;
                }
                if (outcome == PromptOutcome.Busy)
                {
                    response = WaitForOtherPrompt(path, promptId);
                    if (response == null) return 1;
                }
                else
                {
                    // Prompt closed itself because the app was unlocked elsewhere.
                    response = AuthorizeByPath(path, string.Empty);
                }
            }

            if (response.Result != GateSpool.ResultApproved)
            {
                GateLog.Info("gate.launch.refused", "result=" + response.Result);
                ShowError(DescribeRefusal(response));
                return 1;
            }

            uint child = Launch(path, launchArgs);
            GateLog.Info("gate.launch.started", "pid=" + child);
            ActivateAppWindow(string.IsNullOrEmpty(response.AppId) ? null : new[] { response.AppId }, path,
                LaunchWindowWaitMilliseconds, "launch");
            return 0;
        }
        catch (Exception ex)
        {
            GateLog.Exception("gate.launch.failed", ex);
            ShowError("보호 앱을 실행할 수 없습니다.\n" + ex.Message);
            return 1;
        }
    }

    private static SubmitResult HandleLaunchSubmit(string path, string[] launchArgs, string promptId, string pin)
    {
        var result = new SubmitResult { FocusReason = "launch" };
        try
        {
            GateResponse response = AuthorizeByPath(path, pin);
            result.Response = response;
            if (response.Result != GateSpool.ResultApproved) return result;

            uint child = Launch(path, launchArgs);
            GateLog.Info("gate.launch.started", "pid=" + child);
            result.Approved = true;
            LogFocus("gate.focus", "stage=approved", "reason=launch");
            string targetId = string.IsNullOrEmpty(response.AppId) ? promptId : response.AppId;
            result.WindowToActivate = WaitForAppWindow(new[] { targetId }, path, LaunchWindowWaitMilliseconds);
            return result;
        }
        catch (Exception ex)
        {
            result.Error = ex;
            return result;
        }
    }

    // Waits while another Gate shows the PIN prompt for this app: checks authorize every second up to 120 s.
    // Returns the final GateResponse if authorization completed, or null if timed out or the other prompt was cancelled.
    private static GateResponse WaitForOtherPrompt(string path, string appId)
    {
        DateTime deadline = DateTime.UtcNow.AddSeconds(PromptWaitSeconds);
        while (DateTime.UtcNow < deadline)
        {
            Thread.Sleep(1000);
            GateResponse response = AuthorizeByPath(path, string.Empty);
            if (response.Result != GateSpool.ResultPrompt) return response;
            if (IsPromptMutexFree(appId))
            {
                // The other prompt closed: re-check once to avoid a race with approval, then exit if still Prompt.
                GateResponse finalCheck = AuthorizeByPath(path, string.Empty);
                return finalCheck.Result == GateSpool.ResultPrompt ? null : finalCheck;
            }
        }
        return null;
    }

    private static int Unlock(string appId, string appPath)
    {
        try
        {
            Guid parsed;
            if (!Guid.TryParse(appId, out parsed) || !Path.IsPathRooted(appPath)) return 1;
            string path = Path.GetFullPath(appPath);
            GateLog.Info("gate.unlock.requested", "app=" + System.IO.Path.GetFileName(path), "id=" + appId);
            GateResponse response = AuthorizeByApp(appId, string.Empty, null);
            List<string> groupIds = null;
            if (response.Result == GateSpool.ResultPrompt)
            {
                // Several apps relocked together (screen lock, "lock all"): one prompt and one PIN for all of them.
                List<string> groupNames;
                groupIds = FindRelockedGroup(appId, out groupNames);
                IList<string> promptAppIds = groupIds == null ? (IList<string>)new[] { appId } : groupIds;
                GateResponse submitResponse;
                Exception submitError;
                PromptOutcome outcome = RunPrompt(path, groupNames, promptAppIds, true,
                    delegate(string pin) { return HandleUnlockSubmit(appId, path, groupIds, promptAppIds, pin); },
                    out submitResponse, out submitError);

                if (outcome == PromptOutcome.Approved) return 0;
                if (outcome == PromptOutcome.Busy)
                {
                    GateLog.Info("gate.unlock.busy", "id=" + appId);
                    return 0;
                }
                if (outcome == PromptOutcome.Released)
                {
                    GateLog.Info("gate.unlock.released", "id=" + appId);
                    return 0;
                }
                if (outcome == PromptOutcome.Cancelled) return 1;
                if (submitError != null) throw submitError;
                GateLog.Info("gate.unlock.refused", "result=" + (submitResponse == null ? "unknown" : submitResponse.Result));
                ShowError(DescribeRefusal(submitResponse));
                return 1;
            }
            if (response.Result != GateSpool.ResultApproved)
            {
                GateLog.Info("gate.unlock.refused", "result=" + response.Result);
                ShowError(DescribeRefusal(response));
                return 1;
            }
            GateLog.Info("gate.unlock.approved", "id=" + appId, "group=0");
            ActivateAppWindow(new[] { appId }, path, WindowWaitMilliseconds, "unlock");
            return 0;
        }
        catch (Exception ex)
        {
            GateLog.Exception("gate.unlock.failed", ex);
            ShowError("앱을 열 수 없습니다.\n" + ex.Message);
            return 1;
        }
    }

    private static SubmitResult HandleUnlockSubmit(string appId, string path, List<string> groupIds,
        IList<string> promptAppIds, string pin)
    {
        var result = new SubmitResult { FocusReason = "unlock" };
        try
        {
            GateResponse response = AuthorizeByApp(appId, pin, groupIds);
            result.Response = response;
            if (response.Result != GateSpool.ResultApproved) return result;

            GateLog.Info("gate.unlock.approved", "id=" + appId, "group=" + (groupIds == null ? 0 : groupIds.Count));
            result.Approved = true;
            LogFocus("gate.focus", "stage=approved", "reason=unlock");
            result.WindowToActivate = WaitForAppWindow(promptAppIds, path, WindowWaitMilliseconds);
            return result;
        }
        catch (Exception ex)
        {
            result.Error = ex;
            return result;
        }
    }

    private static string DescribeRefusal(GateResponse response)
    {
        if (response == null) return "PIN이 일치하지 않거나 현재 실행할 수 없는 앱입니다.";
        switch (response.Result)
        {
            case GateSpool.ResultRateLimited:
                return "PIN 입력 제한이 활성화되어 있습니다. " +
                    (response.RetryAfterSeconds > 0 ? response.RetryAfterSeconds + "초 후에 다시 시도하세요." : "잠시 후 다시 시도하세요.");
            case GateSpool.ResultUnavailable:
                // Fail closed: without an answer the app is not started.
                return "보호 서비스가 응답하지 않아 실행할 수 없습니다.";
            default:
                return "PIN이 일치하지 않거나 현재 실행할 수 없는 앱입니다.";
        }
    }

    private static GateResponse AuthorizeByPath(string path, string pin)
    {
        return GateSpool.Exchange(new GateRequest { Op = GateSpool.OpAuthorize, Pid = Process.GetCurrentProcess().Id, Path = path, Pin = pin });
    }

    private static GateResponse AuthorizeByApp(string appId, string pin, IList<string> groupIds)
    {
        var request = new GateRequest { Op = GateSpool.OpUnlock, Pid = Process.GetCurrentProcess().Id, AppId = appId, Pin = pin };
        if (groupIds != null)
            foreach (string id in groupIds)
                if (id != appId && request.GroupIds.Count < GateRequest.MaxGroupApps) request.GroupIds.Add(id);
        return GateSpool.Exchange(request);
    }

    // The apps (this one included) that were unlocked before and sit locked again in this session, when there are two
    // or more of them and all are still locked; null otherwise. Names are in the same order, this app first.
    private static List<string> FindRelockedGroup(string appId, out List<string> names)
    {
        names = null;
        EnforcementData data = ReadEnforcement();
        if (data == null) return null;
        int session = Process.GetCurrentProcess().SessionId;
        string sid = CurrentSid();
        List<string> relocked = data.RelockedApps(session, sid);
        if (!relocked.Contains(appId)) return null;
        var ids = new List<string> { appId };
        foreach (string id in relocked)
            if (id != appId && data.FindApp(id) != null && !data.IsUnlocked(session, sid, id)) ids.Add(id);
        if (ids.Count < 2) return null;
        names = ids.Select(id =>
        {
            EnforcementApp app = data.FindApp(id);
            if (app != null && !string.IsNullOrWhiteSpace(app.Name)) return app.Name;
            return app == null ? id : System.IO.Path.GetFileNameWithoutExtension(app.Match);
        }).ToList();
        return ids;
    }

    // ---- the single PIN prompt per app and session ---------------------------------------------------

    private static string PromptMutexName(string appId)
    {
        return @"Local\WAP.Prompt." + (string.IsNullOrEmpty(appId) ? "unknown" : appId);
    }

    private static string PromptProperty(string appId)
    {
        return "WAP.Prompt." + (string.IsNullOrEmpty(appId) ? "unknown" : appId);
    }

    private static bool IsPromptMutexFree(string appId)
    {
        using (var mutex = new Mutex(false, PromptMutexName(appId)))
        {
            bool acquired;
            try { acquired = mutex.WaitOne(0); }
            catch (AbandonedMutexException) { acquired = true; }
            if (!acquired) return false;
            try { return true; }
            finally { mutex.ReleaseMutex(); }
        }
    }

    // Acquires Local\WAP.Prompt.<AppId> for every app this prompt covers (sorted to avoid deadlocks).
    // If any app already has a prompt in this session, brings that prompt to front and returns Busy.
    private static PromptOutcome RunPrompt(string appPath, IList<string> groupNames, IList<string> appIds,
        bool treatAbsentAsUnlocked, Func<string, SubmitResult> onSubmit, out GateResponse response, out Exception error)
    {
        response = null;
        error = null;
        List<string> sortedIds = appIds.Where(id => !string.IsNullOrEmpty(id))
            .Distinct(StringComparer.Ordinal).OrderBy(id => id, StringComparer.Ordinal).ToList();
        if (sortedIds.Count == 0) sortedIds.Add("unknown");

        var held = new List<Mutex>(sortedIds.Count);
        try
        {
            foreach (string id in sortedIds)
            {
                var mutex = new Mutex(false, PromptMutexName(id));
                bool owned;
                try { owned = mutex.WaitOne(0); }
                catch (AbandonedMutexException) { owned = true; }
                if (!owned)
                {
                    mutex.Dispose();
                    BringPromptToFront(id);
                    return PromptOutcome.Busy;
                }
                held.Add(mutex);
            }
            return ShowPrompt(appPath, groupNames, sortedIds, treatAbsentAsUnlocked, onSubmit, out response, out error);
        }
        finally
        {
            for (int i = held.Count - 1; i >= 0; i--)
            {
                try { held[i].ReleaseMutex(); }
                catch (ApplicationException) { }
                held[i].Dispose();
            }
        }
    }

    private static PromptOutcome ShowPrompt(string appPath, IList<string> groupNames, IList<string> appIds,
        bool treatAbsentAsUnlocked, Func<string, SubmitResult> onSubmit, out GateResponse response, out Exception error)
    {
        response = null;
        error = null;
        Application.EnableVisualStyles();
        bool released = false;
        bool seenLocked = treatAbsentAsUnlocked;
        PromptOutcome outcome = PromptOutcome.Cancelled;
        GateResponse capturedResponse = null;
        Exception capturedError = null;

        using (var form = new GateForm(appPath, groupNames))
        using (var watcher = new System.Windows.Forms.Timer { Interval = 500 })
        {
            form.Shown += delegate
            {
                foreach (string id in appIds) SetProp(form.Handle, PromptProperty(id), new IntPtr(1));
            };
            form.FormClosing += delegate
            {
                foreach (string id in appIds) RemoveProp(form.Handle, PromptProperty(id));
            };
            // Closes the prompt by itself when the app(s) were unlocked some other way (another prompt, another route).
            watcher.Tick += delegate
            {
                if (!IsStillLocked(appIds, ref seenLocked))
                {
                    released = true;
                    watcher.Stop();
                    form.Finish(DialogResult.Abort);
                }
            };
            // Keep the PIN window open while verifying and waiting for the app window so Gate retains the
            // foreground right until SetForegroundWindow succeeds on the app window (design section 8.2).
            form.SubmitHandler = delegate(GateForm promptForm)
            {
                watcher.Stop();
                string pin = promptForm.PinText;
                if (string.IsNullOrWhiteSpace(pin))
                {
                    outcome = PromptOutcome.Cancelled;
                    promptForm.Finish(DialogResult.Cancel);
                    return;
                }
                promptForm.SetSubmitting(true);
                ThreadPool.QueueUserWorkItem(delegate
                {
                    SubmitResult submit = onSubmit(pin);
                    try
                    {
                        promptForm.BeginInvoke(new MethodInvoker(delegate
                        {
                            capturedResponse = submit.Response;
                            capturedError = submit.Error;
                            if (submit.Approved)
                            {
                                if (submit.WindowToActivate != IntPtr.Zero)
                                {
                                    // Activate the app window BEFORE closing the PIN window so foreground right is not lost.
                                    promptForm.TopMost = false;
                                    bool activated = Activate(submit.WindowToActivate);
                                    LogFocus("gate.focus", "stage=activated", "reason=" + submit.FocusReason, "ok=" + activated);
                                }
                                else
                                {
                                    LogFocus("gate.focus", "stage=nowindow", "reason=" + submit.FocusReason, "ok=False");
                                }
                                outcome = PromptOutcome.Approved;
                                promptForm.Finish(DialogResult.OK);
                            }
                            else
                            {
                                outcome = PromptOutcome.Failed;
                                promptForm.Finish(DialogResult.No);
                            }
                        }));
                    }
                    catch (ObjectDisposedException) { }
                    catch (InvalidOperationException) { }
                });
            };
            watcher.Start();
            form.ShowDialog();
            watcher.Stop();
            response = capturedResponse;
            error = capturedError;
            if (released) return PromptOutcome.Released;
            return outcome;
        }
    }

    // False when enforcement.txt says every one of the apps is unlocked in this session or no longer locked at all.
    private static bool IsStillLocked(IList<string> appIds, ref bool seenLocked)
    {
        EnforcementData data = ReadEnforcement();
        if (data == null) return true;
        int session = Process.GetCurrentProcess().SessionId;
        string sid = CurrentSid();
        bool anyLocked = false;
        foreach (string appId in appIds)
        {
            if (data.IsUnlocked(session, sid, appId)) continue;
            if (data.FindApp(appId) != null)
            {
                seenLocked = true;
                anyLocked = true;
            }
            // Absent only counts as "no longer locked" once the app has been seen locked (lock hours, lock removed).
            else if (!seenLocked) anyLocked = true;
        }
        return anyLocked;
    }

    private static string currentSid;

    private static string CurrentSid()
    {
        if (currentSid == null)
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                currentSid = identity.User == null ? string.Empty : identity.User.Value;
        }
        return currentSid;
    }

    private static EnforcementData ReadEnforcement()
    {
        try
        {
            string file = WapPaths.EnforcementFile;
            if (!File.Exists(file) || !WapSecurity.IsOwnedByServiceAccount(file)) return null;
            return EnforcementData.Parse(File.ReadAllText(file, Encoding.UTF8));
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
        catch (FormatException) { return null; }
    }

    private static void BringPromptToFront(string appId)
    {
        string property = PromptProperty(appId);
        EnumWindows(delegate(IntPtr window, IntPtr state)
        {
            if (GetProp(window, property) == IntPtr.Zero) return true;
            Activate(window);
            return false;
        }, IntPtr.Zero);
    }

    // ---- foreground ------------------------------------------------------------------------------------

    // Waits for a visible window of the app(s), checking every 100 ms up to timeoutMilliseconds.
    private static IntPtr WaitForAppWindow(IList<string> appIds, string fallbackPath, int timeoutMilliseconds)
    {
        var resolver = new WindowResolver();
        DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds);
        string primaryId = appIds != null && appIds.Count > 0 ? appIds[0] : null;
        string fallbackId = string.IsNullOrEmpty(primaryId) ? "fallback" : primaryId;

        while (true)
        {
            EnforcementData data = ReadEnforcement();
            List<EnforcementApp> apps = data != null ? new List<EnforcementApp>(data.Apps) : new List<EnforcementApp>();
            bool hasTarget = primaryId != null && apps.Any(a => string.Equals(a.Id, primaryId, StringComparison.Ordinal));
            if (!hasTarget && !string.IsNullOrEmpty(fallbackPath))
                apps.Add(new EnforcementApp { Id = fallbackId, Kind = EnforcementApp.KindWindow, Match = fallbackPath });

            if (apps.Count > 0)
            {
                resolver.SetApps(apps);
                IntPtr window = IntPtr.Zero;
                if (!string.IsNullOrEmpty(primaryId)) window = resolver.FindVisibleWindow(primaryId);
                if (window == IntPtr.Zero && appIds != null && appIds.Count > 1) window = resolver.FindVisibleWindow(appIds);
                if (window == IntPtr.Zero && !hasTarget && !string.IsNullOrEmpty(fallbackPath))
                    window = resolver.FindVisibleWindow(fallbackId);
                if (window != IntPtr.Zero) return window;
            }
            if (DateTime.UtcNow >= deadline) return IntPtr.Zero;
            Thread.Sleep(100);
        }
    }

    // Used when no PIN prompt was shown (app was already unlocked).
    private static void ActivateAppWindow(IList<string> appIds, string fallbackPath, int timeoutMilliseconds, string reason)
    {
        try
        {
            LogFocus("gate.focus", "stage=approved", "reason=" + reason);
            IntPtr window = WaitForAppWindow(appIds, fallbackPath, timeoutMilliseconds);
            if (window == IntPtr.Zero)
            {
                LogFocus("gate.focus", "stage=nowindow", "reason=" + reason, "ok=False");
                return;
            }
            bool activated = Activate(window);
            LogFocus("gate.focus", "stage=activated", "reason=" + reason, "ok=" + activated);
        }
        catch (Exception ex)
        {
            GateLog.Exception("gate.focus.failed", ex);
        }
    }

    private static bool Activate(IntPtr window)
    {
        if (IsIconic(window)) ShowWindow(window, 9);
        if (SetForegroundWindow(window)) return true;

        // Refused: join the input of the current foreground thread and of the window's thread, then retry.
        uint me = GetCurrentThreadId();
        uint targetProcess, foregroundProcess;
        uint target = GetWindowThreadProcessId(window, out targetProcess);
        IntPtr foreground = GetForegroundWindow();
        uint foregroundThread = foreground == IntPtr.Zero ? 0 : GetWindowThreadProcessId(foreground, out foregroundProcess);
        bool attachedTarget = target != 0 && target != me && AttachThreadInput(me, target, true);
        bool attachedForeground = foregroundThread != 0 && foregroundThread != me && foregroundThread != target &&
            AttachThreadInput(me, foregroundThread, true);
        try
        {
            BringWindowToTop(window);
            bool ok = SetForegroundWindow(window);
            SetFocus(window);
            return ok;
        }
        finally
        {
            if (attachedTarget) AttachThreadInput(me, target, false);
            if (attachedForeground) AttachThreadInput(me, foregroundThread, false);
        }
    }

    private static void LogFocus(string key, params string[] fields)
    {
        string cursor = "unknown";
        var info = new CursorInfo { Size = (uint)Marshal.SizeOf(typeof(CursorInfo)) };
        if (GetCursorInfo(ref info)) cursor = "0x" + info.Flags.ToString("X");
        string foregroundName = "none";
        try
        {
            uint pid;
            IntPtr foreground = GetForegroundWindow();
            if (foreground != IntPtr.Zero && GetWindowThreadProcessId(foreground, out pid) != 0)
                using (Process process = Process.GetProcessById((int)pid)) foregroundName = process.ProcessName;
        }
        catch (Exception) { }
        GateLog.Info(key, fields.Concat(new[] { "cursorFlags=" + cursor, "foreground=" + foregroundName }).ToArray());
    }

    // ---- process start ---------------------------------------------------------------------------------

    private static void ShowError(string message)
    {
        MessageBox.Show(message, ProductBrand.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }

    private static string Quote(string value)
    {
        if (value.Length > 0 && value.IndexOfAny(new[] { ' ', '\t', '"' }) < 0) return value;
        var result = new StringBuilder("\"");
        int slashes = 0;
        foreach (char c in value)
        {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') result.Append('\\', slashes + 1);
            result.Append('\\', slashes).Append(c);
            slashes = 0;
        }
        return result.Append('\\', slashes * 2).Append('"').ToString();
    }

    private static uint Launch(string path, string[] arguments)
    {
        var command = new StringBuilder(string.Join(" ", new[] { path }.Concat(arguments).Select(Quote)));
        var startup = new StartupInfo { Size = Marshal.SizeOf(typeof(StartupInfo)) };
        ProcessInformation process;
        const uint DebugOnlyThisProcess = 0x2;
        const uint CreateSuspended = 0x4;
        if (!CreateProcess(path, command, IntPtr.Zero, IntPtr.Zero, false,
            DebugOnlyThisProcess | CreateSuspended, IntPtr.Zero, null, ref startup, out process))
            throw new Win32Exception();

        bool started = false;
        try
        {
            var image = new StringBuilder(32768);
            int size = image.Capacity;
            if (!QueryFullProcessImageName(process.Process, 0, image, ref size) ||
                !string.Equals(path, image.ToString(), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("실행 파일을 확인하지 못했습니다.");
            if (!DebugActiveProcessStop(process.ProcessId) || ResumeThread(process.Thread) == uint.MaxValue)
                throw new Win32Exception();
            started = true;
            return process.ProcessId;
        }
        finally
        {
            if (!started) TerminateProcess(process.Process, 1);
            CloseHandle(process.Thread);
            CloseHandle(process.Process);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Size;
        public string Reserved, Desktop, Title;
        public int X, Y, Width, Height, XCount, YCount, Fill, Flags;
        public short Show, ReservedSize;
        public IntPtr ReservedData, Input, Output, Error;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process, Thread;
        public uint ProcessId, ThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcess(string path, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory,
        ref StartupInfo startup, out ProcessInformation process);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder image, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugActiveProcessStop(uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll")]
    private static extern bool TerminateProcess(IntPtr process, uint code);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [StructLayout(LayoutKind.Sequential)]
    private struct ScreenPoint
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CursorInfo
    {
        public uint Size;
        public uint Flags;
        public IntPtr Cursor;
        public ScreenPoint ScreenPosition;
    }

    private delegate bool EnumProc(IntPtr window, IntPtr state);

    [DllImport("user32.dll")]
    private static extern bool GetCursorInfo(ref CursorInfo cursorInfo);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumProc callback, IntPtr state);

    [DllImport("user32.dll")]
    private static extern bool IsIconic(IntPtr window);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr window, int command);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr window);

    [DllImport("user32.dll")]
    private static extern bool BringWindowToTop(IntPtr window);

    [DllImport("user32.dll")]
    private static extern IntPtr SetFocus(IntPtr window);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);

    [DllImport("user32.dll")]
    private static extern bool AttachThreadInput(uint attach, uint attachTo, bool attached);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool SetProp(IntPtr window, string name, IntPtr data);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetProp(IntPtr window, string name);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr RemoveProp(IntPtr window, string name);
}
