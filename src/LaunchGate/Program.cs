using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
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

        // Started by the window agent when it hid a window of a window-mode app (browser): ask for the PIN and,
        // when the service approves, have it release that running process.
        if (args.Length >= 3 && args[0] == "--unlock") return Unlock(args[1], args[2]);

        if (args.Length < 2 || args[0] != "--launch") return 1;
        try
        {
            if (!Path.IsPathRooted(args[1])) throw new InvalidDataException("보호 앱의 전체 경로가 필요합니다.");
            string path = Path.GetFullPath(args[1]);
            if (!File.Exists(path)) throw new FileNotFoundException("보호 앱을 찾을 수 없습니다.");
            GateLog.Info("gate.launch.requested", "app=" + System.IO.Path.GetFileName(path));
            GateResponse response = Authorize(path, string.Empty);
            if (response.Result == GateSpool.ResultPrompt)
            {
                string pin = Prompt(path);
                if (string.IsNullOrWhiteSpace(pin)) return 1;
                response = Authorize(path, pin);
            }
            if (response.Result != GateSpool.ResultApproved)
            {
                GateLog.Info("gate.launch.refused", "result=" + response.Result);
                ShowError(DescribeRefusal(response));
                return 1;
            }

            var child = Launch(path, args.Skip(2).ToArray());
            EnsureCursorVisible();
            GateLog.Info("gate.launch.started", "pid=" + child);
            Track(path, (int)child);
            return 0;
        }
        catch (Exception ex)
        {
            GateLog.Exception("gate.launch.failed", ex);
            ShowError("보호 앱을 실행할 수 없습니다.\n" + ex.Message);
            return 1;
        }
    }

    private static int Unlock(string pidText, string appPath)
    {
        try
        {
            int target;
            if (!int.TryParse(pidText, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out target) ||
                target <= 0 || !Path.IsPathRooted(appPath)) return 1;
            string path = Path.GetFullPath(appPath);
            GateLog.Info("gate.unlock.requested", "app=" + System.IO.Path.GetFileName(path), "pid=" + target);
            GateResponse response = Authorize(path, string.Empty);
            if (response.Result == GateSpool.ResultPrompt)
            {
                string pin = Prompt(path);
                if (string.IsNullOrWhiteSpace(pin)) return 1;
                response = Authorize(path, pin);
            }
            if (response.Result == GateSpool.ResultApproved)
                response = Exchange(new GateRequest { Op = GateSpool.OpUnlock, Pid = Process.GetCurrentProcess().Id, Path = path, Child = target });
            if (response.Result != GateSpool.ResultApproved)
            {
                GateLog.Info("gate.unlock.refused", "result=" + response.Result);
                ShowError(DescribeRefusal(response));
                return 1;
            }
            GateLog.Info("gate.unlock.approved", "pid=" + target);
            return 0;
        }
        catch (Exception ex)
        {
            GateLog.Exception("gate.unlock.failed", ex);
            ShowError("앱을 열 수 없습니다.\n" + ex.Message);
            return 1;
        }
    }

    private static string DescribeRefusal(GateResponse response)
    {
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

    private static GateResponse Authorize(string path, string pin)
    {
        return Exchange(new GateRequest { Op = GateSpool.OpAuthorize, Pid = Process.GetCurrentProcess().Id, Path = path, Pin = pin });
    }

    private static void Track(string path, int child)
    {
        try
        {
            Exchange(new GateRequest { Op = GateSpool.OpTrack, Pid = Process.GetCurrentProcess().Id, Path = path, Child = child });
        }
        catch (IOException) { }
    }

    private static GateResponse Exchange(GateRequest request)
    {
        return GateSpool.Exchange(request);
    }

    private static string Prompt(string appPath)
    {
        Application.EnableVisualStyles();
        using (var form = new GateForm(appPath))
        {
            DialogResult result = form.ShowDialog();
            EnsureCursorVisible();
            return result == DialogResult.OK ? form.PinText : null;
        }
    }

    private static void EnsureCursorVisible()
    {
        for (int i = 0; i < 10 && IsCursorHidden(); i++)
        {
            ShowCursor(true);
        }

        SetCursor(LoadCursor(IntPtr.Zero, IdcArrow));

        // Reset the latched "hide pointer while typing" state (fWinIni=0: persisted setting untouched).
        bool vanishEnabled = false;
        if (SystemParametersInfo(SpiGetMouseVanish, 0, ref vanishEnabled, 0) && vanishEnabled)
        {
            try { SystemParametersInfo(SpiSetMouseVanish, 0, IntPtr.Zero, 0); }
            finally { SystemParametersInfo(SpiSetMouseVanish, 0, new IntPtr(1), 0); }
        }

        // Two separate injections: one {+1,-1} batch nets to zero movement and may not wake the pointer.
        var right = new Input[] { new Input { Type = InputMouse, Mi = new MouseInput { Dx = 2, Dy = 0, Flags = MouseEventfMove } } };
        var left = new Input[] { new Input { Type = InputMouse, Mi = new MouseInput { Dx = -2, Dy = 0, Flags = MouseEventfMove } } };
        int size = Marshal.SizeOf(typeof(Input));
        if (SendInput(1, right, size) == 1)
        {
            System.Threading.Thread.Sleep(15);
            SendInput(1, left, size);
        }
        else
        {
            ScreenPoint point;
            if (GetCursorPos(out point))
            {
                SetCursorPos(point.X + 1, point.Y);
                System.Threading.Thread.Sleep(15);
                SetCursorPos(point.X, point.Y);
            }
        }
    }

    private static bool IsCursorHidden()
    {
        var cursorInfo = new CursorInfo
        {
            Size = (uint)Marshal.SizeOf(typeof(CursorInfo)),
        };
        return GetCursorInfo(ref cursorInfo) && (cursorInfo.Flags & CursorShowing) == 0;
    }

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

    private const uint CursorShowing = 0x00000001;
    private const uint SpiGetMouseVanish = 0x1020;
    private const uint SpiSetMouseVanish = 0x1021;
    private const uint InputMouse = 0;
    private const uint MouseEventfMove = 0x0001;
    private static readonly IntPtr IdcArrow = new IntPtr(32512);

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

    [StructLayout(LayoutKind.Sequential)]
    private struct MouseInput
    {
        public int Dx;
        public int Dy;
        public uint MouseData;
        public uint Flags;
        public uint Time;
        public IntPtr ExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Input
    {
        public uint Type;
        public MouseInput Mi;
    }

    [DllImport("user32.dll")]
    private static extern bool GetCursorInfo(ref CursorInfo cursorInfo);

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out ScreenPoint point);

    [DllImport("user32.dll")]
    private static extern bool SetCursorPos(int x, int y);

    [DllImport("user32.dll")]
    private static extern bool SystemParametersInfo(uint action, uint param, ref bool value, uint flags);

    [DllImport("user32.dll")]
    private static extern bool SystemParametersInfo(uint action, uint param, IntPtr value, uint flags);

    [DllImport("user32.dll")]
    private static extern int ShowCursor(bool show);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadCursor(IntPtr instance, IntPtr cursorName);

    [DllImport("user32.dll")]
    private static extern IntPtr SetCursor(IntPtr cursor);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint inputsCount, Input[] inputs, int size);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}
