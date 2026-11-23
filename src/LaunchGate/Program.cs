using System;
using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

internal static class Gate
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length < 2 || args[0] != "--launch") return 1;
        try
        {
            if (!Path.IsPathRooted(args[1])) throw new InvalidDataException("보호 앱의 전체 경로가 필요합니다.");
            string path = Path.GetFullPath(args[1]);
            if (!File.Exists(path)) throw new FileNotFoundException("보호 앱을 찾을 수 없습니다.");
            byte result = Authorize(path, string.Empty);
            if (result == GateProtocol.PromptRequired)
            {
                string pin = Prompt(Path.GetFileName(path));
                if (string.IsNullOrWhiteSpace(pin)) return 1;
                result = Authorize(path, pin);
            }
            if (result != GateProtocol.Approved)
            {
                ShowError(result == GateProtocol.RateLimited
                    ? "PIN 입력 제한이 활성화되어 있습니다. 잠시 후 다시 시도하세요."
                    : "PIN이 일치하지 않거나 현재 실행할 수 없는 앱입니다.");
                return 1;
            }

            var child = Launch(path, args.Skip(2).ToArray());
            EnsureCursorVisible();
            try { Exchange(GateProtocol.Track, path, child.ToString(System.Globalization.CultureInfo.InvariantCulture)); }
            catch (IOException) { }
            catch (TimeoutException) { }
            return 0;
        }
        catch (Exception ex)
        {
            ShowError("보호 앱을 실행할 수 없습니다.\n" + ex.Message);
            return 1;
        }
    }

    private static byte Authorize(string path, string pin)
    {
        return Exchange(GateProtocol.Authorize, path, pin);
    }

    private static byte Exchange(byte command, string path, string value)
    {
        using (var pipe = GateProtocol.ConnectToService())
        {
            pipe.WriteByte(GateProtocol.Version);
            pipe.WriteByte(command);
            GateProtocol.WriteText(pipe, path, 4096);
            GateProtocol.WriteText(pipe, value, 128);
            pipe.Flush();
            return GateProtocol.Read(pipe, 1, DateTime.UtcNow.AddSeconds(5))[0];
        }
    }

    private static string Prompt(string name)
    {
        Application.EnableVisualStyles();
        using (var form = new Form { Text = ProductBrand.Name, Width = 410, Height = 190,
            StartPosition = FormStartPosition.CenterScreen, FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false, MinimizeBox = false, AutoScaleMode = AutoScaleMode.Font })
        {
            var label = new Label { Left = 16, Top = 16, Width = 365, Height = 34,
                Text = name + " 실행 PIN을 입력하세요.", AutoEllipsis = true };
            var pin = new TextBox { Left = 16, Top = 57, Width = 365, MaxLength = 32,
                UseSystemPasswordChar = true, AccessibleName = "실행 PIN" };
            var open = new Button { Text = "실행", Left = 222, Top = 95, Width = 75, DialogResult = DialogResult.OK };
            var cancel = new Button { Text = "취소", Left = 306, Top = 95, Width = 75, DialogResult = DialogResult.Cancel };
            form.Controls.AddRange(new Control[] { label, pin, open, cancel });
            form.AcceptButton = open;
            form.CancelButton = cancel;
            form.ActiveControl = pin;
            DialogResult result = form.ShowDialog();
            EnsureCursorVisible();
            return result == DialogResult.OK ? pin.Text : null;
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
