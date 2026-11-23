using System.Reflection;
using System.Runtime.InteropServices;

namespace WindowsAppProtector.Platform;

public enum SessionChangeKind
{
    Locked,
    Unlocked,
    ConsoleDisconnect,
    RemoteDisconnect,
    Suspend,
    Resume,
}

public sealed record TrayMenuItem(int Id, string Text, bool IsSeparator = false, bool IsEnabled = true)
{
    public static TrayMenuItem Separator() => new(0, string.Empty, IsSeparator: true, IsEnabled: false);

    public static TrayMenuItem Header(string text) => new(0, text, IsSeparator: false, IsEnabled: false);
}

public sealed class Win32MessageWindow : IDisposable
{
    private static readonly Dictionary<string, int> NamedVirtualKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Back"] = 0x08,
        ["Backspace"] = 0x08,
        ["Tab"] = 0x09,
        ["Clear"] = 0x0C,
        ["Enter"] = 0x0D,
        ["Return"] = 0x0D,
        ["Pause"] = 0x13,
        ["CapitalLock"] = 0x14,
        ["CapsLock"] = 0x14,
        ["Escape"] = 0x1B,
        ["Esc"] = 0x1B,
        ["Space"] = 0x20,
        ["PageUp"] = 0x21,
        ["Prior"] = 0x21,
        ["PageDown"] = 0x22,
        ["Next"] = 0x22,
        ["End"] = 0x23,
        ["Home"] = 0x24,
        ["Left"] = 0x25,
        ["Up"] = 0x26,
        ["Right"] = 0x27,
        ["Down"] = 0x28,
        ["Select"] = 0x29,
        ["Print"] = 0x2A,
        ["Execute"] = 0x2B,
        ["Snapshot"] = 0x2C,
        ["PrintScreen"] = 0x2C,
        ["Insert"] = 0x2D,
        ["Delete"] = 0x2E,
        ["Help"] = 0x2F,
        ["Number0"] = 0x30,
        ["Number1"] = 0x31,
        ["Number2"] = 0x32,
        ["Number3"] = 0x33,
        ["Number4"] = 0x34,
        ["Number5"] = 0x35,
        ["Number6"] = 0x36,
        ["Number7"] = 0x37,
        ["Number8"] = 0x38,
        ["Number9"] = 0x39,
        ["Application"] = 0x5D,
        ["Sleep"] = 0x5F,
        ["NumberPad0"] = 0x60,
        ["NumberPad1"] = 0x61,
        ["NumberPad2"] = 0x62,
        ["NumberPad3"] = 0x63,
        ["NumberPad4"] = 0x64,
        ["NumberPad5"] = 0x65,
        ["NumberPad6"] = 0x66,
        ["NumberPad7"] = 0x67,
        ["NumberPad8"] = 0x68,
        ["NumberPad9"] = 0x69,
        ["NumPad0"] = 0x60,
        ["NumPad1"] = 0x61,
        ["NumPad2"] = 0x62,
        ["NumPad3"] = 0x63,
        ["NumPad4"] = 0x64,
        ["NumPad5"] = 0x65,
        ["NumPad6"] = 0x66,
        ["NumPad7"] = 0x67,
        ["NumPad8"] = 0x68,
        ["NumPad9"] = 0x69,
        ["Num0"] = 0x60,
        ["Num1"] = 0x61,
        ["Num2"] = 0x62,
        ["Num3"] = 0x63,
        ["Num4"] = 0x64,
        ["Num5"] = 0x65,
        ["Num6"] = 0x66,
        ["Num7"] = 0x67,
        ["Num8"] = 0x68,
        ["Num9"] = 0x69,
        ["Multiply"] = 0x6A,
        ["NumMultiply"] = 0x6A,
        ["Add"] = 0x6B,
        ["NumPlus"] = 0x6B,
        ["Separator"] = 0x6C,
        ["Subtract"] = 0x6D,
        ["NumMinus"] = 0x6D,
        ["Decimal"] = 0x6E,
        ["NumDecimal"] = 0x6E,
        ["Divide"] = 0x6F,
        ["NumDivide"] = 0x6F,
        ["NumberKeyLock"] = 0x90,
        ["NumLock"] = 0x90,
        ["Scroll"] = 0x91,
        ["ScrollLock"] = 0x91,
        ["GoBack"] = 0xA6,
        ["GoForward"] = 0xA7,
        ["Refresh"] = 0xA8,
        ["Stop"] = 0xA9,
        ["Search"] = 0xAA,
        ["Favorites"] = 0xAB,
        ["GoHome"] = 0xAC,
    };

    private readonly uint taskbarCreatedMessage = NativeMethods.RegisterWindowMessage("TaskbarCreated");
    private readonly NativeMethods.WndProcDelegate messageWndProcDelegate;
    private readonly HashSet<int> registeredHotkeyIds = new();
    private readonly string trayIconPath;
    private TrayMenuItem[] trayMenuItems =
    {
        new(1, "열기"),
        new(2, "전체 잠금"),
        new(3, "종료"),
    };
    private string trayTooltip;
    private bool trayIconAdded;
    private bool sessionNotificationsRegistered;
    private bool ownsTrayIconHandle;
    private IntPtr trayIconHandle;
    private bool disposed;

    public Win32MessageWindow(string? trayTooltip = null, string? trayIconPath = null)
    {
        this.trayTooltip = trayTooltip ?? $"{ProductBrand.Name} v{GetCurrentVersionText()}";
        this.trayIconPath = trayIconPath ?? Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico");
        messageWndProcDelegate = MessageWndProc;
        Handle = CreateMessageWindow();
    }

    public IntPtr Handle { get; private set; }

    public bool IsTrayIconAdded => trayIconAdded;

    public bool IsSessionNotificationsRegistered => sessionNotificationsRegistered;

    public bool TrayMenuEnabled { get; set; } = true;

    public event Action? ShowRequested;

    public event Action<int>? HotkeyPressed;

    public event Action<SessionChangeKind>? SessionChanged;

    public event Action<int>? TrayMenuCommand;

    public event Action? TrayMenuOpening;

    public event Action? TrayDoubleClick;

    public static void SignalRunningInstance()
    {
        var existing = NativeMethods.FindWindowEx(IntPtr.Zero, IntPtr.Zero, NativeMethods.MessageWindowClassName, null);
        if (existing != IntPtr.Zero)
        {
            NativeMethods.PostMessage(existing, NativeMethods.WmShowRequest, IntPtr.Zero, IntPtr.Zero);
        }
    }

    public void AddTrayIcon()
    {
        EnsureTrayIcon();
    }

    public void EnsureTrayIcon()
    {
        if (disposed || Handle == IntPtr.Zero)
        {
            return;
        }

        var data = CreateTrayIconData();
        if (trayIconAdded && NativeMethods.Shell_NotifyIcon(NativeMethods.NimModify, ref data))
        {
            return;
        }

        trayIconAdded = NativeMethods.Shell_NotifyIcon(NativeMethods.NimAdd, ref data);
    }

    public void RemoveTrayIcon()
    {
        if (trayIconAdded)
        {
            var data = CreateTrayIconData();
            NativeMethods.Shell_NotifyIcon(NativeMethods.NimDelete, ref data);
            trayIconAdded = false;
        }

        if (ownsTrayIconHandle && trayIconHandle != IntPtr.Zero)
        {
            NativeMethods.DestroyIcon(trayIconHandle);
        }

        trayIconHandle = IntPtr.Zero;
        ownsTrayIconHandle = false;
    }

    public void SetTrayMenuItems(IEnumerable<TrayMenuItem> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        trayMenuItems = items.ToArray();
    }

    public void UpdateTrayTooltip(string tooltip)
    {
        trayTooltip = tooltip ?? string.Empty;
        if (trayIconAdded)
        {
            EnsureTrayIcon();
        }
    }

    public bool EnsureSessionNotificationsRegistered()
    {
        if (disposed || Handle == IntPtr.Zero)
        {
            return false;
        }

        if (!sessionNotificationsRegistered)
        {
            sessionNotificationsRegistered = NativeMethods.WTSRegisterSessionNotification(Handle, 0);
        }

        return sessionNotificationsRegistered;
    }

    public bool RegisterHotkey(int id, int modifiers, int virtualKey)
    {
        if (disposed || Handle == IntPtr.Zero)
        {
            return false;
        }

        if (NativeMethods.RegisterHotKey(Handle, id, modifiers | NativeMethods.ModNoRepeat, virtualKey))
        {
            registeredHotkeyIds.Add(id);
            return true;
        }

        return false;
    }

    public bool RegisterHotkey(int id, string hotkeyText)
    {
        if (!TryParseHotkey(hotkeyText, out var modifiers, out var virtualKey))
        {
            return false;
        }

        return RegisterHotkey(id, modifiers, virtualKey);
    }

    public bool UnregisterHotkey(int id)
    {
        if (Handle == IntPtr.Zero)
        {
            registeredHotkeyIds.Remove(id);
            return false;
        }

        var unregistered = NativeMethods.UnregisterHotKey(Handle, id);
        registeredHotkeyIds.Remove(id);
        return unregistered;
    }

    public void UnregisterAll()
    {
        foreach (var id in registeredHotkeyIds.ToArray())
        {
            if (Handle != IntPtr.Zero)
            {
                NativeMethods.UnregisterHotKey(Handle, id);
            }
        }

        registeredHotkeyIds.Clear();
    }

    public static bool TryParseHotkey(string text, out int modifiers, out int virtualKey)
    {
        modifiers = 0;
        virtualKey = 0;

        var normalizedText = text
            .Replace("Num+", "NumPlus", StringComparison.OrdinalIgnoreCase)
            .Replace("Num-", "NumMinus", StringComparison.OrdinalIgnoreCase)
            .Replace("Num*", "NumMultiply", StringComparison.OrdinalIgnoreCase)
            .Replace("Num/", "NumDivide", StringComparison.OrdinalIgnoreCase)
            .Replace("Num.", "NumDecimal", StringComparison.OrdinalIgnoreCase);

        var parts = normalizedText
            .Split('+', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToArray();

        if (parts.Length == 0)
        {
            return false;
        }

        foreach (var part in parts.Take(parts.Length - 1))
        {
            switch (part.ToUpperInvariant())
            {
                case "CTRL":
                case "CONTROL":
                    modifiers |= NativeMethods.ModControl;
                    break;
                case "ALT":
                    modifiers |= NativeMethods.ModAlt;
                    break;
                case "SHIFT":
                    modifiers |= NativeMethods.ModShift;
                    break;
                case "WIN":
                case "WINDOWS":
                    modifiers |= NativeMethods.ModWin;
                    break;
                default:
                    return false;
            }
        }

        return TryParseVirtualKey(parts[^1], out virtualKey);
    }

    public static bool TryParseVirtualKey(string keyText, out int virtualKey)
    {
        virtualKey = 0;
        var normalized = keyText.ToUpperInvariant();

        if (normalized.Length == 1)
        {
            var ch = normalized[0];
            if (ch is >= 'A' and <= 'Z' or >= '0' and <= '9')
            {
                virtualKey = ch;
                return true;
            }
        }

        if (normalized.StartsWith("F", StringComparison.Ordinal) &&
            int.TryParse(normalized[1..], out var functionNumber) &&
            functionNumber is >= 1 and <= 24)
        {
            virtualKey = 0x70 + functionNumber - 1;
            return true;
        }

        if (NamedVirtualKeys.TryGetValue(keyText, out var mappedVirtualKey))
        {
            virtualKey = mappedVirtualKey;
            return true;
        }

        return false;
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        UnregisterAll();
        RemoveTrayIcon();

        if (Handle != IntPtr.Zero)
        {
            if (sessionNotificationsRegistered)
            {
                NativeMethods.WTSUnRegisterSessionNotification(Handle);
                sessionNotificationsRegistered = false;
            }

            NativeMethods.DestroyWindow(Handle);
            Handle = IntPtr.Zero;
        }
    }

    private IntPtr CreateMessageWindow()
    {
        var instance = Marshal.GetHINSTANCE(typeof(Win32MessageWindow).Module);
        var wndClass = new NativeMethods.WindowClassEx
        {
            cbSize = (uint)Marshal.SizeOf<NativeMethods.WindowClassEx>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(messageWndProcDelegate),
            hInstance = instance,
            // This hidden top-level window receives session and power messages. Give it an
            // explicit class cursor so a secure-desktop transition cannot leave its cursor null.
            hCursor = NativeMethods.LoadCursor(IntPtr.Zero, NativeMethods.IdcArrow),
            lpszClassName = NativeMethods.MessageWindowClassName,
        };

        var classAtom = NativeMethods.RegisterClassEx(ref wndClass);
        var registerError = Marshal.GetLastWin32Error();
        if (classAtom == 0 && registerError != NativeMethods.ErrorClassAlreadyExists)
        {
            throw new InvalidOperationException("단축키 메시지 창을 등록할 수 없습니다.");
        }

        // A hidden top-level window (never shown) instead of HWND_MESSAGE: message-only windows
        // do not receive the TaskbarCreated broadcast sent when Explorer restarts.
        var handle = NativeMethods.CreateWindowEx(
            NativeMethods.WsExToolWindow,
            NativeMethods.MessageWindowClassName,
            string.Empty,
            0,
            0,
            0,
            0,
            0,
            IntPtr.Zero,
            IntPtr.Zero,
            instance,
            IntPtr.Zero);

        if (handle == IntPtr.Zero)
        {
            throw new InvalidOperationException("단축키 메시지 창을 만들 수 없습니다.");
        }

        // This process runs elevated; let Explorer (medium integrity) deliver tray messages.
        if (taskbarCreatedMessage != 0)
        {
            NativeMethods.ChangeWindowMessageFilterEx(handle, taskbarCreatedMessage, NativeMethods.MsgFltAllow, IntPtr.Zero);
        }

        NativeMethods.ChangeWindowMessageFilterEx(handle, NativeMethods.WmTrayIcon, NativeMethods.MsgFltAllow, IntPtr.Zero);
        return handle;
    }

    private IntPtr MessageWndProc(IntPtr windowHandle, uint message, IntPtr wParam, IntPtr lParam)
    {
        if (message == NativeMethods.WmWtsSessionChange)
        {
            switch (wParam.ToInt64())
            {
                case NativeMethods.WtsSessionUnlock:
                    SessionChanged?.Invoke(SessionChangeKind.Unlocked);
                    break;
                case NativeMethods.WtsSessionLock:
                    SessionChanged?.Invoke(SessionChangeKind.Locked);
                    return IntPtr.Zero;
                case NativeMethods.WtsConsoleDisconnect:
                    SessionChanged?.Invoke(SessionChangeKind.ConsoleDisconnect);
                    return IntPtr.Zero;
                case NativeMethods.WtsRemoteDisconnect:
                    SessionChanged?.Invoke(SessionChangeKind.RemoteDisconnect);
                    return IntPtr.Zero;
            }
        }

        if (message == NativeMethods.WmPowerBroadcast)
        {
            switch (wParam.ToInt64())
            {
                case NativeMethods.PowerSuspend:
                    SessionChanged?.Invoke(SessionChangeKind.Suspend);
                    return new IntPtr(1);
                case NativeMethods.PowerResumeAutomatic:
                    SessionChanged?.Invoke(SessionChangeKind.Resume);
                    return new IntPtr(1);
            }
        }

        if (message == NativeMethods.WmTrayIcon && lParam.ToInt64() == NativeMethods.WmRButtonUp)
        {
            ShowTrayMenu(windowHandle);
            return IntPtr.Zero;
        }

        if (message == NativeMethods.WmTrayIcon && lParam.ToInt64() == NativeMethods.WmLButtonDblClk)
        {
            TrayDoubleClick?.Invoke();
            return IntPtr.Zero;
        }

        if (taskbarCreatedMessage != 0 && message == taskbarCreatedMessage)
        {
            // Explorer restarted: the old notification icon is gone, add it again.
            trayIconAdded = false;
            EnsureTrayIcon();
            return IntPtr.Zero;
        }

        if (message == NativeMethods.WmShowRequest)
        {
            ShowRequested?.Invoke();
            return IntPtr.Zero;
        }

        if (message == NativeMethods.WmHotkey && registeredHotkeyIds.Contains(wParam.ToInt32()))
        {
            HotkeyPressed?.Invoke(wParam.ToInt32());
            return IntPtr.Zero;
        }

        return NativeMethods.DefWindowProc(windowHandle, message, wParam, lParam);
    }

    private void ShowTrayMenu(IntPtr owner)
    {
        if (!TrayMenuEnabled || disposed)
        {
            return;
        }

        TrayMenuOpening?.Invoke();

        if (trayMenuItems.Length == 0 || !NativeMethods.GetCursorPos(out var point))
        {
            return;
        }

        var menu = NativeMethods.CreatePopupMenu();
        if (menu == IntPtr.Zero)
        {
            return;
        }

        uint command;
        try
        {
            foreach (var item in trayMenuItems)
            {
                if (item.IsSeparator)
                {
                    NativeMethods.AppendMenu(menu, NativeMethods.MfSeparator, 0, string.Empty);
                }
                else
                {
                    var flags = item.IsEnabled
                        ? NativeMethods.MfString
                        : NativeMethods.MfString | NativeMethods.MfDisabled | NativeMethods.MfGrayed;
                    NativeMethods.AppendMenu(menu, flags, (nuint)item.Id, item.Text);
                }
            }

            NativeMethods.SetForegroundWindow(owner);
            command = NativeMethods.TrackPopupMenu(menu, NativeMethods.TpmPopupFlags, point.X, point.Y, 0, owner, IntPtr.Zero);
            NativeMethods.PostMessage(owner, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally
        {
            NativeMethods.DestroyMenu(menu);
        }

        if (command != 0)
        {
            TrayMenuCommand?.Invoke((int)command);
        }
    }

    private NativeMethods.NotifyIconData CreateTrayIconData()
    {
        return new NativeMethods.NotifyIconData
        {
            cbSize = Marshal.SizeOf<NativeMethods.NotifyIconData>(),
            hWnd = Handle,
            uID = 1,
            uFlags = NativeMethods.NifMessage | NativeMethods.NifIcon | NativeMethods.NifTip,
            uCallbackMessage = NativeMethods.WmTrayIcon,
            hIcon = GetTrayIconHandle(),
            szTip = trayTooltip,
        };
    }

    private IntPtr GetTrayIconHandle()
    {
        if (trayIconHandle != IntPtr.Zero)
        {
            return trayIconHandle;
        }

        trayIconHandle = NativeMethods.LoadImage(
            IntPtr.Zero,
            trayIconPath,
            NativeMethods.ImageIcon,
            0,
            0,
            NativeMethods.LrLoadFromFile | NativeMethods.LrDefaultSize);
        ownsTrayIconHandle = trayIconHandle != IntPtr.Zero;
        if (!ownsTrayIconHandle)
        {
            trayIconHandle = NativeMethods.LoadIcon(IntPtr.Zero, NativeMethods.IdiApplication);
        }

        return trayIconHandle;
    }

    private static string GetCurrentVersionText()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? assembly.GetName().Version?.ToString(3)
            ?? "0.0.0";
        var metadataStart = version.IndexOf('+');
        return metadataStart < 0 ? version : version[..metadataStart];
    }
}
