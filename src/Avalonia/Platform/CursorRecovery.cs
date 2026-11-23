using System.Runtime.InteropServices;
using Avalonia.Threading;

namespace WindowsAppProtector.Platform;

public static class CursorRecovery
{
    private const int ShowCursorMaxRetries = 10;
    private const int PointerNudgeDelayMs = 15;
    private const int FirstFollowUpDelayMs = 250;
    private const int SecondFollowUpDeltaMs = 750;

    public static void EnsureCursorVisible()
    {
        for (int i = 0; i < ShowCursorMaxRetries && IsCursorHidden(); i++)
        {
            NativeMethods.ShowCursor(true);
        }

        NativeMethods.SetCursor(NativeMethods.LoadCursor(IntPtr.Zero, NativeMethods.IdcArrow));

        // "Hide pointer while typing" (mouse vanish) stays latched after a PIN is typed; toggling it
        // with fWinIni=0 resets the vanished state without touching the persisted setting.
        bool vanishEnabled = false;
        if (NativeMethods.SystemParametersInfo(NativeMethods.SpiGetMouseVanish, 0, ref vanishEnabled, 0) && vanishEnabled)
        {
            try { NativeMethods.SystemParametersInfo(NativeMethods.SpiSetMouseVanish, 0, IntPtr.Zero, 0); }
            finally { NativeMethods.SystemParametersInfo(NativeMethods.SpiSetMouseVanish, 0, new IntPtr(1), 0); }
        }

        // Two separate injections: a single {+1,-1} batch nets to zero movement and may not wake the pointer.
        var nudgeRight = new NativeMethods.Input[]
        {
            new() { type = NativeMethods.InputMouse, mi = new NativeMethods.MouseInput { dx = 2, dy = 0, dwFlags = NativeMethods.MouseEventfMove } },
        };
        var nudgeLeft = new NativeMethods.Input[]
        {
            new() { type = NativeMethods.InputMouse, mi = new NativeMethods.MouseInput { dx = -2, dy = 0, dwFlags = NativeMethods.MouseEventfMove } },
        };
        if (NativeMethods.SendInput(1, nudgeRight, Marshal.SizeOf<NativeMethods.Input>()) == 1)
        {
            Thread.Sleep(PointerNudgeDelayMs);
            NativeMethods.SendInput(1, nudgeLeft, Marshal.SizeOf<NativeMethods.Input>());
        }
        else if (NativeMethods.GetCursorPos(out var position))
        {
            NativeMethods.SetCursorPos(position.X + 1, position.Y);
            Thread.Sleep(PointerNudgeDelayMs);
            NativeMethods.SetCursorPos(position.X, position.Y);
        }
    }

    /// <summary>Restores the pointer now and again shortly after, once dialog teardown has settled.</summary>
    public static void RestoreAfterUnlock(string reason)
    {
        void RestoreAndLog(string stage)
        {
            var before = DescribeCursorForLog();
            EnsureCursorVisible();
            App.WriteProtectionLog($"{reason}/{stage} cursor {before} -> {DescribeCursorForLog()}");
        }

        RestoreAndLog("now");
        _ = Task.Run(async () =>
        {
            await Task.Delay(FirstFollowUpDelayMs);
            Dispatcher.UIThread.Post(() => RestoreAndLog("+250ms"));
            await Task.Delay(SecondFollowUpDeltaMs);
            Dispatcher.UIThread.Post(() => RestoreAndLog("+1000ms"));
        });
    }

    public static string DescribeCursorForLog()
    {
        var cursorInfo = new NativeMethods.CursorInfo
        {
            cbSize = (uint)Marshal.SizeOf<NativeMethods.CursorInfo>(),
        };
        bool vanishEnabled = false;
        NativeMethods.SystemParametersInfo(NativeMethods.SpiGetMouseVanish, 0, ref vanishEnabled, 0);
        return NativeMethods.GetCursorInfo(ref cursorInfo)
            ? $"flags=0x{cursorInfo.flags:X} hCursor=0x{cursorInfo.hCursor.ToInt64():X} vanish={vanishEnabled} fg=0x{NativeMethods.GetForegroundWindow().ToInt64():X}"
            : "unknown";
    }

    public static bool IsCursorHidden()
    {
        var cursorInfo = new NativeMethods.CursorInfo
        {
            cbSize = (uint)Marshal.SizeOf<NativeMethods.CursorInfo>(),
        };
        return NativeMethods.GetCursorInfo(ref cursorInfo) && (cursorInfo.flags & NativeMethods.CursorShowing) == 0;
    }
}
