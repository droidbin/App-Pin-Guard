using System.Runtime.InteropServices;

namespace WindowsAppProtector.Platform;

/// <summary>
/// After "unlock all" the window agent shows the hidden windows without activating them (it has no foreground
/// right). With no activated window the pointer stays invisible until the next click. The UI process has just
/// received the user's click or hotkey, so it hands the foreground to the front-most restored app window.
/// </summary>
internal static class ForegroundActivator
{
    private const int SwRestore = 9;
    private const int PollIntervalMs = 100;
    private const int WaitMs = 4000;

    /// <summary>Waits for a visible window of one of the apps and activates it. Returns whether one was activated.</summary>
    public static async Task<bool> ActivateFirstWindowOfAsync(IReadOnlyCollection<AppPolicy> apps)
    {
        var enforced = new List<EnforcementApp>();
        foreach (var app in apps)
        {
            if (string.IsNullOrEmpty(app.Id)) continue;
            var match = app.IsPackaged ? app.PackageFamilyName : PolicyRules.NormalizePath(app.Path);
            if (string.IsNullOrWhiteSpace(match)) continue;
            enforced.Add(new EnforcementApp
            {
                Id = app.Id,
                Kind = app.IsPackaged ? EnforcementApp.KindPackage : EnforcementApp.KindWindow,
                Match = match,
            });
        }

        if (enforced.Count == 0) return false;
        var ids = enforced.Select(app => app.Id).ToHashSet(StringComparer.Ordinal);
        var resolver = new WindowResolver();
        resolver.SetApps(enforced);

        for (var waited = 0; waited < WaitMs; waited += PollIntervalMs)
        {
            await Task.Delay(PollIntervalMs);
            var window = resolver.FindVisibleWindow(ids);
            if (window != IntPtr.Zero) return Activate(window);
        }

        return false;
    }

    private static bool Activate(IntPtr window)
    {
        if (IsIconic(window)) ShowWindow(window, SwRestore);
        if (SetForegroundWindow(window)) return true;

        // Refused: join the input of the current foreground thread and of the window's thread, then retry.
        var me = GetCurrentThreadId();
        var target = GetWindowThreadProcessId(window, out _);
        var foreground = GetForegroundWindow();
        var foregroundThread = foreground == IntPtr.Zero ? 0 : GetWindowThreadProcessId(foreground, out _);
        var attachedTarget = target != 0 && target != me && AttachThreadInput(me, target, true);
        var attachedForeground = foregroundThread != 0 && foregroundThread != me && foregroundThread != target &&
            AttachThreadInput(me, foregroundThread, true);
        try
        {
            BringWindowToTop(window);
            var ok = SetForegroundWindow(window);
            SetFocus(window);
            return ok;
        }
        finally
        {
            if (attachedTarget) AttachThreadInput(me, target, false);
            if (attachedForeground) AttachThreadInput(me, foregroundThread, false);
        }
    }

    [DllImport("user32.dll")] private static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr window, int command);
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr window);
    [DllImport("user32.dll")] private static extern bool BringWindowToTop(IntPtr window);
    [DllImport("user32.dll")] private static extern IntPtr SetFocus(IntPtr window);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll")] private static extern bool AttachThreadInput(uint attach, uint attachTo, bool attached);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
}
