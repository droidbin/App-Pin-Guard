using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

// Maps a top-level window to the locked app it belongs to (docs/DESIGN-app-lock-redesign.md section 4.1).
// Used by the session agent (to hide) and by Gate (to find the window it must activate). One instance per scan:
// process lookups are cached until Reset().
internal sealed class WindowResolver
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const int GwlExStyle = -20;
    private const long WsExToolWindow = 0x80;

    private readonly Dictionary<uint, ProcessDetails> cache = new Dictionary<uint, ProcessDetails>();
    private IList<EnforcementApp> apps = new List<EnforcementApp>();
    private bool needFamily;

    private struct ProcessDetails
    {
        internal string Path;
        internal string Family;
        internal long StartTicks;
    }

    // The window's app, its executable (the process that matched) and that process's start time.
    internal struct Resolution
    {
        internal EnforcementApp App;
        internal string Path;
        internal long StartTicks;
    }

    internal void SetApps(IList<EnforcementApp> value)
    {
        apps = value ?? new List<EnforcementApp>();
        needFamily = false;
        foreach (EnforcementApp app in apps)
            if (app.Kind == EnforcementApp.KindPackage) needFamily = true;
        cache.Clear();
    }

    internal void Reset()
    {
        cache.Clear();
    }

    internal bool Resolve(IntPtr window, out Resolution resolution)
    {
        resolution = default(Resolution);
        if (apps.Count == 0) return false;
        uint owner;
        if (GetWindowThreadProcessId(window, out owner) == 0 || owner == 0) return false;

        ProcessDetails details = Describe(owner);
        EnforcementApp app = AppMatcher.Match(apps, details.Path, details.Family);
        if (app != null)
        {
            resolution = new Resolution { App = app, Path = details.Path, StartTicks = details.StartTicks };
            return true;
        }
        if (!needFamily || details.Path == null ||
            !string.Equals(System.IO.Path.GetFileName(details.Path), "ApplicationFrameHost.exe", StringComparison.OrdinalIgnoreCase))
            return false;

        // A packaged app's frame is owned by ApplicationFrameHost; the app's own process owns a child window.
        // Only a process that has a package family counts: a Win32 app (Chrome) owns helper-process child windows
        // that must never decide the fate of the top-level window.
        Resolution found = default(Resolution);
        bool match = false;
        EnumChildWindows(window, delegate(IntPtr child, IntPtr state)
        {
            uint pid;
            GetWindowThreadProcessId(child, out pid);
            if (pid == 0 || pid == owner) return true;
            ProcessDetails childDetails = Describe(pid);
            if (childDetails.Family == null) return true;
            EnforcementApp childApp = AppMatcher.Match(apps, childDetails.Path, childDetails.Family);
            if (childApp == null || childApp.Kind != EnforcementApp.KindPackage) return true;
            found = new Resolution { App = childApp, Path = childDetails.Path, StartTicks = childDetails.StartTicks };
            match = true;
            return false;
        }, IntPtr.Zero);
        resolution = found;
        return match;
    }

    // Executable path and package family of a process (null when it cannot be opened).
    internal void DescribeProcess(uint pid, out string path, out string family)
    {
        ProcessDetails details = Describe(pid);
        path = details.Path;
        family = details.Family;
    }

    // The front-most visible top-level window of the app, or IntPtr.Zero.
    internal IntPtr FindVisibleWindow(string appId)
    {
        return FindVisibleWindow(new[] { appId });
    }

    // The front-most visible top-level window that belongs to any of the apps.
    internal IntPtr FindVisibleWindow(ICollection<string> appIds)
    {
        Reset();
        IntPtr result = IntPtr.Zero;
        EnumWindows(delegate(IntPtr window, IntPtr state)
        {
            if (!IsWindowVisible(window)) return true;
            if ((GetWindowLongPtr(window, GwlExStyle).ToInt64() & WsExToolWindow) != 0) return true;
            Resolution resolution;
            if (Resolve(window, out resolution) && appIds.Contains(resolution.App.Id))
            {
                result = window;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return result;
    }

    private ProcessDetails Describe(uint pid)
    {
        ProcessDetails details;
        if (cache.TryGetValue(pid, out details)) return details;
        IntPtr handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle != IntPtr.Zero)
        {
            try
            {
                var image = new StringBuilder(32768);
                int length = image.Capacity;
                if (QueryFullProcessImageName(handle, 0, image, ref length)) details.Path = image.ToString();
                long created, exited, kernel, user;
                if (GetProcessTimes(handle, out created, out exited, out kernel, out user) && created > 0)
                    details.StartTicks = DateTime.FromFileTimeUtc(created).Ticks;
                if (needFamily)
                {
                    int count = 0;
                    if (GetPackageFamilyName(handle, ref count, null) == 122 && count > 0 && count < 512)
                    {
                        var family = new StringBuilder(count);
                        if (GetPackageFamilyName(handle, ref count, family) == 0) details.Family = family.ToString();
                    }
                }
            }
            finally { CloseHandle(handle); }
        }
        cache[pid] = details;
        return details;
    }

    private delegate bool EnumProc(IntPtr window, IntPtr state);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc callback, IntPtr state);
    [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr window, EnumProc callback, IntPtr state);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")] private static extern IntPtr GetWindowLongPtr(IntPtr window, int index);
    [DllImport("kernel32.dll")] private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder image, ref int size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackageFamilyName(IntPtr process, ref int length, StringBuilder name);
}
