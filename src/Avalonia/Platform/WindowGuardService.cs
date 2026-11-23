using System.Text;
using Avalonia.Threading;

namespace WindowsAppProtector.Platform;

public interface IWindowGuardHost
{
    IntPtr OwnWindowHandle { get; }
    bool IsInitialized { get; }
    IReadOnlySet<string> GetLockedExecutableNames();
    IReadOnlySet<string> GetLockedPackageFamilyNames();
}

public sealed class WindowGuardService : IDisposable
{
    private const int GuardTimerIntervalMs = 700;
    private const long FullWindowScanIntervalMs = 5000;
    private const int MaxPendingWindowChecks = 512;

    private readonly Func<IntPtr> getOwnWindowHandle;
    private readonly Func<bool> isInitialized;
    private readonly Func<IReadOnlySet<string>> getLockedExecutables;
    private readonly Func<IReadOnlySet<string>> getLockedPackageFamilies;
    private readonly Action<Exception> logError;
    private readonly HashSet<IntPtr> hiddenProtectedWindows = new();
    private readonly Dictionary<IntPtr, uint> hiddenWindowOwners = new();
    private readonly string hiddenWindowsStatePath;
    private readonly DispatcherTimer windowGuardTimer = new() { Interval = TimeSpan.FromMilliseconds(GuardTimerIntervalMs) };
    private readonly NativeMethods.WinEventProc winEventCallback;
    private readonly HashSet<IntPtr> pendingWindowChecks = new();
    private IntPtr foregroundEventHook;
    private IntPtr showEventHook;
    private IReadOnlySet<string>? previousLockedExecutables;
    private IReadOnlySet<string>? previousLockedPackages;
    private long nextFullWindowScan;
    private bool started;
    private bool hiddenWindowsLoaded;
    private bool isClosing;

    public WindowGuardService(
        IWindowGuardHost host,
        string? hiddenWindowsStatePath = null,
        Action<Exception>? logError = null)
        : this(
            () => host.OwnWindowHandle,
            () => host.IsInitialized,
            host.GetLockedExecutableNames,
            host.GetLockedPackageFamilyNames,
            hiddenWindowsStatePath,
            logError)
    {
        ArgumentNullException.ThrowIfNull(host);
    }

    public WindowGuardService(
        Func<IntPtr> getOwnWindowHandle,
        Func<bool> isInitialized,
        Func<IReadOnlySet<string>> getLockedExecutables,
        Func<IReadOnlySet<string>> getLockedPackageFamilies,
        string? hiddenWindowsStatePath = null,
        Action<Exception>? logError = null)
    {
        this.getOwnWindowHandle = getOwnWindowHandle ?? throw new ArgumentNullException(nameof(getOwnWindowHandle));
        this.isInitialized = isInitialized ?? throw new ArgumentNullException(nameof(isInitialized));
        this.getLockedExecutables = getLockedExecutables ?? throw new ArgumentNullException(nameof(getLockedExecutables));
        this.getLockedPackageFamilies = getLockedPackageFamilies ?? throw new ArgumentNullException(nameof(getLockedPackageFamilies));
        this.logError = logError ?? App.WriteCrashLog;
        this.hiddenWindowsStatePath = hiddenWindowsStatePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WindowsAppProtector.WinUI",
            "hidden-windows.json");
        winEventCallback = QueueWindowCheck;
    }

    /// <summary>Invoked at the start of every 700ms timer tick, before the initialized check.</summary>
    public event Action? TickStarting;

    /// <summary>Invoked on every 700ms timer tick after the initialized check and before window scanning.</summary>
    public event Func<Task>? BeforeWindowScanAsync;

    public void Start()
    {
        if (started || isClosing)
        {
            return;
        }

        started = true;
        if (!hiddenWindowsLoaded)
        {
            LoadHiddenWindows();
            hiddenWindowsLoaded = true;
        }

        foregroundEventHook = NativeMethods.SetWinEventHook(
            NativeMethods.EventSystemForeground,
            NativeMethods.EventSystemForeground,
            IntPtr.Zero,
            winEventCallback,
            0,
            0,
            NativeMethods.WinEventSkipOwnProcess);
        showEventHook = NativeMethods.SetWinEventHook(
            NativeMethods.EventObjectShow,
            NativeMethods.EventObjectShow,
            IntPtr.Zero,
            winEventCallback,
            0,
            0,
            NativeMethods.WinEventSkipOwnProcess);
        windowGuardTimer.Tick += WindowGuardTimer_Tick;
        windowGuardTimer.Start();
    }

    public void RestoreHiddenProtectedWindows(
        IReadOnlySet<string>? lockedExecutables = null,
        IReadOnlySet<string>? lockedPackageFamilies = null)
    {
        if (hiddenProtectedWindows.Count == 0)
        {
            return;
        }

        var executableCache = new Dictionary<uint, string>();
        var packageCache = new Dictionary<uint, string>();
        var changed = false;
        foreach (var windowHandle in hiddenProtectedWindows.ToArray())
        {
            var owner = hiddenWindowOwners.GetValueOrDefault(windowHandle);
            if (IsOwnedBy(windowHandle, owner))
            {
                if (lockedExecutables is not null && lockedPackageFamilies is not null &&
                    IsProtectedWindow(windowHandle, owner, lockedExecutables, lockedPackageFamilies,
                        executableCache, packageCache, out _))
                {
                    continue;
                }

                if (!NativeMethods.IsWindowVisible(windowHandle))
                {
                    NativeMethods.ShowWindowAsync(windowHandle, NativeMethods.SwShowNa);
                    // Keep the record until the async request takes effect.
                    continue;
                }
            }

            hiddenProtectedWindows.Remove(windowHandle);
            hiddenWindowOwners.Remove(windowHandle);
            changed = true;
        }

        if (changed)
        {
            SaveHiddenWindows();
        }
    }

    public static string GetProcessExecutableName(uint processId)
    {
        var handle = NativeMethods.OpenProcess(NativeMethods.ProcessQueryLimitedInformation, false, processId);
        if (handle == IntPtr.Zero)
        {
            return string.Empty;
        }

        try
        {
            var capacity = 1024;
            var buffer = new StringBuilder(capacity);
            if (NativeMethods.QueryFullProcessImageNameW(handle, 0, buffer, ref capacity))
            {
                return Path.GetFileName(buffer.ToString());
            }

            return string.Empty;
        }
        catch
        {
            return string.Empty;
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    public static string GetProcessPackageFamilyName(uint processId)
    {
        var processHandle = NativeMethods.OpenProcess(NativeMethods.ProcessQueryLimitedInformation, false, processId);
        if (processHandle == IntPtr.Zero)
        {
            return string.Empty;
        }

        try
        {
            uint length = 0;
            if (NativeMethods.GetPackageFamilyName(processHandle, ref length, null) != NativeMethods.ErrorInsufficientBuffer || length == 0)
            {
                return string.Empty;
            }

            var packageFamilyName = new StringBuilder((int)length);
            return NativeMethods.GetPackageFamilyName(processHandle, ref length, packageFamilyName) == 0
                ? packageFamilyName.ToString()
                : string.Empty;
        }
        finally
        {
            NativeMethods.CloseHandle(processHandle);
        }
    }

    public void Dispose()
    {
        if (isClosing)
        {
            return;
        }

        isClosing = true;
        windowGuardTimer.Stop();
        windowGuardTimer.Tick -= WindowGuardTimer_Tick;

        if (foregroundEventHook != IntPtr.Zero)
        {
            NativeMethods.UnhookWinEvent(foregroundEventHook);
            foregroundEventHook = IntPtr.Zero;
        }

        if (showEventHook != IntPtr.Zero)
        {
            NativeMethods.UnhookWinEvent(showEventHook);
            showEventHook = IntPtr.Zero;
        }

        RestoreHiddenProtectedWindows();
    }

    private async void WindowGuardTimer_Tick(object? sender, EventArgs e)
    {
        try
        {
            TickStarting?.Invoke();

            if (!isInitialized() || isClosing)
            {
                return;
            }

            if (BeforeWindowScanAsync is not null)
            {
                foreach (Func<Task> handler in BeforeWindowScanAsync.GetInvocationList())
                {
                    await handler();
                }
            }

            var lockedExecutables = getLockedExecutables();
            var lockedPackageFamilies = getLockedPackageFamilies();
            RestoreHiddenProtectedWindows(lockedExecutables, lockedPackageFamilies);
            if (lockedExecutables.Count == 0 && lockedPackageFamilies.Count == 0)
            {
                return;
            }

            var now = Environment.TickCount64;
            var fullScan = foregroundEventHook == IntPtr.Zero || showEventHook == IntPtr.Zero ||
                now >= nextFullWindowScan || previousLockedExecutables?.SetEquals(lockedExecutables) != true ||
                previousLockedPackages?.SetEquals(lockedPackageFamilies) != true;
            var candidates = fullScan ? null : pendingWindowChecks.ToArray();
            pendingWindowChecks.Clear();
            if (fullScan)
            {
                nextFullWindowScan = now + FullWindowScanIntervalMs;
                previousLockedExecutables = lockedExecutables;
                previousLockedPackages = lockedPackageFamilies;
            }

            if (fullScan || candidates is { Length: > 0 })
            {
                HideLockedAppWindows(lockedExecutables, lockedPackageFamilies, candidates);
            }
        }
        catch (Exception ex)
        {
            logError(ex);
        }
    }

    private void HideLockedAppWindows(
        IReadOnlySet<string> lockedExecutables,
        IReadOnlySet<string> lockedPackageFamilies,
        IntPtr[]? candidates)
    {
        var ownWindowHandle = getOwnWindowHandle();
        var ownProcessId = Environment.ProcessId;
        var exeCache = new Dictionary<uint, string>();
        var pfnCache = new Dictionary<uint, string>();
        var changed = false;

        bool CheckWindow(IntPtr windowHandle, IntPtr _)
        {
            if (windowHandle == ownWindowHandle || !NativeMethods.IsWindowVisible(windowHandle))
            {
                return true;
            }

            NativeMethods.GetWindowThreadProcessId(windowHandle, out var processId);
            if (processId == 0 || processId == ownProcessId)
            {
                return true;
            }

            if (!IsProtectedWindow(windowHandle, processId, lockedExecutables, lockedPackageFamilies, exeCache, pfnCache, out var matchedName))
            {
                return true;
            }

            // Async: a hung protected app must not block this UI thread.
            if (NativeMethods.ShowWindowAsync(windowHandle, NativeMethods.SwHide) &&
                (!hiddenWindowOwners.TryGetValue(windowHandle, out var owner) || owner != processId))
            {
                hiddenProtectedWindows.Add(windowHandle);
                hiddenWindowOwners[windowHandle] = processId;
                changed = true;
            }

            return true;
        }

        if (candidates is null)
        {
            NativeMethods.EnumWindows(CheckWindow, IntPtr.Zero);
        }
        else
        {
            foreach (var candidate in candidates)
            {
                CheckWindow(candidate, IntPtr.Zero);
            }
        }

        if (changed)
        {
            SaveHiddenWindows();
        }
    }

    private void QueueWindowCheck(IntPtr hook, uint eventType, IntPtr windowHandle,
        int objectId, int childId, uint threadId, uint eventTime)
    {
        if (!isInitialized() || isClosing || windowHandle == IntPtr.Zero || objectId != 0 || childId != 0)
        {
            return;
        }

        var root = NativeMethods.GetAncestor(windowHandle, NativeMethods.GaRoot);
        if (root != IntPtr.Zero)
        {
            if (pendingWindowChecks.Count >= MaxPendingWindowChecks)
            {
                nextFullWindowScan = 0;
                return;
            }

            pendingWindowChecks.Add(root);
        }
    }

    private static bool IsProtectedWindow(
        IntPtr windowHandle,
        uint ownerProcessId,
        IReadOnlySet<string> lockedExecutables,
        IReadOnlySet<string> lockedPackageFamilies,
        Dictionary<uint, string> exeCache,
        Dictionary<uint, string> pfnCache,
        out string matchedName)
    {
        if (IsProcessProtected(ownerProcessId, lockedExecutables, lockedPackageFamilies, exeCache, pfnCache, out matchedName))
        {
            return true;
        }

        var hasDifferentChildProcess = false;
        var childProcessIds = new HashSet<uint>();

        NativeMethods.EnumChildWindows(windowHandle, (childWindow, _) =>
        {
            NativeMethods.GetWindowThreadProcessId(childWindow, out var childProcessId);
            if (childProcessId != 0 && childProcessId != ownerProcessId)
            {
                hasDifferentChildProcess = true;
                childProcessIds.Add(childProcessId);
            }

            return true;
        }, IntPtr.Zero);

        if (hasDifferentChildProcess)
        {
            foreach (var processId in childProcessIds)
            {
                if (IsProcessProtected(processId, lockedExecutables, lockedPackageFamilies, exeCache, pfnCache, out matchedName))
                {
                    return true;
                }
            }
        }

        matchedName = string.Empty;
        return false;
    }

    private static bool IsProcessProtected(
        uint processId,
        IReadOnlySet<string> lockedExecutables,
        IReadOnlySet<string> lockedPackageFamilies,
        Dictionary<uint, string> exeCache,
        Dictionary<uint, string> pfnCache,
        out string matchedName)
    {
        if (!exeCache.TryGetValue(processId, out var exeName))
        {
            exeName = GetProcessExecutableName(processId);
            exeCache[processId] = exeName;
        }

        if (!string.IsNullOrWhiteSpace(exeName) && lockedExecutables.Contains(exeName))
        {
            matchedName = exeName;
            return true;
        }

        if (!pfnCache.TryGetValue(processId, out var packageFamilyName))
        {
            packageFamilyName = GetProcessPackageFamilyName(processId);
            pfnCache[processId] = packageFamilyName;
        }

        if (!string.IsNullOrWhiteSpace(packageFamilyName) && lockedPackageFamilies.Contains(packageFamilyName))
        {
            matchedName = packageFamilyName;
            return true;
        }

        matchedName = string.Empty;
        return false;
    }

    private static bool IsOwnedBy(IntPtr windowHandle, uint processId)
    {
        if (processId == 0 || !NativeMethods.IsWindow(windowHandle))
        {
            return false;
        }

        NativeMethods.GetWindowThreadProcessId(windowHandle, out var currentProcessId);
        return currentProcessId == processId;
    }

    private void LoadHiddenWindows()
    {
        // Windows hidden by a previous instance that crashed or was killed are adopted here, so the
        // guard either keeps them hidden (still locked) or restores them on the next tick.
        try
        {
            if (!File.Exists(hiddenWindowsStatePath))
            {
                return;
            }

            var entries = System.Text.Json.JsonSerializer.Deserialize<List<HiddenWindowEntry>>(
                File.ReadAllText(hiddenWindowsStatePath)) ?? new List<HiddenWindowEntry>();
            foreach (var entry in entries)
            {
                var windowHandle = new IntPtr(entry.Handle);
                if (IsOwnedBy(windowHandle, entry.ProcessId))
                {
                    hiddenProtectedWindows.Add(windowHandle);
                    hiddenWindowOwners[windowHandle] = entry.ProcessId;
                }
            }

            SaveHiddenWindows();
        }
        catch (Exception ex)
        {
            logError(ex);
        }
    }

    private void SaveHiddenWindows()
    {
        string? tempPath = null;
        try
        {
            if (hiddenProtectedWindows.Count == 0)
            {
                File.Delete(hiddenWindowsStatePath);
                return;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(hiddenWindowsStatePath)!);
            var entries = hiddenProtectedWindows
                .Select(handle => new HiddenWindowEntry(handle.ToInt64(), hiddenWindowOwners.GetValueOrDefault(handle)))
                .ToList();
            tempPath = $"{hiddenWindowsStatePath}.{Guid.NewGuid():N}.tmp";
            File.WriteAllText(tempPath, System.Text.Json.JsonSerializer.Serialize(entries));
            File.Move(tempPath, hiddenWindowsStatePath, overwrite: true);
        }
        catch (Exception ex)
        {
            logError(ex);
        }
        finally
        {
            if (tempPath is not null)
            {
                try { File.Delete(tempPath); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }

    private sealed record HiddenWindowEntry(long Handle, uint ProcessId);
}
