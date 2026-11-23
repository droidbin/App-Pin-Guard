using System.Runtime.InteropServices;

namespace WindowsAppProtector.Platform;

public sealed class IdleMonitor
{
    private bool isAutoLockCheckRunning;

    public bool IsCheckRunning => isAutoLockCheckRunning;

    public static TimeSpan GetSystemIdleTime()
    {
        var lastInput = new NativeMethods.LastInputInfo
        {
            cbSize = (uint)Marshal.SizeOf<NativeMethods.LastInputInfo>(),
        };

        if (!NativeMethods.GetLastInputInfo(ref lastInput))
        {
            return TimeSpan.Zero;
        }

        var currentTick = unchecked((uint)Environment.TickCount);
        var idleMilliseconds = unchecked(currentTick - lastInput.dwTime);
        return TimeSpan.FromMilliseconds(idleMilliseconds);
    }

    public async Task CheckIdleAsync(
        Func<TimeSpan, Task> autoLockIfIdleAsync,
        Func<int> getIdleLockMinutes,
        Func<bool> isSessionUnlocked,
        Action onSessionIdleLock)
    {
        ArgumentNullException.ThrowIfNull(autoLockIfIdleAsync);
        ArgumentNullException.ThrowIfNull(getIdleLockMinutes);
        ArgumentNullException.ThrowIfNull(isSessionUnlocked);
        ArgumentNullException.ThrowIfNull(onSessionIdleLock);

        if (isAutoLockCheckRunning)
        {
            return;
        }

        isAutoLockCheckRunning = true;
        try
        {
            var idleTime = GetSystemIdleTime();
            await autoLockIfIdleAsync(idleTime);
            var idleLockMinutes = getIdleLockMinutes();
            if (isSessionUnlocked() &&
                idleLockMinutes > 0 &&
                idleTime >= TimeSpan.FromMinutes(idleLockMinutes))
            {
                // An unattended, unlocked management window is locked by the same idle timeout.
                onSessionIdleLock();
            }
        }
        finally
        {
            isAutoLockCheckRunning = false;
        }
    }
}
