using System.ComponentModel;
using System.Runtime.InteropServices;
using WindowsAppProtector.Models;
using WindowsAppProtector.Platform;

namespace WindowsAppProtector.Services;

public enum ProtectionServiceState
{
    Running,
    Stopped,
    NotInstalled,
    Unknown,
}

public static class ProtectionService
{
    public const string ServiceName = "WindowsAppProtectorService";

    public static ProtectionServiceState QueryServiceState()
    {
        var scm = NativeMethods.OpenSCManager(null, null, NativeMethods.ScManagerConnect);
        if (scm == IntPtr.Zero)
        {
            return ProtectionServiceState.Unknown;
        }

        try
        {
            var service = NativeMethods.OpenService(scm, ServiceName, NativeMethods.ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                return error == NativeMethods.ErrorServiceDoesNotExist
                    ? ProtectionServiceState.NotInstalled
                    : ProtectionServiceState.Unknown;
            }

            try
            {
                if (!NativeMethods.QueryServiceStatus(service, out var status))
                {
                    return ProtectionServiceState.Unknown;
                }

                return status.dwCurrentState == NativeMethods.ServiceRunning
                    ? ProtectionServiceState.Running
                    : ProtectionServiceState.Stopped;
            }
            finally
            {
                _ = NativeMethods.CloseServiceHandle(service);
            }
        }
        finally
        {
            _ = NativeMethods.CloseServiceHandle(scm);
        }
    }

    public static Task RestartServiceAsync(CancellationToken cancellationToken = default)
    {
        return Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            var scm = NativeMethods.OpenSCManager(null, null, NativeMethods.ScManagerConnect);
            if (scm == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    $"서비스 관리자에 연결할 수 없습니다. ({new Win32Exception(Marshal.GetLastWin32Error()).Message})");
            }

            try
            {
                var access = NativeMethods.ServiceQueryStatus | NativeMethods.ServiceStart | NativeMethods.ServiceStop;
                var service = NativeMethods.OpenService(scm, ServiceName, access);
                if (service == IntPtr.Zero)
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error == NativeMethods.ErrorServiceDoesNotExist)
                    {
                        throw new InvalidOperationException(
                            "보호 서비스가 설치되어 있지 않습니다. 설치 프로그램을 다시 실행해 서비스를 복구하세요.");
                    }

                    throw new InvalidOperationException(
                        $"보호 서비스를 열 수 없습니다. 관리자 권한으로 다시 실행하세요. ({new Win32Exception(error).Message})");
                }

                try
                {
                    if (NativeMethods.QueryServiceStatus(service, out var currentStatus) &&
                        currentStatus.dwCurrentState != NativeMethods.ServiceStopped)
                    {
                        if (currentStatus.dwCurrentState == NativeMethods.ServiceRunning)
                        {
                            _ = NativeMethods.ControlService(service, NativeMethods.ServiceControlStop, out _);
                        }

                        WaitForServiceState(service, NativeMethods.ServiceStopped, TimeSpan.FromSeconds(10), cancellationToken);
                    }

                    if (!NativeMethods.StartService(service, 0, null))
                    {
                        var startError = Marshal.GetLastWin32Error();
                        throw new InvalidOperationException(
                            $"보호 서비스를 시작할 수 없습니다. ({new Win32Exception(startError).Message})");
                    }

                    if (!WaitForServiceState(service, NativeMethods.ServiceRunning, TimeSpan.FromSeconds(10), cancellationToken))
                    {
                        throw new InvalidOperationException("보호 서비스가 제한 시간 안에 시작되지 않았습니다.");
                    }
                }
                finally
                {
                    _ = NativeMethods.CloseServiceHandle(service);
                }
            }
            finally
            {
                _ = NativeMethods.CloseServiceHandle(scm);
            }
        }, cancellationToken);
    }

    private static bool WaitForServiceState(
        IntPtr service,
        uint desiredState,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (NativeMethods.QueryServiceStatus(service, out var status) &&
                status.dwCurrentState == desiredState)
            {
                return true;
            }

            Thread.Sleep(150);
        }

        return NativeMethods.QueryServiceStatus(service, out var finalStatus) &&
            finalStatus.dwCurrentState == desiredState;
    }
}
