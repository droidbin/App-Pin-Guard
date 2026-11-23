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

public sealed class ProtectionService : IProtectionService
{
    public const string ServiceName = "WindowsAppProtectorService";

    private static readonly HashSet<string> WindowOnlyExecutableNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "arc.exe",
        "brave.exe",
        "chrome.exe",
        "firefox.exe",
        "iexplore.exe",
        "msedge.exe",
        "opera.exe",
        "opera_gx.exe",
        "samsunginternet.exe",
        "vivaldi.exe",
        "whale.exe",
    };

    public Task RequestPolicyResyncAsync(CancellationToken cancellationToken = default)
    {
        return Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                using var pipe = GateProtocol.ConnectToService();
                pipe.WriteByte(GateProtocol.Version);
                pipe.WriteByte(GateProtocol.SyncPolicy);
                pipe.Flush();

                var reply = GateProtocol.Read(pipe, 1, DateTime.UtcNow.AddSeconds(3))[0];
                if (reply != GateProtocol.Approved)
                {
                    throw new InvalidOperationException(reply switch
                    {
                        GateProtocol.SyncCallerRejected => "보호 서비스가 요청한 앱을 설치된 실행 파일로 확인하지 못했습니다.",
                        GateProtocol.SyncNotAdministrator => "보호 서비스가 관리자 권한 세션으로 확인하지 못했습니다.",
                        _ => "보호 서비스가 설정 파일을 읽지 못해 요청을 거부했습니다.",
                    });
                }
            }
            catch (Exception ex) when (ex is not TimeoutException && ex is not IOException && ex is not InvalidOperationException)
            {
                App.WriteProtectionLog("policy-resync-failed " + ex.GetType().Name + " hresult=0x" + ex.HResult.ToString("X8") + " " + ex.Message);
                throw;
            }
            catch (TimeoutException ex)
            {
                throw new InvalidOperationException(
                    "보호 서비스에 연결할 수 없습니다. 서비스가 설치되어 실행 중인지 확인하세요.", ex);
            }
            catch (IOException ex)
            {
                throw new InvalidOperationException(
                    "보호 서비스와 통신할 수 없습니다. 서비스 상태를 확인하세요.", ex);
            }

            cancellationToken.ThrowIfCancellationRequested();
        }, cancellationToken);
    }

    public Task StopProtectedProcessesAsync(IEnumerable<ProtectedApp> apps, CancellationToken cancellationToken = default)
    {
        // Do not terminate already-running targets. Only future launches are blocked through IFEO.
        return Task.CompletedTask;
    }

    private static string GetBlockRuleName(ProtectedApp app)
    {
        if (!string.IsNullOrWhiteSpace(app.ExecutableName))
        {
            return app.ExecutableName;
        }

        return string.IsNullOrWhiteSpace(app.Path) ? string.Empty : Path.GetFileName(app.Path);
    }

    internal static bool UsesWindowOnlyBlocking(ProtectedApp app)
    {
        if (app.IsPackaged) return true;
        var executableName = GetBlockRuleName(app);
        return !string.IsNullOrWhiteSpace(executableName) &&
            WindowOnlyExecutableNames.Contains(executableName);
    }

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
