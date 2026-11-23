using WindowsAppProtector.Models;

namespace WindowsAppProtector.Services;

public sealed class ProtectionService : IProtectionService
{
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
}
