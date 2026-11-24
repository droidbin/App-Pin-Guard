using System.Threading;

namespace WindowsAppProtector.Services;

/// <summary>Reads Runtime\status.json (readable without admin rights) and refreshes it every 2 seconds.</summary>
internal sealed class ServiceStatusReader : IDisposable
{
    private Timer? timer;
    private string lastSnapshot = string.Empty;

    public StatusDocument? Current { get; private set; }

    /// <summary>Raised on a background thread when status.json changed (or became unreadable).</summary>
    public event Action<StatusDocument?>? Changed;

    public void Start()
    {
        timer ??= new Timer(_ => Poll(), null, 0, 2000);
    }

    public void Dispose()
    {
        timer?.Dispose();
        timer = null;
    }

    public static StatusDocument? ReadOnce()
    {
        try
        {
            return PolicyStore.Read<StatusDocument>(WapPaths.StatusFile);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public void Poll()
    {
        var status = ReadOnce();
        var snapshot = status is null
            ? string.Empty
            : status.UpdatedAtUtc + "|" + status.AppliedRevision + "|" +
              string.Join(",", status.Apps.Select(app => app.Id + ":" + app.Rule + ":" + app.UnlockedSessions));
        if (snapshot == lastSnapshot)
        {
            return;
        }

        lastSnapshot = snapshot;
        Current = status;
        Changed?.Invoke(status);
    }
}
