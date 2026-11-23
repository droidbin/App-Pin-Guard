namespace WindowsAppProtector.Services;

/// <summary>
/// Tells the service that policy.json changed and waits until status.json reports the revision as applied.
/// The service also notices the file by itself (watcher, 5 s timer), so a failed signal only costs time.
/// </summary>
internal sealed class PolicyChangeNotifier
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(3);

    public bool Signal()
    {
        try
        {
            using var handle = EventWaitHandle.OpenExisting(WapPaths.PolicyChangedEvent);
            return handle.Set();
        }
        catch (Exception ex) when (ex is WaitHandleCannotBeOpenedException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    /// <summary>True when the service reported <paramref name="revision"/> (or later) as applied within the timeout.</summary>
    public async Task<bool> WaitForAppliedAsync(long revision, TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        var deadline = DateTime.UtcNow + (timeout ?? DefaultTimeout);
        while (true)
        {
            var status = ServiceStatusReader.ReadOnce();
            if (status is not null && status.AppliedRevision >= revision)
            {
                return true;
            }

            if (DateTime.UtcNow >= deadline)
            {
                return false;
            }

            await Task.Delay(100, cancellationToken);
        }
    }

    public async Task<bool> SignalAndWaitAsync(long revision, CancellationToken cancellationToken = default)
    {
        Signal();
        return await WaitForAppliedAsync(revision, null, cancellationToken);
    }
}
