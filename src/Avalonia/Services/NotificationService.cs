using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using Avalonia;
using Avalonia.Threading;

namespace WindowsAppProtector.Services;

public sealed class NotificationService : INotificationService, IDisposable
{
    public static readonly TimeSpan DefaultAutoDismissDelay = TimeSpan.FromSeconds(4);

    private readonly TimeSpan _autoDismissDelay;
    private readonly ConcurrentDictionary<Guid, CancellationTokenSource> _autoDismissTimers = new();
    private NotificationItem? _currentNotification;
    private bool _disposed;

    public NotificationService(TimeSpan? autoDismissDelay = null)
    {
        _autoDismissDelay = autoDismissDelay ?? DefaultAutoDismissDelay;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<NotificationItem> Notifications { get; } = [];

    public NotificationItem? CurrentNotification
    {
        get => _currentNotification;
        private set
        {
            if (ReferenceEquals(_currentNotification, value))
            {
                return;
            }

            _currentNotification = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CurrentNotification)));
        }
    }

    public NotificationItem Show(
        NotificationSeverity severity,
        string message,
        string? title = null,
        string? actionLabel = null,
        Action? action = null)
    {
        var item = new NotificationItem(severity, message ?? string.Empty, title, actionLabel, action);
        if (_disposed)
        {
            return item;
        }

        RunOnUiThread(() =>
        {
            if (_disposed)
            {
                return;
            }

            Notifications.Add(item);
            CurrentNotification = item;

            if (severity is NotificationSeverity.Success or NotificationSeverity.Info)
            {
                ScheduleAutoDismiss(item.Id);
            }
        });

        return item;
    }

    public NotificationItem Info(string message, string? title = null, string? actionLabel = null, Action? action = null)
        => Show(NotificationSeverity.Info, message, title, actionLabel, action);

    public NotificationItem Success(string message, string? title = null, string? actionLabel = null, Action? action = null)
        => Show(NotificationSeverity.Success, message, title, actionLabel, action);

    public NotificationItem Warning(string message, string? title = null, string? actionLabel = null, Action? action = null)
        => Show(NotificationSeverity.Warning, message, title, actionLabel, action);

    public NotificationItem Error(string message, string? title = null, string? actionLabel = null, Action? action = null)
        => Show(NotificationSeverity.Error, message, title, actionLabel, action);

    public void Dismiss(Guid id)
    {
        CancelTimer(id);

        RunOnUiThread(() =>
        {
            for (var i = Notifications.Count - 1; i >= 0; i--)
            {
                if (Notifications[i].Id == id)
                {
                    Notifications.RemoveAt(i);
                    break;
                }
            }

            CurrentNotification = Notifications.Count > 0 ? Notifications[^1] : null;
        });
    }

    public void Clear()
    {
        foreach (var id in _autoDismissTimers.Keys.ToArray())
        {
            CancelTimer(id);
        }

        RunOnUiThread(() =>
        {
            Notifications.Clear();
            CurrentNotification = null;
        });
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (var id in _autoDismissTimers.Keys.ToArray())
        {
            CancelTimer(id);
        }
    }

    private void ScheduleAutoDismiss(Guid id)
    {
        var cts = new CancellationTokenSource();
        if (!_autoDismissTimers.TryAdd(id, cts))
        {
            cts.Dispose();
            return;
        }

        _ = AutoDismissAfterDelayAsync(id, cts.Token);
    }

    private async Task AutoDismissAfterDelayAsync(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(_autoDismissDelay, cancellationToken).ConfigureAwait(false);
            if (!cancellationToken.IsCancellationRequested && !_disposed)
            {
                Dismiss(id);
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            CancelTimer(id);
        }
    }

    private void CancelTimer(Guid id)
    {
        if (_autoDismissTimers.TryRemove(id, out var cts))
        {
            try
            {
                cts.Cancel();
            }
            catch (ObjectDisposedException)
            {
            }

            cts.Dispose();
        }
    }

    private static void RunOnUiThread(Action action)
    {
        if (Application.Current is not null && !Dispatcher.UIThread.CheckAccess())
        {
            Dispatcher.UIThread.Post(action);
            return;
        }

        action();
    }
}
