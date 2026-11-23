using System.Collections.ObjectModel;
using System.ComponentModel;

namespace WindowsAppProtector.Services;

public enum NotificationSeverity
{
    Info,
    Success,
    Warning,
    Error,
}

public sealed class NotificationItem
{
    public NotificationItem(
        NotificationSeverity severity,
        string message,
        string? title = null,
        string? actionLabel = null,
        Action? action = null)
    {
        Id = Guid.NewGuid();
        Severity = severity;
        Message = message;
        Title = string.IsNullOrWhiteSpace(title) ? null : title.Trim();
        ActionLabel = string.IsNullOrWhiteSpace(actionLabel) ? null : actionLabel.Trim();
        Action = action;
        CreatedAt = DateTimeOffset.Now;
    }

    public Guid Id { get; }
    public NotificationSeverity Severity { get; }
    public string Message { get; }
    public string? Title { get; }
    public string? ActionLabel { get; }
    public Action? Action { get; }
    public bool HasAction => !string.IsNullOrWhiteSpace(ActionLabel) && Action is not null;
    public DateTimeOffset CreatedAt { get; }
}

public interface INotificationService : INotifyPropertyChanged
{
    ObservableCollection<NotificationItem> Notifications { get; }
    NotificationItem? CurrentNotification { get; }

    NotificationItem Show(
        NotificationSeverity severity,
        string message,
        string? title = null,
        string? actionLabel = null,
        Action? action = null);

    NotificationItem Info(string message, string? title = null, string? actionLabel = null, Action? action = null);
    NotificationItem Success(string message, string? title = null, string? actionLabel = null, Action? action = null);
    NotificationItem Warning(string message, string? title = null, string? actionLabel = null, Action? action = null);
    NotificationItem Error(string message, string? title = null, string? actionLabel = null, Action? action = null);

    void Dismiss(Guid id);
    void Clear();
}
