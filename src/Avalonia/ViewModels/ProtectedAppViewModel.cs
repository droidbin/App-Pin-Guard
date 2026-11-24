using Avalonia.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;

namespace WindowsAppProtector.ViewModels;

public class ProtectedAppViewModel : ObservableObject
{
    private string name = string.Empty;
    private string identity = string.Empty;
    private string path = string.Empty;
    private string status = "열림";
    private bool isLocked;
    private string policySummary = string.Empty;
    private Bitmap? icon;
    private bool isPackaged;
    private string packageFamilyName = string.Empty;
    private string rawPath = string.Empty;
    private bool canConfigureLaunchPolicy;
    private bool isSelected;
    private string appId = string.Empty;
    private string rule = string.Empty;

    public string Name
    {
        get => name;
        set
        {
            if (SetProperty(ref name, value))
            {
                OnPropertyChanged(nameof(AutomationName));
            }
        }
    }

    public string AppId
    {
        get => appId;
        set => SetProperty(ref appId, value);
    }

    // Rule state reported by the service in status.json: applied-gate, applied-blocked, window-mode, conflict...
    public string Rule
    {
        get => rule;
        set
        {
            if (SetProperty(ref rule, value))
            {
                OnPropertyChanged(nameof(HasConflict));
            }
        }
    }

    public bool HasConflict => string.Equals(rule, "conflict", StringComparison.Ordinal);

    public string Identity
    {
        get => identity;
        set => SetProperty(ref identity, value);
    }

    public string Path
    {
        get => path;
        set => SetProperty(ref path, value);
    }

    public string Status
    {
        get => status;
        set
        {
            if (SetProperty(ref status, value))
            {
                OnPropertyChanged(nameof(AutomationName));
            }
        }
    }

    public bool IsLocked
    {
        get => isLocked;
        set
        {
            if (SetProperty(ref isLocked, value))
            {
                RefreshStatus();
                OnPropertyChanged(nameof(AutomationName));
            }
        }
    }

    // Sessions in which the service currently has this locked app unlocked with a PIN (status.json).
    public int UnlockedSessions
    {
        get => unlockedSessions;
        set
        {
            if (SetProperty(ref unlockedSessions, value))
            {
                RefreshStatus();
                OnPropertyChanged(nameof(LockOnContent));
                OnPropertyChanged(nameof(AutomationName));
            }
        }
    }

    private int unlockedSessions;

    public string LockOnContent => unlockedSessions > 0 ? "잠금 해제됨(사용 중)" : "잠김";

    private void RefreshStatus()
    {
        Status = !isLocked ? "열림" : unlockedSessions > 0 ? "잠금 해제됨(사용 중)" : "잠김";
    }

    public string PolicySummary
    {
        get => policySummary;
        set
        {
            if (SetProperty(ref policySummary, value))
            {
                OnPropertyChanged(nameof(HasPolicySummary));
            }
        }
    }

    public bool HasPolicySummary => !string.IsNullOrWhiteSpace(policySummary);

    public Bitmap? Icon
    {
        get => icon;
        set
        {
            if (SetProperty(ref icon, value))
            {
                OnPropertyChanged(nameof(HasIcon));
                OnPropertyChanged(nameof(HasNoIcon));
            }
        }
    }

    public bool HasIcon => icon is not null;

    public bool HasNoIcon => icon is null;

    public bool IsPackaged
    {
        get => isPackaged;
        set
        {
            if (SetProperty(ref isPackaged, value))
            {
                OnPropertyChanged(nameof(CanOpenFolder));
            }
        }
    }

    public string PackageFamilyName
    {
        get => packageFamilyName;
        set => SetProperty(ref packageFamilyName, value);
    }

    public string RawPath
    {
        get => rawPath;
        set
        {
            if (SetProperty(ref rawPath, value))
            {
                OnPropertyChanged(nameof(CanOpenFolder));
            }
        }
    }

    public bool CanConfigureLaunchPolicy
    {
        get => canConfigureLaunchPolicy;
        set => SetProperty(ref canConfigureLaunchPolicy, value);
    }

    public bool CanOpenFolder => !isPackaged && !string.IsNullOrWhiteSpace(rawPath);

    public bool IsSelected
    {
        get => isSelected;
        set => SetProperty(ref isSelected, value);
    }

    public string AutomationName => $"{Name}, {Status}";

    public override string ToString()
    {
        var lockState = Status.Length == 0 ? "\uB300\uAE30" : Status;
        return $"{Name}    {lockState}    {Path}";
    }
}
