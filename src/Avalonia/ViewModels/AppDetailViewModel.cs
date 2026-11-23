using System.ComponentModel;
using System.Globalization;
using Avalonia.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;

namespace WindowsAppProtector.ViewModels;

public sealed record GracePeriodOption(string Label, int? Minutes)
{
    public bool IsCustom => Minutes is null;

    public override string ToString() => Label;
}

public sealed class AppDetailViewModel : ObservableObject
{
    private static readonly TimeSpan DefaultLockStart = new(22, 0, 0);
    private static readonly TimeSpan DefaultLockEnd = new(7, 0, 0);

    private readonly MainViewModel _mainViewModel;
    private ProtectedAppViewModel? _currentApp;
    private string _appName = string.Empty;
    private string _appPath = string.Empty;
    private Bitmap? _appIcon;
    private bool _isLocked;
    private bool _supportsLaunchPolicy;
    private bool _hasExistingCustomPin;
    private bool _useDefaultPin = true;
    private string _newPin = string.Empty;
    private GracePeriodOption _selectedGracePeriod;
    private string _customMinutesText = string.Empty;
    private bool _relockOnExit;
    private bool _isAlwaysLock = true;
    private TimeSpan? _lockStartTime = DefaultLockStart;
    private TimeSpan? _lockEndTime = DefaultLockEnd;
    private string _pinError = string.Empty;
    private string _graceMinutesError = string.Empty;
    private string _lockHoursError = string.Empty;
    private bool _isBusy;

    public AppDetailViewModel(MainViewModel mainViewModel)
    {
        _mainViewModel = mainViewModel;
        GracePeriodOptions =
        [
            new("실행할 때마다", 0),
            new("5분", 5),
            new("10분", 10),
            new("30분", 30),
            new("1시간", 60),
            new("직접 입력", null),
        ];
        _selectedGracePeriod = GracePeriodOptions[0];
    }

    public IReadOnlyList<GracePeriodOption> GracePeriodOptions { get; }

    public ProtectedAppViewModel? CurrentApp => _currentApp;

    public string AppName
    {
        get => _appName;
        private set
        {
            if (SetProperty(ref _appName, value))
            {
                OnPropertyChanged(nameof(LockToggleAutomationName));
            }
        }
    }

    public string AppPath
    {
        get => _appPath;
        private set => SetProperty(ref _appPath, value);
    }

    public Bitmap? AppIcon
    {
        get => _appIcon;
        private set
        {
            if (SetProperty(ref _appIcon, value))
            {
                OnPropertyChanged(nameof(HasIcon));
                OnPropertyChanged(nameof(HasNoIcon));
            }
        }
    }

    public bool HasIcon => _appIcon is not null;

    public bool HasNoIcon => _appIcon is null;

    public bool IsLocked
    {
        get => _isLocked;
        private set
        {
            if (SetProperty(ref _isLocked, value))
            {
                OnPropertyChanged(nameof(LockToggleAutomationName));
            }
        }
    }

    public string LockToggleAutomationName => $"{AppName}, {(IsLocked ? "잠김" : "열림")}";

    public bool SupportsLaunchPolicy
    {
        get => _supportsLaunchPolicy;
        private set
        {
            if (SetProperty(ref _supportsLaunchPolicy, value))
            {
                OnPropertyChanged(nameof(ShowUnsupportedPolicyNote));
            }
        }
    }

    public bool HasRuleConflict => _currentApp?.HasConflict == true;

    public bool ShowUnsupportedPolicyNote => !_supportsLaunchPolicy && _currentApp is not null;

    public bool HasExistingCustomPin
    {
        get => _hasExistingCustomPin;
        private set
        {
            if (SetProperty(ref _hasExistingCustomPin, value))
            {
                OnPropertyChanged(nameof(NewPinWatermark));
                OnPropertyChanged(nameof(ExistingPinHint));
                OnPropertyChanged(nameof(HasExistingPinHint));
            }
        }
    }

    public bool UseDefaultPin
    {
        get => _useDefaultPin;
        set
        {
            if (SetProperty(ref _useDefaultPin, value))
            {
                OnPropertyChanged(nameof(UseCustomPin));
                OnPropertyChanged(nameof(ExistingPinHint));
                OnPropertyChanged(nameof(HasExistingPinHint));
                PinError = string.Empty;
            }
        }
    }

    public bool UseCustomPin
    {
        get => !_useDefaultPin;
        set
        {
            if (_useDefaultPin == value)
            {
                UseDefaultPin = !value;
            }
        }
    }

    public string NewPin
    {
        get => _newPin;
        set
        {
            var normalized = value ?? string.Empty;
            if (SetProperty(ref _newPin, normalized))
            {
                PinError = string.Empty;
            }
        }
    }

    public string NewPinWatermark => _hasExistingCustomPin
        ? "새 PIN (비우면 기존 유지)"
        : "새 PIN (4자리 이상)";

    public string ExistingPinHint => _hasExistingCustomPin && UseCustomPin
        ? "전용 PIN이 설정되어 있습니다. 변경하려면 새 PIN을 입력하세요."
        : string.Empty;

    public bool HasExistingPinHint => !string.IsNullOrEmpty(ExistingPinHint);

    public GracePeriodOption SelectedGracePeriod
    {
        get => _selectedGracePeriod;
        set
        {
            var next = value ?? GracePeriodOptions[0];
            if (SetProperty(ref _selectedGracePeriod, next))
            {
                OnPropertyChanged(nameof(IsCustomGracePeriod));
                GraceMinutesError = string.Empty;
            }
        }
    }

    public bool IsCustomGracePeriod => _selectedGracePeriod.IsCustom;

    public string CustomMinutesText
    {
        get => _customMinutesText;
        set
        {
            var normalized = value ?? string.Empty;
            if (SetProperty(ref _customMinutesText, normalized))
            {
                GraceMinutesError = string.Empty;
            }
        }
    }

    public bool RelockOnExit
    {
        get => _relockOnExit;
        set => SetProperty(ref _relockOnExit, value);
    }

    public bool IsAlwaysLock
    {
        get => _isAlwaysLock;
        set
        {
            if (SetProperty(ref _isAlwaysLock, value))
            {
                OnPropertyChanged(nameof(IsScheduledLock));
                LockHoursError = string.Empty;
            }
        }
    }

    public bool IsScheduledLock
    {
        get => !_isAlwaysLock;
        set
        {
            if (_isAlwaysLock == value)
            {
                IsAlwaysLock = !value;
            }
        }
    }

    public TimeSpan? LockStartTime
    {
        get => _lockStartTime;
        set
        {
            if (SetProperty(ref _lockStartTime, value))
            {
                LockHoursError = string.Empty;
            }
        }
    }

    public TimeSpan? LockEndTime
    {
        get => _lockEndTime;
        set
        {
            if (SetProperty(ref _lockEndTime, value))
            {
                LockHoursError = string.Empty;
            }
        }
    }

    public string PinError
    {
        get => _pinError;
        private set
        {
            if (SetProperty(ref _pinError, value))
            {
                OnPropertyChanged(nameof(HasPinError));
            }
        }
    }

    public bool HasPinError => !string.IsNullOrEmpty(_pinError);

    public string GraceMinutesError
    {
        get => _graceMinutesError;
        private set
        {
            if (SetProperty(ref _graceMinutesError, value))
            {
                OnPropertyChanged(nameof(HasGraceMinutesError));
            }
        }
    }

    public bool HasGraceMinutesError => !string.IsNullOrEmpty(_graceMinutesError);

    public string LockHoursError
    {
        get => _lockHoursError;
        private set
        {
            if (SetProperty(ref _lockHoursError, value))
            {
                OnPropertyChanged(nameof(HasLockHoursError));
            }
        }
    }

    public bool HasLockHoursError => !string.IsNullOrEmpty(_lockHoursError);

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetProperty(ref _isBusy, value))
            {
                OnPropertyChanged(nameof(IsNotBusy));
            }
        }
    }

    public bool IsNotBusy => !_isBusy;

    public void Load(ProtectedAppViewModel app)
    {
        AttachApp(app);
        ClearErrors();

        var policy = _mainViewModel.GetLaunchPolicy(app);
        if (policy is null)
        {
            SupportsLaunchPolicy = false;
            HasExistingCustomPin = false;
            UseDefaultPin = true;
            NewPin = string.Empty;
            SelectedGracePeriod = GracePeriodOptions[0];
            CustomMinutesText = string.Empty;
            RelockOnExit = false;
            IsAlwaysLock = true;
            LockStartTime = DefaultLockStart;
            LockEndTime = DefaultLockEnd;
            OnPropertyChanged(nameof(ShowUnsupportedPolicyNote));
            return;
        }

        SupportsLaunchPolicy = true;
        HasExistingCustomPin = policy.Value.CustomPin;
        UseDefaultPin = !policy.Value.CustomPin;
        NewPin = string.Empty;

        var preset = GracePeriodOptions.FirstOrDefault(option => option.Minutes == policy.Value.Minutes);
        if (preset is not null)
        {
            SelectedGracePeriod = preset;
            CustomMinutesText = string.Empty;
        }
        else
        {
            SelectedGracePeriod = GracePeriodOptions[^1];
            CustomMinutesText = policy.Value.Minutes.ToString(CultureInfo.InvariantCulture);
        }

        RelockOnExit = policy.Value.RelockOnExit;

        if (policy.Value.Start is >= 0 and < 1440 && policy.Value.End is >= 0 and < 1440)
        {
            IsAlwaysLock = false;
            LockStartTime = TimeSpan.FromMinutes(policy.Value.Start.Value);
            LockEndTime = TimeSpan.FromMinutes(policy.Value.End.Value);
        }
        else
        {
            IsAlwaysLock = true;
            LockStartTime = DefaultLockStart;
            LockEndTime = DefaultLockEnd;
        }

        OnPropertyChanged(nameof(ShowUnsupportedPolicyNote));
    }

    public void SyncAppSnapshot(ProtectedAppViewModel app)
    {
        AttachApp(app);
    }

    public void Clear()
    {
        DetachApp();
        ClearErrors();
        AppName = string.Empty;
        AppPath = string.Empty;
        AppIcon = null;
        IsLocked = false;
        SupportsLaunchPolicy = false;
        HasExistingCustomPin = false;
        NewPin = string.Empty;
        OnPropertyChanged(nameof(ShowUnsupportedPolicyNote));
    }

    public async Task SetLockedAsync(bool targetLocked)
    {
        var app = _currentApp;
        if (app is null || IsBusy)
        {
            return;
        }

        IsBusy = true;
        try
        {
            await _mainViewModel.SetAppLockedAsync(app, targetLocked);
        }
        finally
        {
            IsBusy = false;
            if (_currentApp is not null)
            {
                IsLocked = _currentApp.IsLocked;
            }
        }
    }

    public async Task<bool> SaveAsync()
    {
        var app = _currentApp;
        if (app is null || !SupportsLaunchPolicy || IsBusy)
        {
            return false;
        }

        if (!Validate(out var minutes, out var lockStart, out var lockEnd))
        {
            return false;
        }

        IsBusy = true;
        try
        {
            var saved = await _mainViewModel.SaveLaunchPolicyAsync(
                app,
                UseDefaultPin,
                NewPin,
                minutes,
                lockStart,
                lockEnd,
                RelockOnExit);

            if (saved)
            {
                HasExistingCustomPin = !UseDefaultPin;
                NewPin = string.Empty;
            }

            return saved;
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task RemoveCurrentAppAsync()
    {
        var app = _currentApp;
        if (app is null || IsBusy)
        {
            return;
        }

        IsBusy = true;
        try
        {
            await _mainViewModel.RemoveAppAsync(app);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public bool Validate(out int minutes, out int? lockStart, out int? lockEnd)
    {
        ClearErrors();
        minutes = 0;
        lockStart = null;
        lockEnd = null;

        if (!UseDefaultPin)
        {
            if (NewPin.Length == 0)
            {
                if (!HasExistingCustomPin)
                {
                    PinError = "이 앱 전용 PIN을 입력하세요. (4자리 이상)";
                }
            }
            else if (NewPin.Length < 4)
            {
                PinError = "PIN은 4자리 이상이어야 합니다.";
            }
            else if (NewPin.Length > 32)
            {
                PinError = "PIN은 32자리 이하로 입력하세요.";
            }
        }

        if (SelectedGracePeriod.Minutes is { } presetMinutes)
        {
            minutes = presetMinutes;
        }
        else
        {
            var trimmed = CustomMinutesText.Trim();
            if (!int.TryParse(trimmed, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) ||
                parsed is < 0 or > 1440)
            {
                GraceMinutesError = "0에서 1440 사이의 분 단위 숫자를 입력하세요.";
            }
            else
            {
                minutes = parsed;
            }
        }

        if (IsScheduledLock)
        {
            if (LockStartTime is null || LockEndTime is null)
            {
                LockHoursError = "시작 시간과 종료 시간을 모두 선택하세요.";
            }
            else
            {
                var startMinute = LockStartTime.Value.Hours * 60 + LockStartTime.Value.Minutes;
                var endMinute = LockEndTime.Value.Hours * 60 + LockEndTime.Value.Minutes;
                if (startMinute == endMinute)
                {
                    LockHoursError = "시작 시간과 종료 시간은 다르게 설정하세요.";
                }
                else
                {
                    lockStart = startMinute;
                    lockEnd = endMinute;
                }
            }
        }

        return !HasPinError && !HasGraceMinutesError && !HasLockHoursError;
    }

    private void ClearErrors()
    {
        PinError = string.Empty;
        GraceMinutesError = string.Empty;
        LockHoursError = string.Empty;
    }

    private void AttachApp(ProtectedAppViewModel app)
    {
        if (!ReferenceEquals(_currentApp, app))
        {
            DetachApp();
            _currentApp = app;
            _currentApp.PropertyChanged += OnCurrentAppPropertyChanged;
        }

        AppName = app.Name;
        AppPath = app.Path;
        AppIcon = app.Icon;
        IsLocked = app.IsLocked;
        OnPropertyChanged(nameof(CurrentApp));
        OnPropertyChanged(nameof(HasRuleConflict));
    }

    private void DetachApp()
    {
        if (_currentApp is not null)
        {
            _currentApp.PropertyChanged -= OnCurrentAppPropertyChanged;
            _currentApp = null;
            OnPropertyChanged(nameof(CurrentApp));
        }
    }

    private void OnCurrentAppPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_currentApp is null)
        {
            return;
        }

        switch (e.PropertyName)
        {
            case nameof(ProtectedAppViewModel.Name):
                AppName = _currentApp.Name;
                break;
            case nameof(ProtectedAppViewModel.Path):
                AppPath = _currentApp.Path;
                break;
            case nameof(ProtectedAppViewModel.Icon):
                AppIcon = _currentApp.Icon;
                break;
            case nameof(ProtectedAppViewModel.IsLocked):
                IsLocked = _currentApp.IsLocked;
                break;
            case nameof(ProtectedAppViewModel.Rule):
                OnPropertyChanged(nameof(HasRuleConflict));
                break;
        }
    }
}
