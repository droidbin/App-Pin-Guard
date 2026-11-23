using System.Collections.ObjectModel;
using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;
using WindowsAppProtector.Services;

namespace WindowsAppProtector.ViewModels;

public sealed record IdleLockOption(string Label, int Minutes)
{
    public override string ToString() => Label;
}

public sealed class SettingsViewModel : ObservableObject, IDisposable
{
    private static readonly int[] DefaultIdleLockPresets = [0, 5, 10, 15, 30];

    private readonly MainViewModel _mainViewModel;
    private readonly GitHubUpdateService _updateService;
    private readonly Func<Task<bool>> _changePinAsync;
    private readonly Action _reregisterHotkeys;
    private readonly Func<GitHubReleaseInfo, Task> _installUpdateAsync;
    private readonly string _currentVersionText;
    private readonly SemaphoreSlim _saveLock = new(1, 1);

    private bool _isSynchronizing;
    private bool _disposed;

    private IdleLockOption _selectedIdleLockOption;
    private bool _enableLaunchGate;
    private bool _startWithWindows;
    private bool _closeToBackground;
    private bool _isStableChannel = true;

    private string _pinMessage = string.Empty;
    private bool _isPinError;
    private string _idleLockError = string.Empty;
    private string _launchGateError = string.Empty;
    private string _startWithWindowsError = string.Empty;
    private string _closeToBackgroundError = string.Empty;
    private string _updateChannelError = string.Empty;

    private bool _isCheckingForUpdates;
    private bool _isInstallingUpdate;
    private string _updateStatusMessage = string.Empty;
    private bool _isUpdateStatusError;
    private GitHubReleaseInfo? _availableRelease;

    public SettingsViewModel(
        MainViewModel mainViewModel,
        GitHubUpdateService updateService,
        string currentVersionText,
        Func<Task<bool>> changePinAsync,
        Action reregisterHotkeys,
        Func<GitHubReleaseInfo, Task> installUpdateAsync)
    {
        _mainViewModel = mainViewModel;
        _updateService = updateService;
        _currentVersionText = currentVersionText;
        _changePinAsync = changePinAsync;
        _reregisterHotkeys = reregisterHotkeys;
        _installUpdateAsync = installUpdateAsync;

        IdleLockOptions = new ObservableCollection<IdleLockOption>(
            DefaultIdleLockPresets.Select(CreateIdleLockOption));
        _selectedIdleLockOption = IdleLockOptions[2]; // 10분

        _mainViewModel.PropertyChanged += OnMainViewModelPropertyChanged;
        SyncFromMainViewModel();
    }

    public ObservableCollection<IdleLockOption> IdleLockOptions { get; }

    public ObservableCollection<HotkeySettingViewModel> Hotkeys => _mainViewModel.Hotkeys;

    public string CurrentVersionDisplay => $"현재 버전 v{_currentVersionText}";

    public string PinMessage
    {
        get => _pinMessage;
        private set
        {
            if (SetProperty(ref _pinMessage, value))
            {
                OnPropertyChanged(nameof(HasPinMessage));
            }
        }
    }

    public bool HasPinMessage => !string.IsNullOrEmpty(_pinMessage);

    public bool IsPinError
    {
        get => _isPinError;
        private set => SetProperty(ref _isPinError, value);
    }

    public IdleLockOption SelectedIdleLockOption
    {
        get => _selectedIdleLockOption;
        set
        {
            if (value is null || Equals(_selectedIdleLockOption, value))
            {
                return;
            }

            SetProperty(ref _selectedIdleLockOption, value);
            if (!_isSynchronizing)
            {
                _ = ApplyIdleLockMinutesAsync(value.Minutes);
            }
        }
    }

    public string IdleLockError
    {
        get => _idleLockError;
        private set => SetProperty(ref _idleLockError, value);
    }

    public bool EnableLaunchGate
    {
        get => _enableLaunchGate;
        set
        {
            if (SetProperty(ref _enableLaunchGate, value) && !_isSynchronizing)
            {
                _ = ApplyLaunchGateAsync(value);
            }
        }
    }

    public string LaunchGateError
    {
        get => _launchGateError;
        private set => SetProperty(ref _launchGateError, value);
    }

    public bool StartWithWindows
    {
        get => _startWithWindows;
        set
        {
            if (SetProperty(ref _startWithWindows, value) && !_isSynchronizing)
            {
                _ = ApplyStartWithWindowsAsync(value);
            }
        }
    }

    public string StartWithWindowsError
    {
        get => _startWithWindowsError;
        private set => SetProperty(ref _startWithWindowsError, value);
    }

    public bool CloseToBackground
    {
        get => _closeToBackground;
        set
        {
            if (SetProperty(ref _closeToBackground, value) && !_isSynchronizing)
            {
                _ = ApplyCloseToBackgroundAsync(value);
            }
        }
    }

    public string CloseToBackgroundError
    {
        get => _closeToBackgroundError;
        private set => SetProperty(ref _closeToBackgroundError, value);
    }

    public bool IsStableChannel
    {
        get => _isStableChannel;
        set
        {
            if (SetProperty(ref _isStableChannel, value))
            {
                OnPropertyChanged(nameof(IsBetaChannel));
                if (!_isSynchronizing && value)
                {
                    _ = ApplyUpdateChannelAsync(GitHubUpdateService.StableChannel);
                }
            }
        }
    }

    public bool IsBetaChannel
    {
        get => !_isStableChannel;
        set
        {
            if (_isStableChannel == value)
            {
                if (SetProperty(ref _isStableChannel, !value, nameof(IsStableChannel)))
                {
                    OnPropertyChanged(nameof(IsBetaChannel));
                    if (!_isSynchronizing && value)
                    {
                        _ = ApplyUpdateChannelAsync(GitHubUpdateService.BetaChannel);
                    }
                }
            }
        }
    }

    public string UpdateChannelError
    {
        get => _updateChannelError;
        private set => SetProperty(ref _updateChannelError, value);
    }

    public string HotkeySummaryMessage => _mainViewModel.HotkeyValidationMessage;

    public bool HasHotkeyConflict => !_mainViewModel.CanSaveHotkeys;

    public bool IsCheckingForUpdates
    {
        get => _isCheckingForUpdates;
        private set
        {
            if (SetProperty(ref _isCheckingForUpdates, value))
            {
                OnPropertyChanged(nameof(CanCheckForUpdates));
                OnPropertyChanged(nameof(CheckUpdateButtonText));
            }
        }
    }

    public bool CanCheckForUpdates => !_isCheckingForUpdates && !_isInstallingUpdate;

    public string CheckUpdateButtonText => _isCheckingForUpdates ? "확인 중..." : "업데이트 확인";

    public bool IsInstallingUpdate
    {
        get => _isInstallingUpdate;
        private set
        {
            if (SetProperty(ref _isInstallingUpdate, value))
            {
                OnPropertyChanged(nameof(CanCheckForUpdates));
                OnPropertyChanged(nameof(CanInstallUpdate));
                OnPropertyChanged(nameof(InstallUpdateButtonText));
            }
        }
    }

    public bool CanInstallUpdate => !_isInstallingUpdate && _availableRelease is not null;

    public string InstallUpdateButtonText => _isInstallingUpdate ? "다운로드 중..." : "지금 설치";

    public string UpdateStatusMessage
    {
        get => _updateStatusMessage;
        private set
        {
            if (SetProperty(ref _updateStatusMessage, value))
            {
                OnPropertyChanged(nameof(HasUpdateStatus));
            }
        }
    }

    public bool HasUpdateStatus => !string.IsNullOrEmpty(_updateStatusMessage);

    public bool IsUpdateStatusError
    {
        get => _isUpdateStatusError;
        private set => SetProperty(ref _isUpdateStatusError, value);
    }

    public GitHubReleaseInfo? AvailableRelease
    {
        get => _availableRelease;
        private set
        {
            if (SetProperty(ref _availableRelease, value))
            {
                OnPropertyChanged(nameof(HasAvailableUpdate));
                OnPropertyChanged(nameof(CanInstallUpdate));
            }
        }
    }

    public bool HasAvailableUpdate => _availableRelease is not null;

    public void SyncFromMainViewModel()
    {
        _isSynchronizing = true;
        try
        {
            var idleOption = FindOrAddIdleLockOption(_mainViewModel.IdleLockMinutes);
            SetProperty(ref _selectedIdleLockOption, idleOption, nameof(SelectedIdleLockOption));
            SetProperty(ref _enableLaunchGate, _mainViewModel.EnableLaunchGate, nameof(EnableLaunchGate));
            SetProperty(ref _startWithWindows, _mainViewModel.StartWithWindows, nameof(StartWithWindows));
            SetProperty(ref _closeToBackground, _mainViewModel.CloseToBackground, nameof(CloseToBackground));

            var isStable = !string.Equals(
                _mainViewModel.UpdateChannel,
                GitHubUpdateService.BetaChannel,
                StringComparison.OrdinalIgnoreCase);
            if (SetProperty(ref _isStableChannel, isStable, nameof(IsStableChannel)))
            {
                OnPropertyChanged(nameof(IsBetaChannel));
            }

            OnPropertyChanged(nameof(HotkeySummaryMessage));
            OnPropertyChanged(nameof(HasHotkeyConflict));
        }
        finally
        {
            _isSynchronizing = false;
        }
    }

    public async Task ChangePinAsync()
    {
        PinMessage = string.Empty;
        IsPinError = false;

        try
        {
            var changed = await _changePinAsync();
            if (changed)
            {
                IsPinError = false;
                PinMessage = "PIN이 변경되었습니다.";
            }
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            IsPinError = true;
            PinMessage = $"PIN을 변경할 수 없습니다: {ex.Message}";
        }
    }

    public async Task ApplyHotkeyAsync(string actionKey, string hotkeyText)
    {
        var saved = await _mainViewModel.SetHotkeyAsync(actionKey, hotkeyText);
        OnPropertyChanged(nameof(HotkeySummaryMessage));
        OnPropertyChanged(nameof(HasHotkeyConflict));

        if (saved)
        {
            _reregisterHotkeys();
            OnPropertyChanged(nameof(HotkeySummaryMessage));
            OnPropertyChanged(nameof(HasHotkeyConflict));
        }
    }

    public async Task CheckForUpdatesAsync()
    {
        if (_isCheckingForUpdates || _isInstallingUpdate)
        {
            return;
        }

        IsCheckingForUpdates = true;
        AvailableRelease = null;
        IsUpdateStatusError = false;
        UpdateStatusMessage = "업데이트를 확인하는 중입니다...";

        try
        {
            var result = await _updateService.CheckForUpdateAsync(_mainViewModel.UpdateChannel);
            if (!string.IsNullOrWhiteSpace(result.ErrorMessage))
            {
                IsUpdateStatusError = true;
                UpdateStatusMessage = result.ErrorMessage;
                return;
            }

            if (!result.IsUpdateAvailable || result.Release is null)
            {
                IsUpdateStatusError = false;
                UpdateStatusMessage = $"현재 최신 버전입니다. (v{_currentVersionText})";
                return;
            }

            var release = result.Release;
            var releaseName = string.IsNullOrWhiteSpace(release.ReleaseName)
                ? release.TagName
                : release.ReleaseName;

            AvailableRelease = release;
            IsUpdateStatusError = false;
            UpdateStatusMessage = $"새 버전 {release.LatestVersion} ({releaseName})이 있습니다.";
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            IsUpdateStatusError = true;
            UpdateStatusMessage = $"업데이트를 확인할 수 없습니다: {ex.Message}";
        }
        finally
        {
            IsCheckingForUpdates = false;
        }
    }

    public async Task InstallAvailableUpdateAsync()
    {
        var release = _availableRelease;
        if (release is null || _isInstallingUpdate)
        {
            return;
        }

        IsInstallingUpdate = true;
        IsUpdateStatusError = false;
        UpdateStatusMessage = "업데이트를 다운로드하는 중입니다...";

        try
        {
            await _installUpdateAsync(release);
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            IsUpdateStatusError = true;
            UpdateStatusMessage = $"업데이트를 설치할 수 없습니다: {ex.Message}";
        }
        finally
        {
            IsInstallingUpdate = false;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _mainViewModel.PropertyChanged -= OnMainViewModelPropertyChanged;
        _saveLock.Dispose();
    }

    private Task ApplyIdleLockMinutesAsync(int idleLockMinutes)
    {
        IdleLockError = string.Empty;
        return SavePreferenceAsync(
            closeToBackground: _mainViewModel.CloseToBackground,
            startWithWindows: _mainViewModel.StartWithWindows,
            idleLockMinutes: idleLockMinutes,
            enableLaunchGate: _mainViewModel.EnableLaunchGate,
            updateChannel: _mainViewModel.UpdateChannel,
            setError: message => IdleLockError = message);
    }

    private Task ApplyLaunchGateAsync(bool enableLaunchGate)
    {
        LaunchGateError = string.Empty;
        return SavePreferenceAsync(
            closeToBackground: _mainViewModel.CloseToBackground,
            startWithWindows: _mainViewModel.StartWithWindows,
            idleLockMinutes: _mainViewModel.IdleLockMinutes,
            enableLaunchGate: enableLaunchGate,
            updateChannel: _mainViewModel.UpdateChannel,
            setError: message => LaunchGateError = message);
    }

    private Task ApplyStartWithWindowsAsync(bool startWithWindows)
    {
        StartWithWindowsError = string.Empty;
        return SavePreferenceAsync(
            closeToBackground: _mainViewModel.CloseToBackground,
            startWithWindows: startWithWindows,
            idleLockMinutes: _mainViewModel.IdleLockMinutes,
            enableLaunchGate: _mainViewModel.EnableLaunchGate,
            updateChannel: _mainViewModel.UpdateChannel,
            setError: message => StartWithWindowsError = message);
    }

    private Task ApplyCloseToBackgroundAsync(bool closeToBackground)
    {
        CloseToBackgroundError = string.Empty;
        return SavePreferenceAsync(
            closeToBackground: closeToBackground,
            startWithWindows: _mainViewModel.StartWithWindows,
            idleLockMinutes: _mainViewModel.IdleLockMinutes,
            enableLaunchGate: _mainViewModel.EnableLaunchGate,
            updateChannel: _mainViewModel.UpdateChannel,
            setError: message => CloseToBackgroundError = message);
    }

    private Task ApplyUpdateChannelAsync(string updateChannel)
    {
        UpdateChannelError = string.Empty;
        return SavePreferenceAsync(
            closeToBackground: _mainViewModel.CloseToBackground,
            startWithWindows: _mainViewModel.StartWithWindows,
            idleLockMinutes: _mainViewModel.IdleLockMinutes,
            enableLaunchGate: _mainViewModel.EnableLaunchGate,
            updateChannel: updateChannel,
            setError: message => UpdateChannelError = message);
    }

    private async Task SavePreferenceAsync(
        bool closeToBackground,
        bool startWithWindows,
        int idleLockMinutes,
        bool enableLaunchGate,
        string updateChannel,
        Action<string> setError)
    {
        await _saveLock.WaitAsync();
        try
        {
            var saved = await _mainViewModel.SavePreferencesAsync(
                closeToBackground: closeToBackground,
                closeAppsOnLock: _mainViewModel.CloseAppsOnLock,
                startWithWindows: startWithWindows,
                idleLockMinutes: idleLockMinutes,
                enableLaunchGate: enableLaunchGate,
                updateChannel: updateChannel);

            if (!saved)
            {
                var errorMessage = string.IsNullOrWhiteSpace(_mainViewModel.StatusText)
                    ? "설정을 저장할 수 없습니다."
                    : _mainViewModel.StatusText;
                setError(errorMessage);
                SyncFromMainViewModel();
            }
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            setError($"설정을 적용할 수 없습니다: {ex.Message}");
            SyncFromMainViewModel();
        }
        finally
        {
            _saveLock.Release();
        }
    }

    private void OnMainViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(MainViewModel.IdleLockMinutes)
            or nameof(MainViewModel.EnableLaunchGate)
            or nameof(MainViewModel.StartWithWindows)
            or nameof(MainViewModel.CloseToBackground)
            or nameof(MainViewModel.UpdateChannel))
        {
            SyncFromMainViewModel();
        }
        else if (e.PropertyName is nameof(MainViewModel.HotkeyValidationMessage)
            or nameof(MainViewModel.CanSaveHotkeys))
        {
            OnPropertyChanged(nameof(HotkeySummaryMessage));
            OnPropertyChanged(nameof(HasHotkeyConflict));
        }
    }

    private IdleLockOption FindOrAddIdleLockOption(int minutes)
    {
        var existing = IdleLockOptions.FirstOrDefault(option => option.Minutes == minutes);
        if (existing is not null)
        {
            return existing;
        }

        var custom = CreateIdleLockOption(minutes);
        var insertIndex = 0;
        while (insertIndex < IdleLockOptions.Count && IdleLockOptions[insertIndex].Minutes < minutes)
        {
            insertIndex++;
        }

        IdleLockOptions.Insert(insertIndex, custom);
        return custom;
    }

    private static IdleLockOption CreateIdleLockOption(int minutes)
    {
        return minutes <= 0
            ? new IdleLockOption("사용 안 함", 0)
            : new IdleLockOption($"{minutes}분", minutes);
    }
}
