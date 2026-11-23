using System.Collections.ObjectModel;
using System.Globalization;
using System.Reflection;
using CommunityToolkit.Mvvm.ComponentModel;
using WindowsAppProtector.Models;
using WindowsAppProtector.Services;

namespace WindowsAppProtector.ViewModels;

public class MainViewModel : ObservableObject
{
    private readonly ISettingsStore settingsStore;
    private readonly IProtectionService protectionService;
    private readonly INotificationService? notificationService;
    private readonly ProtectedAppProcessService protectedAppProcessService = new();
    private readonly AppConfig config = new();
    private bool protectionEnabled;
    private string searchText = string.Empty;
    private string statusText = "잠금 상태: 대기";
    private string hotkeyValidationMessage = string.Empty;
    private bool canSaveHotkeys = true;
    private bool autoLockSuppressedUntilActive;
    private ProtectedAppViewModel? selectedApp;
    private ProtectionServiceState serviceState = ProtectionServiceState.Unknown;
    private bool lastPolicySyncFailed;
    private string lastPolicySyncError = string.Empty;

    public MainViewModel()
        : this(new JsonSettingsStore(), new ProtectionService(), notificationService: null)
    {
    }

    public MainViewModel(INotificationService? notificationService)
        : this(new JsonSettingsStore(), new ProtectionService(), notificationService)
    {
    }

    public MainViewModel(
        ISettingsStore settingsStore,
        IProtectionService protectionService,
        INotificationService? notificationService = null)
    {
        this.settingsStore = settingsStore;
        this.protectionService = protectionService;
        this.notificationService = notificationService;
        ValidateHotkeys();
    }

    public bool ProtectionEnabled
    {
        get => protectionEnabled;
        private set => SetProperty(ref protectionEnabled, value);
    }

    public int LockedAppCount => config.ProtectedApps.Count(app => app.Enabled);

    public int TotalAppCount => config.ProtectedApps.Count;

    public ProtectionServiceState ServiceState
    {
        get => serviceState;
        private set
        {
            if (SetProperty(ref serviceState, value))
            {
                NotifyServiceStatusChanged();
            }
        }
    }

    public bool LastPolicySyncFailed
    {
        get => lastPolicySyncFailed;
        private set
        {
            if (SetProperty(ref lastPolicySyncFailed, value))
            {
                NotifyServiceStatusChanged();
            }
        }
    }

    public string LastPolicySyncError
    {
        get => lastPolicySyncError;
        private set
        {
            if (SetProperty(ref lastPolicySyncError, value))
            {
                NotifyServiceStatusChanged();
            }
        }
    }

    public bool HasServiceWarning =>
        serviceState is ProtectionServiceState.Stopped or ProtectionServiceState.NotInstalled ||
        lastPolicySyncFailed;

    public string LockedSummarySentence => LockedAppCount > 0
        ? $"앱 {LockedAppCount}개가 잠겨 있습니다."
        : "잠긴 앱이 없습니다.";

    public string StatusSentence => $"{LockedSummarySentence} 보호 서비스 정상 작동 중.";

    public string ServiceWarningSentence
    {
        get
        {
            var reason = serviceState switch
            {
                ProtectionServiceState.NotInstalled => "보호 서비스가 설치되어 있지 않습니다.",
                ProtectionServiceState.Stopped => "보호 서비스가 꺼져 있습니다.",
                _ when lastPolicySyncFailed && !string.IsNullOrWhiteSpace(lastPolicySyncError) =>
                    $"정책 동기화에 실패했습니다. ({lastPolicySyncError})",
                _ when lastPolicySyncFailed => "정책 동기화에 실패했습니다.",
                _ => "보호 서비스 상태를 확인할 수 없습니다.",
            };

            return $"{LockedSummarySentence} {reason}";
        }
    }

    public bool IsAppRegistered(PackagedAppInfo app)
    {
        if (app.IsPackaged)
        {
            return config.ProtectedApps.Any(item =>
                (!string.IsNullOrWhiteSpace(app.AppUserModelId) &&
                    string.Equals(item.AppUserModelId, app.AppUserModelId, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrWhiteSpace(app.ExecutableName) &&
                    !string.IsNullOrWhiteSpace(item.ExecutableName) &&
                    string.Equals(item.ExecutableName, app.ExecutableName, StringComparison.OrdinalIgnoreCase)));
        }

        if (string.IsNullOrWhiteSpace(app.Path))
        {
            return false;
        }

        try
        {
            var fullPath = Path.GetFullPath(app.Path);
            return config.ProtectedApps.Any(item =>
                !item.IsPackaged &&
                !string.IsNullOrWhiteSpace(item.Path) &&
                string.Equals(Path.GetFullPath(item.Path), fullPath, StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }

    public string SearchText
    {
        get => searchText;
        set
        {
            if (SetProperty(ref searchText, value))
            {
                RefreshApps();
            }
        }
    }

    public string StatusText
    {
        get => statusText;
        set => SetProperty(ref statusText, value);
    }

    public string HotkeyValidationMessage
    {
        get => hotkeyValidationMessage;
        set => SetProperty(ref hotkeyValidationMessage, value);
    }

    public bool CanSaveHotkeys
    {
        get => canSaveHotkeys;
        set => SetProperty(ref canSaveHotkeys, value);
    }

    public ProtectedAppViewModel? SelectedApp
    {
        get => selectedApp;
        set => SetProperty(ref selectedApp, value);
    }

    public bool CloseToBackground
    {
        get => config.CloseToBackground;
        set
        {
            if (config.CloseToBackground != value)
            {
                config.CloseToBackground = value;
                OnPropertyChanged();
            }
        }
    }

    public bool StartWithWindows
    {
        get => config.StartWithWindows;
        set
        {
            if (config.StartWithWindows != value)
            {
                config.StartWithWindows = value;
                OnPropertyChanged();
            }
        }
    }

    public bool CloseAppsOnLock
    {
        get => config.CloseAppsOnLock;
        set
        {
            if (config.CloseAppsOnLock != value)
            {
                config.CloseAppsOnLock = value;
                OnPropertyChanged();
            }
        }
    }

    public int IdleLockMinutes
    {
        get => config.IdleLockMinutes;
        set
        {
            var clampedValue = Math.Clamp(value, 0, 1440);
            if (config.IdleLockMinutes != clampedValue)
            {
                config.IdleLockMinutes = clampedValue;
                OnPropertyChanged();
            }
        }
    }

    public ObservableCollection<ProtectedAppViewModel> Apps { get; } = new();

    public bool HasAppPin =>
        !string.IsNullOrWhiteSpace(config.AppPinSalt) &&
        !string.IsNullOrWhiteSpace(config.AppPinHash);

    public bool EnableLaunchGate => config.EnableLaunchGate;

    public string UpdateChannel
    {
        get
        {
            if (string.Equals(config.UpdateChannel, GitHubUpdateService.BetaChannel, StringComparison.OrdinalIgnoreCase))
                return GitHubUpdateService.BetaChannel;
            if (string.Equals(config.UpdateChannel, GitHubUpdateService.StableChannel, StringComparison.OrdinalIgnoreCase))
                return GitHubUpdateService.StableChannel;
            var informational = Assembly.GetExecutingAssembly()
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            return informational?.Contains('-') == true
                ? GitHubUpdateService.BetaChannel
                : GitHubUpdateService.StableChannel;
        }
    }

    internal (bool CustomPin, int Minutes, int? Start, int? End, bool RelockOnExit)? GetLaunchPolicy(ProtectedAppViewModel? item)
    {
        var app = item is null ? null : FindModel(item);
        if (app is null || app.IsPackaged || ProtectionService.UsesWindowOnlyBlocking(app))
            return null;
        return (!string.IsNullOrEmpty(app.LaunchPinHash), app.LaunchAllowedMinutes,
            app.LaunchLockStartMinute, app.LaunchLockEndMinute, app.LaunchRelockOnExit);
    }

    internal async Task<bool> SaveLaunchPolicyAsync(ProtectedAppViewModel item, bool useDefaultPin,
        string newPin, int minutes, int? start, int? end, bool relockOnExit)
    {
        var app = FindModel(item);
        if (app is null || GetLaunchPolicy(item) is null)
            return false;

        if (useDefaultPin)
        {
            app.LaunchPinSalt = string.Empty;
            app.LaunchPinHash = string.Empty;
        }
        else if (newPin.Length > 0)
        {
            (app.LaunchPinSalt, app.LaunchPinHash) = PinHasher.CreateHash(newPin);
        }
        app.LaunchAllowedMinutes = minutes;
        app.LaunchLockStartMinute = start;
        app.LaunchLockEndMinute = end;
        app.LaunchRelockOnExit = relockOnExit;
        if (await SaveAndResyncPolicyAsync())
        {
            var summary = BuildPolicySummary(app);
            item.PolicySummary = summary;
            foreach (var listed in Apps)
            {
                if (string.Equals(listed.Identity, item.Identity, StringComparison.OrdinalIgnoreCase))
                {
                    listed.PolicySummary = summary;
                }
            }

            ReportStatus($"{app.Name} 실행 정책을 저장했습니다.", NotificationSeverity.Success);
            return true;
        }

        return false;
    }

    public ObservableCollection<HotkeySettingViewModel> Hotkeys { get; } = new()
    {
        new("show-window", "창 보이기/숨기기", "백그라운드 실행 중인 앱 창을 전환합니다.", "Ctrl+Alt+W"),
        new("lock-all", "목록 잠금", "현재 앱 목록의 잠금을 활성화합니다.", "Ctrl+Shift+L"),
        new("unlock-all", "목록 해제", "현재 앱 목록의 잠금을 해제합니다.", "Ctrl+Shift+U"),
    };

    public IReadOnlySet<string> GetLockedExecutableNames()
    {
        if (!LockRulesActive())
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        return config.ProtectedApps
            .Where(app => app.Enabled && !ProtectionService.UsesWindowOnlyBlocking(app) && !config.EnableLaunchGate)
            .Select(GetExecutableName)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public IReadOnlySet<string> GetLockedPackageFamilyNames()
    {
        // Package-family matching is performed by the service-managed session agent.
        return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    }

    public async Task InitializeAsync()
    {
        var loaded = await settingsStore.LoadAsync();
        config.ProtectionEnabled = loaded.ProtectionEnabled;
        config.CloseToBackground = loaded.CloseToBackground;
        config.CloseAppsOnLock = loaded.CloseAppsOnLock;
        config.StartWithWindows = loaded.StartWithWindows;
        config.EnableLaunchGate = loaded.EnableLaunchGate;
        config.UpdateChannel = loaded.UpdateChannel;
        config.IdleLockMinutes = loaded.IdleLockMinutes;
        config.UnlockMinutes = loaded.UnlockMinutes;
        config.UnlockUntil = null;
        config.AppPinSalt = loaded.AppPinSalt;
        config.AppPinHash = loaded.AppPinHash;
        OnPropertyChanged(nameof(CloseToBackground));
        OnPropertyChanged(nameof(CloseAppsOnLock));
        OnPropertyChanged(nameof(StartWithWindows));
        OnPropertyChanged(nameof(IdleLockMinutes));
        OnPropertyChanged(nameof(HasAppPin));
        OnPropertyChanged(nameof(EnableLaunchGate));
        OnPropertyChanged(nameof(UpdateChannel));
        if (loaded.GlobalHotkeys.Count > 0)
        {
            foreach (var hotkey in loaded.GlobalHotkeys)
            {
                config.GlobalHotkeys[hotkey.Key] = hotkey.Value;
            }
        }
        config.ProtectedApps.Clear();
        config.ProtectedApps.AddRange(loaded.ProtectedApps);

        foreach (var hotkey in Hotkeys)
        {
            if (config.GlobalHotkeys.TryGetValue(hotkey.ActionKey, out var value))
            {
                hotkey.HotkeyText = value;
            }
        }

        ProtectionEnabled = LockRulesActive();
        RefreshApps();
        ValidateHotkeys();
        SyncStartupPreference();
        if (await SyncProtectionRulesAsync())
        {
            UpdateStatus();
        }
        await RefreshServiceStatusAsync();
    }

    public async Task RefreshServiceStatusAsync()
    {
        var state = await Task.Run(ProtectionService.QueryServiceState);
        ServiceState = state;
    }

    public async Task RestartServiceAsync()
    {
        try
        {
            ReportStatus("보호 서비스를 다시 시작하는 중입니다...", NotificationSeverity.Info);
            await ProtectionService.RestartServiceAsync();
            await RefreshServiceStatusAsync();

            try
            {
                await protectionService.RequestPolicyResyncAsync();
                LastPolicySyncFailed = false;
                LastPolicySyncError = string.Empty;
                ServiceState = ProtectionServiceState.Running;
                ReportStatus("보호 서비스를 다시 시작하고 정책을 동기화했습니다.", NotificationSeverity.Success);
            }
            catch (Exception syncEx)
            {
                LastPolicySyncFailed = true;
                LastPolicySyncError = syncEx.Message;
                ReportStatus($"보호 서비스는 시작했지만 정책 동기화에 실패했습니다. ({syncEx.Message})", NotificationSeverity.Warning);
            }
        }
        catch (Exception ex)
        {
            await RefreshServiceStatusAsync();
            ReportStatus(ex.Message, NotificationSeverity.Error);
        }
    }

    public async Task SetProtectionEnabledAsync(bool enabled)
    {
        ProtectedAppProcessCloseResult? closeResult = enabled
            ? await CloseAppsBeforeLockAsync(config.ProtectedApps)
            : null;

        foreach (var app in config.ProtectedApps)
        {
            app.Enabled = enabled;
        }

        ProtectionEnabled = LockRulesActive();
        RefreshApps();
        if (!await SyncProtectionRulesAsync()) return;
        UpdateStatus();
        SetCloseResultStatus(closeResult);
    }

    public async Task AddAppAsync(string path)
    {
        await AddAppsAsync(new[] { path });
    }

    public async Task AddAppsAsync(IEnumerable<string> paths)
    {
        var added = new List<ProtectedApp>();
        var skippedDuplicates = 0;
        var missingFiles = 0;

        foreach (var rawPath in paths)
        {
            if (string.IsNullOrWhiteSpace(rawPath) || !File.Exists(rawPath))
            {
                missingFiles++;
                continue;
            }

            var fullPath = Path.GetFullPath(rawPath);
            if (config.ProtectedApps.Any(app =>
                !app.IsPackaged &&
                !string.IsNullOrWhiteSpace(app.Path) &&
                string.Equals(Path.GetFullPath(app.Path), fullPath, StringComparison.OrdinalIgnoreCase)))
            {
                skippedDuplicates++;
                continue;
            }

            var app = new ProtectedApp
            {
                Name = Path.GetFileNameWithoutExtension(fullPath) is { Length: > 0 } baseName
                    ? baseName
                    : Path.GetFileName(fullPath),
                Path = fullPath,
                ExecutableName = Path.GetFileName(fullPath),
                Enabled = true,
            };
            config.ProtectedApps.Add(app);
            added.Add(app);
        }

        if (added.Count == 0)
        {
            if (missingFiles > 0)
            {
                ReportStatus("실행 파일을 찾을 수 없습니다.", NotificationSeverity.Warning);
            }
            else if (skippedDuplicates > 0)
            {
                ReportStatus("이미 보호 목록에 등록된 앱입니다.", NotificationSeverity.Info);
            }

            return;
        }

        var closeResult = await CloseAppsBeforeLockAsync(added);
        RefreshApps();
        if (!await SyncProtectionRulesAsync()) return;
        ReportStatus(
            added.Count == 1
                ? $"{added[0].Name} 앱을 추가하고 잠갔습니다."
                : $"앱 {added.Count}개를 추가하고 잠갔습니다.",
            NotificationSeverity.Success);
        SetCloseResultStatus(closeResult);
    }

    public async Task AddPackagedAppAsync(PackagedAppInfo app)
    {
        await AddPackagedAppsAsync(new[] { app });
    }

    public async Task AddPackagedAppsAsync(IEnumerable<PackagedAppInfo> apps)
    {
        var added = new List<ProtectedApp>();
        var skippedDuplicates = 0;
        var invalidCount = 0;

        foreach (var app in apps)
        {
            if (!app.IsPackaged)
            {
                if (string.IsNullOrWhiteSpace(app.Path) || !File.Exists(app.Path))
                {
                    invalidCount++;
                    continue;
                }

                var fullPath = Path.GetFullPath(app.Path);
                if (config.ProtectedApps.Any(item =>
                    !item.IsPackaged &&
                    !string.IsNullOrWhiteSpace(item.Path) &&
                    string.Equals(Path.GetFullPath(item.Path), fullPath, StringComparison.OrdinalIgnoreCase)))
                {
                    skippedDuplicates++;
                    continue;
                }

                var model = new ProtectedApp
                {
                    Name = string.IsNullOrWhiteSpace(app.Name) ? Path.GetFileName(fullPath) : app.Name,
                    Path = fullPath,
                    IsPackaged = false,
                    ExecutableName = string.IsNullOrWhiteSpace(app.ExecutableName) ? Path.GetFileName(fullPath) : app.ExecutableName,
                    Enabled = true,
                };
                config.ProtectedApps.Add(model);
                added.Add(model);
                continue;
            }

            if (string.IsNullOrWhiteSpace(app.AppUserModelId) || string.IsNullOrWhiteSpace(app.ExecutableName))
            {
                invalidCount++;
                continue;
            }

            if (config.ProtectedApps.Any(item =>
                string.Equals(item.AppUserModelId, app.AppUserModelId, StringComparison.OrdinalIgnoreCase) ||
                (!string.IsNullOrWhiteSpace(item.ExecutableName) &&
                    string.Equals(item.ExecutableName, app.ExecutableName, StringComparison.OrdinalIgnoreCase))))
            {
                skippedDuplicates++;
                continue;
            }

            var packagedModel = new ProtectedApp
            {
                Name = app.Name,
                Path = app.AppUserModelId,
                IsPackaged = true,
                PackageFamilyName = app.PackageFamilyName,
                AppUserModelId = app.AppUserModelId,
                ExecutableName = app.ExecutableName,
                Enabled = true,
            };
            config.ProtectedApps.Add(packagedModel);
            added.Add(packagedModel);
        }

        if (added.Count == 0)
        {
            if (invalidCount > 0)
            {
                ReportStatus("선택한 앱의 실행 정보를 확인할 수 없습니다.", NotificationSeverity.Warning);
            }
            else if (skippedDuplicates > 0)
            {
                ReportStatus("이미 보호 목록에 등록된 앱입니다.", NotificationSeverity.Info);
            }

            return;
        }

        var closeResult = await CloseAppsBeforeLockAsync(added);
        RefreshApps();
        if (!await SyncProtectionRulesAsync()) return;
        ReportStatus(
            added.Count == 1
                ? $"{added[0].Name} 앱을 추가하고 잠갔습니다."
                : $"앱 {added.Count}개를 추가하고 잠갔습니다.",
            NotificationSeverity.Success);
        SetCloseResultStatus(closeResult);
    }

    public async Task RemoveSelectedAppAsync()
    {
        if (SelectedApp is null)
        {
            return;
        }

        await RemoveAppAsync(SelectedApp);
    }

    public async Task RemoveAppAsync(ProtectedAppViewModel item)
    {
        await RemoveAppsAsync(new[] { item });
    }

    public async Task RemoveAppsAsync(IEnumerable<ProtectedAppViewModel> items)
    {
        var targets = items
            .Select(FindModel)
            .Where(model => model is not null)
            .Distinct()
            .Cast<ProtectedApp>()
            .ToList();

        if (targets.Count == 0)
        {
            return;
        }

        foreach (var model in targets)
        {
            config.ProtectedApps.Remove(model);
        }

        if (SelectedApp is not null && FindModel(SelectedApp) is null)
        {
            SelectedApp = null;
        }

        RefreshApps();
        if (!await SyncProtectionRulesAsync()) return;
        ReportStatus(
            targets.Count == 1
                ? $"{targets[0].Name} 앱을 목록에서 제거했습니다."
                : $"선택한 앱 {targets.Count}개를 목록에서 제거했습니다.",
            NotificationSeverity.Success);
    }

    public async Task ToggleSelectedAppAsync()
    {
        if (SelectedApp is null)
        {
            return;
        }

        var model = FindModel(SelectedApp);
        if (model is null)
        {
            return;
        }

        await SetAppsLockedCoreAsync(new[] { model }, !model.Enabled);
    }

    public async Task SetAppLockedAsync(ProtectedAppViewModel item, bool locked)
    {
        var model = FindModel(item);
        if (model is null)
        {
            return;
        }

        await SetAppsLockedCoreAsync(new[] { model }, locked);
    }

    public async Task SetAppsEnabledAsync(IEnumerable<ProtectedAppViewModel> items, bool enabled)
    {
        var targets = items
            .Select(FindModel)
            .Where(model => model is not null)
            .Distinct()
            .Cast<ProtectedApp>()
            .ToList();

        if (targets.Count == 0)
        {
            return;
        }

        await SetAppsLockedCoreAsync(targets, enabled);
    }

    private async Task SetAppsLockedCoreAsync(IReadOnlyList<ProtectedApp> targets, bool locking)
    {
        if (targets.Count == 0)
        {
            return;
        }

        if (!locking)
        {
            autoLockSuppressedUntilActive = true;
        }

        var closeResult = locking
            ? await CloseAppsBeforeLockAsync(targets)
            : null;

        foreach (var model in targets)
        {
            model.Enabled = locking;
        }

        RefreshApps();
        if (!await SyncProtectionRulesAsync()) return;

        var message = targets.Count == 1
            ? (locking ? $"{targets[0].Name} 앱을 잠갔습니다." : $"{targets[0].Name} 앱을 열었습니다.")
            : (locking ? $"선택한 앱 {targets.Count}개를 잠갔습니다." : $"선택한 앱 {targets.Count}개를 열었습니다.");
        ReportStatus(message, NotificationSeverity.Success);
        SetCloseResultStatus(closeResult);
    }

    public async Task SetListedAppsEnabledAsync(bool enabled, bool closeRunningApps = true)
    {
        if (config.ProtectedApps.Count == 0)
        {
            ReportStatus(enabled ? "잠글 앱이 없습니다." : "열 앱이 없습니다.", NotificationSeverity.Info);
            return;
        }

        if (!enabled)
        {
            autoLockSuppressedUntilActive = true;
        }

        ProtectedAppProcessCloseResult? closeResult = enabled && closeRunningApps
            ? await CloseAppsBeforeLockAsync(config.ProtectedApps)
            : null;

        foreach (var app in config.ProtectedApps)
        {
            app.Enabled = enabled;
        }

        RefreshApps();
        if (!await SyncProtectionRulesAsync()) return;
        ReportStatus(
            enabled
                ? $"앱 {config.ProtectedApps.Count}개를 모두 잠갔습니다."
                : $"앱 {config.ProtectedApps.Count}개를 모두 열었습니다.",
            NotificationSeverity.Success);
        SetCloseResultStatus(closeResult);
    }

    public async Task<bool> SavePreferencesAsync(bool closeToBackground, bool closeAppsOnLock,
        bool startWithWindows, int idleLockMinutes, bool enableLaunchGate, string updateChannel)
    {
        var previousCloseToBackground = config.CloseToBackground;
        var previousCloseAppsOnLock = config.CloseAppsOnLock;
        var previousStartWithWindows = config.StartWithWindows;
        var previousIdleLockMinutes = config.IdleLockMinutes;
        var previousEnableLaunchGate = config.EnableLaunchGate;
        var previousUpdateChannel = config.UpdateChannel;

        try
        {
            await Task.Run(() => StartupService.SetEnabled(startWithWindows));
            config.UpdateChannel = updateChannel;
            CloseToBackground = closeToBackground;
            CloseAppsOnLock = closeAppsOnLock;
            StartWithWindows = startWithWindows;
            IdleLockMinutes = idleLockMinutes;
            config.EnableLaunchGate = enableLaunchGate;
            OnPropertyChanged(nameof(EnableLaunchGate));
            OnPropertyChanged(nameof(UpdateChannel));
            if (!await SaveAndResyncPolicyAsync())
            {
                RestorePreferences(
                    previousCloseToBackground,
                    previousCloseAppsOnLock,
                    previousStartWithWindows,
                    previousIdleLockMinutes,
                    previousEnableLaunchGate,
                    previousUpdateChannel);
                return false;
            }

            ReportStatus("설정이 저장되었습니다.", NotificationSeverity.Success);
            return true;
        }
        catch (Exception ex)
        {
            RestorePreferences(
                previousCloseToBackground,
                previousCloseAppsOnLock,
                previousStartWithWindows,
                previousIdleLockMinutes,
                previousEnableLaunchGate,
                previousUpdateChannel);
            ReportStatus($"시작 프로그램 설정을 적용할 수 없습니다: {ex.Message}", NotificationSeverity.Error);
            return false;
        }
    }

    private void RestorePreferences(
        bool closeToBackground,
        bool closeAppsOnLock,
        bool startWithWindows,
        int idleLockMinutes,
        bool enableLaunchGate,
        string updateChannel)
    {
        config.UpdateChannel = updateChannel;
        CloseToBackground = closeToBackground;
        CloseAppsOnLock = closeAppsOnLock;
        StartWithWindows = startWithWindows;
        IdleLockMinutes = idleLockMinutes;
        config.EnableLaunchGate = enableLaunchGate;
        OnPropertyChanged(nameof(EnableLaunchGate));
        OnPropertyChanged(nameof(UpdateChannel));
    }

    public async Task<bool> AutoLockIfIdleAsync(TimeSpan idleTime)
    {
        if (config.IdleLockMinutes <= 0)
        {
            return false;
        }

        // When the user becomes active (idle time under 30 seconds), re-arm idle locking
        if (idleTime < TimeSpan.FromSeconds(30))
        {
            autoLockSuppressedUntilActive = false;
        }

        if (autoLockSuppressedUntilActive ||
            idleTime < TimeSpan.FromMinutes(config.IdleLockMinutes) ||
            config.ProtectedApps.Count == 0 ||
            config.ProtectedApps.All(app => app.Enabled))
        {
            return false;
        }

        var closeResult = await CloseAppsBeforeLockAsync(config.ProtectedApps);
        foreach (var app in config.ProtectedApps)
        {
            app.Enabled = true;
        }

        RefreshApps();
        if (!await SyncProtectionRulesAsync()) return false;
        ReportStatus($"유휴 상태 {config.IdleLockMinutes}분 경과로 보호 앱을 자동 잠금했습니다.", NotificationSeverity.Info);
        SetCloseResultStatus(closeResult);
        return true;
    }

    private async Task<ProtectedAppProcessCloseResult?> CloseAppsBeforeLockAsync(IEnumerable<ProtectedApp> apps)
    {
        if (!config.CloseAppsOnLock)
        {
            return null;
        }

        StatusText = "실행 중인 보호 앱을 종료하는 중입니다...";
        return await protectedAppProcessService.CloseRunningAppsAsync(apps);
    }

    private void SetCloseResultStatus(ProtectedAppProcessCloseResult? result)
    {
        if (result is null)
        {
            return;
        }

        if (result.Value.Failed == 0)
        {
            ReportStatus($"실행 중인 앱 {result.Value.Closed}개를 종료하고 잠갔습니다.", NotificationSeverity.Info);
        }
        else
        {
            ReportStatus($"잠금은 적용했지만, 앱 {result.Value.Failed}개를 종료하지 못했습니다.", NotificationSeverity.Warning);
        }
    }

    public async Task SetAppPinAsync(string pin)
    {
        var hash = PinHasher.CreateHash(pin);
        var previous = (config.AppPinSalt, config.AppPinHash);
        config.AppPinSalt = hash.Salt;
        config.AppPinHash = hash.Hash;
        try
        {
            await SaveAsync();
            OnPropertyChanged(nameof(HasAppPin));
        }
        catch
        {
            (config.AppPinSalt, config.AppPinHash) = previous;
            throw;
        }
    }

    public bool VerifyAppPin(string pin)
    {
        return PinHasher.Verify(pin, config.AppPinSalt, config.AppPinHash);
    }

    public async void SetHotkey(string actionKey, string hotkeyText)
    {
        await SetHotkeyAsync(actionKey, hotkeyText);
    }

    public async Task<bool> SetHotkeyAsync(string actionKey, string hotkeyText)
    {
        var hotkey = Hotkeys.FirstOrDefault(item => item.ActionKey == actionKey);
        if (hotkey is null)
        {
            return false;
        }

        var previousText = hotkey.HotkeyText;
        hotkey.HotkeyText = hotkeyText;
        ValidateHotkeys();
        if (!CanSaveHotkeys)
        {
            return false;
        }

        config.GlobalHotkeys[actionKey] = hotkeyText;
        try
        {
            await SaveAsync();
            return true;
        }
        catch (Exception ex)
        {
            hotkey.HotkeyText = previousText;
            config.GlobalHotkeys[actionKey] = previousText;
            ValidateHotkeys();
            hotkey.ValidationMessage = $"단축키를 저장할 수 없습니다: {ex.Message}";
            ReportStatus($"단축키를 저장할 수 없습니다: {ex.Message}", NotificationSeverity.Error);
            return false;
        }
    }

    public void ValidateHotkeys()
    {
        foreach (var hotkey in Hotkeys)
        {
            hotkey.HasDuplicate = false;
            hotkey.ValidationMessage = string.Empty;
        }

        var duplicateGroups = Hotkeys
            .Where(item => !string.IsNullOrWhiteSpace(item.HotkeyText))
            .GroupBy(item => NormalizeHotkey(item.HotkeyText))
            .Where(group => group.Count() > 1)
            .ToArray();

        foreach (var group in duplicateGroups)
        {
            foreach (var hotkey in group)
            {
                hotkey.HasDuplicate = true;
                hotkey.ValidationMessage = "이미 다른 기능에서 사용 중입니다.";
            }
        }

        CanSaveHotkeys = duplicateGroups.Length == 0;
        HotkeyValidationMessage = CanSaveHotkeys
            ? "단축키를 입력하면 즉시 변경됩니다."
            : $"중복된 단축키가 있습니다: {string.Join(", ", duplicateGroups.Select(group => group.Key))}";
    }

    public void ReportHotkeyRegistrationFailure(string actionKey)
    {
        var hotkey = Hotkeys.FirstOrDefault(item => item.ActionKey == actionKey);
        if (hotkey is null)
        {
            return;
        }

        hotkey.ValidationMessage = "다른 프로그램이 사용 중인 단축키입니다.";
        ReportStatus($"단축키 등록 실패: {hotkey.DisplayName} ({hotkey.HotkeyText})", NotificationSeverity.Warning);
    }

    private async Task<bool> SyncProtectionRulesAsync()
    {
        config.UnlockUntil = null;
        config.ProtectionEnabled = LockRulesActive();
        ProtectionEnabled = config.ProtectionEnabled;
        return await SaveAndResyncPolicyAsync();
    }

    private async Task<bool> SaveAndResyncPolicyAsync()
    {
        try
        {
            await SaveAsync();
        }
        catch (Exception ex)
        {
            ReportStatus($"보호 정책을 저장할 수 없습니다: {ex.Message}", NotificationSeverity.Error);
            return false;
        }

        try
        {
            await protectionService.RequestPolicyResyncAsync();
            LastPolicySyncFailed = false;
            LastPolicySyncError = string.Empty;
            ServiceState = ProtectionServiceState.Running;
            return true;
        }
        catch (Exception ex)
        {
            // The service re-reads the saved policy every few seconds on its own, so a failed immediate
            // request only delays the change; report the reason without treating the save as failed.
            LastPolicySyncFailed = true;
            LastPolicySyncError = ex.Message;
            _ = RefreshServiceStatusAsync();
            ReportStatus(
                $"보호 정책을 저장했습니다. 즉시 적용 요청은 실패했지만 서비스가 실행 중이면 몇 초 안에 자동 반영됩니다. ({ex.Message})",
                NotificationSeverity.Warning);
            return true;
        }
    }

    private async Task SaveAsync()
    {
        config.ProtectionEnabled = ProtectionEnabled;
        config.UnlockUntil = null;
        config.GlobalHotkeys = Hotkeys.ToDictionary(item => item.ActionKey, item => item.HotkeyText);
        await settingsStore.SaveAsync(config);
    }

    private void SyncStartupPreference()
    {
        // Re-registers the logon task on every start (migrates older tasks to the fixed settings)
        // off the UI thread so schtasks.exe never delays the PIN prompt.
        var startWithWindows = config.StartWithWindows;
        _ = Task.Run(() =>
        {
            try
            {
                StartupService.SetEnabled(startWithWindows);
            }
            catch (Exception ex)
            {
                App.WriteCrashLog(ex);
            }
        });
    }

    private void RefreshApps()
    {
        var previousIcons = new Dictionary<string, Avalonia.Media.Imaging.Bitmap?>(StringComparer.OrdinalIgnoreCase);
        var previousSelectedIdentities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var existing in Apps)
        {
            if (existing.Icon is not null)
            {
                previousIcons[existing.Identity] = existing.Icon;
            }

            if (existing.IsSelected)
            {
                previousSelectedIdentities.Add(existing.Identity);
            }
        }

        var selectedIdentity = SelectedApp?.Identity;
        Apps.Clear();

        var apps = string.IsNullOrWhiteSpace(SearchText)
            ? config.ProtectedApps
            : config.ProtectedApps
                .Where(app =>
                    app.Name.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    app.Path.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    app.AppUserModelId.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    app.PackageFamilyName.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    app.ExecutableName.Contains(SearchText, StringComparison.OrdinalIgnoreCase))
                .ToList();

        ProtectedAppViewModel? restoredSelection = null;
        foreach (var app in apps)
        {
            var identity = GetAppIdentity(app);
            var item = new ProtectedAppViewModel
            {
                Name = app.Name,
                Identity = identity,
                Path = GetDisplayPath(app),
                IsLocked = app.Enabled,
                PolicySummary = BuildPolicySummary(app),
                IsPackaged = app.IsPackaged,
                PackageFamilyName = app.PackageFamilyName,
                RawPath = app.Path,
                CanConfigureLaunchPolicy = !app.IsPackaged && !ProtectionService.UsesWindowOnlyBlocking(app),
                IsSelected = previousSelectedIdentities.Contains(identity),
                Icon = previousIcons.TryGetValue(identity, out var cachedIcon) ? cachedIcon : null,
            };

            Apps.Add(item);

            if (!string.IsNullOrEmpty(selectedIdentity) &&
                string.Equals(identity, selectedIdentity, StringComparison.OrdinalIgnoreCase))
            {
                restoredSelection = item;
            }
        }

        if (selectedIdentity is not null)
        {
            SelectedApp = restoredSelection;
        }

        OnPropertyChanged(nameof(LockedAppCount));
        OnPropertyChanged(nameof(TotalAppCount));
        NotifyServiceStatusChanged();
    }

    private void NotifyServiceStatusChanged()
    {
        OnPropertyChanged(nameof(HasServiceWarning));
        OnPropertyChanged(nameof(LockedSummarySentence));
        OnPropertyChanged(nameof(StatusSentence));
        OnPropertyChanged(nameof(ServiceWarningSentence));
    }

    private static string BuildPolicySummary(ProtectedApp app)
    {
        var parts = new List<string>(3);

        if (app.LaunchAllowedMinutes > 0)
        {
            parts.Add(app.LaunchAllowedMinutes % 60 == 0
                ? $"{app.LaunchAllowedMinutes / 60}시간 유예"
                : $"{app.LaunchAllowedMinutes}분 유예");
        }

        if (app.LaunchLockStartMinute is >= 0 and < 1440 &&
            app.LaunchLockEndMinute is >= 0 and < 1440)
        {
            parts.Add($"{FormatMinute(app.LaunchLockStartMinute.Value)}–{FormatMinute(app.LaunchLockEndMinute.Value)}");
        }

        if (!string.IsNullOrEmpty(app.LaunchPinHash))
        {
            parts.Add("전용 PIN");
        }

        return string.Join(" · ", parts);
    }

    private static string FormatMinute(int minute)
    {
        return new TimeOnly(minute / 60, minute % 60).ToString("HH:mm", CultureInfo.InvariantCulture);
    }

    private ProtectedApp? FindModel(ProtectedAppViewModel viewModel)
    {
        return config.ProtectedApps.FirstOrDefault(app =>
            string.Equals(GetAppIdentity(app), viewModel.Identity, StringComparison.OrdinalIgnoreCase));
    }

    private static string GetAppIdentity(ProtectedApp app)
    {
        return app.IsPackaged && !string.IsNullOrWhiteSpace(app.AppUserModelId)
            ? app.AppUserModelId
            : app.Path;
    }

    private static string GetDisplayPath(ProtectedApp app)
    {
        if (app.IsPackaged)
        {
            var exeName = string.IsNullOrWhiteSpace(app.ExecutableName) ? "실행 파일 미확인" : app.ExecutableName;
            var identity = string.IsNullOrWhiteSpace(app.AppUserModelId) ? app.PackageFamilyName : app.AppUserModelId;
            return $"{identity} ({exeName})";
        }

        return app.Path;
    }

    private static string GetExecutableName(ProtectedApp app)
    {
        if (!string.IsNullOrWhiteSpace(app.ExecutableName))
        {
            return app.ExecutableName;
        }

        return string.IsNullOrWhiteSpace(app.Path) ? string.Empty : Path.GetFileName(app.Path);
    }

    private bool LockRulesActive()
    {
        return config.ProtectedApps.Any(app => app.Enabled);
    }

    private void UpdateStatus()
    {
        var lockedCount = LockedAppCount;
        StatusText = lockedCount > 0
            ? $"잠금 상태: 적용 중, 잠금 앱 {lockedCount}개"
            : "잠금 상태: 잠긴 앱 없음";
    }

    private void ReportStatus(string message, NotificationSeverity severity)
    {
        StatusText = message;
        notificationService?.Show(severity, message);
    }

    private static string NormalizeHotkey(string hotkeyText)
    {
        return string.Join(
            "+",
            hotkeyText
                .Split('+')
                .Select(part => part.Trim())
                .Where(part => part.Length > 0)
                .Select(part => part.ToUpperInvariant()));
    }
}
