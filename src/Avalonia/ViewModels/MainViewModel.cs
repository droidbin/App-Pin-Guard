using System.Collections.ObjectModel;
using System.Globalization;
using System.Reflection;
using System.Runtime.Serialization.Json;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using WindowsAppProtector.Models;
using WindowsAppProtector.Platform;
using WindowsAppProtector.Services;

namespace WindowsAppProtector.ViewModels;

/// <summary>
/// Edits the policy (policy.json), secrets (secrets.json) and UI settings (ui.json) and reports what the
/// protection service says it applied. The UI enforces nothing itself: the service does, even when this
/// window is closed.
/// </summary>
public class MainViewModel : ObservableObject
{
    private const string ServiceNotAppliedMessage =
        "보호 서비스가 아직 변경 사항을 적용하지 않았습니다. 서비스 상태를 확인하세요.";

    private readonly INotificationService? notificationService;
    private readonly PolicyChangeNotifier policyNotifier = new();
    private readonly ServiceStatusReader statusReader = new();
    private readonly UiSettingsStore uiStore = new();
    private readonly SemaphoreSlim commitGate = new(1, 1);
    private PolicyDocument policy = new();
    private SecretsDocument secrets = new();
    private UiSettings ui = new();
    private StatusDocument? serviceStatus;
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
        : this(notificationService: null)
    {
    }

    public MainViewModel(INotificationService? notificationService)
    {
        this.notificationService = notificationService;
        ValidateHotkeys();
    }

    public bool ProtectionEnabled
    {
        get => protectionEnabled;
        private set => SetProperty(ref protectionEnabled, value);
    }

    public int LockedAppCount => policy.Apps.Count(app => app.Locked);

    public int TotalAppCount => policy.Apps.Count;

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

    // ---- "보호 상태" card (Settings) -----------------------------------------------------------------

    public string ProtectionServiceText => serviceState switch
    {
        ProtectionServiceState.Running when serviceStatus is { PolicyError: { Length: > 0 } } => "실행 중 (정책 오류)",
        ProtectionServiceState.Running when serviceStatus is { Healthy: false } => "실행 중 (확인 필요)",
        ProtectionServiceState.Running => "실행 중",
        ProtectionServiceState.Stopped => "중지됨",
        ProtectionServiceState.NotInstalled => "설치되지 않음",
        _ => "확인할 수 없음",
    };

    public string ProtectionRevisionText => serviceStatus is null
        ? "적용된 버전: 확인할 수 없음"
        : serviceStatus.AppliedRevision >= policy.Revision
            ? $"적용된 버전: {serviceStatus.AppliedRevision} (최신)"
            : $"적용된 버전: {serviceStatus.AppliedRevision} / 저장된 버전: {policy.Revision}";

    public string ProtectionAgentText
    {
        get
        {
            if (serviceStatus is null || serviceStatus.Agents.Count == 0)
            {
                return "창 에이전트: 실행 중인 세션 없음";
            }

            var running = serviceStatus.Agents.Count(agent => agent.State == "running");
            return $"창 에이전트: 세션 {serviceStatus.Agents.Count}개 중 {running}개 실행 중";
        }
    }

    public string ProtectionTamperText
    {
        get
        {
            var latest = serviceStatus?.TamperEvents.FirstOrDefault();
            return latest is null
                ? "최근 변조 감지: 없음"
                : $"최근 변조 감지: {FormatLocal(latest.AtUtc)} {latest.Detail}";
        }
    }

    public bool IsAppRegistered(PackagedAppInfo app)
    {
        if (app.IsPackaged)
        {
            return policy.Apps.Any(item =>
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
            return policy.Apps.Any(item =>
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
        get => ui.CloseToBackground;
        set
        {
            if (ui.CloseToBackground != value)
            {
                ui.CloseToBackground = value;
                OnPropertyChanged();
            }
        }
    }

    public bool StartWithWindows
    {
        get => ui.StartWithWindows;
        set
        {
            if (ui.StartWithWindows != value)
            {
                ui.StartWithWindows = value;
                OnPropertyChanged();
            }
        }
    }

    public bool CloseAppsOnLock
    {
        get => policy.CloseAppsOnLock;
        set
        {
            if (policy.CloseAppsOnLock != value)
            {
                policy.CloseAppsOnLock = value;
                OnPropertyChanged();
            }
        }
    }

    public int IdleLockMinutes
    {
        get => ui.IdleLockMinutes;
        set
        {
            var clampedValue = Math.Clamp(value, 0, 1440);
            if (ui.IdleLockMinutes != clampedValue)
            {
                ui.IdleLockMinutes = clampedValue;
                OnPropertyChanged();
            }
        }
    }

    public ObservableCollection<ProtectedAppViewModel> Apps { get; } = new();

    public bool HasAppPin => secrets.AppPin.IsSet;

    public bool EnableLaunchGate => policy.EnableLaunchGate;

    public string UpdateChannel
    {
        get
        {
            if (string.Equals(ui.UpdateChannel, GitHubUpdateService.BetaChannel, StringComparison.OrdinalIgnoreCase))
                return GitHubUpdateService.BetaChannel;
            if (string.Equals(ui.UpdateChannel, GitHubUpdateService.StableChannel, StringComparison.OrdinalIgnoreCase))
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
        if (app is null || app.IsPackaged || PolicyRules.IsWindowMode(app))
            return null;
        var customPin = app.Launch.HasOwnPin && secrets.FindAppPin(app.Id)?.IsSet == true;
        return (customPin, app.Launch.AllowedMinutes,
            app.Launch.LockStartMinute, app.Launch.LockEndMinute, app.Launch.RelockOnExit);
    }

    internal async Task<bool> SaveLaunchPolicyAsync(ProtectedAppViewModel item, bool useDefaultPin,
        string newPin, int minutes, int? start, int? end, bool relockOnExit)
    {
        var app = FindModel(item);
        if (app is null || GetLaunchPolicy(item) is null)
            return false;

        if (useDefaultPin)
        {
            secrets.RemoveAppPin(app.Id);
            app.Launch.HasOwnPin = false;
        }
        else if (newPin.Length > 0)
        {
            secrets.SetAppPin(app.Id, PinHash.Create(newPin));
            app.Launch.HasOwnPin = true;
        }
        app.Launch.AllowedMinutes = minutes;
        app.Launch.LockStartMinute = start;
        app.Launch.LockEndMinute = end;
        app.Launch.RelockOnExit = relockOnExit;
        if (await CommitAsync())
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

    public async Task InitializeAsync()
    {
        var loaded = await Task.Run(() =>
        {
            // Older installs keep config.json: convert it before reading. The service does the same.
            LegacyMigration.Run();
            var loadedPolicy = PolicyStore.LoadPolicy() ?? new PolicyDocument();
            var loadedSecrets = PolicyStore.LoadSecrets();
            var loadedUi = PolicyStore.LoadUi();
            // The profile copies of the PIN data are readable without admin rights: remove them once the shared
            // files hold everything.
            if (File.Exists(WapPaths.PolicyFile))
            {
                LegacyMigration.CleanUserProfile();
            }

            return (loadedPolicy, loadedSecrets, loadedUi);
        });

        policy = loaded.loadedPolicy;
        secrets = loaded.loadedSecrets;
        ui = loaded.loadedUi;
        OnPropertyChanged(nameof(CloseToBackground));
        OnPropertyChanged(nameof(CloseAppsOnLock));
        OnPropertyChanged(nameof(StartWithWindows));
        OnPropertyChanged(nameof(IdleLockMinutes));
        OnPropertyChanged(nameof(HasAppPin));
        OnPropertyChanged(nameof(EnableLaunchGate));
        OnPropertyChanged(nameof(UpdateChannel));

        foreach (var hotkey in Hotkeys)
        {
            var saved = ui.GlobalHotkeys.FirstOrDefault(item => item.Action == hotkey.ActionKey);
            if (saved is not null)
            {
                hotkey.HotkeyText = saved.Text;
            }
        }

        ProtectionEnabled = LockRulesActive();
        RefreshApps();
        ValidateHotkeys();
        SyncStartupPreference();

        statusReader.Changed += OnServiceStatusChanged;
        statusReader.Start();
        serviceStatus = ServiceStatusReader.ReadOnce();
        ApplyServiceStatusToApps();
        NotifyProtectionCardChanged();
        UpdateStatus();
        await RefreshServiceStatusAsync();
        _ = BackfillFingerprintsAsync();
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

            // A restarted service re-reads the policy on its own; wait until it reports the saved revision.
            policyNotifier.Signal();
            if (await policyNotifier.WaitForAppliedAsync(policy.Revision, TimeSpan.FromSeconds(8)))
            {
                LastPolicySyncFailed = false;
                LastPolicySyncError = string.Empty;
                ServiceState = ProtectionServiceState.Running;
                ReportStatus("보호 서비스를 다시 시작하고 정책을 적용했습니다.", NotificationSeverity.Success);
            }
            else
            {
                LastPolicySyncFailed = true;
                LastPolicySyncError = ServiceNotAppliedMessage;
                ReportStatus($"보호 서비스는 시작했지만 정책 적용을 확인하지 못했습니다. ({ServiceNotAppliedMessage})", NotificationSeverity.Warning);
            }
        }
        catch (Exception ex)
        {
            await RefreshServiceStatusAsync();
            ReportStatus(ex.Message, NotificationSeverity.Error);
        }
    }

    public async Task AddAppAsync(string path)
    {
        await AddAppsAsync(new[] { path });
    }

    public async Task AddAppsAsync(IEnumerable<string> paths)
    {
        var added = new List<AppPolicy>();
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
            if (policy.Apps.Any(app =>
                !app.IsPackaged &&
                !string.IsNullOrWhiteSpace(app.Path) &&
                string.Equals(Path.GetFullPath(app.Path), fullPath, StringComparison.OrdinalIgnoreCase)))
            {
                skippedDuplicates++;
                continue;
            }

            var (size, hash) = await FileFingerprint.ComputeAsync(fullPath);
            var app = new AppPolicy
            {
                Id = Guid.NewGuid().ToString("N"),
                Name = Path.GetFileNameWithoutExtension(fullPath) is { Length: > 0 } baseName
                    ? baseName
                    : Path.GetFileName(fullPath),
                Path = fullPath,
                ExecutableName = Path.GetFileName(fullPath),
                Locked = true,
                LockedAtUtc = NowUtcText(),
                FileSize = size,
                Sha256 = hash,
            };
            policy.Apps.Add(app);
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

        RefreshApps();
        if (!await SyncProtectionRulesAsync()) return;
        ReportStatus(
            added.Count == 1
                ? $"{added[0].Name} 앱을 추가하고 잠갔습니다."
                : $"앱 {added.Count}개를 추가하고 잠갔습니다.",
            NotificationSeverity.Success);
    }

    public async Task AddPackagedAppAsync(PackagedAppInfo app)
    {
        await AddPackagedAppsAsync(new[] { app });
    }

    public async Task AddPackagedAppsAsync(IEnumerable<PackagedAppInfo> apps)
    {
        var added = new List<AppPolicy>();
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
                if (policy.Apps.Any(item =>
                    !item.IsPackaged &&
                    !string.IsNullOrWhiteSpace(item.Path) &&
                    string.Equals(Path.GetFullPath(item.Path), fullPath, StringComparison.OrdinalIgnoreCase)))
                {
                    skippedDuplicates++;
                    continue;
                }

                var (size, hash) = await FileFingerprint.ComputeAsync(fullPath);
                var model = new AppPolicy
                {
                    Id = Guid.NewGuid().ToString("N"),
                    Name = string.IsNullOrWhiteSpace(app.Name) ? Path.GetFileName(fullPath) : app.Name,
                    Path = fullPath,
                    IsPackaged = false,
                    ExecutableName = string.IsNullOrWhiteSpace(app.ExecutableName) ? Path.GetFileName(fullPath) : app.ExecutableName,
                    Locked = true,
                    LockedAtUtc = NowUtcText(),
                    FileSize = size,
                    Sha256 = hash,
                };
                policy.Apps.Add(model);
                added.Add(model);
                continue;
            }

            if (string.IsNullOrWhiteSpace(app.AppUserModelId) || string.IsNullOrWhiteSpace(app.ExecutableName))
            {
                invalidCount++;
                continue;
            }

            if (policy.Apps.Any(item =>
                string.Equals(item.AppUserModelId, app.AppUserModelId, StringComparison.OrdinalIgnoreCase) ||
                (!string.IsNullOrWhiteSpace(item.ExecutableName) &&
                    string.Equals(item.ExecutableName, app.ExecutableName, StringComparison.OrdinalIgnoreCase))))
            {
                skippedDuplicates++;
                continue;
            }

            var packagedModel = new AppPolicy
            {
                Id = Guid.NewGuid().ToString("N"),
                Name = app.Name,
                Path = app.AppUserModelId,
                IsPackaged = true,
                PackageFamilyName = app.PackageFamilyName,
                AppUserModelId = app.AppUserModelId,
                ExecutableName = app.ExecutableName,
                Locked = true,
                LockedAtUtc = NowUtcText(),
            };
            policy.Apps.Add(packagedModel);
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

        RefreshApps();
        if (!await SyncProtectionRulesAsync()) return;
        ReportStatus(
            added.Count == 1
                ? $"{added[0].Name} 앱을 추가하고 잠갔습니다."
                : $"앱 {added.Count}개를 추가하고 잠갔습니다.",
            NotificationSeverity.Success);
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
            .Cast<AppPolicy>()
            .ToList();

        if (targets.Count == 0)
        {
            return;
        }

        foreach (var model in targets)
        {
            policy.Apps.Remove(model);
            secrets.RemoveAppPin(model.Id);
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

        await SetAppsLockedCoreAsync(new[] { model }, !model.Locked);
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
            .Cast<AppPolicy>()
            .ToList();

        if (targets.Count == 0)
        {
            return;
        }

        await SetAppsLockedCoreAsync(targets, enabled);
    }

    private async Task SetAppsLockedCoreAsync(IReadOnlyList<AppPolicy> targets, bool locking)
    {
        if (targets.Count == 0)
        {
            return;
        }

        if (!locking)
        {
            autoLockSuppressedUntilActive = true;
        }

        foreach (var model in targets)
        {
            SetLocked(model, locking);
        }

        RefreshApps();
        if (!await SyncProtectionRulesAsync()) return;

        var message = targets.Count == 1
            ? (locking ? $"{targets[0].Name} 앱을 잠갔습니다." : $"{targets[0].Name} 앱을 열었습니다.")
            : (locking ? $"선택한 앱 {targets.Count}개를 잠갔습니다." : $"선택한 앱 {targets.Count}개를 열었습니다.");
        ReportStatus(message, NotificationSeverity.Success);
    }

    /// <param name="closeRunningApps">Kept for callers; closing running apps on lock is the service's job (CloseAppsOnLock).</param>
    public async Task SetListedAppsEnabledAsync(bool enabled, bool closeRunningApps = true)
    {
        _ = closeRunningApps;
        if (policy.Apps.Count == 0)
        {
            ReportStatus(enabled ? "잠글 앱이 없습니다." : "열 앱이 없습니다.", NotificationSeverity.Info);
            return;
        }

        if (!enabled)
        {
            autoLockSuppressedUntilActive = true;
        }

        foreach (var app in policy.Apps)
        {
            SetLocked(app, enabled);
        }

        RefreshApps();
        if (!await SyncProtectionRulesAsync()) return;
        ReportStatus(
            enabled
                ? $"앱 {policy.Apps.Count}개를 모두 잠갔습니다."
                : $"앱 {policy.Apps.Count}개를 모두 열었습니다.",
            NotificationSeverity.Success);
        if (!enabled) _ = FocusRestoredWindowAsync(policy.Apps.ToList());
    }

    // The agent restores the windows without activating one; activating the front-most one here brings the pointer back.
    private static async Task FocusRestoredWindowAsync(IReadOnlyCollection<AppPolicy> apps)
    {
        try
        {
            var activated = await ForegroundActivator.ActivateFirstWindowOfAsync(apps);
            CursorRecovery.RestoreAfterUnlock(activated ? "unlock-all/focused" : "unlock-all/no-window");
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
        }
    }

    public async Task<bool> SavePreferencesAsync(bool closeToBackground, bool closeAppsOnLock,
        bool startWithWindows, int idleLockMinutes, bool enableLaunchGate, string updateChannel)
    {
        var previousCloseToBackground = ui.CloseToBackground;
        var previousCloseAppsOnLock = policy.CloseAppsOnLock;
        var previousStartWithWindows = ui.StartWithWindows;
        var previousIdleLockMinutes = ui.IdleLockMinutes;
        var previousEnableLaunchGate = policy.EnableLaunchGate;
        var previousUpdateChannel = ui.UpdateChannel;

        try
        {
            await Task.Run(() => StartupService.SetEnabled(startWithWindows));
            ui.UpdateChannel = updateChannel;
            CloseToBackground = closeToBackground;
            CloseAppsOnLock = closeAppsOnLock;
            StartWithWindows = startWithWindows;
            IdleLockMinutes = idleLockMinutes;
            policy.EnableLaunchGate = enableLaunchGate;
            OnPropertyChanged(nameof(EnableLaunchGate));
            OnPropertyChanged(nameof(UpdateChannel));
            if (!await CommitAsync())
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
        ui.UpdateChannel = updateChannel;
        CloseToBackground = closeToBackground;
        CloseAppsOnLock = closeAppsOnLock;
        StartWithWindows = startWithWindows;
        IdleLockMinutes = idleLockMinutes;
        policy.EnableLaunchGate = enableLaunchGate;
        OnPropertyChanged(nameof(EnableLaunchGate));
        OnPropertyChanged(nameof(UpdateChannel));
    }

    public async Task<bool> AutoLockIfIdleAsync(TimeSpan idleTime)
    {
        if (ui.IdleLockMinutes <= 0)
        {
            return false;
        }

        // When the user becomes active (idle time under 30 seconds), re-arm idle locking
        if (idleTime < TimeSpan.FromSeconds(30))
        {
            autoLockSuppressedUntilActive = false;
        }

        if (autoLockSuppressedUntilActive ||
            idleTime < TimeSpan.FromMinutes(ui.IdleLockMinutes) ||
            policy.Apps.Count == 0 ||
            policy.Apps.All(app => app.Locked))
        {
            return false;
        }

        foreach (var app in policy.Apps)
        {
            SetLocked(app, true);
        }

        RefreshApps();
        if (!await SyncProtectionRulesAsync()) return false;
        ReportStatus($"유휴 상태 {ui.IdleLockMinutes}분 경과로 보호 앱을 자동 잠금했습니다.", NotificationSeverity.Info);
        return true;
    }

    public async Task SetAppPinAsync(string pin)
    {
        var previous = secrets.AppPin;
        secrets.AppPin = PinHash.Create(pin);
        try
        {
            if (!await CommitAsync(throwOnSaveFailure: true))
            {
                secrets.AppPin = previous;
                return;
            }

            OnPropertyChanged(nameof(HasAppPin));
        }
        catch
        {
            secrets.AppPin = previous;
            throw;
        }
    }

    public bool VerifyAppPin(string pin)
    {
        return PinHash.Verify(pin, secrets.AppPin);
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

        try
        {
            CaptureHotkeys();
            await uiStore.SaveAsync(ui);
            return true;
        }
        catch (Exception ex)
        {
            hotkey.HotkeyText = previousText;
            CaptureHotkeys();
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

    // ---- saving ----------------------------------------------------------------------------------------

    private async Task<bool> SyncProtectionRulesAsync()
    {
        ProtectionEnabled = LockRulesActive();
        return await CommitAsync();
    }

    /// <summary>
    /// Writes policy.json (+ secrets.json, ui.json) and waits for the service to report the revision as applied.
    /// Returns false only when nothing could be saved; a service that is late is reported but the save stands.
    /// </summary>
    private async Task<bool> CommitAsync(bool throwOnSaveFailure = false)
    {
        await commitGate.WaitAsync();
        try
        {
            long revision;
            try
            {
                CaptureHotkeys();
                // Serialize from a snapshot so edits made while the files are being written cannot tear it.
                var policySnapshot = Clone(policy);
                var secretsSnapshot = Clone(secrets);
                var uiSnapshot = Clone(ui);
                revision = await Task.Run(() =>
                {
                    PolicyStore.SaveUi(uiSnapshot);
                    return PolicyStore.Save(policySnapshot, secretsSnapshot);
                });
                policy.Revision = revision;
            }
            catch (Exception ex)
            {
                App.WriteCrashLog(ex);
                ReportStatus($"보호 정책을 저장할 수 없습니다: {ex.Message}", NotificationSeverity.Error);
                if (throwOnSaveFailure)
                {
                    throw;
                }

                return false;
            }

            OnPropertyChanged(nameof(LockedAppCount));
            var applied = await policyNotifier.SignalAndWaitAsync(revision);
            if (applied)
            {
                LastPolicySyncFailed = false;
                LastPolicySyncError = string.Empty;
                ServiceState = ProtectionServiceState.Running;
                serviceStatus = ServiceStatusReader.ReadOnce();
                ApplyServiceStatusToApps();
            }
            else
            {
                LastPolicySyncFailed = true;
                LastPolicySyncError = ServiceNotAppliedMessage;
                _ = RefreshServiceStatusAsync();
                ReportStatus(ServiceNotAppliedMessage, NotificationSeverity.Warning);
            }

            NotifyProtectionCardChanged();
            return true;
        }
        finally
        {
            commitGate.Release();
        }
    }

    private void CaptureHotkeys()
    {
        ui.GlobalHotkeys = Hotkeys
            .Select(item => new HotkeyEntry { Action = item.ActionKey, Text = item.HotkeyText })
            .ToList();
    }

    private static T Clone<T>(T value) where T : class
    {
        var serializer = new DataContractJsonSerializer(typeof(T));
        using var stream = new MemoryStream();
        serializer.WriteObject(stream, value);
        stream.Position = 0;
        return (T)serializer.ReadObject(stream)!;
    }

    private void SyncStartupPreference()
    {
        // Re-registers the logon task on every start (migrates older tasks to the fixed settings)
        // off the UI thread so schtasks.exe never delays the PIN prompt.
        var startWithWindows = ui.StartWithWindows;
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

    // Policies migrated from older builds carry no fingerprint: fill it in so the service can recognise
    // renamed or copied executables.
    private async Task BackfillFingerprintsAsync()
    {
        try
        {
            var missing = policy.Apps
                .Where(app => !app.IsPackaged && app.FileSize == 0 && !string.IsNullOrWhiteSpace(app.Path) && File.Exists(app.Path))
                .ToList();
            if (missing.Count == 0)
            {
                return;
            }

            var changed = false;
            foreach (var app in missing)
            {
                var (size, hash) = await FileFingerprint.ComputeAsync(app.Path);
                if (size > 0)
                {
                    app.FileSize = size;
                    app.Sha256 = hash;
                    changed = true;
                }
            }

            if (changed)
            {
                await CommitAsync();
            }
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
        }
    }

    // ---- service status ------------------------------------------------------------------------------------

    private void OnServiceStatusChanged(StatusDocument? status)
    {
        Dispatcher.UIThread.Post(() =>
        {
            serviceStatus = status;
            ApplyServiceStatusToApps();
            NotifyProtectionCardChanged();
            _ = RefreshServiceStatusAsync();
        });
    }

    private void ApplyServiceStatusToApps()
    {
        foreach (var item in Apps)
        {
            var reported = serviceStatus?.Apps.FirstOrDefault(app => app.Id == item.AppId);
            item.Rule = reported?.Rule ?? string.Empty;
            item.UnlockedSessions = reported?.UnlockedSessions ?? 0;
        }
    }

    private void NotifyProtectionCardChanged()
    {
        OnPropertyChanged(nameof(ProtectionServiceText));
        OnPropertyChanged(nameof(ProtectionRevisionText));
        OnPropertyChanged(nameof(ProtectionAgentText));
        OnPropertyChanged(nameof(ProtectionTamperText));
    }

    // ---- list ---------------------------------------------------------------------------------------------------

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
            ? policy.Apps
            : policy.Apps
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
            var reported = serviceStatus?.Apps.FirstOrDefault(r => r.Id == app.Id);
            var item = new ProtectedAppViewModel
            {
                AppId = app.Id,
                Name = app.Name,
                Identity = identity,
                Path = GetDisplayPath(app),
                IsLocked = app.Locked,
                UnlockedSessions = reported?.UnlockedSessions ?? 0,
                PolicySummary = BuildPolicySummary(app),
                IsPackaged = app.IsPackaged,
                PackageFamilyName = app.PackageFamilyName,
                RawPath = app.Path,
                CanConfigureLaunchPolicy = !app.IsPackaged && !PolicyRules.IsWindowMode(app),
                IsSelected = previousSelectedIdentities.Contains(identity),
                Icon = previousIcons.TryGetValue(identity, out var cachedIcon) ? cachedIcon : null,
                Rule = reported?.Rule ?? string.Empty,
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
        OnPropertyChanged(nameof(ProtectionServiceText));
    }

    private static string BuildPolicySummary(AppPolicy app)
    {
        var parts = new List<string>(3);

        if (app.Launch.AllowedMinutes > 0)
        {
            parts.Add(app.Launch.AllowedMinutes % 60 == 0
                ? $"{app.Launch.AllowedMinutes / 60}시간 유예"
                : $"{app.Launch.AllowedMinutes}분 유예");
        }

        if (app.Launch.LockStartMinute is >= 0 and < 1440 &&
            app.Launch.LockEndMinute is >= 0 and < 1440)
        {
            parts.Add($"{FormatMinute(app.Launch.LockStartMinute.Value)}–{FormatMinute(app.Launch.LockEndMinute.Value)}");
        }

        if (app.Launch.HasOwnPin)
        {
            parts.Add("전용 PIN");
        }

        return string.Join(" · ", parts);
    }

    private static string FormatMinute(int minute)
    {
        return new TimeOnly(minute / 60, minute % 60).ToString("HH:mm", CultureInfo.InvariantCulture);
    }

    private static string FormatLocal(string utcText)
    {
        return DateTime.TryParse(utcText, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var utc)
            ? utc.ToLocalTime().ToString("MM-dd HH:mm", CultureInfo.InvariantCulture)
            : utcText;
    }

    private static string NowUtcText() => DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);

    // Records when an app becomes locked, so the service knows which already-running processes to hide.
    private static void SetLocked(AppPolicy app, bool locked)
    {
        if (locked && !app.Locked)
        {
            app.LockedAtUtc = NowUtcText();
        }

        app.Locked = locked;
    }

    private AppPolicy? FindModel(ProtectedAppViewModel viewModel)
    {
        return policy.Apps.FirstOrDefault(app =>
            string.Equals(GetAppIdentity(app), viewModel.Identity, StringComparison.OrdinalIgnoreCase));
    }

    private static string GetAppIdentity(AppPolicy app)
    {
        return app.IsPackaged && !string.IsNullOrWhiteSpace(app.AppUserModelId)
            ? app.AppUserModelId
            : app.Path;
    }

    private static string GetDisplayPath(AppPolicy app)
    {
        if (app.IsPackaged)
        {
            var exeName = string.IsNullOrWhiteSpace(app.ExecutableName) ? "실행 파일 미확인" : app.ExecutableName;
            var identity = string.IsNullOrWhiteSpace(app.AppUserModelId) ? app.PackageFamilyName : app.AppUserModelId;
            return $"{identity} ({exeName})";
        }

        return app.Path;
    }

    private bool LockRulesActive()
    {
        return policy.Apps.Any(app => app.Locked);
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
