using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform;
using Avalonia.Threading;
using WindowsAppProtector.Platform;
using WindowsAppProtector.Services;
using WindowsAppProtector.ViewModels;
using WindowsAppProtector.Views;

namespace WindowsAppProtector;

public partial class MainWindow : Window
{
    private const int TrayCommandLockAll = 1;
    private const int TrayCommandOpenWindow = 2;
    private const int TrayCommandExit = 3;
    private const double CompactRailBreakpoint = 900.0;
    private const int CrossfadeDurationMs = 180;

    private readonly NotificationService _notificationService = new();
    private readonly IconService _iconService = new();
    private readonly GitHubUpdateService _updateService = new();
    private readonly IdleMonitor _idleMonitor = new();
    private readonly Win32MessageWindow _messageWindow;
    private readonly WindowGuardService _windowGuardService;
    private readonly Dictionary<int, string> _registeredHotkeys = new();
    private readonly bool _startInBackground;

    private IntPtr _hwnd;
    private int _nextHotkeyId = 100;
    private bool _initialized;
    private bool _isClosing;
    private bool _isExitRequested;
    private bool _isAuthenticating;
    private bool _isCheckingForUpdates;
    private bool _isSessionUnlocked;
    private bool _hasCheckedUpdatesAfterUnlock;
    private bool _sessionRelockPending;
    private bool _sessionRelockRunning;
    private bool _servicesDisposed;
    private int _authenticationGeneration;
    private Task<bool>? _pendingAuthentication;
    private TaskCompletionSource<bool>? _authenticationTcs;
    private NotificationItem? _displayedNotification;
    private CancellationTokenSource? _crossfadeCts;
    private ChangePinWindow? _activeChangePinWindow;

    public MainViewModel ViewModel { get; }
    public INotificationService Notifications => _notificationService;

    public MainWindow()
        : this(startInBackground: false)
    {
    }

    public MainWindow(bool startInBackground)
    {
        _startInBackground = startInBackground;
        ViewModel = new MainViewModel(_notificationService);

        InitializeComponent();
        ConfigureWindowChromeAndIcon();

        LockPageView.VerifyPin = ViewModel.VerifyAppPin;
        LockPageView.UnlockCompleted += OnLockPageUnlockCompleted;
        LockPageView.SetLoadingState();

        OnboardingPageView.Initialize(ViewModel, _iconService, _notificationService);
        OnboardingPageView.OnboardingCompleted += OnOnboardingCompleted;

        AppsPageView.Initialize(ViewModel, _iconService, _notificationService, GetWindowHandle);
        AppsPageView.AppActivated += OnAppsPageAppActivated;

        AppDetailPaneView.Initialize(ViewModel, _notificationService);
        AppDetailPaneView.CloseRequested += OnAppDetailPaneCloseRequested;

        SettingsPageView.Initialize(
            ViewModel,
            _updateService,
            GetCurrentVersionText(),
            ChangePinAsync,
            RegisterConfiguredHotkeys,
            InstallUpdateAsync);

        _notificationService.PropertyChanged += OnNotificationServicePropertyChanged;
        ViewModel.PropertyChanged += OnViewModelPropertyChanged;
        ViewModel.Apps.CollectionChanged += OnViewModelAppsChanged;

        _messageWindow = new Win32MessageWindow(
            trayTooltip: $"{ProductBrand.Name} v{GetCurrentVersionText()}",
            trayIconPath: Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico"))
        {
            TrayMenuEnabled = false,
        };
        _messageWindow.ShowRequested += OnMessageWindowShowRequested;
        _messageWindow.TrayDoubleClick += OnMessageWindowTrayDoubleClick;
        _messageWindow.TrayMenuOpening += OnMessageWindowTrayMenuOpening;
        _messageWindow.TrayMenuCommand += OnMessageWindowTrayMenuCommand;
        _messageWindow.HotkeyPressed += OnMessageWindowHotkeyPressed;
        _messageWindow.SessionChanged += OnMessageWindowSessionChanged;
        UpdateTrayMenu();
        _messageWindow.AddTrayIcon();

        _windowGuardService = new WindowGuardService(
            getOwnWindowHandle: GetWindowHandle,
            isInitialized: () => _initialized && !_isClosing,
            getLockedExecutables: ViewModel.GetLockedExecutableNames,
            getLockedPackageFamilies: ViewModel.GetLockedPackageFamilyNames);
        _windowGuardService.TickStarting += OnWindowGuardTickStarting;
        _windowGuardService.BeforeWindowScanAsync += OnWindowGuardBeforeScanAsync;
        _windowGuardService.Start();

        SizeChanged += OnWindowSizeChanged;
        Closing += OnWindowClosing;
        Closed += OnWindowClosed;

        UpdateResponsiveLayout(Width);

        _ = InitializeAsync();
    }

    private void ConfigureWindowChromeAndIcon()
    {
        Title = $"{ProductBrand.Name} v{GetCurrentVersionText()}";

        try
        {
            var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico");
            if (File.Exists(iconPath))
            {
                Icon = new WindowIcon(iconPath);
            }
            else
            {
                using var stream = AssetLoader.Open(new Uri("avares://WindowsAppProtector.WinUI/Assets/AppIcon.ico"));
                Icon = new WindowIcon(stream);
            }
        }
        catch
        {
        }
    }

    private async Task InitializeAsync()
    {
        try
        {
            await ViewModel.InitializeAsync();
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            var loadErrorMessage = "보호 설정 파일을 읽을 수 없습니다. 설치 또는 설정을 복구한 뒤 다시 시작하세요.";
            ViewModel.StatusText = $"설정을 불러오지 못했습니다: {ex.Message}";
            _notificationService.Error($"{loadErrorMessage} ({ex.Message})", title: "설정 로드 실패");
            LockPageView.SetLoadFailure(loadErrorMessage);
            if (_startInBackground)
            {
                HideToTray();
            }
            return;
        }

        RegisterConfiguredHotkeys();
        SettingsPageView.RefreshFromViewModel();
        _initialized = true;
        _messageWindow.TrayMenuEnabled = true;
        UpdateTrayMenu();

        if (_sessionRelockPending)
        {
            await RelockForSystemEventAsync();
        }

        if (_startInBackground)
        {
            // 로그온 시 백그라운드 시작: 트레이에서 보호만 유지하고 열 때 PIN 요구
            HideToTray();
            return;
        }

        // PIN 입력 실패/취소 시 창만 트레이로 숨기고 백그라운드 보호는 계속 유지
        if (!await EnsureWindowAccessAsync(isInitialLaunch: true))
        {
            HideToTray();
        }
    }

    private void OnTitleBarPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            BeginMoveDrag(e);
        }
    }

    private void OnTitleBarDoubleTapped(object? sender, TappedEventArgs e)
    {
        WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;
    }

    private async void OnLockNowClick(object? sender, RoutedEventArgs e)
    {
        await RunLoggedAsync(LockNowAsync);
    }

    private async Task LockNowAsync()
    {
        if (!_initialized || _isClosing)
        {
            return;
        }

        _authenticationGeneration++;
        CancelPendingAuthentication();
        SetSessionUnlocked(false, animate: false);

        await ViewModel.SetListedAppsEnabledAsync(true);
        UpdateTrayMenu();

        if (!await EnsureWindowAccessAsync(isInitialLaunch: false))
        {
            HideToTray();
        }
    }

    private void OnNavAppsClick(object? sender, RoutedEventArgs e)
    {
        SelectNavigationTab(isSettings: false);
    }

    private void OnNavSettingsClick(object? sender, RoutedEventArgs e)
    {
        SelectNavigationTab(isSettings: true);
    }

    private void SelectNavigationTab(bool isSettings)
    {
        NavAppsButton.Classes.Set("selected", !isSettings);
        NavSettingsButton.Classes.Set("selected", isSettings);
        AppsPageView.IsVisible = !isSettings;
        SettingsPageView.IsVisible = isSettings;

        if (isSettings)
        {
            CloseAppDetailPane();
            SettingsPageView.RefreshFromViewModel();
        }
    }

    private void OnAppsPageAppActivated(object? sender, ProtectedAppViewModel app)
    {
        ViewModel.SelectedApp = app;
        OpenAppDetailPane(app);
    }

    private void OnAppDetailPaneCloseRequested(object? sender, EventArgs e)
    {
        CloseAppDetailPane();
    }

    private void OpenAppDetailPane(ProtectedAppViewModel app)
    {
        AppDetailPaneView.Open(app);
        AppDetailPaneView.IsVisible = true;
        UpdateDetailPaneLayout(Bounds.Width > 0 ? Bounds.Width : Width);
    }

    private void CloseAppDetailPane()
    {
        AppDetailPaneView.IsVisible = false;
        AppDetailPaneView.Clear();
    }

    private void OnWindowSizeChanged(object? sender, SizeChangedEventArgs e)
    {
        UpdateResponsiveLayout(e.NewSize.Width);
    }

    private void UpdateResponsiveLayout(double windowWidth)
    {
        var compact = windowWidth < CompactRailBreakpoint;

        NavRailBorder.Width = compact ? 60 : 200;
        NavAppsLabel.IsVisible = !compact;
        NavSettingsLabel.IsVisible = !compact;
        NavAppsButton.Classes.Set("compact", compact);
        NavSettingsButton.Classes.Set("compact", compact);

        var horizontalPadding = compact ? 16 : 32;
        var verticalPadding = compact ? 16 : 24;
        ContentHostGrid.Margin = new Thickness(horizontalPadding, verticalPadding);
        NotificationInfoBar.Margin = new Thickness(horizontalPadding, 16, horizontalPadding, 0);

        UpdateDetailPaneLayout(windowWidth);
    }

    private void UpdateDetailPaneLayout(double windowWidth)
    {
        var overlay = windowWidth < CompactRailBreakpoint;
        if (overlay)
        {
            Grid.SetColumn(AppDetailPaneView, 0);
            Grid.SetColumnSpan(AppDetailPaneView, 3);
            AppDetailPaneView.Width = double.NaN;
        }
        else
        {
            Grid.SetColumn(AppDetailPaneView, 2);
            Grid.SetColumnSpan(AppDetailPaneView, 1);
            AppDetailPaneView.Width = 360;
        }

        AppDetailPaneView.SetOverlayMode(overlay);
    }

    private void OnNotificationServicePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(INotificationService.CurrentNotification))
        {
            Dispatcher.UIThread.Post(UpdateInfoBar);
        }
    }

    private void UpdateInfoBar()
    {
        var item = _notificationService.CurrentNotification;
        _displayedNotification = item;

        if (item is null)
        {
            NotificationInfoBar.IsVisible = false;
            return;
        }

        NotificationInfoBar.Classes.Set("warning", item.Severity == NotificationSeverity.Warning);
        NotificationInfoBar.Classes.Set("error", item.Severity == NotificationSeverity.Error);

        InfoBarTitle.Text = item.Title ?? string.Empty;
        InfoBarTitle.IsVisible = !string.IsNullOrWhiteSpace(item.Title);
        InfoBarMessage.Text = item.Message;

        InfoBarActionButton.Content = item.ActionLabel ?? string.Empty;
        InfoBarActionButton.IsVisible = item.HasAction;

        UpdateInfoBarSeverityVisuals(item.Severity);
        NotificationInfoBar.IsVisible = true;
    }

    private void UpdateInfoBarSeverityVisuals(NotificationSeverity severity)
    {
        var brushKey = severity switch
        {
            NotificationSeverity.Error => "DangerBrush",
            NotificationSeverity.Warning => "LatchBrush",
            _ => "InkBrush",
        };

        if (this.TryFindResource(brushKey, ActualThemeVariant, out var resource) && resource is IBrush brush)
        {
            InfoBarIcon.Stroke = brush;
            InfoBarTitle.Foreground = brush;
        }

        var iconData = severity switch
        {
            NotificationSeverity.Success => "M 3,8.5 L 6.5,12 L 13,4.5",
            NotificationSeverity.Warning => "M 8,2 L 14.5,13.5 H 1.5 Z M 8,6.5 V 9.8 M 8,11.8 V 12",
            NotificationSeverity.Error => "M 8,2 A 6,6 0 1 0 8,14 A 6,6 0 1 0 8,2 Z M 5.5,5.5 L 10.5,10.5 M 10.5,5.5 L 5.5,10.5",
            _ => "M 8,2 A 6,6 0 1 0 8,14 A 6,6 0 1 0 8,2 Z M 8,7 V 11 M 8,5 V 5.2",
        };

        InfoBarIcon.Data = StreamGeometry.Parse(iconData);
    }

    private void OnInfoBarActionClick(object? sender, RoutedEventArgs e)
    {
        var item = _displayedNotification;
        if (item is null)
        {
            return;
        }

        item.Action?.Invoke();
        _notificationService.Dismiss(item.Id);
    }

    private void OnDismissNotificationClick(object? sender, RoutedEventArgs e)
    {
        if (_displayedNotification is { } item)
        {
            _notificationService.Dismiss(item.Id);
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(MainViewModel.LockedAppCount) or nameof(MainViewModel.TotalAppCount) or nameof(MainViewModel.ProtectionEnabled))
        {
            Dispatcher.UIThread.Post(UpdateTrayMenu);
            return;
        }

        if (e.PropertyName == nameof(MainViewModel.SelectedApp))
        {
            Dispatcher.UIThread.Post(SyncDetailPaneWithSelection);
        }
    }

    private void SyncDetailPaneWithSelection()
    {
        if (!AppDetailPaneView.IsVisible)
        {
            return;
        }

        var selected = ViewModel.SelectedApp;
        if (selected is null)
        {
            CloseAppDetailPane();
            return;
        }

        var current = AppDetailPaneView.CurrentApp;
        if (current is not null &&
            string.Equals(current.Identity, selected.Identity, StringComparison.OrdinalIgnoreCase))
        {
            AppDetailPaneView.SyncApp(selected);
        }
        else
        {
            AppDetailPaneView.Open(selected);
        }
    }

    private void OnViewModelAppsChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        Dispatcher.UIThread.Post(UpdateTrayMenu);
    }

    private void UpdateTrayMenu()
    {
        var lockedCount = ViewModel.LockedAppCount;
        var statusLine = lockedCount > 0
            ? $"{ProductBrand.Name} — 앱 {lockedCount}개 잠김"
            : $"{ProductBrand.Name} — 잠긴 앱 없음";

        _messageWindow.SetTrayMenuItems(
        [
            TrayMenuItem.Header(statusLine),
            TrayMenuItem.Separator(),
            new TrayMenuItem(TrayCommandLockAll, "지금 모두 잠그기"),
            new TrayMenuItem(TrayCommandOpenWindow, "관리 화면 열기"),
            TrayMenuItem.Separator(),
            new TrayMenuItem(TrayCommandExit, "종료"),
        ]);
    }

    private void OnMessageWindowTrayMenuOpening()
    {
        UpdateTrayMenu();
    }

    private void OnMessageWindowShowRequested()
    {
        Dispatcher.UIThread.Post(() => _ = RunLoggedAsync(ShowMainWindowAsync));
    }

    private void OnMessageWindowTrayDoubleClick()
    {
        Dispatcher.UIThread.Post(() => _ = RunLoggedAsync(ShowMainWindowAsync));
    }

    private void OnMessageWindowTrayMenuCommand(int commandId)
    {
        Dispatcher.UIThread.Post(() =>
        {
            switch (commandId)
            {
                case TrayCommandLockAll:
                    _ = RunLoggedAsync(() => ExecuteHotkeyActionAsync("lock-all"));
                    break;
                case TrayCommandOpenWindow:
                    _ = RunLoggedAsync(ShowMainWindowAsync);
                    break;
                case TrayCommandExit:
                    _ = RunLoggedAsync(async () =>
                    {
                        await ShowMainWindowAsync();
                        if (_isSessionUnlocked)
                        {
                            ExitApplication();
                        }
                    });
                    break;
            }
        });
    }

    private void OnMessageWindowHotkeyPressed(int hotkeyId)
    {
        if (_registeredHotkeys.TryGetValue(hotkeyId, out var actionKey))
        {
            Dispatcher.UIThread.Post(() => _ = RunLoggedAsync(() => ExecuteHotkeyActionAsync(actionKey)));
        }
    }

    private void OnMessageWindowSessionChanged(SessionChangeKind kind)
    {
        if (kind == SessionChangeKind.Unlocked)
        {
            Dispatcher.UIThread.Post(() => CursorRecovery.RestoreAfterUnlock("session-unlock"));
            return;
        }

        if (kind == SessionChangeKind.Resume)
        {
            Dispatcher.UIThread.Post(() => CursorRecovery.RestoreAfterUnlock("power-resume"));
        }

        if (kind is SessionChangeKind.Locked
            or SessionChangeKind.ConsoleDisconnect
            or SessionChangeKind.RemoteDisconnect
            or SessionChangeKind.Suspend
            or SessionChangeKind.Resume)
        {
            Dispatcher.UIThread.Post(() =>
            {
                _authenticationGeneration++;
                _sessionRelockPending = true;
                CancelPendingAuthentication();
                _ = RunLoggedAsync(RelockForSystemEventAsync);
            });
        }
    }

    private void OnWindowGuardTickStarting()
    {
        if (!_messageWindow.IsSessionNotificationsRegistered)
        {
            _messageWindow.EnsureSessionNotificationsRegistered();
        }

        if (!_messageWindow.IsTrayIconAdded)
        {
            _messageWindow.EnsureTrayIcon();
        }
    }

    private Task OnWindowGuardBeforeScanAsync()
    {
        return _idleMonitor.CheckIdleAsync(
            ViewModel.AutoLockIfIdleAsync,
            () => ViewModel.IdleLockMinutes,
            () => _isSessionUnlocked,
            HideToTray);
    }

    private void RegisterConfiguredHotkeys()
    {
        UnregisterConfiguredHotkeys();
        ViewModel.ValidateHotkeys();
        _nextHotkeyId = 100;

        if (!ViewModel.CanSaveHotkeys)
        {
            return;
        }

        foreach (var hotkey in ViewModel.Hotkeys)
        {
            if (!Win32MessageWindow.TryParseHotkey(hotkey.HotkeyText, out var modifiers, out var virtualKey))
            {
                continue;
            }

            var id = _nextHotkeyId++;
            if (_messageWindow.RegisterHotkey(id, modifiers, virtualKey))
            {
                _registeredHotkeys[id] = hotkey.ActionKey;
            }
            else
            {
                ViewModel.ReportHotkeyRegistrationFailure(hotkey.ActionKey);
            }
        }
    }

    private void UnregisterConfiguredHotkeys()
    {
        _messageWindow.UnregisterAll();
        _registeredHotkeys.Clear();
    }

    private async Task RelockForSystemEventAsync()
    {
        if (!_initialized || _isClosing || _sessionRelockRunning)
        {
            return;
        }

        _sessionRelockRunning = true;
        try
        {
            do
            {
                _sessionRelockPending = false;
                HideToTray();
                App.WriteProtectionLog("system-relock-requested");
                await ViewModel.SetListedAppsEnabledAsync(true, closeRunningApps: false);
                UpdateTrayMenu();
            } while (_sessionRelockPending && !_isClosing);
        }
        finally
        {
            _sessionRelockRunning = false;
        }
    }

    private async Task ExecuteHotkeyActionAsync(string actionKey)
    {
        switch (actionKey)
        {
            case "show-window":
                await ToggleWindowVisibilityAsync();
                break;
            case "lock-all":
                await ViewModel.SetListedAppsEnabledAsync(true);
                UpdateTrayMenu();
                break;
            case "unlock-all":
                if (!_isSessionUnlocked)
                {
                    await ShowMainWindowAsync();
                    if (!_isSessionUnlocked)
                    {
                        return;
                    }
                }

                await ViewModel.SetListedAppsEnabledAsync(false);
                _windowGuardService.RestoreHiddenProtectedWindows();
                UpdateTrayMenu();
                break;
        }
    }

    private void HideToTray()
    {
        CancelPendingAuthentication();
        SetSessionUnlocked(false, animate: false);

        if (IsVisible)
        {
            Hide();
        }

        var hwnd = GetWindowHandle();
        if (hwnd != IntPtr.Zero && NativeMethods.IsWindowVisible(hwnd))
        {
            NativeMethods.ShowWindow(hwnd, NativeMethods.SwHide);
        }

        ViewModel.StatusText = "백그라운드에서 실행 중입니다. 트레이 아이콘에서 다시 열 수 있습니다.";
    }

    private void ForceForegroundWindow()
    {
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop &&
            desktop.MainWindow is null)
        {
            desktop.MainWindow = this;
        }

        if (!IsVisible)
        {
            Show();
        }

        if (WindowState == WindowState.Minimized)
        {
            WindowState = WindowState.Normal;
        }

        var targetHwnd = GetWindowHandle();
        if (targetHwnd != IntPtr.Zero)
        {
            NativeMethods.ShowWindow(targetHwnd, NativeMethods.SwShow);
            if (NativeMethods.IsIconic(targetHwnd))
            {
                NativeMethods.ShowWindow(targetHwnd, NativeMethods.SwRestore);
            }

            NativeMethods.BringWindowToTop(targetHwnd);
            NativeMethods.SetForegroundWindow(targetHwnd);
        }

        Activate();
    }

    private async Task ShowMainWindowAsync()
    {
        if (_sessionRelockRunning || (_isAuthenticating && _pendingAuthentication is null))
        {
            return;
        }

        ForceForegroundWindow();

        if (!_initialized || _isSessionUnlocked)
        {
            return;
        }

        if (!await EnsureWindowAccessAsync(isInitialLaunch: false))
        {
            HideToTray();
        }
    }

    private async Task ToggleWindowVisibilityAsync()
    {
        var hwnd = GetWindowHandle();
        if (IsVisible &&
            hwnd != IntPtr.Zero &&
            NativeMethods.IsWindowVisible(hwnd) &&
            !NativeMethods.IsIconic(hwnd) &&
            NativeMethods.GetForegroundWindow() == hwnd &&
            !_isAuthenticating)
        {
            HideToTray();
            return;
        }

        await ShowMainWindowAsync();
    }

    private Task<bool> EnsureWindowAccessAsync(bool isInitialLaunch)
    {
        if (!_initialized)
        {
            return Task.FromResult(false);
        }

        var authentication = _pendingAuthentication ??= AuthenticateAsync(isInitialLaunch);
        if (authentication.IsCompleted)
        {
            _pendingAuthentication = null;
        }

        return authentication;
    }

    private async Task<bool> AuthenticateAsync(bool isInitialLaunch)
    {
        var generation = _authenticationGeneration;
        _isAuthenticating = true;
        try
        {
            ForceForegroundWindow();

            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _authenticationTcs = tcs;

            var useOnboarding = !ViewModel.HasAppPin;
            if (useOnboarding)
            {
                ShowOnboardingView();
            }
            else
            {
                ShowLockView(isInitialLaunch
                    ? "PIN을 입력해 관리 화면을 여세요"
                    : "PIN을 입력해 관리 화면을 여세요");
            }

            var authenticated = await tcs.Task;
            authenticated &= generation == _authenticationGeneration && !_isClosing;
            SetSessionUnlocked(authenticated, animate: authenticated && !useOnboarding);

            if (authenticated)
            {
                CursorRecovery.RestoreAfterUnlock("pin-unlock");
            }

            if (authenticated && !_hasCheckedUpdatesAfterUnlock)
            {
                _hasCheckedUpdatesAfterUnlock = true;
                _ = RunLoggedAsync(() => CheckForUpdatesAsync(showNoUpdateMessage: false));
            }

            return authenticated;
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            SetSessionUnlocked(false, animate: false);
            return false;
        }
        finally
        {
            _isAuthenticating = false;
            _pendingAuthentication = null;
            _authenticationTcs = null;
        }
    }

    private void OnLockPageUnlockCompleted()
    {
        _authenticationTcs?.TrySetResult(true);
    }

    private void OnOnboardingCompleted()
    {
        UpdateTrayMenu();
        _authenticationTcs?.TrySetResult(true);
    }

    private void CancelPendingAuthentication()
    {
        _authenticationTcs?.TrySetResult(false);
        if (_activeChangePinWindow is { } pinWindow)
        {
            _activeChangePinWindow = null;
            try
            {
                pinWindow.Close(false);
            }
            catch
            {
            }
        }
    }

    private async Task<bool> ChangePinAsync()
    {
        if (!_isSessionUnlocked || !ViewModel.HasAppPin || _isAuthenticating)
        {
            return false;
        }

        var generation = _authenticationGeneration;
        _isAuthenticating = true;
        var dialog = new ChangePinWindow(ViewModel.VerifyAppPin, ViewModel.SetAppPinAsync);
        _activeChangePinWindow = dialog;
        try
        {
            var result = await dialog.ShowDialog<bool?>(this);
            if (result == true && _isSessionUnlocked && generation == _authenticationGeneration)
            {
                ViewModel.StatusText = "PIN이 변경되었습니다.";
                _notificationService.Success("PIN이 변경되었습니다.");
                return true;
            }

            return false;
        }
        finally
        {
            if (ReferenceEquals(_activeChangePinWindow, dialog))
            {
                _activeChangePinWindow = null;
            }

            _isAuthenticating = false;
        }
    }

    private void ShowLockView(string? subtitle = null)
    {
        CancelCrossfade();
        MainShellGrid.IsVisible = false;
        OnboardingPageView.IsVisible = false;
        LockPageView.Opacity = 1;
        LockPageView.IsVisible = true;
        LockNowButton.IsVisible = false;
        LockPageView.PrepareForPrompt(subtitle);
    }

    private void ShowOnboardingView()
    {
        CancelCrossfade();
        MainShellGrid.IsVisible = false;
        LockPageView.IsVisible = false;
        OnboardingPageView.Opacity = 1;
        OnboardingPageView.IsVisible = true;
        LockNowButton.IsVisible = false;
        OnboardingPageView.Reset();
    }

    private void SetSessionUnlocked(bool unlocked, bool animate)
    {
        _isSessionUnlocked = unlocked;
        LockNowButton.IsVisible = unlocked;

        if (!unlocked)
        {
            CancelCrossfade();
            CloseAppDetailPane();
            MainShellGrid.IsVisible = false;
            MainShellGrid.Opacity = 1;
            OnboardingPageView.IsVisible = false;
            LockPageView.Opacity = 1;
            LockPageView.IsVisible = true;
            return;
        }

        if (animate && LockPageView.IsVisible && LockPage.AreClientAreaAnimationsEnabled())
        {
            _ = CrossfadeToMainShellAsync();
            return;
        }

        CancelCrossfade();
        LockPageView.IsVisible = false;
        OnboardingPageView.IsVisible = false;
        MainShellGrid.Opacity = 1;
        MainShellGrid.IsVisible = true;
    }

    private async Task CrossfadeToMainShellAsync()
    {
        CancelCrossfade();
        var cts = new CancellationTokenSource();
        _crossfadeCts = cts;

        OnboardingPageView.IsVisible = false;
        MainShellGrid.Opacity = 0;
        MainShellGrid.IsVisible = true;
        LockPageView.Opacity = 1;
        LockPageView.IsVisible = true;

        var stopwatch = Stopwatch.StartNew();
        try
        {
            while (true)
            {
                cts.Token.ThrowIfCancellationRequested();
                var progress = Math.Clamp(stopwatch.Elapsed.TotalMilliseconds / CrossfadeDurationMs, 0.0, 1.0);
                MainShellGrid.Opacity = progress;
                LockPageView.Opacity = 1.0 - progress;

                if (progress >= 1.0)
                {
                    break;
                }

                await Task.Delay(16, cts.Token);
            }

            if (_isSessionUnlocked)
            {
                LockPageView.IsVisible = false;
                LockPageView.Opacity = 1;
                MainShellGrid.Opacity = 1;
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            if (ReferenceEquals(_crossfadeCts, cts))
            {
                _crossfadeCts = null;
            }

            cts.Dispose();
        }
    }

    private void CancelCrossfade()
    {
        if (_crossfadeCts is null)
        {
            return;
        }

        try
        {
            _crossfadeCts.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }

        _crossfadeCts = null;
    }

    private async Task CheckForUpdatesAsync(bool showNoUpdateMessage)
    {
        if (_isCheckingForUpdates)
        {
            return;
        }

        _isCheckingForUpdates = true;
        try
        {
            if (showNoUpdateMessage)
            {
                _notificationService.Info("업데이트를 확인하는 중입니다.");
            }

            var result = await _updateService.CheckForUpdateAsync(ViewModel.UpdateChannel);
            if (!string.IsNullOrWhiteSpace(result.ErrorMessage))
            {
                if (showNoUpdateMessage)
                {
                    _notificationService.Error(result.ErrorMessage, title: "업데이트 확인 실패");
                }

                return;
            }

            if (!result.IsUpdateAvailable || result.Release is null)
            {
                if (showNoUpdateMessage)
                {
                    _notificationService.Info($"현재 최신 버전입니다. ({GetCurrentVersionText()})", title: "업데이트");
                }

                return;
            }

            var release = result.Release;
            var releaseName = string.IsNullOrWhiteSpace(release.ReleaseName)
                ? release.TagName
                : release.ReleaseName;

            _notificationService.Warning(
                $"새 버전 {release.LatestVersion} ({releaseName})이 있습니다. 지금 설치할 수 있습니다.",
                title: "새 업데이트",
                actionLabel: "설치",
                action: () => _ = RunLoggedAsync(() => InstallUpdateAsync(release)));
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            if (showNoUpdateMessage)
            {
                _notificationService.Error(ex.Message, title: "업데이트 확인 실패");
            }
        }
        finally
        {
            _isCheckingForUpdates = false;
        }
    }

    private async Task InstallUpdateAsync(GitHubReleaseInfo release)
    {
        _notificationService.Info("업데이트를 다운로드하는 중입니다.");
        var installerPath = await _updateService.DownloadInstallerAsync(release);

        Process.Start(new ProcessStartInfo
        {
            FileName = installerPath,
            Arguments = "--update-pid " + Environment.ProcessId + " --install-dir " + QuoteArgument(AppContext.BaseDirectory),
            UseShellExecute = true,
            Verb = "runas",
        });

        ExitApplication();
    }

    private void ExitApplication()
    {
        _isExitRequested = true;
        Close();
    }

    private void OnWindowClosing(object? sender, WindowClosingEventArgs e)
    {
        if (_isExitRequested || (!ViewModel.CloseToBackground && _isSessionUnlocked))
        {
            return;
        }

        e.Cancel = true;
        HideToTray();
    }

    private void OnWindowClosed(object? sender, EventArgs e)
    {
        if (_isClosing)
        {
            return;
        }

        _isClosing = true;
        CancelPendingAuthentication();
        CancelCrossfade();
        DisposeServices();

        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.Shutdown();
        }
    }

    private void DisposeServices()
    {
        if (_servicesDisposed)
        {
            return;
        }

        _servicesDisposed = true;
        _messageWindow.TrayMenuEnabled = false;
        _windowGuardService.TickStarting -= OnWindowGuardTickStarting;
        _windowGuardService.BeforeWindowScanAsync -= OnWindowGuardBeforeScanAsync;
        _windowGuardService.Dispose();

        _messageWindow.ShowRequested -= OnMessageWindowShowRequested;
        _messageWindow.TrayDoubleClick -= OnMessageWindowTrayDoubleClick;
        _messageWindow.TrayMenuOpening -= OnMessageWindowTrayMenuOpening;
        _messageWindow.TrayMenuCommand -= OnMessageWindowTrayMenuCommand;
        _messageWindow.HotkeyPressed -= OnMessageWindowHotkeyPressed;
        _messageWindow.SessionChanged -= OnMessageWindowSessionChanged;
        _messageWindow.Dispose();

        _notificationService.PropertyChanged -= OnNotificationServicePropertyChanged;
        AppsPageView.AppActivated -= OnAppsPageAppActivated;
        AppDetailPaneView.CloseRequested -= OnAppDetailPaneCloseRequested;
        SettingsPageView.DisposeViewModel();
        _notificationService.Dispose();
        _iconService.Dispose();
    }

    private IntPtr GetWindowHandle()
    {
        if (_hwnd == IntPtr.Zero)
        {
            _hwnd = TryGetPlatformHandle()?.Handle ?? IntPtr.Zero;
        }

        return _hwnd;
    }

    private static async Task RunLoggedAsync(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
        }
    }

    private static string GetCurrentVersionText()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? assembly.GetName().Version?.ToString(3)
            ?? "0.0.0";
        var metadataStart = version.IndexOf('+');
        return metadataStart < 0 ? version : version[..metadataStart];
    }

    private static string QuoteArgument(string value)
    {
        return "\"" + value.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Replace("\"", "\\\"") + "\"";
    }
}
