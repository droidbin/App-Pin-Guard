using System.Collections.ObjectModel;
using System.ComponentModel;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using WindowsAppProtector.Models;
using WindowsAppProtector.Services;
using WindowsAppProtector.ViewModels;

namespace WindowsAppProtector.Views;

public sealed class OnboardingAppItem : ObservableObject
{
    private bool _isSelected;
    private Bitmap? _icon;

    public OnboardingAppItem(PackagedAppInfo info, bool isRecommended)
    {
        Info = info;
        IsRecommended = isRecommended;
        Name = string.IsNullOrWhiteSpace(info.Name) ? info.ExecutableName : info.Name;
        Detail = info.IsPackaged
            ? (string.IsNullOrWhiteSpace(info.Source) ? info.ExecutableName : $"{info.Source} · {info.ExecutableName}")
            : info.Path;
    }

    public PackagedAppInfo Info { get; }
    public string Name { get; }
    public string Detail { get; }
    public bool IsRecommended { get; }

    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }

    public Bitmap? Icon
    {
        get => _icon;
        set => SetProperty(ref _icon, value);
    }
}

public partial class OnboardingPage : UserControl
{
    private static readonly string[] RecommendedKeywords =
    [
        // 메신저
        "kakaotalk", "카카오톡", "discord", "telegram", "slack", "teams",
        "line", "whatsapp", "wechat", "signal", "messenger", "nateon", "네이트온",
        // 브라우저
        "chrome", "msedge", "edge", "firefox", "whale", "웨일", "brave", "opera", "vivaldi", "arc",
        // 사진
        "photos", "사진", "gallery", "honeyview", "꿀뷰", "bandiview", "반디뷰", "alsee", "알씨",
        // 메일
        "outlook", "mail", "메일", "thunderbird", "emclient",
    ];

    private readonly List<OnboardingAppItem> _allInstalledApps = new();
    private readonly ObservableCollection<OnboardingAppItem> _filteredInstalledApps = new();

    private MainViewModel? _viewModel;
    private IconService? _iconService;
    private INotificationService? _notificationService;
    private CancellationTokenSource? _loadAppsCts;
    private string _pendingPin = string.Empty;
    private bool _pinSaved;
    private bool _isApplying;
    private bool _appsLoaded;
    private int _lockedAppsCount;

    public OnboardingPage()
    {
        InitializeComponent();

        InstalledAppsList.ItemsSource = _filteredInstalledApps;

        NewPinInput.PinChanged += OnStep1PinChanged;
        ConfirmPinInput.PinChanged += OnStep1PinChanged;
        NewPinInput.Submitted += OnNewPinSubmitted;
        ConfirmPinInput.Submitted += OnConfirmPinSubmitted;
    }

    public event Action? OnboardingCompleted;

    public void Initialize(
        MainViewModel viewModel,
        IconService iconService,
        INotificationService notificationService)
    {
        _viewModel = viewModel;
        _iconService = iconService;
        _notificationService = notificationService;
    }

    public void Reset()
    {
        CancelAppsLoad();
        _pendingPin = string.Empty;
        _pinSaved = false;
        _isApplying = false;
        _appsLoaded = false;
        _lockedAppsCount = 0;

        foreach (var item in _allInstalledApps)
        {
            item.PropertyChanged -= OnAppItemPropertyChanged;
        }
        _allInstalledApps.Clear();
        _filteredInstalledApps.Clear();

        NewPinInput.Pin = string.Empty;
        NewPinInput.ErrorText = null;
        ConfirmPinInput.Pin = string.Empty;
        ConfirmPinInput.ErrorText = null;
        AppSearchBox.Text = string.Empty;
        Step2ErrorText.Text = string.Empty;
        Step2ErrorText.IsVisible = false;
        AutoStartToggle.IsChecked = true;

        ShowStep(1);
        UpdateStep1State();
        UpdateSelectedAppsSummary();
        Dispatcher.UIThread.Post(() => NewPinInput.FocusInput(), DispatcherPriority.Input);
    }

    protected override void OnDetachedFromVisualTree(Avalonia.VisualTreeAttachmentEventArgs e)
    {
        CancelAppsLoad();
        base.OnDetachedFromVisualTree(e);
    }

    private void ShowStep(int step)
    {
        Step1Panel.IsVisible = step == 1;
        Step2Panel.IsVisible = step == 2;
        Step3Panel.IsVisible = step == 3;

        StepDot1.Classes.Set("active", step == 1);
        StepDot2.Classes.Set("active", step == 2);
        StepDot3.Classes.Set("active", step == 3);

        StepLabel1.FontWeight = step == 1 ? Avalonia.Media.FontWeight.SemiBold : Avalonia.Media.FontWeight.Normal;
        StepLabel2.FontWeight = step == 2 ? Avalonia.Media.FontWeight.SemiBold : Avalonia.Media.FontWeight.Normal;
        StepLabel3.FontWeight = step == 3 ? Avalonia.Media.FontWeight.SemiBold : Avalonia.Media.FontWeight.Normal;
    }

    private void OnStep1PinChanged(object? sender, string _)
    {
        ValidateStep1Inline();
        UpdateStep1State();
    }

    private void OnNewPinSubmitted(object? sender, string pin)
    {
        if (pin.Length < 4)
        {
            NewPinInput.ErrorText = "PIN은 4자리 이상 숫자입니다.";
            NewPinInput.Shake();
            NewPinInput.FocusInput();
            return;
        }

        NewPinInput.ErrorText = null;
        ConfirmPinInput.FocusInput();
    }

    private void OnConfirmPinSubmitted(object? sender, string _)
    {
        AdvanceFromStep1();
    }

    private void OnStep1NextClick(object? sender, RoutedEventArgs e)
    {
        AdvanceFromStep1();
    }

    private void ValidateStep1Inline()
    {
        var pin = NewPinInput.Pin;
        var confirm = ConfirmPinInput.Pin;

        if (pin.Length >= 4)
        {
            NewPinInput.ErrorText = null;
        }

        if (confirm.Length == 0)
        {
            ConfirmPinInput.ErrorText = null;
        }
        else if (!string.Equals(pin, confirm, StringComparison.Ordinal))
        {
            ConfirmPinInput.ErrorText = "PIN 확인이 일치하지 않습니다.";
        }
        else
        {
            ConfirmPinInput.ErrorText = null;
        }
    }

    private void UpdateStep1State()
    {
        var pin = NewPinInput.Pin;
        var confirm = ConfirmPinInput.Pin;
        Step1NextButton.IsEnabled = pin.Length >= 4 && string.Equals(pin, confirm, StringComparison.Ordinal);
    }

    private void AdvanceFromStep1()
    {
        var pin = NewPinInput.Pin;
        var confirm = ConfirmPinInput.Pin;

        if (pin.Length < 4)
        {
            NewPinInput.ErrorText = "PIN은 4자리 이상 숫자입니다.";
            NewPinInput.Shake();
            NewPinInput.FocusInput();
            return;
        }

        if (!string.Equals(pin, confirm, StringComparison.Ordinal))
        {
            ConfirmPinInput.ErrorText = "PIN 확인이 일치하지 않습니다.";
            ConfirmPinInput.Shake();
            ConfirmPinInput.FocusInput();
            return;
        }

        _pendingPin = pin;
        NewPinInput.ErrorText = null;
        ConfirmPinInput.ErrorText = null;

        ShowStep(2);
        if (!_appsLoaded)
        {
            _ = LoadInstalledAppsAsync();
        }
    }

    private async Task LoadInstalledAppsAsync()
    {
        CancelAppsLoad();
        var cts = new CancellationTokenSource();
        _loadAppsCts = cts;

        AppsLoadingPanel.IsVisible = true;
        AppsEmptyPanel.IsVisible = false;
        AppsListScrollViewer.IsVisible = false;

        try
        {
            var discovered = await new PackagedAppDiscoveryService().GetInstalledAppsAsync(cts.Token);
            if (cts.IsCancellationRequested)
            {
                return;
            }

            foreach (var oldItem in _allInstalledApps)
            {
                oldItem.PropertyChanged -= OnAppItemPropertyChanged;
            }
            _allInstalledApps.Clear();

            var ordered = discovered
                .Select(info => new OnboardingAppItem(info, IsRecommendedApp(info)))
                .OrderByDescending(item => item.IsRecommended)
                .ThenBy(item => item.Name, StringComparer.CurrentCultureIgnoreCase)
                .ToList();

            foreach (var item in ordered)
            {
                item.PropertyChanged += OnAppItemPropertyChanged;
                _allInstalledApps.Add(item);
            }

            _appsLoaded = true;
            ApplyAppFilter();
            _ = LoadIconsInBackgroundAsync(ordered, cts.Token);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            AppsEmptyMessage.Text = $"설치된 앱 목록을 불러오지 못했습니다. ({ex.Message})";
            AppsEmptyPanel.IsVisible = true;
            AppsListScrollViewer.IsVisible = false;
        }
        finally
        {
            AppsLoadingPanel.IsVisible = false;
            if (ReferenceEquals(_loadAppsCts, cts))
            {
                _loadAppsCts = null;
            }

            cts.Dispose();
        }
    }

    private async Task LoadIconsInBackgroundAsync(IReadOnlyList<OnboardingAppItem> items, CancellationToken cancellationToken)
    {
        var iconService = _iconService;
        if (iconService is null)
        {
            return;
        }

        await Task.Run(() =>
        {
            foreach (var item in items)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return;
                }

                var icon = iconService.GetAppIcon(item.Info);
                if (icon is not null)
                {
                    Dispatcher.UIThread.Post(() => item.Icon = icon, DispatcherPriority.Background);
                }
            }
        }, cancellationToken);
    }

    private void OnAppSearchTextChanged(object? sender, TextChangedEventArgs e)
    {
        if (_appsLoaded)
        {
            ApplyAppFilter();
        }
    }

    private void OnRetryLoadAppsClick(object? sender, RoutedEventArgs e)
    {
        _ = LoadInstalledAppsAsync();
    }

    private void ApplyAppFilter()
    {
        var query = AppSearchBox.Text?.Trim() ?? string.Empty;
        _filteredInstalledApps.Clear();

        IEnumerable<OnboardingAppItem> matches = string.IsNullOrEmpty(query)
            ? _allInstalledApps
            : _allInstalledApps.Where(item =>
                item.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                item.Detail.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                item.Info.ExecutableName.Contains(query, StringComparison.OrdinalIgnoreCase));

        foreach (var item in matches)
        {
            _filteredInstalledApps.Add(item);
        }

        var hasItems = _filteredInstalledApps.Count > 0;
        AppsListScrollViewer.IsVisible = hasItems;
        AppsEmptyPanel.IsVisible = !hasItems;
        if (!hasItems)
        {
            AppsEmptyMessage.Text = string.IsNullOrEmpty(query)
                ? "추가할 설치 앱을 찾을 수 없습니다."
                : $"'{query}'와 일치하는 설치 앱이 없습니다.";
        }
    }

    private void OnAppItemPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(OnboardingAppItem.IsSelected))
        {
            UpdateSelectedAppsSummary();
        }
    }

    private void UpdateSelectedAppsSummary()
    {
        var count = _allInstalledApps.Count(item => item.IsSelected);
        SelectedCountText.Text = count > 0 ? $"앱 {count}개 선택됨" : "선택한 앱 없음";
        Step2NextButton.Content = count > 0 ? $"선택한 {count}개 잠그기" : "다음";
    }

    private void OnStep2BackClick(object? sender, RoutedEventArgs e)
    {
        if (_isApplying)
        {
            return;
        }

        Step2ErrorText.IsVisible = false;
        ShowStep(1);
        NewPinInput.FocusInput();
    }

    private async void OnStep2SkipClick(object? sender, RoutedEventArgs e)
    {
        await ApplyPinAndSelectedAppsAsync(includeSelectedApps: false);
    }

    private async void OnStep2NextClick(object? sender, RoutedEventArgs e)
    {
        await ApplyPinAndSelectedAppsAsync(includeSelectedApps: true);
    }

    private async Task ApplyPinAndSelectedAppsAsync(bool includeSelectedApps)
    {
        if (_isApplying || _viewModel is null)
        {
            return;
        }

        _isApplying = true;
        SetStep2Busy(true);
        Step2ErrorText.IsVisible = false;

        try
        {
            if (!_pinSaved)
            {
                await _viewModel.SetAppPinAsync(_pendingPin);
                _pinSaved = true;
            }

            var addedCount = 0;
            if (includeSelectedApps)
            {
                var selected = _allInstalledApps.Where(item => item.IsSelected).ToArray();
                foreach (var item in selected)
                {
                    var beforeCount = _viewModel.TotalAppCount;
                    await _viewModel.AddPackagedAppAsync(item.Info);
                    if (_viewModel.TotalAppCount > beforeCount)
                    {
                        addedCount++;
                    }
                }
            }

            _lockedAppsCount = addedCount;
            CompleteSummaryText.Text = _lockedAppsCount > 0
                ? $"앱 {_lockedAppsCount}개를 잠갔습니다. 다음에 열 때 PIN을 묻습니다."
                : "PIN 설정이 끝났습니다. 보호 앱 화면에서 잠글 앱을 추가하세요.";

            ShowStep(3);
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            var message = $"설정을 저장할 수 없습니다: {ex.Message}";
            Step2ErrorText.Text = message;
            Step2ErrorText.IsVisible = true;
            _notificationService?.Error(message);
        }
        finally
        {
            _isApplying = false;
            SetStep2Busy(false);
        }
    }

    private void SetStep2Busy(bool busy)
    {
        Step2BackButton.IsEnabled = !busy;
        Step2SkipButton.IsEnabled = !busy;
        Step2NextButton.IsEnabled = !busy;
        AppSearchBox.IsEnabled = !busy;
    }

    private async void OnFinishClick(object? sender, RoutedEventArgs e)
    {
        if (_isApplying || _viewModel is null)
        {
            return;
        }

        _isApplying = true;
        FinishButton.IsEnabled = false;
        try
        {
            var startWithWindows = AutoStartToggle.IsChecked == true;
            await _viewModel.SavePreferencesAsync(
                _viewModel.CloseToBackground,
                _viewModel.CloseAppsOnLock,
                startWithWindows,
                _viewModel.IdleLockMinutes,
                _viewModel.EnableLaunchGate,
                _viewModel.UpdateChannel);

            OnboardingCompleted?.Invoke();
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            _notificationService?.Error($"시작 설정을 적용할 수 없습니다: {ex.Message}");
            OnboardingCompleted?.Invoke();
        }
        finally
        {
            _isApplying = false;
            FinishButton.IsEnabled = true;
        }
    }

    private static bool IsRecommendedApp(PackagedAppInfo app)
    {
        var haystack = $"{app.Name} {app.ExecutableName} {app.PackageFamilyName}";
        foreach (var keyword in RecommendedKeywords)
        {
            if (haystack.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private void CancelAppsLoad()
    {
        if (_loadAppsCts is null)
        {
            return;
        }

        try
        {
            _loadAppsCts.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }

        _loadAppsCts = null;
    }
}
