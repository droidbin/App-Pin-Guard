using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Avalonia.VisualTree;
using WindowsAppProtector.Models;
using WindowsAppProtector.Platform;
using WindowsAppProtector.Services;
using WindowsAppProtector.ViewModels;

namespace WindowsAppProtector.Views;

public partial class AppsPage : UserControl
{
    private readonly HashSet<ProtectedAppViewModel> _subscribedItems = new();
    private MainViewModel? _viewModel;
    private IconService? _iconService;
    private INotificationService? _notificationService;
    private Func<IntPtr>? _getOwnerHwnd;
    private CancellationTokenSource? _iconLoadCts;
    private bool _syncingSearchText;
    private bool _isRestartingService;

    public AppsPage()
    {
        InitializeComponent();
    }

    public event EventHandler<ProtectedAppViewModel>? AppActivated;

    public void Initialize(
        MainViewModel viewModel,
        IconService iconService,
        INotificationService notificationService,
        Func<IntPtr>? getOwnerHwnd = null)
    {
        DetachViewModel();

        _viewModel = viewModel;
        _iconService = iconService;
        _notificationService = notificationService;
        _getOwnerHwnd = getOwnerHwnd;

        AppsItemsControl.ItemsSource = viewModel.Apps;
        viewModel.PropertyChanged += OnViewModelPropertyChanged;
        viewModel.Apps.CollectionChanged += OnViewModelAppsChanged;

        ResubscribeAppItems();
        RefreshUiState();
        ScheduleIconLoading();
    }

    public Task RefreshServiceStatusAsync()
    {
        return _viewModel is null
            ? Task.CompletedTask
            : _viewModel.RefreshServiceStatusAsync();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        CancelIconLoading();
        base.OnDetachedFromVisualTree(e);
    }

    private void DetachViewModel()
    {
        CancelIconLoading();
        ClearItemSubscriptions();

        if (_viewModel is not null)
        {
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
            _viewModel.Apps.CollectionChanged -= OnViewModelAppsChanged;
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.SearchText))
        {
            Dispatcher.UIThread.Post(() =>
            {
                if (_viewModel is not null && SearchBox.Text != _viewModel.SearchText)
                {
                    _syncingSearchText = true;
                    try
                    {
                        SearchBox.Text = _viewModel.SearchText;
                    }
                    finally
                    {
                        _syncingSearchText = false;
                    }
                }

                UpdateListVisibility();
            });
            return;
        }

        if (e.PropertyName is nameof(MainViewModel.LockedAppCount)
            or nameof(MainViewModel.TotalAppCount)
            or nameof(MainViewModel.HasServiceWarning)
            or nameof(MainViewModel.StatusSentence)
            or nameof(MainViewModel.ServiceWarningSentence)
            or nameof(MainViewModel.ServiceState)
            or nameof(MainViewModel.LastPolicySyncFailed))
        {
            Dispatcher.UIThread.Post(RefreshUiState);
        }
    }

    private void OnViewModelAppsChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        Dispatcher.UIThread.Post(() =>
        {
            ResubscribeAppItems();
            RefreshUiState();
            ScheduleIconLoading();
        });
    }

    private void ResubscribeAppItems()
    {
        ClearItemSubscriptions();
        if (_viewModel is null)
        {
            return;
        }

        foreach (var item in _viewModel.Apps)
        {
            item.PropertyChanged += OnAppItemPropertyChanged;
            _subscribedItems.Add(item);
        }
    }

    private void ClearItemSubscriptions()
    {
        foreach (var item in _subscribedItems)
        {
            item.PropertyChanged -= OnAppItemPropertyChanged;
        }

        _subscribedItems.Clear();
    }

    private void OnAppItemPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ProtectedAppViewModel.IsSelected))
        {
            UpdateBulkActionBar();
        }
    }

    private void RefreshUiState()
    {
        if (_viewModel is null)
        {
            return;
        }

        var showWarning = _viewModel.HasServiceWarning;
        StatusSentenceText.IsVisible = !showWarning;
        StatusSentenceText.Text = _viewModel.StatusSentence;
        ServiceWarningInfoBar.IsVisible = showWarning;
        ServiceWarningText.Text = _viewModel.ServiceWarningSentence;
        RestartServiceButton.IsEnabled = !_isRestartingService;

        LockAllDropDownButton.IsEnabled = _viewModel.TotalAppCount > 0;
        SearchClearInlineButton.IsVisible = !string.IsNullOrEmpty(SearchBox.Text);

        UpdateListVisibility();
        UpdateBulkActionBar();
    }

    private void UpdateListVisibility()
    {
        if (_viewModel is null)
        {
            return;
        }

        var totalCount = _viewModel.TotalAppCount;
        var visibleCount = _viewModel.Apps.Count;
        var query = _viewModel.SearchText.Trim();

        SearchClearInlineButton.IsVisible = !string.IsNullOrEmpty(SearchBox.Text);

        if (totalCount == 0)
        {
            AppsListScrollViewer.IsVisible = false;
            EmptyStatePanel.IsVisible = true;
            NoSearchResultsPanel.IsVisible = false;
            return;
        }

        if (visibleCount == 0)
        {
            AppsListScrollViewer.IsVisible = false;
            EmptyStatePanel.IsVisible = false;
            NoSearchResultsPanel.IsVisible = true;
            NoSearchResultsText.Text = string.IsNullOrEmpty(query)
                ? "표시할 앱이 없습니다."
                : $"‘{query}’와 일치하는 앱이 없습니다.";
            return;
        }

        AppsListScrollViewer.IsVisible = true;
        EmptyStatePanel.IsVisible = false;
        NoSearchResultsPanel.IsVisible = false;
    }

    private void UpdateBulkActionBar()
    {
        if (_viewModel is null)
        {
            BulkActionBar.IsVisible = false;
            return;
        }

        var selectedCount = _viewModel.Apps.Count(item => item.IsSelected);
        BulkActionBar.IsVisible = selectedCount > 0;
        if (selectedCount > 0)
        {
            BulkSelectionText.Text = $"선택한 {selectedCount}개:";
        }
    }

    private void ScheduleIconLoading()
    {
        CancelIconLoading();
        if (_viewModel is null || _iconService is null)
        {
            return;
        }

        var itemsToLoad = _viewModel.Apps.Where(item => item.Icon is null).ToArray();
        if (itemsToLoad.Length == 0)
        {
            return;
        }

        var iconService = _iconService;
        var cts = new CancellationTokenSource();
        _iconLoadCts = cts;

        _ = Task.Run(() =>
        {
            foreach (var item in itemsToLoad)
            {
                if (cts.Token.IsCancellationRequested)
                {
                    return;
                }

                var bitmap = iconService.GetProtectedAppIcon(item.IsPackaged, item.RawPath, item.PackageFamilyName);
                if (bitmap is not null)
                {
                    Dispatcher.UIThread.Post(() => item.Icon = bitmap, DispatcherPriority.Background);
                }
            }
        }, cts.Token);
    }

    private void CancelIconLoading()
    {
        if (_iconLoadCts is null)
        {
            return;
        }

        try
        {
            _iconLoadCts.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }

        _iconLoadCts.Dispose();
        _iconLoadCts = null;
    }

    private void OnSearchTextChanged(object? sender, TextChangedEventArgs e)
    {
        SearchClearInlineButton.IsVisible = !string.IsNullOrEmpty(SearchBox.Text);
        if (_syncingSearchText || _viewModel is null)
        {
            return;
        }

        _viewModel.SearchText = SearchBox.Text ?? string.Empty;
    }

    private void OnClearSearchClick(object? sender, RoutedEventArgs e)
    {
        SearchBox.Text = string.Empty;
        SearchBox.Focus();
    }

    private async void OnRestartServiceClick(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is null || _isRestartingService)
        {
            return;
        }

        _isRestartingService = true;
        RestartServiceButton.IsEnabled = false;
        try
        {
            await _viewModel.RestartServiceAsync();
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            _notificationService?.Error($"보호 서비스를 다시 시작할 수 없습니다. ({ex.Message})");
        }
        finally
        {
            _isRestartingService = false;
            RefreshUiState();
        }
    }

    private async void OnAddInstalledAppsClick(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        var owner = GetOwnerWindow();
        if (owner is null)
        {
            return;
        }

        try
        {
            var picker = new InstalledAppsPicker(_iconService, _viewModel.IsAppRegistered);
            var selected = await picker.ShowDialog<IReadOnlyList<PackagedAppInfo>?>(owner);
            if (selected is { Count: > 0 })
            {
                await _viewModel.AddPackagedAppsAsync(selected);
            }
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            _notificationService?.Error($"설치된 앱을 추가할 수 없습니다. ({ex.Message})");
        }
    }

    private async void OnAddExecutableClick(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        try
        {
            var ownerHwnd = _getOwnerHwnd?.Invoke()
                ?? GetOwnerWindow()?.TryGetPlatformHandle()?.Handle
                ?? IntPtr.Zero;

            var paths = WindowsAppProtector.Platform.FileDialog.ShowExecutableOpenDialog(ownerHwnd);
            if (paths.Count > 0)
            {
                await _viewModel.AddAppsAsync(paths);
            }
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            _notificationService?.Error($"실행 파일을 추가할 수 없습니다. ({ex.Message})");
        }
    }

    private async void OnLockAllClick(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        try
        {
            await _viewModel.SetListedAppsEnabledAsync(true);
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            _notificationService?.Error($"앱을 잠글 수 없습니다. ({ex.Message})");
        }
    }

    private async void OnUnlockAllClick(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        try
        {
            await _viewModel.SetListedAppsEnabledAsync(false);
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            _notificationService?.Error($"앱 잠금을 열 수 없습니다. ({ex.Message})");
        }
    }

    private async void OnBulkLockClick(object? sender, RoutedEventArgs e)
    {
        await ApplyBulkLockAsync(enabled: true);
    }

    private async void OnBulkUnlockClick(object? sender, RoutedEventArgs e)
    {
        await ApplyBulkLockAsync(enabled: false);
    }

    private async Task ApplyBulkLockAsync(bool enabled)
    {
        if (_viewModel is null)
        {
            return;
        }

        var selected = _viewModel.Apps.Where(item => item.IsSelected).ToArray();
        if (selected.Length == 0)
        {
            return;
        }

        try
        {
            await _viewModel.SetAppsEnabledAsync(selected, enabled);
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            _notificationService?.Error(enabled
                ? $"선택한 앱을 잠글 수 없습니다. ({ex.Message})"
                : $"선택한 앱을 열 수 없습니다. ({ex.Message})");
        }
    }

    private async void OnBulkRemoveClick(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        var selected = _viewModel.Apps.Where(item => item.IsSelected).ToArray();
        if (selected.Length == 0)
        {
            return;
        }

        var owner = GetOwnerWindow();
        if (owner is null)
        {
            return;
        }

        var message = selected.Length == 1
            ? $"‘{selected[0].Name}’ 앱을 보호 목록에서 제거할까요? 제거하면 실행할 때 PIN을 묻지 않습니다."
            : $"선택한 앱 {selected.Length}개를 보호 목록에서 제거할까요? 제거하면 실행할 때 PIN을 묻지 않습니다.";

        var confirmed = await ConfirmDialog.ShowAsync(
            owner,
            title: "목록에서 제거",
            message: message,
            confirmLabel: "제거");

        if (!confirmed)
        {
            return;
        }

        try
        {
            await _viewModel.RemoveAppsAsync(selected);
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            _notificationService?.Error($"선택한 앱을 제거할 수 없습니다. ({ex.Message})");
        }
    }

    private void OnClearSelectionClick(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        foreach (var item in _viewModel.Apps)
        {
            item.IsSelected = false;
        }

        UpdateBulkActionBar();
    }

    private async void OnAppToggleClick(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is null || sender is not ToggleSwitch { DataContext: ProtectedAppViewModel item } toggle)
        {
            return;
        }

        var targetLocked = toggle.IsChecked == true;
        toggle.IsEnabled = false;
        try
        {
            await _viewModel.SetAppLockedAsync(item, targetLocked);
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            toggle.IsChecked = item.IsLocked;
            _notificationService?.Error($"잠금 상태를 바꿀 수 없습니다. ({ex.Message})");
        }
        finally
        {
            toggle.IsEnabled = true;
        }
    }

    private void OnRowPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            return;
        }

        if (e.Source is Visual sourceVisual && IsInteractiveRowControl(sourceVisual))
        {
            return;
        }

        if (sender is Border { DataContext: ProtectedAppViewModel item })
        {
            ActivateAppRow(item);
        }
    }

    private void OnRowKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key is not (Key.Enter or Key.Space))
        {
            return;
        }

        if (e.Source is Visual sourceVisual && IsInteractiveRowControl(sourceVisual))
        {
            return;
        }

        if (sender is Border { DataContext: ProtectedAppViewModel item })
        {
            ActivateAppRow(item);
            e.Handled = true;
        }
    }

    private void OnRowPolicyMenuClick(object? sender, RoutedEventArgs e)
    {
        if (sender is MenuItem { DataContext: ProtectedAppViewModel item })
        {
            ActivateAppRow(item);
        }
    }

    private void OnRowOpenFolderMenuClick(object? sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem { DataContext: ProtectedAppViewModel item })
        {
            return;
        }

        if (item.IsPackaged || string.IsNullOrWhiteSpace(item.RawPath))
        {
            _notificationService?.Info("스토어/MSIX 앱은 폴더에서 보기를 지원하지 않습니다.");
            return;
        }

        try
        {
            if (File.Exists(item.RawPath))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{item.RawPath}\"",
                    UseShellExecute = true,
                });
                return;
            }

            var directory = Path.GetDirectoryName(item.RawPath);
            if (!string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"\"{directory}\"",
                    UseShellExecute = true,
                });
                return;
            }

            _notificationService?.Warning("앱 파일 위치를 찾을 수 없습니다. 앱이 이동되었거나 삭제되었을 수 있습니다.");
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            _notificationService?.Error($"폴더를 열 수 없습니다. ({ex.Message})");
        }
    }

    private async void OnRowRemoveMenuClick(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is null || sender is not MenuItem { DataContext: ProtectedAppViewModel item })
        {
            return;
        }

        var owner = GetOwnerWindow();
        if (owner is null)
        {
            return;
        }

        var confirmed = await ConfirmDialog.ShowAsync(
            owner,
            title: "목록에서 제거",
            message: $"‘{item.Name}’ 앱을 보호 목록에서 제거할까요? 제거하면 실행할 때 PIN을 묻지 않습니다.",
            confirmLabel: "제거");

        if (!confirmed)
        {
            return;
        }

        try
        {
            await _viewModel.RemoveAppAsync(item);
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            _notificationService?.Error($"앱을 목록에서 제거할 수 없습니다. ({ex.Message})");
        }
    }

    private void ActivateAppRow(ProtectedAppViewModel item)
    {
        if (_viewModel is null)
        {
            return;
        }

        _viewModel.SelectedApp = item;
        AppActivated?.Invoke(this, item);
    }

    private Window? GetOwnerWindow()
    {
        return TopLevel.GetTopLevel(this) as Window;
    }

    private static bool IsInteractiveRowControl(Visual source)
    {
        return source.FindAncestorOfType<CheckBox>(includeSelf: true) is not null
            || source.FindAncestorOfType<ToggleSwitch>(includeSelf: true) is not null
            || source.FindAncestorOfType<Button>(includeSelf: true) is not null
            || source.FindAncestorOfType<MenuItem>(includeSelf: true) is not null;
    }
}
