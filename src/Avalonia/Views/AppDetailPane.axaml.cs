using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using WindowsAppProtector.Services;
using WindowsAppProtector.ViewModels;

namespace WindowsAppProtector.Views;

public partial class AppDetailPane : UserControl
{
    private AppDetailViewModel? _viewModel;
    private INotificationService? _notificationService;

    public AppDetailPane()
    {
        InitializeComponent();
    }

    public event EventHandler? CloseRequested;

    public ProtectedAppViewModel? CurrentApp => _viewModel?.CurrentApp;

    public void Initialize(MainViewModel mainViewModel, INotificationService notificationService)
    {
        _notificationService = notificationService;
        _viewModel = new AppDetailViewModel(mainViewModel);
        DataContext = _viewModel;
    }

    public void Open(ProtectedAppViewModel app)
    {
        _viewModel?.Load(app);
    }

    public void SyncApp(ProtectedAppViewModel app)
    {
        _viewModel?.SyncAppSnapshot(app);
    }

    public void Clear()
    {
        _viewModel?.Clear();
    }

    public void SetOverlayMode(bool isOverlay)
    {
        PaneRootBorder.BorderThickness = isOverlay
            ? new Thickness(0, 1, 0, 0)
            : new Thickness(1, 1, 0, 0);
        BackButton.IsVisible = isOverlay;
        PaneHeaderTitle.IsVisible = !isOverlay;
    }

    private void OnCloseClick(object? sender, RoutedEventArgs e)
    {
        CloseRequested?.Invoke(this, EventArgs.Empty);
    }

    private void OnPaneKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            CloseRequested?.Invoke(this, EventArgs.Empty);
            e.Handled = true;
        }
    }

    private async void OnLockToggleClick(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is null || sender is not ToggleSwitch toggle)
        {
            return;
        }

        var targetLocked = toggle.IsChecked == true;
        try
        {
            await _viewModel.SetLockedAsync(targetLocked);
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            toggle.IsChecked = _viewModel.IsLocked;
            _notificationService?.Error($"잠금 상태를 바꿀 수 없습니다. ({ex.Message})");
        }
    }

    private async void OnSaveClick(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        try
        {
            var saved = await _viewModel.SaveAsync();
            if (saved)
            {
                CloseRequested?.Invoke(this, EventArgs.Empty);
            }
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            _notificationService?.Error($"실행 정책을 저장할 수 없습니다. ({ex.Message})");
        }
    }

    private async void OnRemoveClick(object? sender, RoutedEventArgs e)
    {
        var app = _viewModel?.CurrentApp;
        if (_viewModel is null || app is null)
        {
            return;
        }

        var owner = TopLevel.GetTopLevel(this) as Window;
        if (owner is null)
        {
            return;
        }

        var confirmed = await ConfirmDialog.ShowAsync(
            owner,
            title: "목록에서 제거",
            message: $"‘{app.Name}’ 앱을 보호 목록에서 제거할까요? 제거하면 실행할 때 PIN을 묻지 않습니다.",
            confirmLabel: "제거");

        if (!confirmed)
        {
            return;
        }

        try
        {
            await _viewModel.RemoveCurrentAppAsync();
            CloseRequested?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            _notificationService?.Error($"앱을 목록에서 제거할 수 없습니다. ({ex.Message})");
        }
    }
}
