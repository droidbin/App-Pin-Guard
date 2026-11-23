using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using WindowsAppProtector.Services;
using WindowsAppProtector.ViewModels;

namespace WindowsAppProtector.Views;

public partial class SettingsPage : UserControl
{
    private SettingsViewModel? _viewModel;

    public SettingsPage()
    {
        InitializeComponent();
        AddHandler(InputElement.KeyDownEvent, OnPreviewKeyDown, RoutingStrategies.Tunnel);
    }

    public void Initialize(
        MainViewModel mainViewModel,
        GitHubUpdateService updateService,
        string currentVersionText,
        Func<Task<bool>> changePinAsync,
        Action reregisterHotkeys,
        Func<GitHubReleaseInfo, Task> installUpdateAsync)
    {
        _viewModel?.Dispose();
        _viewModel = new SettingsViewModel(
            mainViewModel,
            updateService,
            currentVersionText,
            changePinAsync,
            reregisterHotkeys,
            installUpdateAsync);
        DataContext = _viewModel;
    }

    public void RefreshFromViewModel()
    {
        _viewModel?.SyncFromMainViewModel();
    }

    public void DisposeViewModel()
    {
        _viewModel?.Dispose();
        _viewModel = null;
        DataContext = null;
    }

    private async void OnPreviewKeyDown(object? sender, KeyEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        var focused = TopLevel.GetTopLevel(this)?.FocusManager?.GetFocusedElement() as TextBox
            ?? e.Source as TextBox;
        if (focused is null || !focused.Classes.Contains("HotkeyBox") || focused.Tag is not string actionKey)
        {
            return;
        }

        // 키보드 포커스 이동(Tab / Shift+Tab)은 가로채지 않는다.
        if (e.Key == Key.Tab && (e.KeyModifiers == KeyModifiers.None || e.KeyModifiers == KeyModifiers.Shift))
        {
            return;
        }

        if (e.Key == Key.Escape && e.KeyModifiers == KeyModifiers.None)
        {
            e.Handled = true;
            return;
        }

        var hotkeyText = HotkeyFormatter.FromKey(e.Key, e.KeyModifiers);
        e.Handled = true;
        if (hotkeyText is null)
        {
            return;
        }

        await _viewModel.ApplyHotkeyAsync(actionKey, hotkeyText);
    }

    private async void OnChangePinClick(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is not null)
        {
            await _viewModel.ChangePinAsync();
        }
    }

    private async void OnCheckForUpdatesClick(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is not null)
        {
            await _viewModel.CheckForUpdatesAsync();
        }
    }

    private async void OnInstallUpdateClick(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is not null)
        {
            await _viewModel.InstallAvailableUpdateAsync();
        }
    }
}
