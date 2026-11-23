using System.Collections.ObjectModel;
using System.ComponentModel;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using Avalonia.VisualTree;
using CommunityToolkit.Mvvm.ComponentModel;
using WindowsAppProtector.Models;
using WindowsAppProtector.Services;

namespace WindowsAppProtector.Views;

public sealed class InstalledAppPickerItem : ObservableObject
{
    private bool _isSelected;
    private Bitmap? _icon;

    public InstalledAppPickerItem(PackagedAppInfo info, bool isRecommended, bool isAlreadyRegistered)
    {
        Info = info;
        IsRecommended = isRecommended;
        IsAlreadyRegistered = isAlreadyRegistered;
        Name = string.IsNullOrWhiteSpace(info.Name) ? info.ExecutableName : info.Name;
        Detail = info.IsPackaged
            ? (string.IsNullOrWhiteSpace(info.Source) ? info.ExecutableName : $"{info.Source} · {info.ExecutableName}")
            : info.Path;
    }

    public PackagedAppInfo Info { get; }
    public string Name { get; }
    public string Detail { get; }
    public bool IsRecommended { get; }
    public bool IsAlreadyRegistered { get; }
    public bool CanSelect => !IsAlreadyRegistered;
    public bool ShowRecommendedBadge => IsRecommended && !IsAlreadyRegistered;

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (!CanSelect && value)
            {
                return;
            }

            SetProperty(ref _isSelected, value);
        }
    }

    public Bitmap? Icon
    {
        get => _icon;
        set
        {
            if (SetProperty(ref _icon, value))
            {
                OnPropertyChanged(nameof(HasIcon));
                OnPropertyChanged(nameof(HasNoIcon));
            }
        }
    }

    public bool HasIcon => _icon is not null;
    public bool HasNoIcon => _icon is null;
}

public partial class InstalledAppsPicker : Window
{
    private static readonly string[] RecommendedKeywords =
    [
        "kakaotalk", "카카오톡", "discord", "telegram", "slack", "teams",
        "line", "whatsapp", "wechat", "signal", "messenger", "nateon", "네이트온",
        "chrome", "msedge", "edge", "firefox", "whale", "웨일", "brave", "opera", "vivaldi", "arc",
        "photos", "사진", "gallery", "honeyview", "꿀뷰", "bandiview", "반디뷰", "alsee", "알씨",
        "outlook", "mail", "메일", "thunderbird", "emclient",
    ];

    private readonly IconService? _iconService;
    private readonly Func<PackagedAppInfo, bool>? _isAlreadyRegistered;
    private readonly List<InstalledAppPickerItem> _allItems = new();
    private readonly ObservableCollection<InstalledAppPickerItem> _filteredItems = new();
    private CancellationTokenSource? _loadCts;
    private bool _loaded;

    public InstalledAppsPicker()
        : this(iconService: null, isAlreadyRegistered: null)
    {
    }

    public InstalledAppsPicker(
        IconService? iconService,
        Func<PackagedAppInfo, bool>? isAlreadyRegistered = null)
    {
        _iconService = iconService;
        _isAlreadyRegistered = isAlreadyRegistered;

        InitializeComponent();
        AppsItemsControl.ItemsSource = _filteredItems;

        Opened += OnWindowOpened;
        Closed += OnWindowClosed;
    }

    private void OnWindowOpened(object? sender, EventArgs e)
    {
        SearchBox.Focus();
        _ = LoadInstalledAppsAsync();
    }

    private void OnWindowClosed(object? sender, EventArgs e)
    {
        CancelLoad();
        foreach (var item in _allItems)
        {
            item.PropertyChanged -= OnItemPropertyChanged;
        }
    }

    private async Task LoadInstalledAppsAsync()
    {
        CancelLoad();
        var cts = new CancellationTokenSource();
        _loadCts = cts;
        _loaded = false;

        LoadingPanel.IsVisible = true;
        EmptyPanel.IsVisible = false;
        AppsScrollViewer.IsVisible = false;
        ClearSearchButton.IsVisible = false;
        RetryButton.IsVisible = false;

        try
        {
            var discovered = await new PackagedAppDiscoveryService().GetInstalledAppsAsync(cts.Token);
            if (cts.IsCancellationRequested)
            {
                return;
            }

            foreach (var oldItem in _allItems)
            {
                oldItem.PropertyChanged -= OnItemPropertyChanged;
            }
            _allItems.Clear();

            var ordered = discovered
                .Select(info => new InstalledAppPickerItem(
                    info,
                    isRecommended: IsRecommendedApp(info),
                    isAlreadyRegistered: _isAlreadyRegistered?.Invoke(info) == true))
                .OrderBy(item => item.IsAlreadyRegistered)
                .ThenByDescending(item => item.IsRecommended)
                .ThenBy(item => item.Name, StringComparer.CurrentCultureIgnoreCase)
                .ToList();

            foreach (var item in ordered)
            {
                item.PropertyChanged += OnItemPropertyChanged;
                _allItems.Add(item);
            }

            _loaded = true;
            ApplyFilter();
            UpdateSelectionSummary();
            _ = LoadIconsInBackgroundAsync(ordered, cts.Token);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            EmptyMessageText.Text = $"설치된 앱 목록을 불러오지 못했습니다. ({ex.Message})";
            RetryButton.IsVisible = true;
            ClearSearchButton.IsVisible = false;
            EmptyPanel.IsVisible = true;
            AppsScrollViewer.IsVisible = false;
        }
        finally
        {
            LoadingPanel.IsVisible = false;
            if (ReferenceEquals(_loadCts, cts))
            {
                _loadCts = null;
            }

            cts.Dispose();
        }
    }

    private async Task LoadIconsInBackgroundAsync(
        IReadOnlyList<InstalledAppPickerItem> items,
        CancellationToken cancellationToken)
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

    private void OnSearchTextChanged(object? sender, TextChangedEventArgs e)
    {
        if (_loaded)
        {
            ApplyFilter();
        }
    }

    private void OnClearSearchClick(object? sender, RoutedEventArgs e)
    {
        SearchBox.Text = string.Empty;
        SearchBox.Focus();
    }

    private void OnRetryClick(object? sender, RoutedEventArgs e)
    {
        _ = LoadInstalledAppsAsync();
    }

    private void OnRowPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            return;
        }

        // CheckBox 자체 클릭이면 중복 토글 방지
        if (e.Source is Avalonia.Visual sourceVisual &&
            sourceVisual.FindAncestorOfType<CheckBox>(includeSelf: true) is not null)
        {
            return;
        }

        if (sender is Border { DataContext: InstalledAppPickerItem item } && item.CanSelect)
        {
            item.IsSelected = !item.IsSelected;
            e.Handled = true;
        }
    }

    private void OnItemPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(InstalledAppPickerItem.IsSelected))
        {
            UpdateSelectionSummary();
        }
    }

    private void ApplyFilter()
    {
        var query = SearchBox.Text?.Trim() ?? string.Empty;
        _filteredItems.Clear();

        IEnumerable<InstalledAppPickerItem> matches = string.IsNullOrEmpty(query)
            ? _allItems
            : _allItems.Where(item =>
                item.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                item.Detail.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                item.Info.ExecutableName.Contains(query, StringComparison.OrdinalIgnoreCase));

        foreach (var item in matches)
        {
            _filteredItems.Add(item);
        }

        var hasItems = _filteredItems.Count > 0;
        AppsScrollViewer.IsVisible = hasItems;
        EmptyPanel.IsVisible = !hasItems;
        if (!hasItems)
        {
            if (string.IsNullOrEmpty(query))
            {
                EmptyMessageText.Text = "추가할 설치 앱을 찾을 수 없습니다.";
                ClearSearchButton.IsVisible = false;
                RetryButton.IsVisible = true;
            }
            else
            {
                EmptyMessageText.Text = $"‘{query}’와 일치하는 앱이 없습니다.";
                ClearSearchButton.IsVisible = true;
                RetryButton.IsVisible = false;
            }
        }
    }

    private void UpdateSelectionSummary()
    {
        var count = _allItems.Count(item => item.IsSelected);
        SelectedCountText.Text = count > 0 ? $"앱 {count}개 선택됨" : "선택한 앱 없음";
        ConfirmButton.IsEnabled = count > 0;
        ConfirmButton.Content = count > 0 ? $"선택한 {count}개 추가" : "추가";
    }

    private void OnCancelClick(object? sender, RoutedEventArgs e)
    {
        Close(null);
    }

    private void OnConfirmClick(object? sender, RoutedEventArgs e)
    {
        IReadOnlyList<PackagedAppInfo> selected = _allItems
            .Where(item => item.IsSelected)
            .Select(item => item.Info)
            .ToArray();

        if (selected.Count == 0)
        {
            return;
        }

        Close(selected);
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

    private void CancelLoad()
    {
        if (_loadCts is null)
        {
            return;
        }

        try
        {
            _loadCts.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }

        _loadCts = null;
    }
}
