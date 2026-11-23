using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using WindowsAppProtector.Platform;

namespace WindowsAppProtector.Controls;

public partial class PinInput : UserControl
{
    public const int SlotCount = 6;
    private const string FilledGlyph = "•";

    public static readonly StyledProperty<string> PinProperty =
        AvaloniaProperty.Register<PinInput, string>(
            nameof(Pin),
            defaultValue: string.Empty,
            defaultBindingMode: BindingMode.TwoWay);

    public static readonly StyledProperty<string?> ErrorTextProperty =
        AvaloniaProperty.Register<PinInput, string?>(
            nameof(ErrorText),
            defaultValue: null);

    private readonly Border[] _slots;
    private readonly TextBlock[] _glyphs;
    private readonly TranslateTransform _shakeTransform = new();
    private bool _synchronizing;
    private CancellationTokenSource? _shakeCts;

    public PinInput()
    {
        InitializeComponent();

        SlotsHost.RenderTransform = _shakeTransform;
        _slots = [Slot0, Slot1, Slot2, Slot3, Slot4, Slot5];
        _glyphs = [Glyph0, Glyph1, Glyph2, Glyph3, Glyph4, Glyph5];

        PinTextBox.AddHandler(TextInputEvent, OnPinTextInput, RoutingStrategies.Tunnel);
        PinTextBox.AddHandler(KeyDownEvent, OnPinKeyDown, RoutingStrategies.Tunnel);
        PinTextBox.TextChanged += OnPinTextChanged;
        PinTextBox.GotFocus += OnPinFocusChanged;
        PinTextBox.LostFocus += OnPinFocusChanged;

        UpdateVisualSlots();
        UpdateErrorVisual();
    }

    public event EventHandler<string>? Submitted;

    public event EventHandler<string>? PinChanged;

    public string Pin
    {
        get => GetValue(PinProperty);
        set => SetValue(PinProperty, NormalizeDigits(value));
    }

    public string? ErrorText
    {
        get => GetValue(ErrorTextProperty);
        set => SetValue(ErrorTextProperty, value);
    }

    public void Clear()
    {
        Pin = string.Empty;
        ErrorText = null;
        FocusInput();
    }

    public void FocusInput()
    {
        PinTextBox.Focus();
        PinTextBox.CaretIndex = PinTextBox.Text?.Length ?? 0;
    }

    public void Shake()
    {
        if (!AreClientAreaAnimationsEnabled())
        {
            return;
        }

        _ = ShakeAsync();
    }

    public async Task ShakeAsync()
    {
        if (!AreClientAreaAnimationsEnabled())
        {
            return;
        }

        CancelShake();
        var cts = new CancellationTokenSource();
        _shakeCts = cts;

        double[] offsets = [-10, 10, -8, 8, -4, 4, 0];
        try
        {
            foreach (var offset in offsets)
            {
                cts.Token.ThrowIfCancellationRequested();
                _shakeTransform.X = offset;
                await Task.Delay(38, cts.Token);
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            _shakeTransform.X = 0;
            if (ReferenceEquals(_shakeCts, cts))
            {
                _shakeCts = null;
            }

            cts.Dispose();
        }
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);

        if (change.Property == PinProperty)
        {
            var normalized = NormalizeDigits(change.GetNewValue<string>());
            if (!string.Equals(normalized, PinTextBox.Text ?? string.Empty, StringComparison.Ordinal))
            {
                _synchronizing = true;
                try
                {
                    PinTextBox.Text = normalized;
                    PinTextBox.CaretIndex = normalized.Length;
                }
                finally
                {
                    _synchronizing = false;
                }
            }

            UpdateVisualSlots();
            PinChanged?.Invoke(this, normalized);
        }
        else if (change.Property == ErrorTextProperty)
        {
            UpdateErrorVisual();
            UpdateVisualSlots();
        }
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        CancelShake();
        base.OnDetachedFromVisualTree(e);
    }

    private void OnSlotsHostPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        FocusInput();
    }

    private void OnPinTextInput(object? sender, TextInputEventArgs e)
    {
        if (string.IsNullOrEmpty(e.Text))
        {
            return;
        }

        foreach (var ch in e.Text)
        {
            if (ch is < '0' or > '9')
            {
                e.Handled = true;
                return;
            }
        }
    }

    private void OnPinKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key is Key.Enter or Key.Return)
        {
            e.Handled = true;
            Submitted?.Invoke(this, Pin);
            return;
        }

        if (e.Key == Key.Space)
        {
            e.Handled = true;
        }
    }

    private void OnPinTextChanged(object? sender, TextChangedEventArgs e)
    {
        if (_synchronizing)
        {
            return;
        }

        var raw = PinTextBox.Text ?? string.Empty;
        var normalized = NormalizeDigits(raw);
        if (!string.Equals(raw, normalized, StringComparison.Ordinal))
        {
            _synchronizing = true;
            try
            {
                PinTextBox.Text = normalized;
                PinTextBox.CaretIndex = normalized.Length;
            }
            finally
            {
                _synchronizing = false;
            }
        }

        if (!string.Equals(Pin, normalized, StringComparison.Ordinal))
        {
            SetCurrentValue(PinProperty, normalized);
        }
        else
        {
            UpdateVisualSlots();
        }
    }

    private void OnPinFocusChanged(object? sender, RoutedEventArgs e)
    {
        UpdateVisualSlots();
    }

    private void UpdateVisualSlots()
    {
        var value = Pin ?? string.Empty;
        var hasError = !string.IsNullOrWhiteSpace(ErrorText);
        var isFocused = PinTextBox.IsFocused;
        var activeIndex = Math.Min(value.Length, SlotCount - 1);

        for (var i = 0; i < SlotCount; i++)
        {
            var isFilled = i < value.Length;
            _glyphs[i].Text = isFilled ? FilledGlyph : string.Empty;

            _slots[i].Classes.Set("filled", isFilled);
            _slots[i].Classes.Set("active", isFocused && !hasError && i == activeIndex);
            _slots[i].Classes.Set("error", hasError);
        }
    }

    private void UpdateErrorVisual()
    {
        var hasError = !string.IsNullOrWhiteSpace(ErrorText);
        ErrorTextBlock.Text = hasError ? ErrorText : string.Empty;
        ErrorTextBlock.IsVisible = hasError;
    }

    private void CancelShake()
    {
        if (_shakeCts is null)
        {
            return;
        }

        try
        {
            _shakeCts.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }

        _shakeCts = null;
    }

    private static string NormalizeDigits(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        Span<char> buffer = stackalloc char[SlotCount];
        var count = 0;
        foreach (var ch in input)
        {
            if (ch is >= '0' and <= '9')
            {
                buffer[count++] = ch;
                if (count == SlotCount)
                {
                    break;
                }
            }
        }

        return count == 0 ? string.Empty : new string(buffer[..count]);
    }

    private static bool AreClientAreaAnimationsEnabled()
    {
        try
        {
            var enabled = true;
            if (NativeMethods.SystemParametersInfo(NativeMethods.SpiGetClientAreaAnimation, 0, ref enabled, 0))
            {
                return enabled;
            }
        }
        catch
        {
        }

        return true;
    }
}
