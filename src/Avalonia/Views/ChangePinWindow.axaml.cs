using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;

namespace WindowsAppProtector.Views;

public partial class ChangePinWindow : Window
{
    private const int MaxPinAttemptsBeforeLockout = 5;
    private static readonly TimeSpan BasePinLockout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan MaxPinLockout = TimeSpan.FromMinutes(15);

    private readonly Func<string, bool>? _verifyPin;
    private readonly Func<string, Task>? _setPinAsync;
    private readonly DispatcherTimer _lockoutTimer = new() { Interval = TimeSpan.FromMilliseconds(500) };

    private int _failedAttempts;
    private DateTimeOffset _lockoutUntil = DateTimeOffset.MinValue;
    private bool _isSaving;

    public ChangePinWindow()
    {
        InitializeComponent();
        WireEvents();
    }

    public ChangePinWindow(Func<string, bool> verifyPin, Func<string, Task> setPinAsync)
    {
        _verifyPin = verifyPin;
        _setPinAsync = setPinAsync;
        InitializeComponent();
        WireEvents();
    }

    private bool IsLockedOut => _lockoutUntil > DateTimeOffset.Now;

    private void WireEvents()
    {
        CurrentPinInput.PinChanged += OnCurrentPinChanged;
        CurrentPinInput.Submitted += OnCurrentPinSubmitted;

        NewPinInput.PinChanged += OnNewPinChanged;
        NewPinInput.Submitted += OnNewPinSubmitted;

        ConfirmPinInput.PinChanged += OnNewPinChanged;
        ConfirmPinInput.Submitted += OnConfirmPinSubmitted;

        _lockoutTimer.Tick += OnLockoutTimerTick;
        Opened += OnWindowOpened;
        Closed += OnWindowClosed;
    }

    private void OnWindowOpened(object? sender, EventArgs e)
    {
        Dispatcher.UIThread.Post(() => CurrentPinInput.FocusInput(), DispatcherPriority.Input);
    }

    private void OnWindowClosed(object? sender, EventArgs e)
    {
        _lockoutTimer.Stop();
    }

    private void OnWindowKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape && !_isSaving)
        {
            e.Handled = true;
            Close(false);
        }
    }

    private void OnCurrentPinChanged(object? sender, string pin)
    {
        if (!IsLockedOut && pin.Length > 0 && !string.IsNullOrEmpty(CurrentPinInput.ErrorText))
        {
            CurrentPinInput.ErrorText = null;
        }

        UpdateVerifyButtonState();
    }

    private void OnCurrentPinSubmitted(object? sender, string _)
    {
        VerifyCurrentPin();
    }

    private void OnVerifyNextClick(object? sender, RoutedEventArgs e)
    {
        VerifyCurrentPin();
    }

    private void VerifyCurrentPin()
    {
        var lockoutRemaining = _lockoutUntil - DateTimeOffset.Now;
        if (lockoutRemaining > TimeSpan.Zero)
        {
            UpdateLockoutMessage();
            _lockoutTimer.Start();
            CurrentPinInput.Shake();
            return;
        }

        var pin = CurrentPinInput.Pin;
        if (pin.Length < 4)
        {
            CurrentPinInput.ErrorText = "PIN은 4자리 이상 입력하세요.";
            CurrentPinInput.Shake();
            CurrentPinInput.FocusInput();
            return;
        }

        if (_verifyPin is null)
        {
            return;
        }

        if (_verifyPin(pin))
        {
            _failedAttempts = 0;
            _lockoutUntil = DateTimeOffset.MinValue;
            _lockoutTimer.Stop();
            CurrentPinInput.ErrorText = null;

            VerifyStepPanel.IsVisible = false;
            NewPinStepPanel.IsVisible = true;
            NewPinInput.Pin = string.Empty;
            NewPinInput.ErrorText = null;
            ConfirmPinInput.Pin = string.Empty;
            ConfirmPinInput.ErrorText = null;
            UpdateSaveButtonState();
            Dispatcher.UIThread.Post(() => NewPinInput.FocusInput(), DispatcherPriority.Input);
            return;
        }

        _failedAttempts++;
        App.WriteProtectionLog("pin-verification-failed");

        if (_failedAttempts >= MaxPinAttemptsBeforeLockout)
        {
            var exponent = Math.Min(_failedAttempts - MaxPinAttemptsBeforeLockout, 10);
            var lockout = TimeSpan.FromTicks(Math.Min(BasePinLockout.Ticks << exponent, MaxPinLockout.Ticks));
            _lockoutUntil = DateTimeOffset.Now + lockout;
            CurrentPinInput.ErrorText = $"PIN이 {_failedAttempts}회 틀렸습니다. {Math.Ceiling(lockout.TotalSeconds):0}초 동안 입력할 수 없습니다.";
            _lockoutTimer.Start();
        }
        else
        {
            var remaining = MaxPinAttemptsBeforeLockout - _failedAttempts;
            CurrentPinInput.ErrorText = $"PIN이 틀렸습니다. {remaining}번 더 틀리면 {(int)BasePinLockout.TotalSeconds}초 동안 입력할 수 없습니다.";
        }

        CurrentPinInput.Pin = string.Empty;
        UpdateVerifyButtonState();
        CurrentPinInput.Shake();
        CurrentPinInput.FocusInput();
    }

    private void OnLockoutTimerTick(object? sender, EventArgs e)
    {
        if (!IsLockedOut)
        {
            _lockoutTimer.Stop();
            CurrentPinInput.ErrorText = null;
            UpdateVerifyButtonState();
            CurrentPinInput.FocusInput();
            return;
        }

        UpdateLockoutMessage();
        UpdateVerifyButtonState();
    }

    private void UpdateLockoutMessage()
    {
        var remaining = _lockoutUntil - DateTimeOffset.Now;
        if (remaining > TimeSpan.Zero)
        {
            CurrentPinInput.ErrorText = $"PIN 입력 오류가 반복되었습니다. {Math.Ceiling(remaining.TotalSeconds):0}초 후 다시 시도하세요.";
        }
    }

    private void UpdateVerifyButtonState()
    {
        VerifyNextButton.IsEnabled = !IsLockedOut && CurrentPinInput.Pin.Length >= 4;
    }

    private void OnNewPinChanged(object? sender, string _)
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

        UpdateSaveButtonState();
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

    private async void OnConfirmPinSubmitted(object? sender, string _)
    {
        await SaveNewPinAsync();
    }

    private async void OnSavePinClick(object? sender, RoutedEventArgs e)
    {
        await SaveNewPinAsync();
    }

    private async Task SaveNewPinAsync()
    {
        if (_isSaving || _setPinAsync is null)
        {
            return;
        }

        var pin = NewPinInput.Pin;
        var confirm = ConfirmPinInput.Pin;

        if (pin.Length < 4)
        {
            NewPinInput.ErrorText = "PIN은 4자리 이상으로 설정하세요.";
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

        _isSaving = true;
        SetSavingState(true);
        try
        {
            await _setPinAsync(pin);
            Close(true);
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            ConfirmPinInput.ErrorText = $"PIN을 저장할 수 없습니다: {ex.Message}";
            ConfirmPinInput.Shake();
        }
        finally
        {
            _isSaving = false;
            SetSavingState(false);
        }
    }

    private void SetSavingState(bool saving)
    {
        NewPinInput.IsEnabled = !saving;
        ConfirmPinInput.IsEnabled = !saving;
        SaveCancelButton.IsEnabled = !saving;
        UpdateSaveButtonState();
    }

    private void UpdateSaveButtonState()
    {
        var pin = NewPinInput.Pin;
        var confirm = ConfirmPinInput.Pin;
        SavePinButton.IsEnabled = !_isSaving && pin.Length >= 4 && string.Equals(pin, confirm, StringComparison.Ordinal);
    }

    private void OnCancelClick(object? sender, RoutedEventArgs e)
    {
        if (!_isSaving)
        {
            Close(false);
        }
    }
}
