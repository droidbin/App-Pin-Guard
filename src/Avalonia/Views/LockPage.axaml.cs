using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using WindowsAppProtector.Platform;

namespace WindowsAppProtector.Views;

public partial class LockPage : UserControl
{
    private const int MaxPinAttemptsBeforeLockout = 5;
    private const int UnlockMotionDurationMs = 300;
    private static readonly TimeSpan BasePinLockout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan MaxPinLockout = TimeSpan.FromMinutes(15);

    private readonly TranslateTransform _shackleTranslate = new();
    private readonly RotateTransform _shackleRotate = new();
    private readonly DispatcherTimer _lockoutTimer = new() { Interval = TimeSpan.FromMilliseconds(500) };

    private int _failedPinAttempts;
    private DateTimeOffset _pinLockoutUntil = DateTimeOffset.MinValue;
    private bool _isUnlocking;
    private bool _hasLoadFailure;
    private CancellationTokenSource? _motionCts;

    public LockPage()
    {
        InitializeComponent();

        ShacklePath.RenderTransformOrigin = new RelativePoint(0.85, 0.9, RelativeUnit.Relative);
        ShacklePath.RenderTransform = new TransformGroup
        {
            Children = { _shackleTranslate, _shackleRotate },
        };

        PinInputControl.PinChanged += OnPinChanged;
        PinInputControl.Submitted += OnPinSubmitted;
        _lockoutTimer.Tick += OnLockoutTimerTick;
    }

    public Func<string, bool>? VerifyPin { get; set; }

    public event Action? UnlockCompleted;

    public bool IsLockedOut => _pinLockoutUntil > DateTimeOffset.Now;

    public void PrepareForPrompt(string? subtitle = null)
    {
        CancelUnlockMotion();
        _isUnlocking = false;
        _hasLoadFailure = false;
        ResetShackleVisual();
        ForgotPinPopup.IsOpen = false;

        SubtitleText.Text = string.IsNullOrWhiteSpace(subtitle)
            ? "PIN을 입력해 관리 화면을 여세요"
            : subtitle;

        PinInputControl.IsEnabled = true;
        PinInputControl.Pin = string.Empty;

        if (IsLockedOut)
        {
            UpdateLockoutMessage();
            _lockoutTimer.Start();
        }
        else
        {
            _lockoutTimer.Stop();
            PinInputControl.ErrorText = null;
        }

        UpdateSubmitState();
        Dispatcher.UIThread.Post(() => PinInputControl.FocusInput(), DispatcherPriority.Input);
    }

    public void SetLoadingState()
    {
        CancelUnlockMotion();
        _isUnlocking = false;
        _hasLoadFailure = false;
        ResetShackleVisual();
        ForgotPinPopup.IsOpen = false;
        SubtitleText.Text = "보호 설정을 불러오는 중입니다...";
        PinInputControl.Pin = string.Empty;
        PinInputControl.ErrorText = null;
        PinInputControl.IsEnabled = false;
        UnlockButton.IsEnabled = false;
    }

    public void SetLoadFailure(string message)
    {
        CancelUnlockMotion();
        _isUnlocking = false;
        _hasLoadFailure = true;
        _lockoutTimer.Stop();
        ResetShackleVisual();
        ForgotPinPopup.IsOpen = false;
        SubtitleText.Text = message;
        PinInputControl.Pin = string.Empty;
        PinInputControl.ErrorText = null;
        PinInputControl.IsEnabled = false;
        UnlockButton.IsEnabled = false;
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        _lockoutTimer.Stop();
        CancelUnlockMotion();
        base.OnDetachedFromVisualTree(e);
    }

    private void OnPinChanged(object? sender, string pin)
    {
        if (!_isUnlocking && !IsLockedOut && pin.Length > 0 && !string.IsNullOrEmpty(PinInputControl.ErrorText))
        {
            PinInputControl.ErrorText = null;
        }

        UpdateSubmitState();
    }

    private async void OnPinSubmitted(object? sender, string pin)
    {
        await TrySubmitAsync();
    }

    private async void OnUnlockClick(object? sender, RoutedEventArgs e)
    {
        await TrySubmitAsync();
    }

    private void OnForgotPinClick(object? sender, RoutedEventArgs e)
    {
        ForgotPinPopup.IsOpen = !ForgotPinPopup.IsOpen;
    }

    private void OnCloseForgotPinPopupClick(object? sender, RoutedEventArgs e)
    {
        ForgotPinPopup.IsOpen = false;
        PinInputControl.FocusInput();
    }

    private void OnLockoutTimerTick(object? sender, EventArgs e)
    {
        if (!IsLockedOut)
        {
            _lockoutTimer.Stop();
            PinInputControl.ErrorText = null;
            UpdateSubmitState();
            PinInputControl.FocusInput();
            return;
        }

        UpdateLockoutMessage();
        UpdateSubmitState();
    }

    private async Task TrySubmitAsync()
    {
        if (_isUnlocking || _hasLoadFailure)
        {
            return;
        }

        var lockoutRemaining = _pinLockoutUntil - DateTimeOffset.Now;
        if (lockoutRemaining > TimeSpan.Zero)
        {
            UpdateLockoutMessage();
            _lockoutTimer.Start();
            PinInputControl.Shake();
            return;
        }

        var pin = PinInputControl.Pin;
        if (pin.Length < 4)
        {
            PinInputControl.ErrorText = "PIN은 4자리 이상 입력하세요.";
            PinInputControl.Shake();
            PinInputControl.FocusInput();
            return;
        }

        var verifier = VerifyPin;
        if (verifier is null)
        {
            return;
        }

        if (verifier(pin))
        {
            _failedPinAttempts = 0;
            _pinLockoutUntil = DateTimeOffset.MinValue;
            _lockoutTimer.Stop();
            _isUnlocking = true;
            ForgotPinPopup.IsOpen = false;
            PinInputControl.ErrorText = null;
            PinInputControl.IsEnabled = false;
            UnlockButton.IsEnabled = false;

            await PlayUnlockMotionAsync();
            if (_isUnlocking)
            {
                UnlockCompleted?.Invoke();
            }
            return;
        }

        _failedPinAttempts++;
        App.WriteProtectionLog("pin-verification-failed");

        if (_failedPinAttempts >= MaxPinAttemptsBeforeLockout)
        {
            // 30초, 60초, 120초 ... 최대 15분까지 지수 백오프 (기존 로직 그대로 유지)
            var exponent = Math.Min(_failedPinAttempts - MaxPinAttemptsBeforeLockout, 10);
            var lockout = TimeSpan.FromTicks(Math.Min(BasePinLockout.Ticks << exponent, MaxPinLockout.Ticks));
            _pinLockoutUntil = DateTimeOffset.Now + lockout;
            PinInputControl.ErrorText = $"PIN이 {_failedPinAttempts}회 틀렸습니다. {Math.Ceiling(lockout.TotalSeconds):0}초 동안 입력할 수 없습니다.";
            _lockoutTimer.Start();
        }
        else
        {
            var remaining = MaxPinAttemptsBeforeLockout - _failedPinAttempts;
            PinInputControl.ErrorText = $"PIN이 틀렸습니다. {remaining}번 더 틀리면 {(int)BasePinLockout.TotalSeconds}초 동안 입력할 수 없습니다.";
        }

        PinInputControl.Pin = string.Empty;
        UpdateSubmitState();
        PinInputControl.Shake();
        PinInputControl.FocusInput();
    }

    private void UpdateLockoutMessage()
    {
        var remaining = _pinLockoutUntil - DateTimeOffset.Now;
        if (remaining > TimeSpan.Zero)
        {
            PinInputControl.ErrorText = $"PIN 입력 오류가 반복되었습니다. {Math.Ceiling(remaining.TotalSeconds):0}초 후 다시 시도하세요.";
        }
    }

    private void UpdateSubmitState()
    {
        UnlockButton.IsEnabled = !_isUnlocking && !_hasLoadFailure && !IsLockedOut && PinInputControl.Pin.Length >= 4;
    }

    private async Task PlayUnlockMotionAsync()
    {
        if (!AreClientAreaAnimationsEnabled())
        {
            return;
        }

        CancelUnlockMotion();
        var cts = new CancellationTokenSource();
        _motionCts = cts;
        var stopwatch = Stopwatch.StartNew();

        try
        {
            while (true)
            {
                cts.Token.ThrowIfCancellationRequested();
                var progress = Math.Clamp(stopwatch.Elapsed.TotalMilliseconds / UnlockMotionDurationMs, 0.0, 1.0);
                var eased = 1.0 - Math.Pow(1.0 - progress, 3.0);

                _shackleTranslate.Y = -6.5 * eased;
                _shackleRotate.Angle = -24.0 * eased;

                if (progress >= 1.0)
                {
                    break;
                }

                await Task.Delay(16, cts.Token);
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            if (ReferenceEquals(_motionCts, cts))
            {
                _motionCts = null;
            }

            cts.Dispose();
        }
    }

    private void ResetShackleVisual()
    {
        _shackleTranslate.Y = 0;
        _shackleRotate.Angle = 0;
    }

    private void CancelUnlockMotion()
    {
        if (_motionCts is null)
        {
            return;
        }

        try
        {
            _motionCts.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }

        _motionCts = null;
    }

    internal static bool AreClientAreaAnimationsEnabled()
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
