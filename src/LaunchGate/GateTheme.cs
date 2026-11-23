using System;
using System.Drawing;
using System.Windows.Forms;
using Microsoft.Win32;

internal sealed class GateTheme
{
    private const string LightInkHex = "#1A2330";
    private const string LightInkMutedHex = "#5B6676";
    private const string LightSurfaceHex = "#FFFFFF";
    private const string LightCanvasHex = "#EEF1F5";
    private const string LightLatchHex = "#9A6414";
    private const string LightLatchSubtleHex = "#F6EBD7";
    private const string LightDangerHex = "#B3261E";
    private const string LightDividerHex = "#E1E5EB";

    private const string DarkInkHex = "#E8ECF1";
    private const string DarkInkMutedHex = "#9AA5B4";
    private const string DarkSurfaceHex = "#232831";
    private const string DarkCanvasHex = "#171B21";
    private const string DarkLatchHex = "#E3AE52";
    private const string DarkLatchSubtleHex = "#3A2F1C";
    private const string DarkDangerHex = "#FF8A80";
    private const string DarkDividerHex = "#2F3540";

    private readonly bool _isDark;
    private readonly bool _isHighContrast;
    private readonly Color _ink;
    private readonly Color _inkMuted;
    private readonly Color _surface;
    private readonly Color _canvas;
    private readonly Color _latch;
    private readonly Color _latchSubtle;
    private readonly Color _danger;
    private readonly Color _divider;
    private readonly Color _primaryButtonBack;
    private readonly Color _primaryButtonFore;
    private readonly Color _primaryButtonHoverBack;
    private readonly Color _primaryButtonPressedBack;
    private readonly Color _secondaryButtonHoverBack;
    private readonly Color _secondaryButtonPressedBack;

    private GateTheme(
        bool isDark,
        bool isHighContrast,
        Color ink,
        Color inkMuted,
        Color surface,
        Color canvas,
        Color latch,
        Color latchSubtle,
        Color danger,
        Color divider,
        Color primaryButtonBack,
        Color primaryButtonFore)
    {
        _isDark = isDark;
        _isHighContrast = isHighContrast;
        _ink = ink;
        _inkMuted = inkMuted;
        _surface = surface;
        _canvas = canvas;
        _latch = latch;
        _latchSubtle = latchSubtle;
        _danger = danger;
        _divider = divider;
        _primaryButtonBack = primaryButtonBack;
        _primaryButtonFore = primaryButtonFore;
        _primaryButtonHoverBack = isHighContrast
            ? primaryButtonBack
            : Blend(primaryButtonBack, isDark ? canvas : surface, 0.14f);
        _primaryButtonPressedBack = isHighContrast
            ? primaryButtonBack
            : Blend(primaryButtonBack, isDark ? canvas : surface, 0.24f);
        _secondaryButtonHoverBack = isHighContrast
            ? surface
            : Blend(surface, ink, 0.06f);
        _secondaryButtonPressedBack = isHighContrast
            ? surface
            : Blend(surface, ink, 0.12f);
    }

    internal bool IsDark { get { return _isDark; } }
    internal bool IsHighContrast { get { return _isHighContrast; } }
    internal Color Ink { get { return _ink; } }
    internal Color InkMuted { get { return _inkMuted; } }
    internal Color Surface { get { return _surface; } }
    internal Color Canvas { get { return _canvas; } }
    internal Color Latch { get { return _latch; } }
    internal Color LatchSubtle { get { return _latchSubtle; } }
    internal Color Danger { get { return _danger; } }
    internal Color Divider { get { return _divider; } }
    internal Color PrimaryButtonBack { get { return _primaryButtonBack; } }
    internal Color PrimaryButtonFore { get { return _primaryButtonFore; } }
    internal Color PrimaryButtonHoverBack { get { return _primaryButtonHoverBack; } }
    internal Color PrimaryButtonPressedBack { get { return _primaryButtonPressedBack; } }
    internal Color SecondaryButtonHoverBack { get { return _secondaryButtonHoverBack; } }
    internal Color SecondaryButtonPressedBack { get { return _secondaryButtonPressedBack; } }

    internal static GateTheme Current()
    {
        if (SystemInformation.HighContrast)
        {
            return new GateTheme(
                isDark: false,
                isHighContrast: true,
                ink: SystemColors.WindowText,
                inkMuted: SystemColors.GrayText,
                surface: SystemColors.Window,
                canvas: SystemColors.Window,
                latch: SystemColors.Highlight,
                latchSubtle: SystemColors.Control,
                danger: SystemColors.Highlight,
                divider: SystemColors.WindowText,
                primaryButtonBack: SystemColors.Highlight,
                primaryButtonFore: SystemColors.HighlightText);
        }

        bool dark = IsDarkMode();
        if (dark)
        {
            Color ink = FromHex(DarkInkHex);
            Color canvas = FromHex(DarkCanvasHex);
            return new GateTheme(
                isDark: true,
                isHighContrast: false,
                ink: ink,
                inkMuted: FromHex(DarkInkMutedHex),
                surface: FromHex(DarkSurfaceHex),
                canvas: canvas,
                latch: FromHex(DarkLatchHex),
                latchSubtle: FromHex(DarkLatchSubtleHex),
                danger: FromHex(DarkDangerHex),
                divider: FromHex(DarkDividerHex),
                primaryButtonBack: ink,
                primaryButtonFore: canvas);
        }

        Color lightInk = FromHex(LightInkHex);
        Color lightSurface = FromHex(LightSurfaceHex);
        return new GateTheme(
            isDark: false,
            isHighContrast: false,
            ink: lightInk,
            inkMuted: FromHex(LightInkMutedHex),
            surface: lightSurface,
            canvas: FromHex(LightCanvasHex),
            latch: FromHex(LightLatchHex),
            latchSubtle: FromHex(LightLatchSubtleHex),
            danger: FromHex(LightDangerHex),
            divider: FromHex(LightDividerHex),
            primaryButtonBack: lightInk,
            primaryButtonFore: lightSurface);
    }

    internal static bool IsDarkMode()
    {
        try
        {
            using (var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
            {
                if (key != null)
                {
                    object value = key.GetValue("AppsUseLightTheme");
                    if (value is int)
                    {
                        return (int)value == 0;
                    }
                }
            }
        }
        catch
        {
        }

        return false;
    }

    private static Color FromHex(string hex)
    {
        int value = Convert.ToInt32(hex.Substring(1), 16);
        return Color.FromArgb((value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF);
    }

    private static Color Blend(Color baseColor, Color targetColor, float amount)
    {
        int r = (int)Math.Round(baseColor.R + (targetColor.R - baseColor.R) * amount);
        int g = (int)Math.Round(baseColor.G + (targetColor.G - baseColor.G) * amount);
        int b = (int)Math.Round(baseColor.B + (targetColor.B - baseColor.B) * amount);
        return Color.FromArgb(ClampByte(r), ClampByte(g), ClampByte(b));
    }

    private static int ClampByte(int value)
    {
        if (value < 0) return 0;
        if (value > 255) return 255;
        return value;
    }
}
