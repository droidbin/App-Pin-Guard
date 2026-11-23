using System.Collections.Generic;
using System.Runtime.InteropServices;
using Avalonia.Input;

namespace WindowsAppProtector.Services;

public static class HotkeyFormatter
{
    private const int VkBack = 0x08;
    private const int VkTab = 0x09;
    private const int VkReturn = 0x0D;
    private const int VkShift = 0x10;
    private const int VkControl = 0x11;
    private const int VkMenu = 0x12;
    private const int VkEscape = 0x1B;
    private const int VkSpace = 0x20;
    private const int VkPrior = 0x21;
    private const int VkNext = 0x22;
    private const int VkEnd = 0x23;
    private const int VkHome = 0x24;
    private const int VkLeft = 0x25;
    private const int VkUp = 0x26;
    private const int VkRight = 0x27;
    private const int VkDown = 0x28;
    private const int VkInsert = 0x2D;
    private const int VkDelete = 0x2E;
    private const int VkDigit0 = 0x30;
    private const int VkDigit9 = 0x39;
    private const int VkA = 0x41;
    private const int VkZ = 0x5A;
    private const int VkLWin = 0x5B;
    private const int VkRWin = 0x5C;
    private const int VkNumPad0 = 0x60;
    private const int VkNumPad9 = 0x69;
    private const int VkMultiply = 0x6A;
    private const int VkAdd = 0x6B;
    private const int VkSubtract = 0x6D;
    private const int VkDecimal = 0x6E;
    private const int VkDivide = 0x6F;
    private const int VkF1 = 0x70;
    private const int VkF24 = 0x87;
    private const int VkLShift = 0xA0;
    private const int VkRShift = 0xA1;
    private const int VkLControl = 0xA2;
    private const int VkRControl = 0xA3;
    private const int VkLMenu = 0xA4;
    private const int VkRMenu = 0xA5;

    public static string? FromKey(Key key, KeyModifiers modifiers = KeyModifiers.None)
    {
        if (IsModifierKey(key))
        {
            return null;
        }

        var keyText = FormatKey(key);
        if (keyText is null)
        {
            return null;
        }

        var parts = new List<string>(5);

        if (modifiers.HasFlag(KeyModifiers.Control) || IsKeyDown(VkControl))
        {
            parts.Add("Ctrl");
        }

        if (modifiers.HasFlag(KeyModifiers.Alt) || IsKeyDown(VkMenu))
        {
            parts.Add("Alt");
        }

        if (modifiers.HasFlag(KeyModifiers.Shift) || IsKeyDown(VkShift))
        {
            parts.Add("Shift");
        }

        if (modifiers.HasFlag(KeyModifiers.Meta) || IsKeyDown(VkLWin) || IsKeyDown(VkRWin))
        {
            parts.Add("Win");
        }

        parts.Add(keyText);
        return string.Join("+", parts);
    }

    public static string? FromVirtualKey(int virtualKey)
    {
        if (IsModifierVirtualKey(virtualKey))
        {
            return null;
        }

        var keyText = FormatVirtualKey(virtualKey);
        if (keyText is null)
        {
            return null;
        }

        var parts = new List<string>(5);

        if (IsKeyDown(VkControl))
        {
            parts.Add("Ctrl");
        }

        if (IsKeyDown(VkMenu))
        {
            parts.Add("Alt");
        }

        if (IsKeyDown(VkShift))
        {
            parts.Add("Shift");
        }

        if (IsKeyDown(VkLWin) || IsKeyDown(VkRWin))
        {
            parts.Add("Win");
        }

        parts.Add(keyText);
        return string.Join("+", parts);
    }

    private static bool IsKeyDown(int virtualKey)
    {
        return (GetAsyncKeyState(virtualKey) & 0x8000) != 0;
    }

    private static bool IsModifierKey(Key key)
    {
        return key is Key.LeftCtrl
            or Key.RightCtrl
            or Key.LeftAlt
            or Key.RightAlt
            or Key.LeftShift
            or Key.RightShift
            or Key.LWin
            or Key.RWin;
    }

    private static bool IsModifierVirtualKey(int virtualKey)
    {
        return virtualKey is VkControl
            or VkLControl
            or VkRControl
            or VkMenu
            or VkLMenu
            or VkRMenu
            or VkShift
            or VkLShift
            or VkRShift
            or VkLWin
            or VkRWin;
    }

    private static string? FormatKey(Key key)
    {
        if (key is >= Key.A and <= Key.Z)
        {
            return key.ToString();
        }

        if (key is >= Key.D0 and <= Key.D9)
        {
            return ((int)key - (int)Key.D0).ToString();
        }

        if (key is >= Key.NumPad0 and <= Key.NumPad9)
        {
            return $"Num{(int)key - (int)Key.NumPad0}";
        }

        if (key is >= Key.F1 and <= Key.F24)
        {
            return key.ToString();
        }

        return key switch
        {
            Key.Back => "Backspace",
            Key.Tab => "Tab",
            Key.Enter => "Enter",
            Key.Escape => "Esc",
            Key.Space => "Space",
            Key.PageUp => "PageUp",
            Key.PageDown => "PageDown",
            Key.End => "End",
            Key.Home => "Home",
            Key.Left => "Left",
            Key.Up => "Up",
            Key.Right => "Right",
            Key.Down => "Down",
            Key.Insert => "Insert",
            Key.Delete => "Delete",
            Key.Add => "Num+",
            Key.Subtract => "Num-",
            Key.Multiply => "Num*",
            Key.Divide => "Num/",
            Key.Decimal => "Num.",
            _ => null,
        };
    }

    private static string? FormatVirtualKey(int virtualKey)
    {
        if (virtualKey is >= VkA and <= VkZ)
        {
            return ((char)virtualKey).ToString();
        }

        if (virtualKey is >= VkDigit0 and <= VkDigit9)
        {
            return (virtualKey - VkDigit0).ToString();
        }

        if (virtualKey is >= VkNumPad0 and <= VkNumPad9)
        {
            return $"Num{virtualKey - VkNumPad0}";
        }

        if (virtualKey is >= VkF1 and <= VkF24)
        {
            return $"F{virtualKey - VkF1 + 1}";
        }

        return virtualKey switch
        {
            VkBack => "Backspace",
            VkTab => "Tab",
            VkReturn => "Enter",
            VkEscape => "Esc",
            VkSpace => "Space",
            VkPrior => "PageUp",
            VkNext => "PageDown",
            VkEnd => "End",
            VkHome => "Home",
            VkLeft => "Left",
            VkUp => "Up",
            VkRight => "Right",
            VkDown => "Down",
            VkInsert => "Insert",
            VkDelete => "Delete",
            VkAdd => "Num+",
            VkSubtract => "Num-",
            VkMultiply => "Num*",
            VkDivide => "Num/",
            VkDecimal => "Num.",
            _ => null,
        };
    }

    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int virtualKey);
}
