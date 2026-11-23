using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

internal sealed class GateForm : Form
{
    private const int FormWidth = 440;
    private const int FormHeight = 260;
    private const int CornerRadius = 8;
    private const int ControlCornerRadius = 4;
    private const int DwmwaWindowCornerPreference = 33;
    private const int DwmwcpRound = 2;
    private const int WmNclButtonDown = 0xA1;
    private const int HtCaption = 0x2;

    private readonly GateTheme _theme;
    private readonly string _appName;
    private readonly Icon _appIcon;
    private readonly bool _ownsAppIcon;
    private PrivateFontCollection _fontCollection;
    private FontFamily _fontFamily;
    private FontFamily _boldFontFamily;
    private readonly Font _titleFont;
    private readonly Font _subtitleFont;
    private readonly Font _buttonFont;
    private readonly Font _pinInputFont;
    private readonly PinInputPanel _pinPanel;
    private readonly GateButton _cancelButton;
    private readonly GateButton _openButton;
    private bool _usesDwmRoundedCorners;

    internal GateForm(string appPath)
    {
        _theme = GateTheme.Current();
        _appName = ResolveAppName(appPath);
        _appIcon = LoadAppIcon(appPath, out _ownsAppIcon);
        LoadCustomFont();

        _titleFont = CreateUiFont(18f, FontStyle.Bold);
        _subtitleFont = CreateUiFont(13f, FontStyle.Regular);
        _buttonFont = CreateUiFont(14f, FontStyle.Bold);
        _pinInputFont = CreateInputFont(16f);

        Text = ProductBrand.Name;
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.CenterScreen;
        TopMost = true;
        ShowInTaskbar = true;
        MaximizeBox = false;
        MinimizeBox = false;
        AutoScaleMode = AutoScaleMode.None;
        ClientSize = new Size(FormWidth, FormHeight);
        BackColor = _theme.Canvas;
        ForeColor = _theme.Ink;
        DoubleBuffered = true;
        KeyPreview = true;

        _pinPanel = new PinInputPanel(_theme, _pinInputFont, CornerRadius);
        _pinPanel.Bounds = new Rectangle(28, 104, 384, 48);
        _pinPanel.TabIndex = 0;

        _cancelButton = new GateButton(_theme, _buttonFont, isPrimary: false, cornerRadius: ControlCornerRadius);
        _cancelButton.Text = "취소";
        _cancelButton.AccessibleName = "취소";
        _cancelButton.DialogResult = DialogResult.Cancel;
        _cancelButton.Bounds = new Rectangle(208, 192, 96, 40);
        _cancelButton.TabIndex = 2;

        _openButton = new GateButton(_theme, _buttonFont, isPrimary: true, cornerRadius: ControlCornerRadius);
        _openButton.Text = "열기";
        _openButton.AccessibleName = "열기";
        _openButton.DialogResult = DialogResult.OK;
        _openButton.Bounds = new Rectangle(316, 192, 96, 40);
        _openButton.TabIndex = 1;

        Controls.Add(_pinPanel);
        Controls.Add(_openButton);
        Controls.Add(_cancelButton);

        AcceptButton = _openButton;
        CancelButton = _cancelButton;
        ActiveControl = _pinPanel.PinTextBox;
    }

    internal string PinText
    {
        get { return _pinPanel.PinTextBox.Text; }
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        ApplyRoundedCorners();
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        Activate();
        BringToFront();
        _pinPanel.PinTextBox.Focus();
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        if (e.Button == MouseButtons.Left)
        {
            ReleaseCapture();
            SendMessage(Handle, WmNclButtonDown, new IntPtr(HtCaption), IntPtr.Zero);
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

        g.Clear(_theme.Canvas);

        // Window border
        using (var borderPath = CreateRoundedRectanglePath(new RectangleF(0.5f, 0.5f, Width - 1f, Height - 1f), CornerRadius))
        using (var borderPen = new Pen(_theme.Divider, 1f))
        {
            g.DrawPath(borderPen, borderPath);
        }

        // App icon badge (48x48, corner radius 8, LatchSubtle background)
        var badgeRect = new RectangleF(28f, 28f, 48f, 48f);
        using (var badgePath = CreateRoundedRectanglePath(badgeRect, CornerRadius))
        using (var badgeBrush = new SolidBrush(_theme.LatchSubtle))
        {
            g.FillPath(badgeBrush, badgePath);
            if (_theme.IsHighContrast)
            {
                using (var badgePen = new Pen(_theme.Divider, 1f))
                {
                    g.DrawPath(badgePen, badgePath);
                }
            }
        }

        if (_appIcon != null)
        {
            g.DrawIcon(_appIcon, new Rectangle(36, 36, 32, 32));
        }

        // App name + locked subtitle
        var textArea = new RectangleF(92f, 28f, 320f, 26f);
        var subtitleArea = new RectangleF(92f, 56f, 320f, 20f);
        using (var titleFormat = new StringFormat(StringFormatFlags.NoWrap))
        using (var titleBrush = new SolidBrush(_theme.Ink))
        using (var subtitleBrush = new SolidBrush(_theme.InkMuted))
        {
            titleFormat.Trimming = StringTrimming.EllipsisCharacter;
            titleFormat.LineAlignment = StringAlignment.Center;
            g.DrawString(_appName, _titleFont, titleBrush, textArea, titleFormat);
            g.DrawString("잠긴 앱입니다", _subtitleFont, subtitleBrush, subtitleArea, titleFormat);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _titleFont.Dispose();
            _subtitleFont.Dispose();
            _buttonFont.Dispose();
            _pinInputFont.Dispose();
            if (_ownsAppIcon && _appIcon != null)
            {
                _appIcon.Dispose();
            }
            if (_fontCollection != null)
            {
                _fontCollection.Dispose();
                _fontCollection = null;
            }
        }

        base.Dispose(disposing);
    }

    private void ApplyRoundedCorners()
    {
        _usesDwmRoundedCorners = false;
        try
        {
            int preference = DwmwcpRound;
            if (DwmSetWindowAttribute(Handle, DwmwaWindowCornerPreference, ref preference, sizeof(int)) == 0)
            {
                _usesDwmRoundedCorners = true;
            }
        }
        catch
        {
        }

        if (!_usesDwmRoundedCorners)
        {
            using (var path = CreateRoundedRectanglePath(new RectangleF(0f, 0f, Width, Height), CornerRadius))
            {
                Region = new Region(path);
            }
        }
    }

    private void LoadCustomFont()
    {
        try
        {
            string regularPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Pretendard-Regular.otf");
            string semiBoldPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Pretendard-SemiBold.otf");
            if (!File.Exists(regularPath))
            {
                return;
            }

            var collection = new PrivateFontCollection();
            collection.AddFontFile(regularPath);
            if (File.Exists(semiBoldPath))
            {
                collection.AddFontFile(semiBoldPath);
            }

            foreach (FontFamily family in collection.Families)
            {
                if (family.Name == "Pretendard") _fontFamily = family;
                else if (family.Name == "Pretendard SemiBold") _boldFontFamily = family;
            }

            if (_fontFamily != null)
            {
                _fontCollection = collection;
            }
            else
            {
                _boldFontFamily = null;
                collection.Dispose();
            }
        }
        catch
        {
        }
    }

    private Font CreateUiFont(float pixelSize, FontStyle style)
    {
        if (_fontFamily != null)
        {
            try
            {
                if ((style & FontStyle.Bold) != 0 && _boldFontFamily != null)
                {
                    return new Font(_boldFontFamily, pixelSize, FontStyle.Regular, GraphicsUnit.Pixel);
                }

                return new Font(_fontFamily, pixelSize, FontStyle.Regular, GraphicsUnit.Pixel);
            }
            catch
            {
            }
        }

        return CreateFallbackFont(pixelSize, style);
    }

    private static Font CreateInputFont(float pixelSize)
    {
        return CreateFallbackFont(pixelSize, FontStyle.Regular);
    }

    private static Font CreateFallbackFont(float pixelSize, FontStyle style)
    {
        try
        {
            return new Font("Malgun Gothic", pixelSize, style, GraphicsUnit.Pixel);
        }
        catch
        {
            return new Font(SystemFonts.MessageBoxFont.FontFamily, pixelSize, FontStyle.Regular, GraphicsUnit.Pixel);
        }
    }

    private static string ResolveAppName(string appPath)
    {
        if (string.IsNullOrWhiteSpace(appPath))
        {
            return ProductBrand.Name;
        }

        string withoutExt = Path.GetFileNameWithoutExtension(appPath);
        if (!string.IsNullOrWhiteSpace(withoutExt))
        {
            return withoutExt;
        }

        string fileName = Path.GetFileName(appPath);
        return string.IsNullOrWhiteSpace(fileName) ? appPath : fileName;
    }

    private static Icon LoadAppIcon(string appPath, out bool ownsIcon)
    {
        ownsIcon = false;
        if (!string.IsNullOrWhiteSpace(appPath) && File.Exists(appPath))
        {
            try
            {
                Icon extracted = Icon.ExtractAssociatedIcon(appPath);
                if (extracted != null)
                {
                    ownsIcon = true;
                    return extracted;
                }
            }
            catch
            {
            }
        }

        return SystemIcons.Application;
    }

    internal static GraphicsPath CreateRoundedRectanglePath(RectangleF bounds, float radius)
    {
        var path = new GraphicsPath();
        if (bounds.Width <= 0f || bounds.Height <= 0f)
        {
            return path;
        }

        float maxRadius = Math.Min(bounds.Width, bounds.Height) / 2f;
        float r = Math.Min(radius, maxRadius);
        float d = r * 2f;

        path.AddArc(bounds.X, bounds.Y, d, d, 180f, 90f);
        path.AddArc(bounds.Right - d, bounds.Y, d, d, 270f, 90f);
        path.AddArc(bounds.Right - d, bounds.Bottom - d, d, d, 0f, 90f);
        path.AddArc(bounds.X, bounds.Bottom - d, d, d, 90f, 90f);
        path.CloseFigure();
        return path;
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    [DllImport("user32.dll")]
    private static extern bool ReleaseCapture();

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    private sealed class PinInputPanel : Control
    {
        private readonly GateTheme _theme;
        private readonly int _cornerRadius;
        private readonly TextBox _textBox;

        internal PinInputPanel(GateTheme theme, Font inputFont, int cornerRadius)
        {
            _theme = theme;
            _cornerRadius = cornerRadius;

            SetStyle(
                ControlStyles.UserPaint |
                ControlStyles.AllPaintingInWmPaint |
                ControlStyles.OptimizedDoubleBuffer |
                ControlStyles.ResizeRedraw,
                true);

            BackColor = theme.Canvas;
            Cursor = Cursors.IBeam;

            _textBox = new TextBox();
            _textBox.BorderStyle = BorderStyle.None;
            _textBox.MaxLength = 32;
            _textBox.UseSystemPasswordChar = true;
            _textBox.AccessibleName = "실행 PIN";
            _textBox.Font = inputFont;
            _textBox.BackColor = theme.Surface;
            _textBox.ForeColor = theme.Ink;
            _textBox.GotFocus += OnTextBoxFocusChanged;
            _textBox.LostFocus += OnTextBoxFocusChanged;

            Controls.Add(_textBox);
        }

        internal TextBox PinTextBox
        {
            get { return _textBox; }
        }

        protected override void OnLayout(LayoutEventArgs levent)
        {
            base.OnLayout(levent);
            const int horizontalPadding = 14;
            int textHeight = _textBox.PreferredHeight;
            int y = Math.Max(0, (Height - textHeight) / 2);
            _textBox.Bounds = new Rectangle(
                horizontalPadding,
                y,
                Math.Max(10, Width - (horizontalPadding * 2)),
                textHeight);
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            _textBox.Focus();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;

            g.Clear(_theme.Canvas);

            bool focused = _textBox.Focused;
            float borderWidth = focused ? 2f : 1f;
            float inset = borderWidth / 2f;
            var rect = new RectangleF(inset, inset, Width - borderWidth, Height - borderWidth);

            using (var path = CreateRoundedRectanglePath(rect, _cornerRadius))
            using (var fillBrush = new SolidBrush(_theme.Surface))
            using (var borderPen = new Pen(focused ? _theme.Latch : _theme.Divider, borderWidth))
            {
                g.FillPath(fillBrush, path);
                g.DrawPath(borderPen, path);
            }
        }

        private void OnTextBoxFocusChanged(object sender, EventArgs e)
        {
            Invalidate();
        }
    }

    private sealed class GateButton : Button
    {
        private readonly GateTheme _theme;
        private readonly Font _labelFont;
        private readonly bool _isPrimary;
        private readonly int _cornerRadius;
        private bool _hovered;
        private bool _pressed;

        internal GateButton(GateTheme theme, Font labelFont, bool isPrimary, int cornerRadius)
        {
            _theme = theme;
            _labelFont = labelFont;
            _isPrimary = isPrimary;
            _cornerRadius = cornerRadius;

            SetStyle(
                ControlStyles.UserPaint |
                ControlStyles.AllPaintingInWmPaint |
                ControlStyles.OptimizedDoubleBuffer |
                ControlStyles.ResizeRedraw,
                true);

            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            TabStop = true;
            Cursor = Cursors.Hand;
            BackColor = theme.Canvas;
        }

        protected override void OnMouseEnter(EventArgs e)
        {
            base.OnMouseEnter(e);
            _hovered = true;
            Invalidate();
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            _hovered = false;
            _pressed = false;
            Invalidate();
        }

        protected override void OnMouseDown(MouseEventArgs mevent)
        {
            base.OnMouseDown(mevent);
            if (mevent.Button == MouseButtons.Left)
            {
                _pressed = true;
                Invalidate();
            }
        }

        protected override void OnMouseUp(MouseEventArgs mevent)
        {
            base.OnMouseUp(mevent);
            _pressed = false;
            Invalidate();
        }

        protected override void OnGotFocus(EventArgs e)
        {
            base.OnGotFocus(e);
            Invalidate();
        }

        protected override void OnLostFocus(EventArgs e)
        {
            base.OnLostFocus(e);
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs pevent)
        {
            Graphics g = pevent.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

            g.Clear(_theme.Canvas);

            Color fillColor;
            Color textColor;
            if (_isPrimary)
            {
                fillColor = _pressed
                    ? _theme.PrimaryButtonPressedBack
                    : (_hovered ? _theme.PrimaryButtonHoverBack : _theme.PrimaryButtonBack);
                textColor = _theme.PrimaryButtonFore;
            }
            else
            {
                fillColor = _pressed
                    ? _theme.SecondaryButtonPressedBack
                    : (_hovered ? _theme.SecondaryButtonHoverBack : _theme.Surface);
                textColor = _theme.Ink;
            }

            var outerRect = new RectangleF(0.5f, 0.5f, Width - 1f, Height - 1f);
            using (var path = CreateRoundedRectanglePath(outerRect, _cornerRadius))
            using (var fillBrush = new SolidBrush(fillColor))
            {
                g.FillPath(fillBrush, path);

                if (!_isPrimary)
                {
                    Color borderColor = Focused ? _theme.InkMuted : _theme.Divider;
                    using (var borderPen = new Pen(borderColor, Focused ? 1.5f : 1f))
                    {
                        g.DrawPath(borderPen, path);
                    }
                }
                else if (Focused && ShowFocusCues)
                {
                    var focusRect = new RectangleF(2.5f, 2.5f, Width - 5f, Height - 5f);
                    using (var focusPath = CreateRoundedRectanglePath(focusRect, Math.Max(1f, _cornerRadius - 1f)))
                    using (var focusPen = new Pen(_theme.PrimaryButtonFore, 1f))
                    {
                        g.DrawPath(focusPen, focusPath);
                    }
                }
            }

            using (var textFormat = new StringFormat())
            using (var textBrush = new SolidBrush(textColor))
            {
                textFormat.Alignment = StringAlignment.Center;
                textFormat.LineAlignment = StringAlignment.Center;
                g.DrawString(Text, _labelFont, textBrush, new RectangleF(0f, 0f, Width, Height), textFormat);
            }
        }
    }
}
