using Avalonia;
using Avalonia.Controls;

namespace WindowsAppProtector.Controls;

public partial class SettingsCard : UserControl
{
    public static readonly StyledProperty<string> HeaderProperty =
        AvaloniaProperty.Register<SettingsCard, string>(nameof(Header), defaultValue: string.Empty);

    public static readonly StyledProperty<string?> DescriptionProperty =
        AvaloniaProperty.Register<SettingsCard, string?>(nameof(Description), defaultValue: null);

    public static readonly StyledProperty<string?> TagTextProperty =
        AvaloniaProperty.Register<SettingsCard, string?>(nameof(TagText), defaultValue: null);

    public static readonly StyledProperty<object?> ActionContentProperty =
        AvaloniaProperty.Register<SettingsCard, object?>(nameof(ActionContent), defaultValue: null);

    public static readonly StyledProperty<object?> FooterContentProperty =
        AvaloniaProperty.Register<SettingsCard, object?>(nameof(FooterContent), defaultValue: null);

    public static readonly StyledProperty<string?> CardMessageProperty =
        AvaloniaProperty.Register<SettingsCard, string?>(nameof(CardMessage), defaultValue: null);

    public static readonly StyledProperty<bool> IsCardMessageErrorProperty =
        AvaloniaProperty.Register<SettingsCard, bool>(nameof(IsCardMessageError), defaultValue: true);

    public SettingsCard()
    {
        InitializeComponent();
        UpdateVisuals();
    }

    public string Header
    {
        get => GetValue(HeaderProperty);
        set => SetValue(HeaderProperty, value);
    }

    public string? Description
    {
        get => GetValue(DescriptionProperty);
        set => SetValue(DescriptionProperty, value);
    }

    public string? TagText
    {
        get => GetValue(TagTextProperty);
        set => SetValue(TagTextProperty, value);
    }

    public object? ActionContent
    {
        get => GetValue(ActionContentProperty);
        set => SetValue(ActionContentProperty, value);
    }

    public object? FooterContent
    {
        get => GetValue(FooterContentProperty);
        set => SetValue(FooterContentProperty, value);
    }

    public string? CardMessage
    {
        get => GetValue(CardMessageProperty);
        set => SetValue(CardMessageProperty, value);
    }

    public bool IsCardMessageError
    {
        get => GetValue(IsCardMessageErrorProperty);
        set => SetValue(IsCardMessageErrorProperty, value);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);

        if (change.Property == HeaderProperty ||
            change.Property == DescriptionProperty ||
            change.Property == TagTextProperty ||
            change.Property == ActionContentProperty ||
            change.Property == FooterContentProperty ||
            change.Property == CardMessageProperty ||
            change.Property == IsCardMessageErrorProperty)
        {
            UpdateVisuals();
        }
    }

    private void UpdateVisuals()
    {
        if (HeaderTextBlock is null)
        {
            return;
        }

        HeaderTextBlock.Text = Header ?? string.Empty;

        var hasDescription = !string.IsNullOrWhiteSpace(Description);
        DescriptionTextBlock.Text = hasDescription ? Description : string.Empty;
        DescriptionTextBlock.IsVisible = hasDescription;

        var hasTag = !string.IsNullOrWhiteSpace(TagText);
        TagChipTextBlock.Text = hasTag ? TagText : string.Empty;
        TagChipBorder.IsVisible = hasTag;

        ActionContentPresenter.Content = ActionContent;
        ActionContentPresenter.IsVisible = ActionContent is not null;

        FooterContentPresenter.Content = FooterContent;
        FooterContentPresenter.IsVisible = FooterContent is not null;

        var hasMessage = !string.IsNullOrWhiteSpace(CardMessage);
        CardMessageTextBlock.Text = hasMessage ? CardMessage : string.Empty;
        CardMessageBorder.IsVisible = hasMessage;
        CardMessageBorder.Classes.Set("error", hasMessage && IsCardMessageError);
    }
}
