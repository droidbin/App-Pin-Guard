using Avalonia.Controls;
using Avalonia.Interactivity;

namespace WindowsAppProtector.Views;

public partial class ConfirmDialog : Window
{
    public ConfirmDialog()
    {
        InitializeComponent();
    }

    public ConfirmDialog(
        string title,
        string message,
        string confirmLabel = "제거",
        string cancelLabel = "취소",
        bool isDanger = true)
    {
        InitializeComponent();

        Title = title;
        DialogTitleText.Text = title;
        DialogMessageText.Text = message;
        ConfirmButton.Content = confirmLabel;
        CancelButton.Content = cancelLabel;
        ConfirmButton.Classes.Set("Danger", isDanger);
        ConfirmButton.Classes.Set("Primary", !isDanger);
    }

    public static async Task<bool> ShowAsync(
        Window owner,
        string title,
        string message,
        string confirmLabel = "제거",
        string cancelLabel = "취소",
        bool isDanger = true)
    {
        var dialog = new ConfirmDialog(title, message, confirmLabel, cancelLabel, isDanger);
        var result = await dialog.ShowDialog<bool?>(owner);
        return result == true;
    }

    private void OnCancelClick(object? sender, RoutedEventArgs e)
    {
        Close(false);
    }

    private void OnConfirmClick(object? sender, RoutedEventArgs e)
    {
        Close(true);
    }
}
