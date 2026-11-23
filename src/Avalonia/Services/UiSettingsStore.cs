namespace WindowsAppProtector.Services;

/// <summary>Reads and writes ui.json: settings only the UI uses (hotkeys, idle lock, update channel...).</summary>
internal sealed class UiSettingsStore
{
    public Task<UiSettings> LoadAsync() => Task.Run(PolicyStore.LoadUi);

    public Task SaveAsync(UiSettings settings) => Task.Run(() => PolicyStore.SaveUi(settings));
}
