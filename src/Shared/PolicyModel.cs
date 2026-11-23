using System;
using System.Collections.Generic;
using System.Runtime.Serialization;

// Single schema compiled into the service, gate, agent, installer helper and the UI.
// Defaults are assigned by the constructor and, because DataContract deserialization skips constructors,
// again by [OnDeserializing] so both paths agree.

[DataContract]
internal sealed class PolicyDocument
{
    internal const int CurrentSchemaVersion = 3;

    public PolicyDocument() { Initialize(); }

    [OnDeserializing]
    private void OnDeserializing(StreamingContext context) { Initialize(); }

    private void Initialize()
    {
        SchemaVersion = CurrentSchemaVersion;
        Revision = 0;
        EnableLaunchGate = true;
        CloseAppsOnLock = false;
        Apps = new List<AppPolicy>();
    }

    [DataMember] public int SchemaVersion { get; set; }
    // Incremented on every UI save. The service reports the value it applied in status.json.
    [DataMember] public long Revision { get; set; }
    [DataMember] public bool EnableLaunchGate { get; set; }
    [DataMember] public bool CloseAppsOnLock { get; set; }
    [DataMember] public List<AppPolicy> Apps { get; set; }
}

[DataContract]
internal sealed class AppPolicy
{
    public AppPolicy() { Initialize(); }

    [OnDeserializing]
    private void OnDeserializing(StreamingContext context) { Initialize(); }

    private void Initialize()
    {
        Id = string.Empty;
        Name = string.Empty;
        Path = string.Empty;
        IsPackaged = false;
        PackageFamilyName = string.Empty;
        AppUserModelId = string.Empty;
        ExecutableName = string.Empty;
        Locked = true;
        LockedAtUtc = string.Empty;
        FileSize = 0;
        Sha256 = string.Empty;
        Launch = new LaunchPolicy();
    }

    [DataMember] public string Id { get; set; }
    [DataMember] public string Name { get; set; }
    [DataMember] public string Path { get; set; }
    [DataMember] public bool IsPackaged { get; set; }
    [DataMember] public string PackageFamilyName { get; set; }
    [DataMember] public string AppUserModelId { get; set; }
    [DataMember] public string ExecutableName { get; set; }
    [DataMember] public bool Locked { get; set; }
    // ISO-8601 UTC. Written by the UI when Locked changes from false to true.
    [DataMember] public string LockedAtUtc { get; set; }
    // 0 means "no fingerprint": the service then matches by path only.
    [DataMember] public long FileSize { get; set; }
    [DataMember] public string Sha256 { get; set; }
    [DataMember] public LaunchPolicy Launch { get; set; }
}

[DataContract]
internal sealed class LaunchPolicy
{
    public LaunchPolicy() { Initialize(); }

    [OnDeserializing]
    private void OnDeserializing(StreamingContext context) { Initialize(); }

    private void Initialize()
    {
        AllowedMinutes = 0;
        LockStartMinute = null;
        LockEndMinute = null;
        RelockOnExit = false;
        HasOwnPin = false;
    }

    [DataMember] public int AllowedMinutes { get; set; }
    [DataMember] public int? LockStartMinute { get; set; }
    [DataMember] public int? LockEndMinute { get; set; }
    [DataMember] public bool RelockOnExit { get; set; }
    [DataMember] public bool HasOwnPin { get; set; }
}

[DataContract]
internal sealed class PinRecord
{
    internal const int DefaultIterations = 120000;

    public PinRecord() { Initialize(); }

    [OnDeserializing]
    private void OnDeserializing(StreamingContext context) { Initialize(); }

    private void Initialize()
    {
        Salt = string.Empty;
        Hash = string.Empty;
        Iterations = DefaultIterations;
        Version = 0;
    }

    [DataMember] public string Salt { get; set; }
    [DataMember] public string Hash { get; set; }
    [DataMember] public int Iterations { get; set; }
    // Changes whenever the PIN changes; grants are keyed on it instead of the hash.
    [DataMember] public long Version { get; set; }

    internal bool IsSet
    {
        get { return !string.IsNullOrEmpty(Salt) && !string.IsNullOrEmpty(Hash); }
    }
}

[DataContract]
internal sealed class AppPinEntry
{
    [DataMember] public string AppId { get; set; }
    [DataMember] public PinRecord Pin { get; set; }
}

[DataContract]
internal sealed class SecretsDocument
{
    internal const int CurrentSchemaVersion = 1;

    public SecretsDocument() { Initialize(); }

    [OnDeserializing]
    private void OnDeserializing(StreamingContext context) { Initialize(); }

    private void Initialize()
    {
        SchemaVersion = CurrentSchemaVersion;
        AppPin = new PinRecord();
        AppPins = new List<AppPinEntry>();
    }

    [DataMember] public int SchemaVersion { get; set; }
    [DataMember] public PinRecord AppPin { get; set; }
    // Per-app PINs keyed by AppPolicy.Id (a list, not a dictionary, so every serializer agrees on the shape).
    [DataMember] public List<AppPinEntry> AppPins { get; set; }

    internal PinRecord FindAppPin(string appId)
    {
        if (AppPins == null || string.IsNullOrEmpty(appId)) return null;
        foreach (AppPinEntry entry in AppPins)
        {
            if (entry != null && entry.Pin != null && string.Equals(entry.AppId, appId, StringComparison.Ordinal))
                return entry.Pin;
        }
        return null;
    }

    internal void SetAppPin(string appId, PinRecord pin)
    {
        RemoveAppPin(appId);
        if (pin != null) AppPins.Add(new AppPinEntry { AppId = appId, Pin = pin });
    }

    internal void RemoveAppPin(string appId)
    {
        AppPins.RemoveAll(delegate(AppPinEntry entry)
        {
            return entry == null || string.Equals(entry.AppId, appId, StringComparison.Ordinal);
        });
    }
}

[DataContract]
internal sealed class HotkeyEntry
{
    [DataMember] public string Action { get; set; }
    [DataMember] public string Text { get; set; }
}

// UI-only settings (ui.json). The service never reads this file.
[DataContract]
internal sealed class UiSettings
{
    internal const int CurrentSchemaVersion = 1;

    public UiSettings() { Initialize(); }

    [OnDeserializing]
    private void OnDeserializing(StreamingContext context) { Initialize(); }

    private void Initialize()
    {
        SchemaVersion = CurrentSchemaVersion;
        CloseToBackground = true;
        StartWithWindows = false;
        UpdateChannel = string.Empty;
        IdleLockMinutes = 10;
        UnlockMinutes = 10;
        UnlockUntil = string.Empty;
        GlobalHotkeys = new List<HotkeyEntry>();
    }

    [DataMember] public int SchemaVersion { get; set; }
    [DataMember] public bool CloseToBackground { get; set; }
    [DataMember] public bool StartWithWindows { get; set; }
    // "stable" | "beta" | empty (unset: prerelease builds follow beta, others stable)
    [DataMember] public string UpdateChannel { get; set; }
    [DataMember] public int IdleLockMinutes { get; set; }
    [DataMember] public int UnlockMinutes { get; set; }
    [DataMember] public string UnlockUntil { get; set; }
    [DataMember] public List<HotkeyEntry> GlobalHotkeys { get; set; }
}
