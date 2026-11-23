using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Security.AccessControl;

// Converts the pre-redesign config.json (StorageVersion 0/2) into policy.json + secrets.json + ui.json.
// The service and the UI both call Run(); whichever runs first produces the same result.
internal static class LegacyMigration
{
    // Returns true when a migration was performed by this call.
    internal static bool Run()
    {
        if (!File.Exists(WapPaths.LegacyConfigFile) || File.Exists(WapPaths.PolicyFile)) return false;
        using (WapSecurity.AcquirePolicyLock(10000))
        {
            // Re-check inside the lock: the other component may have finished while this one waited.
            if (!File.Exists(WapPaths.LegacyConfigFile) || File.Exists(WapPaths.PolicyFile)) return false;

            LegacyConfig config = ReadLegacyConfig(WapPaths.LegacyConfigFile);
            if (config == null) return false;
            if (config.ProtectedApps == null) config.ProtectedApps = new List<LegacyApp>();

            // The shared file can lack the PIN when an older build kept it in the user profile.
            string salt = config.AppPinSalt ?? string.Empty;
            string hash = config.AppPinHash ?? string.Empty;
            if (string.IsNullOrEmpty(hash))
            {
                LegacyPinBackup backup = TryRead<LegacyPinBackup>(WapPaths.LegacyUserPinFile);
                if (backup != null && !string.IsNullOrEmpty(backup.Hash))
                {
                    salt = backup.Salt ?? string.Empty;
                    hash = backup.Hash ?? string.Empty;
                }
            }

            var policy = new PolicyDocument();
            var secrets = new SecretsDocument();
            var ui = new UiSettings();
            string now = DateTime.UtcNow.ToString("o");

            policy.EnableLaunchGate = config.EnableLaunchGate;
            policy.CloseAppsOnLock = config.CloseAppsOnLock;
            secrets.AppPin = new PinRecord { Salt = salt, Hash = hash, Version = DateTime.UtcNow.Ticks };

            foreach (LegacyApp old in config.ProtectedApps)
            {
                if (old == null) continue;
                var app = new AppPolicy
                {
                    Id = Guid.NewGuid().ToString("N"),
                    Name = old.Name ?? string.Empty,
                    Path = old.Path ?? string.Empty,
                    IsPackaged = old.IsPackaged,
                    PackageFamilyName = old.PackageFamilyName ?? string.Empty,
                    AppUserModelId = old.AppUserModelId ?? string.Empty,
                    ExecutableName = old.ExecutableName ?? string.Empty,
                    Locked = old.Enabled,
                    LockedAtUtc = now,
                };
                app.Launch.AllowedMinutes = old.LaunchAllowedMinutes;
                app.Launch.LockStartMinute = old.LaunchLockStartMinute;
                app.Launch.LockEndMinute = old.LaunchLockEndMinute;
                app.Launch.RelockOnExit = old.LaunchRelockOnExit;
                if (!string.IsNullOrEmpty(old.LaunchPinHash))
                {
                    app.Launch.HasOwnPin = true;
                    secrets.SetAppPin(app.Id, new PinRecord
                    {
                        Salt = old.LaunchPinSalt ?? string.Empty,
                        Hash = old.LaunchPinHash,
                        Version = DateTime.UtcNow.Ticks,
                    });
                }
                policy.Apps.Add(app);
            }

            ui.CloseToBackground = config.CloseToBackground;
            ui.StartWithWindows = config.StartWithWindows;
            ui.UpdateChannel = config.UpdateChannel ?? string.Empty;
            ui.IdleLockMinutes = config.IdleLockMinutes;
            ui.UnlockMinutes = config.UnlockMinutes;
            ui.UnlockUntil = config.UnlockUntil ?? string.Empty;
            if (config.GlobalHotkeys != null)
            {
                foreach (KeyValuePair<string, string> hotkey in config.GlobalHotkeys)
                    if (!string.IsNullOrEmpty(hotkey.Key))
                        ui.GlobalHotkeys.Add(new HotkeyEntry { Action = hotkey.Key, Text = hotkey.Value ?? string.Empty });
            }

            // Secrets and ui first; policy.json is the commit point, so a crash re-runs the whole migration.
            PolicyStore.WriteAtomic(WapPaths.SecretsFile, secrets);
            PolicyStore.WriteAtomic(WapPaths.UiSettingsFile, ui);
            policy.Revision = 1;
            PolicyStore.WriteAtomic(WapPaths.PolicyFile, policy);

            ArchiveOriginal();
            return true;
        }
    }

    // Removes the profile copies of the PIN data. Only the UI calls this: the service never touches a user profile.
    internal static void CleanUserProfile()
    {
        TryDelete(WapPaths.LegacyUserPinFile);
        TryDelete(WapPaths.LegacyUserConfigFile);
    }

    private static void ArchiveOriginal()
    {
        string source = WapPaths.LegacyConfigFile;
        string backup = WapPaths.LegacyConfigBackup;
        try
        {
            if (File.Exists(backup)) File.Delete(backup);
            File.Move(source, backup);
            // Only SYSTEM and Administrators may read the backup: it still holds the old PIN hashes.
            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(WapSecurity.AdminsSid);
            security.AddAccessRule(new FileSystemAccessRule(WapSecurity.SystemSid, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(WapSecurity.AdminsSid, FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(backup).SetAccessControl(security);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        catch (InvalidOperationException) { }
    }

    // config.json stores GlobalHotkeys as a plain JSON object, which needs the simple dictionary format.
    private static LegacyConfig ReadLegacyConfig(string path)
    {
        byte[] bytes = File.ReadAllBytes(path);
        int start = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? 3 : 0;
        var settings = new System.Runtime.Serialization.Json.DataContractJsonSerializerSettings
        {
            UseSimpleDictionaryFormat = true,
        };
        try
        {
            using (var stream = new MemoryStream(bytes, start, bytes.Length - start))
                return new System.Runtime.Serialization.Json.DataContractJsonSerializer(typeof(LegacyConfig), settings)
                    .ReadObject(stream) as LegacyConfig;
        }
        catch (SerializationException ex)
        {
            throw new InvalidDataException("Cannot parse config.json: " + ex.Message, ex);
        }
    }

    private static T TryRead<T>(string path) where T : class
    {
        try { return PolicyStore.Read<T>(path); }
        catch (InvalidDataException) { return null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    // ---- legacy shapes -----------------------------------------------------------------------------
    // beta.13 and earlier wrote config.json with System.Text.Json (hotkeys as a JSON object) or with the
    // service's DataContract model. The hotkey object is read through a custom shape below.

    [DataContract]
    private sealed class LegacyConfig
    {
        [DataMember] public bool CloseToBackground { get; set; }
        [DataMember] public bool CloseAppsOnLock { get; set; }
        [DataMember] public bool StartWithWindows { get; set; }
        [DataMember] public bool EnableLaunchGate { get; set; }
        [DataMember] public string UpdateChannel { get; set; }
        [DataMember] public int IdleLockMinutes { get; set; }
        [DataMember] public int UnlockMinutes { get; set; }
        [DataMember] public string UnlockUntil { get; set; }
        [DataMember] public string AppPinSalt { get; set; }
        [DataMember] public string AppPinHash { get; set; }
        [DataMember] public Dictionary<string, string> GlobalHotkeys { get; set; }
        [DataMember] public List<LegacyApp> ProtectedApps { get; set; }

        [OnDeserializing]
        private void OnDeserializing(StreamingContext context)
        {
            CloseToBackground = true;
            EnableLaunchGate = true;
            IdleLockMinutes = 10;
            UnlockMinutes = 10;
        }
    }

    [DataContract]
    private sealed class LegacyApp
    {
        [DataMember] public string Name { get; set; }
        [DataMember] public string Path { get; set; }
        [DataMember] public bool IsPackaged { get; set; }
        [DataMember] public string PackageFamilyName { get; set; }
        [DataMember] public string AppUserModelId { get; set; }
        [DataMember] public string ExecutableName { get; set; }
        [DataMember] public bool Enabled { get; set; }
        [DataMember] public string LaunchPinSalt { get; set; }
        [DataMember] public string LaunchPinHash { get; set; }
        [DataMember] public int LaunchAllowedMinutes { get; set; }
        [DataMember] public int? LaunchLockStartMinute { get; set; }
        [DataMember] public int? LaunchLockEndMinute { get; set; }
        [DataMember] public bool LaunchRelockOnExit { get; set; }

        [OnDeserializing]
        private void OnDeserializing(StreamingContext context) { Enabled = true; }
    }

    [DataContract]
    private sealed class LegacyPinBackup
    {
        [DataMember] public string Salt { get; set; }
        [DataMember] public string Hash { get; set; }
    }
}
