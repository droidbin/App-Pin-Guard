using System;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Threading;

// Reads and atomically writes policy.json, secrets.json and ui.json.
internal static class PolicyStore
{
    private const int LockTimeoutMilliseconds = 10000;
    private static readonly int[] RetryDelays = { 50, 100, 200 };

    // Returns null when the file does not exist. Throws InvalidDataException when it cannot be parsed.
    internal static T Read<T>(string path) where T : class
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                if (!File.Exists(path)) return null;
                byte[] bytes;
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete))
                {
                    bytes = new byte[stream.Length];
                    int offset = 0;
                    while (offset < bytes.Length)
                    {
                        int count = stream.Read(bytes, offset, bytes.Length - offset);
                        if (count == 0) break;
                        offset += count;
                    }
                    if (offset != bytes.Length) Array.Resize(ref bytes, offset);
                }

                int start = 0;
                if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) start = 3;
                if (bytes.Length - start == 0) throw new InvalidDataException("File is empty: " + path);
                using (var memory = new MemoryStream(bytes, start, bytes.Length - start))
                {
                    var serializer = new DataContractJsonSerializer(typeof(T));
                    var value = serializer.ReadObject(memory) as T;
                    if (value == null) throw new InvalidDataException("File has no content: " + path);
                    return value;
                }
            }
            catch (IOException)
            {
                if (attempt >= RetryDelays.Length) throw;
                Thread.Sleep(RetryDelays[attempt]);
            }
            catch (System.Runtime.Serialization.SerializationException ex)
            {
                throw new InvalidDataException("Cannot parse " + Path.GetFileName(path) + ": " + ex.Message, ex);
            }
        }
    }

    // Temp file in the same folder, flushed to disk, then swapped in so readers never see a partial file.
    internal static void WriteAtomic<T>(string path, T value) where T : class
    {
        string directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                new DataContractJsonSerializer(typeof(T)).WriteObject(stream, value);
                stream.Flush(true);
            }
            if (File.Exists(path)) File.Replace(temporary, path, null);
            else File.Move(temporary, path);
        }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    // ---- policy.json -------------------------------------------------------------------------------

    // Null when policy.json does not exist yet. Throws on an unknown SchemaVersion.
    internal static PolicyDocument LoadPolicy()
    {
        var policy = Read<PolicyDocument>(WapPaths.PolicyFile);
        if (policy == null) return null;
        if (policy.SchemaVersion != PolicyDocument.CurrentSchemaVersion)
            throw new InvalidDataException("Unsupported policy schema version " + policy.SchemaVersion + ".");
        if (policy.Apps == null) policy.Apps = new System.Collections.Generic.List<AppPolicy>();
        policy.Apps.RemoveAll(delegate(AppPolicy app) { return app == null; });
        foreach (AppPolicy app in policy.Apps)
        {
            if (string.IsNullOrEmpty(app.Id)) app.Id = Guid.NewGuid().ToString("N");
            if (app.Launch == null) app.Launch = new LaunchPolicy();
        }
        return policy;
    }

    internal static SecretsDocument LoadSecrets()
    {
        var secrets = Read<SecretsDocument>(WapPaths.SecretsFile);
        if (secrets == null) return new SecretsDocument();
        if (secrets.SchemaVersion != SecretsDocument.CurrentSchemaVersion)
            throw new InvalidDataException("Unsupported secrets schema version " + secrets.SchemaVersion + ".");
        if (secrets.AppPin == null) secrets.AppPin = new PinRecord();
        if (secrets.AppPins == null) secrets.AppPins = new System.Collections.Generic.List<AppPinEntry>();
        if (!PinHash.IsValid(secrets.AppPin))
            throw new InvalidDataException("secrets.json contains an invalid PIN record.");
        foreach (AppPinEntry entry in secrets.AppPins)
            if (entry == null || entry.Pin == null || !PinHash.IsValid(entry.Pin))
                throw new InvalidDataException("secrets.json contains an invalid app PIN record.");
        return secrets;
    }

    // Bumps the revision under the write lock and returns the revision that was stored.
    internal static long SavePolicy(PolicyDocument policy)
    {
        return Save(policy, null);
    }

    // Writes secrets first, then the policy that references them, under one lock.
    internal static long Save(PolicyDocument policy, SecretsDocument secrets)
    {
        if (policy == null) throw new ArgumentNullException("policy");
        policy.SchemaVersion = PolicyDocument.CurrentSchemaVersion;
        using (WapSecurity.AcquirePolicyLock(LockTimeoutMilliseconds))
        {
            long current = 0;
            try
            {
                var stored = Read<PolicyDocument>(WapPaths.PolicyFile);
                if (stored != null) current = stored.Revision;
            }
            catch (InvalidDataException) { }
            if (secrets != null) WriteAtomic(WapPaths.SecretsFile, secrets);
            policy.Revision = Math.Max(current, policy.Revision) + 1;
            WriteAtomic(WapPaths.PolicyFile, policy);
            return policy.Revision;
        }
    }

    internal static void SaveSecrets(SecretsDocument secrets)
    {
        using (WapSecurity.AcquirePolicyLock(LockTimeoutMilliseconds))
            WriteAtomic(WapPaths.SecretsFile, secrets);
    }

    // ---- ui.json -----------------------------------------------------------------------------------

    internal static UiSettings LoadUi()
    {
        var ui = Read<UiSettings>(WapPaths.UiSettingsFile);
        if (ui == null) return new UiSettings();
        if (ui.GlobalHotkeys == null) ui.GlobalHotkeys = new System.Collections.Generic.List<HotkeyEntry>();
        return ui;
    }

    internal static void SaveUi(UiSettings ui)
    {
        using (WapSecurity.AcquirePolicyLock(LockTimeoutMilliseconds))
            WriteAtomic(WapPaths.UiSettingsFile, ui);
    }
}
