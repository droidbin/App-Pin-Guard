using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

// Creates the data folders and enforces their ACLs on every service start (design section 3.2).
internal static class SecureLayout
{
    private static readonly InheritanceFlags BothInherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

    internal static void Ensure()
    {
        Directory.CreateDirectory(WapPaths.Root);
        Protect(WapPaths.Root, null);

        EnsureDirectory(WapPaths.RuntimeDir, true, WapSecurity.UsersSid, FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize);
        EnsureDirectory(WapPaths.AttemptsDir, true, null, 0);
        EnsureDirectory(WapPaths.GateDir, true, null, 0);
        EnsureRequestsDirectory();
        EnsureDirectory(WapPaths.ResponsesDir, true, null, 0);
        EnsureDirectory(WapPaths.LogsDir, true, WapSecurity.UsersSid, FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize);

        foreach (string file in new[] { WapPaths.PolicyFile, WapPaths.SecretsFile, WapPaths.UiSettingsFile })
            if (File.Exists(file)) ProtectFile(file);

        // Files left by an older build keep their old, SYSTEM-only ACL (File.Replace preserves it), which hides
        // them from the agent. Reset them so every user can read them.
        foreach (string file in new[] { WapPaths.EnforcementFile, WapPaths.StatusFile })
            if (File.Exists(file)) ShareRuntimeFile(file);

        RemoveLegacy();
    }

    private static void EnsureDirectory(string path, bool protect, SecurityIdentifier readers, FileSystemRights readRights)
    {
        Directory.CreateDirectory(path);
        if (protect) Protect(path, readers == null ? null : new FileSystemAccessRule(readers, readRights, BothInherit,
            PropagationFlags.None, AccessControlType.Allow));
    }

    // Users may create files here and nothing else: they cannot list, read, replace or delete anyone's request.
    private static void EnsureRequestsDirectory()
    {
        string path = WapPaths.RequestsDir;
        Directory.CreateDirectory(path);
        var security = NewProtectedSecurity();
        security.AddAccessRule(new FileSystemAccessRule(WapSecurity.UsersSid, FileSystemRights.CreateFiles,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        // The creator gets full control of the file it makes, so it can write the request body.
        security.AddAccessRule(new FileSystemAccessRule(WapSecurity.CreatorOwnerSid, FileSystemRights.FullControl,
            InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly, AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }

    private static DirectorySecurity NewProtectedSecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        try { security.SetOwner(WapSecurity.SystemSid); }
        catch (InvalidOperationException) { }
        security.AddAccessRule(new FileSystemAccessRule(WapSecurity.SystemSid, FileSystemRights.FullControl,
            BothInherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(WapSecurity.AdminsSid, FileSystemRights.FullControl,
            BothInherit, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    private static void Protect(string path, FileSystemAccessRule extra)
    {
        var security = NewProtectedSecurity();
        if (extra != null) security.AddAccessRule(extra);
        new DirectoryInfo(path).SetAccessControl(security);
    }

    // Runtime\enforcement.txt and status.json: written by the service, readable by everyone. Applied explicitly
    // after every write because File.Replace keeps the ACL of the file it replaces.
    internal static void ShareRuntimeFile(string path)
    {
        try
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(WapSecurity.SystemSid, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(WapSecurity.AdminsSid, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(WapSecurity.UsersSid, FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(security);
        }
        catch (IOException ex) { ServiceLog.Exception("layout.share.failed", ex); }
        catch (UnauthorizedAccessException ex) { ServiceLog.Exception("layout.share.failed", ex); }
    }

    // policy.json, secrets.json and ui.json: SYSTEM and Administrators only.
    private static void ProtectFile(string path)
    {
        try
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(WapSecurity.SystemSid, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(WapSecurity.AdminsSid, FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(security);
        }
        catch (IOException ex) { ServiceLog.Exception("layout.protect.failed", ex); }
        catch (UnauthorizedAccessException ex) { ServiceLog.Exception("layout.protect.failed", ex); }
    }

    // Files the earlier pipe-based design left behind.
    private static void RemoveLegacy()
    {
        try
        {
            if (Directory.Exists(WapPaths.LegacyPolicyFolder)) Directory.Delete(WapPaths.LegacyPolicyFolder, true);
            // The old write lease and per-user attempt counters (now Runtime\attempts\<sid>.json).
            foreach (string file in Directory.GetFiles(WapPaths.Root, "*.lock")) File.Delete(file);
            foreach (string file in Directory.GetFiles(WapPaths.Root, "launch-attempts-*.json")) File.Delete(file);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
