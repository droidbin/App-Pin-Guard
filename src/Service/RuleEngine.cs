using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32;

// Keeps the Image File Execution Options rules in line with the policy and heals them when they are removed.
// The key layout (WindowsAppProtectorManaged marker, WAP.Launch.N filters, Gate.exe --blocked) is unchanged
// because the uninstall script and installed copies depend on it.
internal sealed class RuleEngine : IDisposable
{
    private const string IfeoRegistryPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string SaferCodeIdentifiersPath = @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers";
    private const string MarkerName = "WindowsAppProtectorManaged";

    private readonly string gatePath;
    private readonly StatusWriter status;
    private readonly Action onExternalChange;
    private readonly object sync = new object();
    // Rule name -> signature of what was last applied. A rule that has to be rewritten identically was tampered with.
    private readonly Dictionary<string, string> applied = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> loggedStates = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    private readonly ManualResetEvent stopWatching = new ManualResetEvent(false);
    private Thread watchThread;

    internal RuleEngine(string gatePath, StatusWriter status, Action onExternalChange)
    {
        this.gatePath = gatePath;
        this.status = status;
        this.onExternalChange = onExternalChange;
    }

    internal bool GateAvailable
    {
        get { return File.Exists(gatePath); }
    }

    // Returns the rule state of every app in the policy, keyed by AppId.
    internal Dictionary<string, string> Sync(PolicyDocument policy)
    {
        lock (sync)
        {
            var states = new Dictionary<string, string>(StringComparer.Ordinal);
            var groups = new Dictionary<string, List<AppPolicy>>(StringComparer.OrdinalIgnoreCase);
            foreach (AppPolicy app in policy.Apps)
            {
                if (!app.Locked) { states[app.Id] = StatusDocument.RuleNone; continue; }
                if (PolicyRules.IsWindowMode(app)) { states[app.Id] = StatusDocument.RuleWindow; continue; }
                string name = PolicyRules.GetRuleName(app);
                if (string.IsNullOrWhiteSpace(name)) { states[app.Id] = "error:no-name"; continue; }
                List<AppPolicy> list;
                if (!groups.TryGetValue(name, out list)) groups[name] = list = new List<AppPolicy>();
                list.Add(app);
            }

            bool gateExists = GateAvailable;
            try
            {
                using (var localMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                {
                    CleanupLegacySoftwareRestrictionRules(localMachine, policy.Apps);
                    using (RegistryKey root = localMachine.OpenSubKey(IfeoRegistryPath, true))
                    {
                        if (root == null)
                        {
                            foreach (var group in groups)
                                foreach (AppPolicy app in group.Value) states[app.Id] = "error:no-ifeo-root";
                            return states;
                        }

                        foreach (string existing in ReadManagedRuleNames(root).Except(groups.Keys, StringComparer.OrdinalIgnoreCase).ToArray())
                        {
                            DeleteManagedRule(root, existing);
                            applied.Remove(existing);
                        }

                        foreach (var group in groups)
                        {
                            string state = ApplyGroup(root, group.Key, group.Value, policy.EnableLaunchGate && gateExists);
                            foreach (AppPolicy app in group.Value) states[app.Id] = state;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                ServiceLog.Exception("rule.sync.denied", ex);
                foreach (var group in groups)
                    foreach (AppPolicy app in group.Value)
                        if (!states.ContainsKey(app.Id)) states[app.Id] = "error:access-denied";
            }
            catch (SecurityException ex)
            {
                ServiceLog.Exception("rule.sync.denied", ex);
                foreach (var group in groups)
                    foreach (AppPolicy app in group.Value)
                        if (!states.ContainsKey(app.Id)) states[app.Id] = "error:access-denied";
            }
            return states;
        }
    }

    private string ApplyGroup(RegistryKey root, string name, List<AppPolicy> apps, bool useGateRequested)
    {
        using (RegistryKey key = root.CreateSubKey(name))
        {
            if (key == null) return "error:create-failed";
            bool owned = Convert.ToString(key.GetValue(MarkerName)) == "1";
            // Another product's rule on this executable: leave it alone and say so.
            if (key.GetSubKeyNames().Any(child => !IsManagedFilter(key, child)) ||
                (!owned && (key.GetValue("Debugger") != null || key.GetValue("UseFilter") != null)))
            {
                LogState(name, "conflict");
                applied.Remove(name);
                return StatusDocument.RuleConflict;
            }

            bool useGate = useGateRequested && apps.All(PolicyRules.CanUseGate);
            string[] targets = useGate
                ? apps.Select(app => Path.GetFullPath(app.Path)).Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray()
                : new string[0];
            string signature = useGate ? "gate|" + string.Join("|", targets) : "blocked";

            bool changed = SetString(key, MarkerName, "1");
            if (useGate)
            {
                for (int index = 0; index < targets.Length; index++)
                {
                    string filterName = "WAP.Launch." + index;
                    RegistryKey filter = key.OpenSubKey(filterName, true);
                    if (filter == null) { filter = key.CreateSubKey(filterName); changed = true; }
                    using (filter)
                    {
                        changed |= SetString(filter, MarkerName, "1");
                        changed |= SetString(filter, "FilterFullPath", targets[index]);
                        changed |= SetString(filter, "Debugger", "\"" + gatePath + "\" --launch");
                    }
                }
                changed |= SetDword(key, "UseFilter", 1);
                if (key.GetValue("Debugger") != null) { key.DeleteValue("Debugger", false); changed = true; }
                changed |= DeleteManagedFilters(key, Enumerable.Range(0, targets.Length).Select(i => "WAP.Launch." + i));
            }
            else
            {
                // Gate.exe runs unelevated, so the block message always shows (the UI exe needs admin: error 740).
                changed |= SetString(key, "Debugger", "\"" + gatePath + "\" --blocked");
                if (key.GetValue("UseFilter") != null) { key.DeleteValue("UseFilter", false); changed = true; }
                changed |= DeleteManagedFilters(key, Enumerable.Empty<string>());
            }

            string previous;
            if (changed && applied.TryGetValue(name, out previous) && previous == signature)
                status.AddTamper("IFEO rule restored: " + name);
            applied[name] = signature;

            string state = useGate ? StatusDocument.RuleGate : StatusDocument.RuleBlocked;
            LogState(name, state);
            return state;
        }
    }

    private void LogState(string name, string state)
    {
        string previous;
        if (loggedStates.TryGetValue(name, out previous) && previous == state) return;
        loggedStates[name] = state;
        ServiceLog.Info("rule.applied", "app=" + name, "mode=" + state);
    }

    private static bool SetString(RegistryKey key, string name, string value)
    {
        if (string.Equals(key.GetValue(name) as string, value, StringComparison.Ordinal)) return false;
        key.SetValue(name, value, RegistryValueKind.String);
        return true;
    }

    private static bool SetDword(RegistryKey key, string name, int value)
    {
        object current = key.GetValue(name);
        if (current is int && (int)current == value) return false;
        key.SetValue(name, value, RegistryValueKind.DWord);
        return true;
    }

    private static bool IsManagedFilter(RegistryKey key, string name)
    {
        if (!name.StartsWith("WAP.Launch.", StringComparison.Ordinal)) return false;
        using (RegistryKey filter = key.OpenSubKey(name))
            return filter != null && Convert.ToString(filter.GetValue(MarkerName)) == "1";
    }

    private static bool DeleteManagedFilters(RegistryKey key, IEnumerable<string> keep)
    {
        bool deleted = false;
        foreach (string name in key.GetSubKeyNames().Except(keep, StringComparer.OrdinalIgnoreCase).ToArray())
        {
            if (!IsManagedFilter(key, name)) continue;
            key.DeleteSubKey(name, false);
            deleted = true;
        }
        return deleted;
    }

    private static IEnumerable<string> ReadManagedRuleNames(RegistryKey root)
    {
        foreach (string name in root.GetSubKeyNames())
        {
            RegistryKey key = null;
            try
            {
                key = root.OpenSubKey(name);
                if (key != null && Convert.ToString(key.GetValue(MarkerName)) == "1") yield return name;
            }
            finally
            {
                if (key != null) key.Dispose();
            }
        }
    }

    private static void DeleteManagedRule(RegistryKey root, string exeName)
    {
        try
        {
            using (RegistryKey key = root.OpenSubKey(exeName, true))
            {
                if (key == null || Convert.ToString(key.GetValue(MarkerName)) != "1") return;
                key.DeleteValue("Debugger", false);
                key.DeleteValue(MarkerName, false);
                DeleteManagedFilters(key, Enumerable.Empty<string>());
                if (key.SubKeyCount == 0) key.DeleteValue("UseFilter", false);
            }
            try
            {
                using (RegistryKey key = root.OpenSubKey(exeName))
                    if (key == null || key.ValueCount != 0 || key.SubKeyCount != 0) return;
                root.DeleteSubKey(exeName, false);
            }
            catch (Exception) { }
        }
        catch (Exception) { }
    }

    // ---- registry change watcher -------------------------------------------------------------------

    internal void StartWatching()
    {
        if (watchThread != null) return;
        stopWatching.Reset();
        watchThread = new Thread(Watch) { IsBackground = true, Name = "WAP IFEO watcher" };
        watchThread.Start();
    }

    public void Dispose()
    {
        stopWatching.Set();
        Thread thread = watchThread;
        if (thread != null) thread.Join(3000);
        watchThread = null;
    }

    private void Watch()
    {
        try
        {
            using (var localMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (RegistryKey root = localMachine.OpenSubKey(IfeoRegistryPath))
            using (var changed = new ManualResetEvent(false))
            {
                if (root == null) return;
                IntPtr handle = root.Handle.DangerousGetHandle();
                while (!stopWatching.WaitOne(0))
                {
                    changed.Reset();
                    // REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, whole subtree, signalled through the event.
                    int result = RegNotifyChangeKeyValue(handle, true, 0x1 | 0x4, changed.SafeWaitHandle.DangerousGetHandle(), true);
                    if (result != 0)
                    {
                        ServiceLog.Error("rule.watch.failed", "code=" + result);
                        return;
                    }
                    int index = WaitHandle.WaitAny(new WaitHandle[] { stopWatching, changed });
                    if (index == 0) return;
                    // Let a burst of writes (ours or a tool's) settle before re-applying.
                    if (stopWatching.WaitOne(250)) return;
                    try { onExternalChange(); }
                    catch (Exception ex) { ServiceLog.Exception("rule.watch.callback.failed", ex); }
                }
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Exception("rule.watch.crashed", ex);
        }
    }

    [DllImport("advapi32.dll")]
    private static extern int RegNotifyChangeKeyValue(IntPtr key, bool watchSubtree, uint filter, IntPtr eventHandle, bool asynchronous);

    // ---- legacy Software Restriction Policy rules (older builds) -----------------------------------

    private static void CleanupLegacySoftwareRestrictionRules(RegistryKey localMachine, IEnumerable<AppPolicy> apps)
    {
        using (RegistryKey codeIdentifiers = localMachine.OpenSubKey(SaferCodeIdentifiersPath, true))
        {
            if (codeIdentifiers == null) return;
            HashSet<string> signatures = BuildLegacyRuleSignatures(apps);
            if (signatures.Count == 0) return;
            DeleteMatchingLegacyRules(codeIdentifiers, @"0\Paths", signatures);
            DeleteMatchingLegacyRules(codeIdentifiers, @"0\Hashes", signatures);
        }
    }

    private static HashSet<string> BuildLegacyRuleSignatures(IEnumerable<AppPolicy> apps)
    {
        var signatures = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (AppPolicy app in apps)
        {
            if (app == null) continue;
            AddSignature(signatures, app.Name);
            AddSignature(signatures, app.Path);
            AddSignature(signatures, app.ExecutableName);
            AddSignature(signatures, app.PackageFamilyName);
            AddSignature(signatures, app.AppUserModelId);
            if (!string.IsNullOrWhiteSpace(app.PackageFamilyName))
            {
                int separator = app.PackageFamilyName.IndexOf('_');
                if (separator > 0) AddSignature(signatures, app.PackageFamilyName.Substring(0, separator));
            }
        }
        return signatures;
    }

    private static void AddSignature(HashSet<string> signatures, string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        string trimmed = value.Trim();
        if (trimmed.Length >= 4) signatures.Add(trimmed);
    }

    private static void DeleteMatchingLegacyRules(RegistryKey codeIdentifiers, string relativePath, HashSet<string> signatures)
    {
        using (RegistryKey container = codeIdentifiers.OpenSubKey(relativePath, true))
        {
            if (container == null) return;
            foreach (string ruleName in container.GetSubKeyNames())
            {
                try
                {
                    using (RegistryKey rule = container.OpenSubKey(ruleName))
                        if (rule == null || !LegacyRuleMatches(rule, signatures)) continue;
                    DeleteLegacyRule(container, ruleName);
                }
                catch (Exception) { }
            }
        }
    }

    private static bool LegacyRuleMatches(RegistryKey rule, HashSet<string> signatures)
    {
        foreach (string valueName in new[] { "Description", "ItemPath", "ItemData" })
        {
            string value = Convert.ToString(rule.GetValue(valueName));
            if (string.IsNullOrWhiteSpace(value)) continue;
            foreach (string signature in signatures)
                if (value.IndexOf(signature, StringComparison.OrdinalIgnoreCase) >= 0) return true;
        }
        return false;
    }

    private static void DeleteLegacyRule(RegistryKey container, string ruleName)
    {
        try
        {
            container.DeleteSubKeyTree(ruleName, false);
            return;
        }
        catch (UnauthorizedAccessException) { }
        catch (SecurityException) { }

        if (!RepairLegacyRuleAccess(container, ruleName)) return;
        container.DeleteSubKeyTree(ruleName, false);
    }

    private static bool RepairLegacyRuleAccess(RegistryKey container, string ruleName)
    {
        NativeApi.EnablePrivilege("SeTakeOwnershipPrivilege");
        NativeApi.EnablePrivilege("SeRestorePrivilege");
        NativeApi.EnablePrivilege("SeBackupPrivilege");
        try
        {
            using (RegistryKey rule = container.OpenSubKey(ruleName, RegistryKeyPermissionCheck.ReadWriteSubTree,
                RegistryRights.ReadKey | RegistryRights.ReadPermissions | RegistryRights.ChangePermissions | RegistryRights.TakeOwnership))
            {
                if (rule == null) return false;
                RegistrySecurity security = rule.GetAccessControl(AccessControlSections.All);
                security.SetOwner(WapSecurity.AdminsSid);
                security.SetAccessRuleProtection(false, false);
                security.SetAccessRule(new RegistryAccessRule(WapSecurity.SystemSid, RegistryRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                security.SetAccessRule(new RegistryAccessRule(WapSecurity.AdminsSid, RegistryRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                rule.SetAccessControl(security);
                return true;
            }
        }
        catch (Exception)
        {
            return false;
        }
    }
}
