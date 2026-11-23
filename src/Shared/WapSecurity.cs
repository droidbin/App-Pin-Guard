using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

internal static class WapSecurity
{
    internal static SecurityIdentifier SystemSid
    {
        get { return new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null); }
    }

    internal static SecurityIdentifier AdminsSid
    {
        get { return new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null); }
    }

    internal static SecurityIdentifier UsersSid
    {
        get { return new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null); }
    }

    internal static SecurityIdentifier CreatorOwnerSid
    {
        get { return new SecurityIdentifier(WellKnownSidType.CreatorOwnerSid, null); }
    }

    internal static SecurityIdentifier GetFileOwner(string path)
    {
        var security = new FileInfo(path).GetAccessControl(AccessControlSections.Owner);
        return security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
    }

    // Files the service writes are owned by SYSTEM or, depending on the token's default owner, Administrators.
    // A standard user can create files owned by neither, and cannot write into the folders involved at all.
    internal static bool IsOwnedByServiceAccount(string path)
    {
        try
        {
            SecurityIdentifier owner = GetFileOwner(path);
            return owner != null && (owner.Equals(SystemSid) || owner.Equals(AdminsSid));
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    // Serializes policy/secrets writers across the UI, the service and the installer helper.
    internal static IDisposable AcquirePolicyLock(int timeoutMilliseconds)
    {
        bool created;
#if NET5_0_OR_GREATER
        // The UI runs elevated; the default DACL of an elevated token already grants only SYSTEM and Administrators.
        Mutex mutex = new Mutex(false, WapPaths.PolicyWriteMutex, out created);
#else
        var security = new MutexSecurity();
        security.AddAccessRule(new MutexAccessRule(SystemSid, MutexRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new MutexAccessRule(AdminsSid, MutexRights.FullControl, AccessControlType.Allow));
        Mutex mutex = new Mutex(false, WapPaths.PolicyWriteMutex, out created, security);
#endif
        bool owned = false;
        try
        {
            try { owned = mutex.WaitOne(timeoutMilliseconds); }
            catch (AbandonedMutexException) { owned = true; }
            if (!owned) throw new TimeoutException("Timed out waiting for the policy write lock.");
            return new PolicyLock(mutex);
        }
        catch
        {
            if (owned) mutex.ReleaseMutex();
            mutex.Dispose();
            throw;
        }
    }

    private sealed class PolicyLock : IDisposable
    {
        private Mutex mutex;

        internal PolicyLock(Mutex mutex) { this.mutex = mutex; }

        public void Dispose()
        {
            Mutex held = Interlocked.Exchange(ref mutex, null);
            if (held == null) return;
            try { held.ReleaseMutex(); }
            catch (ApplicationException) { }
            catch (InvalidOperationException) { }
            held.Dispose();
        }
    }
}
