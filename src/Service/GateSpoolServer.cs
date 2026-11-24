using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

// Serves Gate\Requests\*.req and answers with Gate\Responses\*.res (design section 6).
internal sealed class GateSpoolServer : IDisposable
{
    private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);
    private static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(1);

    private readonly PolicyHost policyHost;
    private readonly UnlockTable unlocks;
    private readonly string gatePath;
    private readonly object sync = new object();
    private readonly HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
    private FileSystemWatcher watcher;
    private Timer scan;
    private int scanning;
    private DateTime lastCleanup = DateTime.UtcNow;
    private volatile bool stopping;

    internal GateSpoolServer(PolicyHost policyHost, UnlockTable unlocks, string gatePath)
    {
        this.policyHost = policyHost;
        this.unlocks = unlocks;
        this.gatePath = gatePath;
    }

    internal void Start()
    {
        stopping = false;
        try
        {
            watcher = new FileSystemWatcher(WapPaths.RequestsDir, "*" + GateSpool.RequestExtension);
            watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite;
            watcher.InternalBufferSize = 32768;
            watcher.Created += delegate { ScanSoon(); };
            watcher.Changed += delegate { ScanSoon(); };
            watcher.Error += delegate { ScanSoon(); };
            watcher.EnableRaisingEvents = true;
        }
        catch (Exception ex)
        {
            // The 300 ms scan below still serves requests.
            ServiceLog.Exception("spool.watcher.failed", ex);
        }
        scan = new Timer(delegate { Scan(); }, null, 0, 300);
    }

    public void Dispose()
    {
        stopping = true;
        if (scan != null) { scan.Dispose(); scan = null; }
        if (watcher != null) { watcher.Dispose(); watcher = null; }
    }

    private void ScanSoon()
    {
        ThreadPool.QueueUserWorkItem(delegate { Scan(); });
    }

    private void Scan()
    {
        if (stopping || Interlocked.Exchange(ref scanning, 1) != 0) return;
        try
        {
            foreach (string file in Directory.GetFiles(WapPaths.RequestsDir, "*" + GateSpool.RequestExtension))
            {
                if (stopping) return;
                try { Handle(file); }
                catch (Exception ex) { ServiceLog.Exception("spool.request.failed", ex); }
            }
            CleanupIfDue();
        }
        catch (DirectoryNotFoundException) { }
        catch (IOException ex) { ServiceLog.Exception("spool.scan.failed", ex); }
        finally { Interlocked.Exchange(ref scanning, 0); }
    }

    private void Handle(string file)
    {
        string name = Path.GetFileNameWithoutExtension(file);
        if (!GateSpool.IsValidNonce(name))
        {
            TryDelete(file);
            return;
        }
        lock (sync)
        {
            if (!seen.Add(name)) return;
            if (seen.Count > 4096) seen.Clear();
        }

        string text;
        SecurityIdentifier owner;
        try
        {
            using (var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                if (stream.Length > GateSpool.MaxRequestBytes)
                {
                    stream.Close();
                    TryDelete(file);
                    return;
                }
                owner = new FileInfo(file).GetAccessControl(AccessControlSections.Owner)
                    .GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
                byte[] bytes = new byte[stream.Length];
                int offset = 0;
                while (offset < bytes.Length)
                {
                    int count = stream.Read(bytes, offset, bytes.Length - offset);
                    if (count == 0) break;
                    offset += count;
                }
                text = Utf8.GetString(bytes, 0, offset);
            }
        }
        catch (IOException)
        {
            // Still being written: try again on the next scan.
            lock (sync) seen.Remove(name);
            return;
        }
        // The PIN must not stay on disk a moment longer than necessary.
        TryDelete(file);

        GateRequest request = GateRequest.Parse(text);
        if (request == null || !string.Equals(request.Nonce, name, StringComparison.Ordinal))
        {
            ServiceLog.Warn("spool.request.malformed", "nonce=" + name);
            return;
        }

        string result;
        int retryAfter = 0;
        string requesterSid = null;
        string appId = null;
        try
        {
            result = Process(request, owner, out requesterSid, out retryAfter, out appId);
        }
        catch (Exception ex)
        {
            ServiceLog.Exception("spool.process.failed", ex);
            result = GateSpool.ResultDenied;
        }
        // A request that failed the identity checks is still answered ("denied") to its file owner.
        string readerSid = requesterSid;
        if (readerSid == null && owner != null && !owner.Equals(WapSecurity.AdminsSid)) readerSid = owner.Value;
        WriteResponse(request.Nonce, result, retryAfter, readerSid, appId);
    }

    private string Process(GateRequest request, SecurityIdentifier fileOwner, out string requesterSid, out int retryAfter,
        out string appId)
    {
        retryAfter = 0;
        requesterSid = null;
        appId = null;

        // Identity of the caller: a running Gate.exe from the install folder, in a user session,
        // whose token user is the same person that created the request file.
        string image = NativeApi.GetImagePath(request.Pid);
        int session = NativeApi.GetSessionId(request.Pid);
        string userSid = NativeApi.GetUserSid(request.Pid);
        if (image == null || userSid == null || session <= 0 ||
            !string.Equals(image, gatePath, StringComparison.OrdinalIgnoreCase))
        {
            ServiceLog.Warn("spool.identity.rejected", "pid=" + request.Pid, "reason=process");
            return GateSpool.ResultDenied;
        }
        requesterSid = userSid;
        if (fileOwner == null || (!string.Equals(fileOwner.Value, userSid, StringComparison.OrdinalIgnoreCase) &&
            !fileOwner.Equals(WapSecurity.AdminsSid)))
        {
            ServiceLog.Warn("spool.identity.rejected", "pid=" + request.Pid, "reason=owner");
            return GateSpool.ResultDenied;
        }

        PolicyState state = policyHost.Current;
        if (state == null) return GateSpool.ResultUnavailable;

        // A launch-mode app is named by its path; a window-mode app (browser, packaged app) by its AppId.
        AppPolicy app;
        if (request.Op == GateSpool.OpUnlock) app = PolicyRules.FindById(state.Policy, request.AppId);
        else
        {
            string path = PolicyRules.NormalizePath(request.Path);
            app = path.Length == 0 ? null : PolicyRules.FindLaunchAppByPath(state.Policy, path);
        }
        if (app == null || !app.Locked)
        {
            ServiceLog.Warn(request.Op == GateSpool.OpUnlock ? "gate.unlock" : "gate.authorize", "app=" + (app == null ? "unknown" : app.Name),
                "result=denied", "session=" + session, "reason=not-locked");
            return GateSpool.ResultDenied;
        }
        appId = app.Id;

        AuthResult result = unlocks.Authorize(state.Policy, state.Secrets, app, userSid, session,
            request.Pin, DateTime.UtcNow, request.GroupIds, out retryAfter);
        ServiceLog.Info(request.Op == GateSpool.OpUnlock ? "gate.unlock" : "gate.authorize", "app=" + app.Name,
            "result=" + result, "session=" + session, "group=" + request.GroupIds.Count);
        // The agent learns about a new unlock from enforcement.txt.
        if (result == AuthResult.Approved) policyHost.RequestApply();
        switch (result)
        {
            case AuthResult.Approved: return GateSpool.ResultApproved;
            case AuthResult.Prompt: return GateSpool.ResultPrompt;
            case AuthResult.RateLimited: return GateSpool.ResultRateLimited;
            default: return GateSpool.ResultDenied;
        }
    }

    private void WriteResponse(string nonce, string result, int retryAfter, string requesterSid, string appId)
    {
        string final = Path.Combine(WapPaths.ResponsesDir, nonce + GateSpool.ResponseExtension);
        string temporary = final + ".tmp";
        try
        {
            var response = new GateResponse { Nonce = nonce, Result = result, RetryAfterSeconds = retryAfter, AppId = appId ?? string.Empty };
            using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                byte[] bytes = Utf8.GetBytes(response.Serialize());
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }
            if (!string.IsNullOrEmpty(requesterSid))
            {
                // Only SYSTEM, Administrators and the requester may read (and clear) the answer.
                var security = new FileSecurity();
                security.SetAccessRuleProtection(true, false);
                security.AddAccessRule(new FileSystemAccessRule(WapSecurity.SystemSid, FileSystemRights.FullControl, AccessControlType.Allow));
                security.AddAccessRule(new FileSystemAccessRule(WapSecurity.AdminsSid, FileSystemRights.FullControl, AccessControlType.Allow));
                security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(requesterSid),
                    FileSystemRights.Read | FileSystemRights.Delete | FileSystemRights.Synchronize, AccessControlType.Allow));
                new FileInfo(temporary).SetAccessControl(security);
            }
            File.Move(temporary, final);
        }
        catch (Exception ex)
        {
            ServiceLog.Exception("spool.response.failed", ex);
            TryDelete(temporary);
        }
    }

    private void CleanupIfDue()
    {
        DateTime now = DateTime.UtcNow;
        if (now - lastCleanup < TimeSpan.FromSeconds(30)) return;
        lastCleanup = now;
        foreach (string directory in new[] { WapPaths.RequestsDir, WapPaths.ResponsesDir })
        {
            foreach (string file in Directory.GetFiles(directory))
            {
                try
                {
                    if (now - File.GetLastWriteTimeUtc(file) > StaleAfter) File.Delete(file);
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
