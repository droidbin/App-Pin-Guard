using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

// File-spool protocol between Gate.exe (user session) and the service (SYSTEM).
// Gate creates Gate\Requests\<nonce>.req; the service answers with Gate\Responses\<nonce>.res.
internal static class GateSpool
{
    internal const string Magic = "WAP-GATE 1";
    // authorize: a launch-mode app named by its path. unlock: a locked app named by its AppId (window-mode apps).
    internal const string OpAuthorize = "authorize";
    internal const string OpUnlock = "unlock";
    internal const string ResultApproved = "approved";
    internal const string ResultDenied = "denied";
    internal const string ResultPrompt = "prompt";
    internal const string ResultRateLimited = "ratelimited";
    internal const string ResultUnavailable = "unavailable";
    internal const int MaxRequestBytes = 8 * 1024;
    internal const int ResponseTimeoutMilliseconds = 4000;
    internal const string RequestExtension = ".req";
    internal const string ResponseExtension = ".res";

    private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);

    internal static string NewNonce()
    {
        byte[] bytes = new byte[16];
        using (var random = RandomNumberGenerator.Create()) random.GetBytes(bytes);
        var text = new StringBuilder(32);
        foreach (byte value in bytes) text.Append(value.ToString("x2", CultureInfo.InvariantCulture));
        return text.ToString();
    }

    internal static bool IsValidNonce(string nonce)
    {
        if (string.IsNullOrEmpty(nonce) || nonce.Length != 32) return false;
        foreach (char c in nonce)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        return true;
    }

    internal static string EncodeText(string value)
    {
        return Convert.ToBase64String(Utf8.GetBytes(value ?? string.Empty));
    }

    internal static string DecodeText(string value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        return Utf8.GetString(Convert.FromBase64String(value));
    }

    internal static Dictionary<string, string> ParseFields(string text, out bool validMagic)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        string[] lines = text.Replace("\r", string.Empty).Split('\n');
        validMagic = lines.Length > 0 && lines[0] == Magic;
        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i];
            int equals = line.IndexOf('=');
            if (equals <= 0) continue;
            fields[line.Substring(0, equals)] = line.Substring(equals + 1);
        }
        return fields;
    }

    // ---- client side (Gate.exe) --------------------------------------------------------------------

    // Sends a request and waits for the answer. Returns ResultUnavailable when the service does not respond.
    internal static GateResponse Exchange(GateRequest request)
    {
        string requestPath = Path.Combine(WapPaths.RequestsDir, request.Nonce + RequestExtension);
        string responsePath = Path.Combine(WapPaths.ResponsesDir, request.Nonce + ResponseExtension);
        try
        {
            byte[] bytes = Utf8.GetBytes(request.Serialize());
            if (bytes.Length > MaxRequestBytes) throw new InvalidDataException("Gate request exceeds the size limit.");
            using (var stream = new FileStream(requestPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }
        }
        catch (IOException) { return GateResponse.Unavailable(request.Nonce); }
        catch (UnauthorizedAccessException) { return GateResponse.Unavailable(request.Nonce); }

        DateTime deadline = DateTime.UtcNow.AddMilliseconds(ResponseTimeoutMilliseconds);
        while (DateTime.UtcNow < deadline)
        {
            GateResponse response = TryReadResponse(responsePath, request.Nonce);
            if (response != null) return response;
            Thread.Sleep(50);
        }
        try { File.Delete(requestPath); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return GateResponse.Unavailable(request.Nonce);
    }

    private static GateResponse TryReadResponse(string path, string nonce)
    {
        try
        {
            if (!File.Exists(path)) return null;
            // A response not written by the service is never trusted.
            if (!WapSecurity.IsOwnedByServiceAccount(path)) return null;
            string text;
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var reader = new StreamReader(stream, Utf8))
                text = reader.ReadToEnd();
            GateResponse response = GateResponse.Parse(text);
            if (response == null || response.Nonce != nonce) return null;
            try { File.Delete(path); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            return response;
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }
}

internal sealed class GateRequest
{
    private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);
    internal const int MaxGroupApps = 32;

    internal string Op = GateSpool.OpAuthorize;
    internal string Nonce = GateSpool.NewNonce();
    internal int Pid;
    internal string Path = string.Empty;
    internal string Pin = string.Empty;
    internal string AppId = string.Empty;
    // Other relocked apps the user opened with the same PIN (grouped prompt). Only meaningful for unlock.
    internal readonly List<string> GroupIds = new List<string>();

    internal string Serialize()
    {
        var text = new StringBuilder();
        text.Append(GateSpool.Magic).Append('\n');
        text.Append("op=").Append(Op).Append('\n');
        text.Append("nonce=").Append(Nonce).Append('\n');
        text.Append("pid=").Append(Pid.ToString(CultureInfo.InvariantCulture)).Append('\n');
        text.Append("path=").Append(GateSpool.EncodeText(Path)).Append('\n');
        text.Append("pin=").Append(GateSpool.EncodeText(Pin)).Append('\n');
        if (Op == GateSpool.OpUnlock)
        {
            text.Append("app=").Append(AppId).Append('\n');
            if (GroupIds.Count > 0) text.Append("group=").Append(string.Join(",", GroupIds.ToArray())).Append('\n');
        }
        return text.ToString();
    }

    // Returns null for anything that is not a well-formed request.
    internal static GateRequest Parse(string text)
    {
        try
        {
            bool validMagic;
            Dictionary<string, string> fields = GateSpool.ParseFields(text, out validMagic);
            if (!validMagic) return null;
            string op, nonce, pid, path, pin, app;
            if (!fields.TryGetValue("op", out op) || !fields.TryGetValue("nonce", out nonce) ||
                !fields.TryGetValue("pid", out pid) || !fields.TryGetValue("path", out path)) return null;
            if (op != GateSpool.OpAuthorize && op != GateSpool.OpUnlock) return null;
            if (!GateSpool.IsValidNonce(nonce)) return null;
            var request = new GateRequest { Op = op, Nonce = nonce };
            if (!int.TryParse(pid, NumberStyles.None, CultureInfo.InvariantCulture, out request.Pid) || request.Pid <= 0)
                return null;
            request.Path = GateSpool.DecodeText(path);
            if (fields.TryGetValue("pin", out pin)) request.Pin = GateSpool.DecodeText(pin);
            if (op == GateSpool.OpUnlock)
            {
                Guid parsed;
                if (!fields.TryGetValue("app", out app) || !Guid.TryParse(app, out parsed)) return null;
                request.AppId = app;
                string group;
                if (fields.TryGetValue("group", out group) && group.Length > 0)
                {
                    foreach (string id in group.Split(','))
                    {
                        if (!Guid.TryParse(id, out parsed)) return null;
                        if (request.GroupIds.Count >= MaxGroupApps) return null;
                        request.GroupIds.Add(id);
                    }
                }
            }
            return request;
        }
        catch (FormatException) { return null; }
        catch (ArgumentException) { return null; }
    }
}

internal sealed class GateResponse
{
    internal string Nonce = string.Empty;
    internal string Result = GateSpool.ResultDenied;
    internal int RetryAfterSeconds;
    // The app the request resolved to; lets Gate name its single PIN prompt per app.
    internal string AppId = string.Empty;

    internal static GateResponse Unavailable(string nonce)
    {
        return new GateResponse { Nonce = nonce, Result = GateSpool.ResultUnavailable };
    }

    internal string Serialize()
    {
        var text = new StringBuilder();
        text.Append(GateSpool.Magic).Append('\n');
        text.Append("nonce=").Append(Nonce).Append('\n');
        text.Append("result=").Append(Result).Append('\n');
        if (!string.IsNullOrEmpty(AppId)) text.Append("app=").Append(AppId).Append('\n');
        if (Result == GateSpool.ResultRateLimited)
            text.Append("retryAfter=").Append(RetryAfterSeconds.ToString(CultureInfo.InvariantCulture)).Append('\n');
        return text.ToString();
    }

    internal static GateResponse Parse(string text)
    {
        bool validMagic;
        Dictionary<string, string> fields = GateSpool.ParseFields(text, out validMagic);
        if (!validMagic) return null;
        string nonce, result, retry, app;
        if (!fields.TryGetValue("nonce", out nonce) || !fields.TryGetValue("result", out result)) return null;
        var response = new GateResponse { Nonce = nonce, Result = result };
        Guid parsedApp;
        if (fields.TryGetValue("app", out app) && Guid.TryParse(app, out parsedApp)) response.AppId = app;
        if (fields.TryGetValue("retryAfter", out retry))
            int.TryParse(retry, NumberStyles.None, CultureInfo.InvariantCulture, out response.RetryAfterSeconds);
        return response;
    }
}
