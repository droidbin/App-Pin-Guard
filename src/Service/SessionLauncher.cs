using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

// CreateProcessAsUser into an interactive session. Used for the window agent and for Gate notices.
internal static class SessionLauncher
{
    internal struct Launched
    {
        internal IntPtr Process;
        internal int ProcessId;
    }

    private const uint CreateUnicodeEnvironment = 0x400;
    private const uint TokenAssignPrimary = 0x0001;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenQuery = 0x0008;
    private const int TokenElevationTypeInfo = 18;
    private const int TokenLinkedTokenInfo = 19;
    private const int TokenElevationTypeFull = 2;

    // limited = true runs the child with the user's non-elevated token, so a program started from a Gate
    // notice cannot end up elevated.
    internal static Launched Start(int sessionId, string exePath, string arguments, bool limited)
    {
        IntPtr userToken;
        if (!WTSQueryUserToken(sessionId, out userToken)) throw new Win32Exception();
        IntPtr token = userToken;
        IntPtr limitedToken = IntPtr.Zero;
        try
        {
            if (limited)
            {
                limitedToken = TryGetLimitedToken(userToken);
                if (limitedToken != IntPtr.Zero) token = limitedToken;
            }
            IntPtr environment;
            if (!CreateEnvironmentBlock(out environment, token, false)) throw new Win32Exception();
            try
            {
                var startup = new Startup { Size = Marshal.SizeOf(typeof(Startup)), Desktop = @"winsta0\default" };
                var command = new StringBuilder("\"" + exePath + "\"" + (string.IsNullOrEmpty(arguments) ? string.Empty : " " + arguments));
                ProcessHandles process;
                if (!CreateProcessAsUser(token, exePath, command, IntPtr.Zero, IntPtr.Zero, false,
                    CreateUnicodeEnvironment, environment, Path.GetDirectoryName(exePath), ref startup, out process))
                    throw new Win32Exception();
                NativeApi.CloseHandle(process.Thread);
                return new Launched { Process = process.Process, ProcessId = (int)process.ProcessId };
            }
            finally { DestroyEnvironmentBlock(environment); }
        }
        finally
        {
            if (limitedToken != IntPtr.Zero) NativeApi.CloseHandle(limitedToken);
            NativeApi.CloseHandle(userToken);
        }
    }

    // Quotes one command-line argument.
    internal static string Quote(string value)
    {
        return "\"" + (value ?? string.Empty).Replace("\"", "\\\"") + "\"";
    }

    private static IntPtr TryGetLimitedToken(IntPtr token)
    {
        try
        {
            int size = sizeof(int);
            IntPtr buffer = Marshal.AllocHGlobal(IntPtr.Size);
            try
            {
                uint returned;
                if (!GetTokenInformation(token, TokenElevationTypeInfo, buffer, (uint)size, out returned)) return IntPtr.Zero;
                if (Marshal.ReadInt32(buffer) != TokenElevationTypeFull) return IntPtr.Zero;
                if (!GetTokenInformation(token, TokenLinkedTokenInfo, buffer, (uint)IntPtr.Size, out returned)) return IntPtr.Zero;
                IntPtr linked = Marshal.ReadIntPtr(buffer);
                try
                {
                    IntPtr primary;
                    // SecurityImpersonation = 2, TokenPrimary = 1
                    if (!DuplicateTokenEx(linked, TokenAssignPrimary | TokenDuplicate | TokenQuery, IntPtr.Zero, 2, 1, out primary))
                        return IntPtr.Zero;
                    return primary;
                }
                finally { NativeApi.CloseHandle(linked); }
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        catch (Exception)
        {
            return IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Startup
    {
        internal int Size;
        internal string Reserved, Desktop, Title;
        internal int X, Y, Width, Height, XCount, YCount, Fill, Flags;
        internal short Show, ReservedSize;
        internal IntPtr ReservedData, Input, Output, Error;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessHandles
    {
        internal IntPtr Process, Thread;
        internal uint ProcessId, ThreadId;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(int session, out IntPtr token);
    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);
    [DllImport("userenv.dll")]
    private static extern bool DestroyEnvironmentBlock(IntPtr environment);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessAsUser(IntPtr token, string app, StringBuilder command, IntPtr processSecurity,
        IntPtr threadSecurity, bool inherit, uint flags, IntPtr environment, string directory, ref Startup startup,
        out ProcessHandles process);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int informationClass, IntPtr information, uint length,
        out uint returnLength);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(IntPtr existing, uint access, IntPtr attributes, int impersonation,
        int tokenType, out IntPtr duplicate);
}
