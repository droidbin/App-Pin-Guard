using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

// Win32 helpers shared by the service components.
internal static class NativeApi
{
    internal const uint ProcessTerminate = 0x0001;
    internal const uint ProcessQueryLimitedInformation = 0x1000;
    internal const uint ReadControl = 0x00020000;
    internal const uint Synchronize = 0x00100000;
    private const uint TokenQuery = 0x0008;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint SePrivilegeEnabled = 0x00000002;
    private const uint Th32csSnapProcess = 0x00000002;

    internal struct ProcessEntry
    {
        internal int Pid;
        internal int ParentPid;
        internal string ExeFile;
    }

    internal static List<ProcessEntry> SnapshotProcesses()
    {
        var result = new List<ProcessEntry>(256);
        IntPtr snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1)) return result;
        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf(typeof(ProcessEntry32)) };
            if (!Process32First(snapshot, ref entry)) return result;
            do
            {
                result.Add(new ProcessEntry { Pid = (int)entry.ProcessId, ParentPid = (int)entry.ParentProcessId, ExeFile = entry.ExeFile });
                entry.Size = (uint)Marshal.SizeOf(typeof(ProcessEntry32));
            }
            while (Process32Next(snapshot, ref entry));
        }
        finally { CloseHandle(snapshot); }
        return result;
    }

    internal static string GetImagePath(int pid)
    {
        IntPtr handle = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
        if (handle == IntPtr.Zero) return null;
        try { return GetImagePath(handle); }
        finally { CloseHandle(handle); }
    }

    internal static string GetImagePath(IntPtr process)
    {
        var image = new StringBuilder(32768);
        int size = image.Capacity;
        return QueryFullProcessImageName(process, 0, image, ref size) ? image.ToString() : null;
    }

    // Creation time as UTC ticks; 0 when it cannot be read.
    internal static long GetStartTicks(int pid)
    {
        IntPtr handle = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
        if (handle == IntPtr.Zero) return 0;
        try
        {
            long created, exited, kernel, user;
            if (!GetProcessTimes(handle, out created, out exited, out kernel, out user) || created <= 0) return 0;
            return DateTime.FromFileTimeUtc(created).Ticks;
        }
        finally { CloseHandle(handle); }
    }

    internal static int GetSessionId(int pid)
    {
        uint session;
        return ProcessIdToSessionId((uint)pid, out session) ? (int)session : -1;
    }

    internal static string GetUserSid(int pid)
    {
        IntPtr process = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
        if (process == IntPtr.Zero) return null;
        try
        {
            IntPtr token;
            if (!OpenProcessToken(process, TokenQuery, out token)) return null;
            try
            {
                using (var identity = new WindowsIdentity(token))
                    return identity.User == null ? null : identity.User.Value;
            }
            finally { CloseHandle(token); }
        }
        finally { CloseHandle(process); }
    }

    internal static string GetPackageFamilyName(int pid)
    {
        IntPtr process = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
        if (process == IntPtr.Zero) return null;
        try
        {
            int length = 0;
            if (GetPackageFamilyName(process, ref length, null) != 122 || length <= 0 || length >= 512) return null;
            var family = new StringBuilder(length);
            return GetPackageFamilyName(process, ref length, family) == 0 ? family.ToString() : null;
        }
        finally { CloseHandle(process); }
    }

    internal static bool IsRunning(int pid, long startTicks)
    {
        return startTicks > 0 && GetStartTicks(pid) == startTicks;
    }

    internal static bool Terminate(int pid)
    {
        IntPtr handle = OpenProcess(ProcessTerminate, false, (uint)pid);
        if (handle == IntPtr.Zero) return false;
        try { return TerminateProcess(handle, 1); }
        finally { CloseHandle(handle); }
    }

    internal static bool EnablePrivilege(string privilegeName)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out token)) return false;
        try
        {
            Luid luid;
            if (!LookupPrivilegeValue(null, privilegeName, out luid)) return false;
            var privileges = new TokenPrivileges { PrivilegeCount = 1, Luid = luid, Attributes = SePrivilegeEnabled };
            return AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero) &&
                Marshal.GetLastWin32Error() == 0;
        }
        finally { CloseHandle(token); }
    }

    // Owner of a kernel object (for example a process) or null.
    internal static SecurityIdentifier GetKernelObjectOwner(IntPtr handle)
    {
        IntPtr owner, descriptor;
        // OWNER_SECURITY_INFORMATION = 1, SE_KERNEL_OBJECT = 6
        uint result = GetSecurityInfo(handle, 6, 1, out owner, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out descriptor);
        if (result != 0 || owner == IntPtr.Zero) return null;
        try { return new SecurityIdentifier(owner); }
        finally { LocalFree(descriptor); }
    }

    // Makes a process unreachable for its own user: owner SYSTEM, DACL = SYSTEM all access + everyone
    // PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE. A standard user cannot terminate or inject into it.
    internal static void ProtectProcess(IntPtr process)
    {
        EnablePrivilege("SeRestorePrivilege");
        EnablePrivilege("SeTakeOwnershipPrivilege");
        IntPtr descriptor = IntPtr.Zero;
        try
        {
            uint size;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor("O:SYD:P(A;;0x1FFFFF;;;SY)(A;;0x101000;;;WD)", 1,
                out descriptor, out size)) throw new Win32Exception();
            IntPtr owner, dacl;
            bool defaulted, present;
            if (!GetSecurityDescriptorOwner(descriptor, out owner, out defaulted)) throw new Win32Exception();
            if (!GetSecurityDescriptorDacl(descriptor, out present, out dacl, out defaulted) || !present)
                throw new Win32Exception();
            // OWNER | DACL | PROTECTED_DACL
            uint result = SetSecurityInfo(process, 6, 0x80000005u, owner, IntPtr.Zero, dacl, IntPtr.Zero);
            if (result != 0) throw new Win32Exception((int)result);
        }
        finally
        {
            if (descriptor != IntPtr.Zero) LocalFree(descriptor);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        internal uint Size;
        internal uint Usage;
        internal uint ProcessId;
        internal UIntPtr DefaultHeapId;
        internal uint ModuleId;
        internal uint Threads;
        internal uint ParentProcessId;
        internal int PriorityClassBase;
        internal uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        internal string ExeFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        internal uint LowPart;
        internal int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        internal uint PrivilegeCount;
        internal Luid Luid;
        internal uint Attributes;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder image, ref int size);
    [DllImport("kernel32.dll")]
    private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll")]
    private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);
    [DllImport("kernel32.dll")]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackageFamilyName(IntPtr process, ref int length, StringBuilder name);
    [DllImport("kernel32.dll")]
    internal static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string systemName, string name, out Luid luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges state,
        uint length, IntPtr previous, IntPtr returnLength);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(IntPtr handle, int objectType, uint info, out IntPtr owner,
        IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    private static extern uint SetSecurityInfo(IntPtr handle, int objectType, uint info, IntPtr owner, IntPtr group,
        IntPtr dacl, IntPtr sacl);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint revision,
        out IntPtr descriptor, out uint size);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorOwner(IntPtr descriptor, out IntPtr owner, out bool defaulted);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorDacl(IntPtr descriptor, out bool present, out IntPtr dacl,
        out bool defaulted);
}
