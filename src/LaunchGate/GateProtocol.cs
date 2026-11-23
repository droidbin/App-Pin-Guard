using System;
using System.IO;
using System.IO.Pipes;
using System.Text;

internal static class GateProtocol
{
    internal const string PipeName = "WindowsAppProtector.Launch.v2";
    internal const string ExeName = "WindowsAppProtector.Gate.exe";
    internal const byte Version = 1;
    internal const byte Authorize = 1;
    internal const byte Track = 2;
    internal const byte ReadWindowPolicy = 3;
    internal const byte SyncPolicy = 4;
    internal const int MaxWindowPolicyBytes = 60000;
    internal const byte Denied = 0;
    internal const byte Approved = 1;
    internal const byte RateLimited = 2;
    internal const byte PromptRequired = 3;
    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);

    internal static NamedPipeClientStream ConnectToService()
    {
#if NET5_0_OR_GREATER
        // PipeDirection.InOut asks for GENERIC_WRITE (append/attributes), which the service ACL deliberately
        // does not grant; open the handle with exactly the rights the ACL allows instead.
        var pipe = OpenWithExactRights();
        try
        {
            var system = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
            if (!system.Equals(pipe.GetAccessControl().GetOwner(typeof(System.Security.Principal.SecurityIdentifier))))
                throw new UnauthorizedAccessException("보호 서비스의 신원을 확인할 수 없습니다.");
            return pipe;
        }
        catch { pipe.Dispose(); throw; }
#else
        var pipe = new NamedPipeClientStream(".", PipeName,
            PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadPermissions |
                PipeAccessRights.Synchronize, PipeOptions.Asynchronous,
            System.Security.Principal.TokenImpersonationLevel.Identification, HandleInheritability.None);
        try
        {
            pipe.Connect(1500);
            var system = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
            if (!system.Equals(pipe.GetAccessControl().GetOwner(typeof(System.Security.Principal.SecurityIdentifier))))
                throw new UnauthorizedAccessException("보호 서비스의 신원을 확인할 수 없습니다.");
            return pipe;
        }
        catch { pipe.Dispose(); throw; }
#endif
    }

#if NET5_0_OR_GREATER
    private const uint PipeReadData = 0x1, PipeWriteData = 0x2, ReadControl = 0x20000, SynchronizeRight = 0x100000;
    private const uint OpenExisting = 3, FlagOverlapped = 0x40000000;
    private const uint SecuritySqosPresent = 0x100000, SecurityIdentification = 0x10000;
    private const int ErrorFileNotFound = 2, ErrorPipeBusy = 231;

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern Microsoft.Win32.SafeHandles.SafePipeHandle CreateFile(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    private static NamedPipeClientStream OpenWithExactRights()
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(1500);
        while (true)
        {
            var handle = CreateFile(@"\\.\pipe\" + PipeName,
                PipeReadData | PipeWriteData | ReadControl | SynchronizeRight, 0, IntPtr.Zero, OpenExisting,
                FlagOverlapped | SecuritySqosPresent | SecurityIdentification, IntPtr.Zero);
            if (!handle.IsInvalid)
                return new NamedPipeClientStream(PipeDirection.InOut, true, true, handle);

            int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            handle.Dispose();
            if ((error != ErrorFileNotFound && error != ErrorPipeBusy) || DateTime.UtcNow >= deadline)
            {
                if (error == ErrorFileNotFound || error == ErrorPipeBusy)
                    throw new TimeoutException("Gate pipe connect timed out.");
                throw new System.ComponentModel.Win32Exception(error);
            }
            System.Threading.Thread.Sleep(50);
        }
    }
#endif

    internal static void WriteText(Stream stream, string value, int maximum)
    {
        var bytes = Utf8.GetBytes(value);
        if (bytes.Length > maximum) throw new InvalidDataException("Gate request exceeds the size limit.");
        stream.WriteByte((byte)bytes.Length);
        stream.WriteByte((byte)(bytes.Length >> 8));
        stream.Write(bytes, 0, bytes.Length);
    }

    internal static string ReadText(PipeStream stream, int maximum, DateTime deadline)
    {
        var header = Read(stream, 2, deadline);
        var length = header[0] | (header[1] << 8);
        if (length > maximum) throw new InvalidDataException("Gate request exceeds the size limit.");
        return Utf8.GetString(Read(stream, length, deadline));
    }

    internal static byte[] Read(PipeStream stream, int length, DateTime deadline)
    {
        var bytes = new byte[length];
        for (int offset = 0; offset < length;)
        {
            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero) throw new TimeoutException("Gate request timed out.");
            var pending = stream.BeginRead(bytes, offset, length - offset, null, null);
            using (var ready = pending.AsyncWaitHandle)
            {
                if (!ready.WaitOne(remaining)) throw new TimeoutException("Gate request timed out.");
                var count = stream.EndRead(pending);
                if (count == 0) throw new EndOfStreamException();
                offset += count;
            }
        }
        return bytes;
    }
}
