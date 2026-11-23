using System.Runtime.InteropServices;

namespace WindowsAppProtector.Platform;

public static class FileDialog
{
    private const int BufferCharacters = 32768;

    public static IReadOnlyList<string> ShowExecutableOpenDialog(IntPtr ownerHandle = default)
    {
        var buffer = Marshal.AllocCoTaskMem(BufferCharacters * sizeof(char));

        try
        {
            var emptyBuffer = new byte[BufferCharacters * sizeof(char)];
            Marshal.Copy(emptyBuffer, 0, buffer, emptyBuffer.Length);

            var dialog = new NativeMethods.OpenFileName
            {
                lStructSize = Marshal.SizeOf<NativeMethods.OpenFileName>(),
                hwndOwner = ownerHandle,
                lpstrFilter = "\uC2E4\uD589 \uD30C\uC77C (*.exe)\0*.exe\0\uBAA8\uB4E0 \uD30C\uC77C (*.*)\0*.*\0",
                lpstrFile = buffer,
                nMaxFile = BufferCharacters,
                lpstrTitle = "\uC571 \uCD94\uAC00",
                lpstrDefExt = "exe",
                Flags = NativeMethods.OfnExplorer
                    | NativeMethods.OfnAllowMultiSelect
                    | NativeMethods.OfnFileMustExist
                    | NativeMethods.OfnPathMustExist
                    | NativeMethods.OfnNoChangeDir
                    | NativeMethods.OfnEnableSizing,
            };

            if (NativeMethods.GetOpenFileName(dialog))
            {
                var values = (Marshal.PtrToStringUni(buffer, BufferCharacters) ?? string.Empty)
                    .Split('\0', StringSplitOptions.RemoveEmptyEntries);
                if (values.Length <= 1)
                {
                    return values;
                }

                return values.Skip(1).Select(fileName => Path.Combine(values[0], fileName)).ToArray();
            }

            var error = NativeMethods.CommDlgExtendedError();
            if (error != 0)
            {
                throw new InvalidOperationException($"\uD30C\uC77C \uC120\uD0DD \uCC3D \uC624\uB958: 0x{error:X}");
            }

            return Array.Empty<string>();
        }
        finally
        {
            Marshal.FreeCoTaskMem(buffer);
        }
    }
}
