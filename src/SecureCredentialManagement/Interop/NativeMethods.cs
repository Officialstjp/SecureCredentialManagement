/* SPDX - License - Identifier: Apache - 2.0 
 * Copyright(c) 2025 Stefan Ploch */

using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SecureCredentialManagement;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct CREDENTIAL
{
    public uint Flags;
    public uint Type;
    public nint TargetName;
    public nint Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public uint CredentialBlobSize;
    public nint CredentialBlob;
    public uint Persist;
    public uint AttributeCount;
    public nint Attributes;
    public nint TargetAlias;
    public nint UserName;
}

internal struct CREDENTIAL_ATTRIBUTE
{
    public nint Keyword;    // LPWSTR - attribute name, pointer to a null-terminated string
    public uint Flags;      // DWORD - reserved for future use, must be zero
    public uint ValueSize;  // DWORD - size of the attribute data in bytes
    public nint Value;      // LPBYTE - pointer to the attribute data
}

internal static partial class NativeMethods
{
    public const int ERROR_NOT_FOUND = 1168;
    public const int ERROR_INVALID_PARAMETER = 87;

    [LibraryImport("Advapi32.dll", EntryPoint = "CredReadW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CredRead(string target, CredentialType type, int reservedFlag, out nint credentialPtr);

    // DllImport required for ref struct marshalling without DisableRuntimeMarshalling
    [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CredWrite(ref CREDENTIAL credential, uint flags);

    [LibraryImport("Advapi32.dll", EntryPoint = "CredDeleteW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CredDelete(string target, CredentialType type, int flags);

    [LibraryImport("Advapi32.dll", EntryPoint = "CredEnumerateW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CredEnumerate(string? filter, int flags, out int count, out nint credentials);

    [LibraryImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CredFree(nint credential);
}

internal sealed class CriticalCredentialHandle : CriticalHandleZeroOrMinusOneIsInvalid
{
    public CriticalCredentialHandle(nint preexistingHandle) => SetHandle(preexistingHandle);

    public CREDENTIAL GetCredential()
    {
        if (IsInvalid)
            throw new InvalidOperationException("Invalid credential handle.");

        return Marshal.PtrToStructure<CREDENTIAL>(handle);
    }

    protected override bool ReleaseHandle()
    {
        if (IsInvalid)
            return false;

        NativeMethods.CredFree(handle);
        SetHandleAsInvalid();
        return true;
    }
}