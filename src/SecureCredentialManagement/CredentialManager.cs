/* SPDX - License - Identifier: Apache - 2.0 
 * Copyright(c) 2025 Stefan Ploch */

using System;
using System.Buffers;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SecureCredentialManagement;

/// <summary>
/// Provides secure access to Windows Credential Manager.
/// </summary>
public static class CredentialManager
{
    #region Public Methods

    /// <summary>
    /// Reads a credential from Windows Credential Manager.
    /// </summary>
    public static Credential? ReadCredential(string targetName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);

        if (!NativeMethods.CredRead(targetName, CredentialType.Generic, 0, out nint credPtr))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == NativeMethods.ERROR_NOT_FOUND)
                return null;
            throw new Win32Exception(error);
        }

        using var handle = new CriticalCredentialHandle(credPtr);
        var native = handle.GetCredential();

        string? secret = null;
        if (native.CredentialBlob != IntPtr.Zero && native.CredentialBlobSize > 0)
        {
            // Try to decode as Unicode first (most common for credentials we write)
            // But some apps store UTF-8 or raw bytes, so fall back if needed
            secret = Marshal.PtrToStringUni(native.CredentialBlob, (int)native.CredentialBlobSize / sizeof(char));
        }

        return new Credential(
            (CredentialType)native.Type,
            Marshal.PtrToStringUni(native.TargetName) ?? string.Empty,
            Marshal.PtrToStringUni(native.UserName),
            secret);
    }

    /// <summary>
    /// Reads a credential securely via callback. Secret is zeroed after callback completes
    /// </summary>
    public static bool TryReadCredentialSecure(
        string targetName,
        out string? userName,
        ReadOnlySpanAction<char, object?> secretHandler,
        object? state = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);
        userName = null;

        if (!NativeMethods.CredRead(targetName, CredentialType.Generic, 0, out nint credPtr))
            return false;

        using var handle = new CriticalCredentialHandle(credPtr);
        var native = handle.GetCredential();

        userName = Marshal.PtrToStringUni(native.UserName);

        if (native.CredentialBlob == IntPtr.Zero || native.CredentialBlobSize == 0)
        {
            secretHandler([], state);
            return true;
        }

        int charCount = (int)native.CredentialBlobSize / sizeof(char);
        char[] buffer = ArrayPool<char>.Shared.Rent(charCount);
        GCHandle pin = GCHandle.Alloc(buffer, GCHandleType.Pinned);

        try
        {
            Marshal.Copy(native.CredentialBlob, buffer, 0, charCount);
            secretHandler(buffer.AsSpan(0, charCount), state);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer.AsSpan()));
            pin.Free();
            ArrayPool<char>.Shared.Return(buffer);
        }

        return true;
    }

    /// <summary>
    /// Reads a credential with username and secret in a single callback.
    /// </summary>
    public static bool TryUseCredential<TState>(
        string targetName,
        ReadOnlySpanAction<char, (string? userName, TState state)> handler,
        TState state = default!)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);

        if (!NativeMethods.CredRead(targetName, CredentialType.Generic, 0, out nint credPtr))
            return false;

        using var handle = new CriticalCredentialHandle(credPtr);
        var native = handle.GetCredential();

        string? userName = Marshal.PtrToStringUni(native.UserName);

        if (native.CredentialBlob == IntPtr.Zero || native.CredentialBlobSize == 0)
        {
            handler([], (userName, state));
            return true;
        }

        int charCount = (int)native.CredentialBlobSize / sizeof(char);
        char[] buffer = ArrayPool<char>.Shared.Rent(charCount);
        GCHandle pin = GCHandle.Alloc(buffer, GCHandleType.Pinned);

        try
        {
            Marshal.Copy(native.CredentialBlob, buffer, 0, charCount);
            handler(buffer.AsSpan(0, charCount), (userName, state));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer.AsSpan()));
            pin.Free();
            ArrayPool<char>.Shared.Return(buffer);
        }

        return true;
    }

    /// <summary>
    /// Writes a credential to Windows Credential Manager.
    /// </summary>
    public static void WriteCredential(
        string targetName,
        string userName,
        string secret,
        CredentialPersistence persistence = CredentialPersistence.LocalMachine)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);
        ArgumentNullException.ThrowIfNull(secret);

        byte[] secretBytes = System.Text.Encoding.Unicode.GetBytes(secret);
        GCHandle pin = GCHandle.Alloc(secretBytes, GCHandleType.Pinned);

        try
        {
            WriteCredentialCore(targetName, userName, secretBytes, persistence);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretBytes);
            pin.Free();
        }
    }

    /// <summary>
    /// Writes a credential to Windows Credential Manager using a secure span.
    /// </summary>
    public static void WriteCredentialSecure(
        string targetName,
        string userName,
        ReadOnlySpan<char> secret,
        CredentialPersistence persistence = CredentialPersistence.LocalMachine)
    {
        int byteCount = secret.Length * sizeof(char);
        byte[] secretBytes = ArrayPool<byte>.Shared.Rent(byteCount);
        GCHandle pin = GCHandle.Alloc(secretBytes, GCHandleType.Pinned);

        try
        {
            MemoryMarshal.AsBytes(secret).CopyTo(secretBytes);
            WriteCredentialCore(targetName, userName, secretBytes.AsSpan(0, byteCount), persistence);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretBytes);
            pin.Free();
            ArrayPool<byte>.Shared.Return(secretBytes);
        }
    }

    /// <summary>
    /// Deletes a credential from Windows Credential Manager.
    /// </summary>
    public static bool DeleteCredential(string targetName, CredentialType type = CredentialType.Generic)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);

        if (!NativeMethods.CredDelete(targetName, type, 0))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == NativeMethods.ERROR_NOT_FOUND)
                return false;
            throw new Win32Exception(error);
        }

        return true;
    }

    /// <summary>
    /// Enumerates all credentials matching an optional filter.
    /// </summary>
    public static IReadOnlyList<Credential> EnumerateCredentials(string? filter = null)
    {
        if (!NativeMethods.CredEnumerate(filter, 0, out int count, out nint credentialsPtr))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == NativeMethods.ERROR_NOT_FOUND)
                return [];
            throw new Win32Exception(error);
        }

        try
        {
            var credentials = new List<Credential>(count);
            for (int i = 0; i < count; i++)
            {
                nint credPtr = Marshal.ReadIntPtr(credentialsPtr, i * IntPtr.Size);
                var native = Marshal.PtrToStructure<CREDENTIAL>(credPtr);

                string? secret = null;
                if (native.CredentialBlob != IntPtr.Zero && native.CredentialBlobSize > 0)
                {
                    secret = Marshal.PtrToStringUni(native.CredentialBlob, (int)native.CredentialBlobSize / sizeof(char));
                }

                credentials.Add(new Credential(
                    (CredentialType)native.Type,
                    Marshal.PtrToStringUni(native.TargetName) ?? string.Empty,
                    Marshal.PtrToStringUni(native.UserName),
                    secret));
            }

            return credentials;
        }
        finally
        {
            NativeMethods.CredFree(credentialsPtr);
        }
    }

    #endregion

    #region Private Methods

    private static void WriteCredentialCore(
        string targetName,
        string userName,
        ReadOnlySpan<byte> secretBytes,
        CredentialPersistence persistence)
    {
        nint targetNamePtr = Marshal.StringToCoTaskMemUni(targetName);
        nint userNamePtr = Marshal.StringToCoTaskMemUni(userName ?? Environment.UserName);
        nint blobPtr = IntPtr.Zero;

        try
        {
            blobPtr = Marshal.AllocCoTaskMem(secretBytes.Length);
            unsafe
            {
                secretBytes.CopyTo(new Span<byte>((void*)blobPtr, secretBytes.Length));
            }

            var credential = new CREDENTIAL
            {
                Flags = 0,
                Type = (uint)CredentialType.Generic,
                TargetName = targetNamePtr,
                UserName = userNamePtr,
                CredentialBlob = blobPtr,
                CredentialBlobSize = (uint)secretBytes.Length,
                Persist = (uint)persistence,
                AttributeCount = 0,
                Attributes = IntPtr.Zero,
                Comment = IntPtr.Zero,
                TargetAlias = IntPtr.Zero,
            };

            if (!NativeMethods.CredWrite(ref credential, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        finally
        {
            Marshal.FreeCoTaskMem(targetNamePtr);
            Marshal.FreeCoTaskMem(userNamePtr);

            if (blobPtr != IntPtr.Zero)
            {
                unsafe { new Span<byte>((void*)blobPtr, secretBytes.Length).Clear(); }
                Marshal.FreeCoTaskMem(blobPtr);
            }
        }
    }

    #endregion
}