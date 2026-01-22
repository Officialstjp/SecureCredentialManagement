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

    public static CredentialBuilder CreateCredential(string targetName) 
        => CredentialBuilder.Create(targetName);

    // Credential types that can be read via CredRead without special handling.
    // DomainCertificate/GenericCertificate may fail with ERROR_INVALID_PARAMETER for some queries.
    // DomainExtended requires special structures. We handle these by catching errors.
    private static readonly CredentialType[] ReadableTypes =
    [
        CredentialType.Generic,
        CredentialType.DomainPassword,
        CredentialType.DomainVisiblePassword,
        CredentialType.DomainCertificate,
        CredentialType.GenericCertificate
    ];

    /// <summary>
    /// Reads a credential from Windows Credential Manager.
    /// When type is null (default), automatically tries all common credential types.
    /// </summary>
    /// <param name="targetName">The target name of the credential to read.</param>
    /// <param name="type">Optional credential type. If null, auto-detects by trying all types.</param>
    /// <returns>The credential if found, null otherwise.</returns>
    public static Credential? ReadCredential(
        string targetName,
        CredentialType? type = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);

        if (type.HasValue)
        {
            return ReadCredentialInternal(targetName, type.Value);
        }

        // Auto-detect: try each type until one succeeds
        foreach (var credType in ReadableTypes)
        {
            try
            {
                var credential = ReadCredentialInternal(targetName, credType);
                if (credential is not null)
                {
                    CredentialAudit.RaiseAccessed(targetName, credential.CredentialType, 
                        CredentialAudit.CredentialAccessOperation.Read, secretRetrieved: true);
                    return credential;
                }
            }
            catch (Win32Exception)
            {
                // Type may not be valid for this credential, try next
                continue;
            }
        }

        return null;
    }

    private static Credential? ReadCredentialInternal(string targetName, CredentialType type)
    {
        if (!NativeMethods.CredRead(targetName, type, 0, out nint credPtr))
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
            secret,
            Marshal.PtrToStringUni(native.Comment),
            Marshal.PtrToStringUni(native.TargetAlias),
            FileTimeToDateTimeOffset(native.LastWritten),
            ParseAttributes(native.Attributes, native.AttributeCount));
    }

    /// <summary>
    /// Reads a credential securely via callback. Secret is zeroed after callback completes.
    /// When type is null (default), automatically tries all common credential types.
    /// </summary>
    public static bool TryReadCredentialSecure(
        string targetName,
        out string? userName,
        ReadOnlySpanAction<char, object?> secretHandler,
        object? state = null,
        CredentialType? type = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);
        userName = null;

        nint credPtr;
        if (type.HasValue)
        {
            if (!NativeMethods.CredRead(targetName, type.Value, 0, out credPtr))
                CredentialAudit.RaiseAccessed(targetName, type.Value, 
                    CredentialAudit.CredentialAccessOperation.Read, secretRetrieved: true);
                return false;
        }
        else
        {
            // Auto-detect: try each type until one succeeds
            credPtr = IntPtr.Zero;
            foreach (var credType in ReadableTypes)
            {
                if (NativeMethods.CredRead(targetName, credType, 0, out credPtr))
                {
                    CredentialAudit.RaiseAccessed(targetName, credType, 
                        CredentialAudit.CredentialAccessOperation.Read, secretRetrieved: true);
                    break;
                }
            }
            if (credPtr == IntPtr.Zero)
                return false;
        }

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
    /// When type is null (default), automatically tries all common credential types.
    /// </summary>
    public static bool TryUseCredential<TState>(
        string targetName,
        ReadOnlySpanAction<char, (string? userName, TState state)> handler,
        TState state = default!,
        CredentialType? type = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);

        nint credPtr;
        if (type.HasValue)
        {
            if (!NativeMethods.CredRead(targetName, type.Value, 0, out credPtr))
                return false;
        }
        else
        {
            // Auto-detect: try each type until one succeeds
            credPtr = IntPtr.Zero;
            foreach (var credType in ReadableTypes)
            {
                if (NativeMethods.CredRead(targetName, credType, 0, out credPtr))
                {
                    CredentialAudit.RaiseAccessed(targetName, credType,
                        CredentialAudit.CredentialAccessOperation.UseCredential, secretRetrieved: true);
                    break;
                }
            }
            if (credPtr == IntPtr.Zero)
                return false;
        }

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
        CredentialPersistence persistence = CredentialPersistence.LocalMachine,
        CredentialType type = CredentialType.Generic,
        string? comment = null,
        string? targetAlias = null,
        IDictionary<string, byte[]>? attributes = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);
        ArgumentNullException.ThrowIfNull(secret);

        byte[] secretBytes = System.Text.Encoding.Unicode.GetBytes(secret);
        GCHandle pin = GCHandle.Alloc(secretBytes, GCHandleType.Pinned);

        try
        {
            WriteCredentialCore(targetName, userName, secretBytes, persistence, type, comment, targetAlias, attributes);
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
        CredentialPersistence persistence = CredentialPersistence.LocalMachine,
        CredentialType type = CredentialType.Generic,
        string? comment = null,
        string? targetAlias = null,
        IDictionary<string, byte[]>? attributes = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);

        int byteCount = secret.Length * sizeof(char);
        byte[] secretBytes = ArrayPool<byte>.Shared.Rent(byteCount);
        GCHandle pin = GCHandle.Alloc(secretBytes, GCHandleType.Pinned);

        try
        {
            MemoryMarshal.AsBytes(secret).CopyTo(secretBytes);
            WriteCredentialCore(targetName, userName, secretBytes.AsSpan(0, byteCount), persistence, type, comment, targetAlias, attributes);
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
    /// When type is null (default), automatically finds and deletes the credential regardless of type.
    /// </summary>
    public static bool DeleteCredential(string targetName, CredentialType? type = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);

        if (type.HasValue)
        {
            if (!NativeMethods.CredDelete(targetName, type.Value, 0))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == NativeMethods.ERROR_NOT_FOUND)
                    return false;
                throw new Win32Exception(error);
            }
            return true;
        }

        // Auto-detect: try each type until one succeeds
        foreach (var credType in ReadableTypes)
        {
            if (NativeMethods.CredDelete(targetName, credType, 0))
            {
                CredentialAudit.RaiseDeleted(targetName, credType);
                return true;
            }
            
            int error = Marshal.GetLastWin32Error();
            if (error != NativeMethods.ERROR_NOT_FOUND && error != NativeMethods.ERROR_INVALID_PARAMETER)
                throw new Win32Exception(error);
        }

        return false;
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
                    secret,
                    Marshal.PtrToStringUni(native.Comment),
                    Marshal.PtrToStringUni(native.TargetAlias),
                    FileTimeToDateTimeOffset(native.LastWritten),
                    ParseAttributes(native.Attributes, native.AttributeCount)));
            }
            CredentialAudit.RaiseEnumerated(filter, credentials.Count);

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
        CredentialPersistence persistence,
        CredentialType type,
        string? comment,
        string? targetAlias,
        IDictionary<string, byte[]>? attributes)
    {
        // Validate credential type before attempting write
        if (!type.IsWritable())
        {
            var reason = type.GetWriteRestrictionReason() ?? "This credential type cannot be created with username/password.";
            throw new CredentialException($"Cannot write credential: {reason}", CredentialException.ErrorCodes.ERROR_INVALID_PARAMETER, type);
        }

        nint targetNamePtr = Marshal.StringToCoTaskMemUni(targetName);
        nint userNamePtr = Marshal.StringToCoTaskMemUni(userName ?? Environment.UserName);
        nint commentPtr = comment != null ? Marshal.StringToCoTaskMemUni(comment) : IntPtr.Zero;
        nint targetAliasPtr = targetAlias != null ? Marshal.StringToCoTaskMemUni(targetAlias) : IntPtr.Zero;
        nint blobPtr = IntPtr.Zero;
        nint attributesPtr = IntPtr.Zero;
        var attrHandles = new List<GCHandle>();
        var keywordPtrs = new List<nint>();

        try
        {
            blobPtr = Marshal.AllocCoTaskMem(secretBytes.Length);
            unsafe
            {
                secretBytes.CopyTo(new Span<byte>((void*)blobPtr, secretBytes.Length));
            }
            
            uint attrCount = 0;
            if (attributes is { Count: > 0 })
            {
                attrCount = (uint)attributes.Count;
                attributesPtr = MarshalAttributes(attributes, attrHandles, keywordPtrs);
            }

            var credential = new CREDENTIAL
            {
                Flags = 0,
                Type = (uint)type,
                TargetName = targetNamePtr,
                UserName = userNamePtr,
                CredentialBlob = blobPtr,
                CredentialBlobSize = (uint)secretBytes.Length,
                Persist = (uint)persistence,
                Comment = commentPtr,
                TargetAlias = targetAliasPtr,
                AttributeCount = attrCount,
                Attributes = attributesPtr,
            };

            if (!NativeMethods.CredWrite(ref credential, 0))
            {
                var win32Ex = new Win32Exception(Marshal.GetLastWin32Error());
                throw CredentialException.FromWin32Exception(win32Ex, $"write credential '{targetName}'", type);
            }
        }
        finally
        {
            Marshal.FreeCoTaskMem(targetNamePtr);
            Marshal.FreeCoTaskMem(userNamePtr);
            if (commentPtr != IntPtr.Zero)Marshal.FreeCoTaskMem(commentPtr);
            if (targetAliasPtr != IntPtr.Zero)Marshal.FreeCoTaskMem(targetAliasPtr);
            
            foreach (var h in attrHandles)
                if (h.IsAllocated) h.Free();
            
            foreach (var ptr in keywordPtrs)
                Marshal.FreeCoTaskMem(ptr);
            
            if (attributesPtr != IntPtr.Zero)
                Marshal.FreeCoTaskMem(attributesPtr);

            if (blobPtr != IntPtr.Zero)
            {
                unsafe { new Span<byte>((void*)blobPtr, secretBytes.Length).Clear(); }
                Marshal.FreeCoTaskMem(blobPtr);
            }
        }
    }

    private static DateTimeOffset FileTimeToDateTimeOffset(
        System.Runtime.InteropServices.ComTypes.FILETIME fileTime)
    {
        long ft = ((long)fileTime.dwHighDateTime << 32) | (uint)fileTime.dwLowDateTime;
        return ft == 0
            ? DateTimeOffset.MinValue
            : DateTimeOffset.FromFileTime(ft);
    }

    private static Dictionary<string, byte[]> ParseAttributes(nint attributesPtr, uint count)
    {
        var result = new Dictionary<string, byte[]>((int)count, StringComparer.OrdinalIgnoreCase);

        if (attributesPtr == IntPtr.Zero || count == 0)
            return result;

        int attrSize = Marshal.SizeOf<CREDENTIAL_ATTRIBUTE>();

        for (int i = 0; i < count; i++)
        {
            nint attrPtr = IntPtr.Add(attributesPtr, i * attrSize);
            var attr = Marshal.PtrToStructure<CREDENTIAL_ATTRIBUTE>(attrPtr);

            string? keyword = Marshal.PtrToStringUni(attr.Keyword);
            if (keyword is null)
                continue;
            
            byte[] value = new byte[attr.ValueSize];
            if (attr.Value != IntPtr.Zero && attr.ValueSize > 0)
            {
                Marshal.Copy(attr.Value, value, 0, (int)attr.ValueSize);
            }

            result[keyword] = value;
        }

        return result;
    }

    private static nint MarshalAttributes(
        IDictionary<string, byte[]> attributes,
        List<GCHandle> handles,
        List<nint> keywordPtrs)
    {
        int attrSize = Marshal.SizeOf<CREDENTIAL_ATTRIBUTE>();
        nint arrayPtr = Marshal.AllocCoTaskMem(attrSize * attributes.Count);
    
        int i = 0;
        foreach (var kvp in attributes)
        {
            var valueHandle = GCHandle.Alloc(kvp.Value, GCHandleType.Pinned);
            handles.Add(valueHandle);
            
            nint keywordPtr = Marshal.StringToCoTaskMemUni(kvp.Key);
            keywordPtrs.Add(keywordPtr);
            
            var attr = new CREDENTIAL_ATTRIBUTE
            {
                Keyword = keywordPtr,
                Flags = 0,
                ValueSize = (uint)kvp.Value.Length,
                Value = valueHandle.AddrOfPinnedObject()
            };
            
            Marshal.StructureToPtr(attr, arrayPtr + (i * attrSize), false);
            i++;
        }
        
        return arrayPtr;
    }

    #endregion
}