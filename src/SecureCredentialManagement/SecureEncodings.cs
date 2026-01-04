/* SPDX - License - Identifier: Apache - 2.0 
 * Copyright(c) 2025 Stefan Ploch */

using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace SecureCredentialManagement;

/// <summary>
/// Least-allocation encoding helpers for credential operations
/// </summary>
public static class SecureEncoding
{
    /// <summary>
    /// Creates a Basic auth header value. Intermediate buffers are zeroed after use.
    /// </summary>
    public static string CreateBasicAuthHeader(ReadOnlySpan<char> userName, ReadOnlySpan<char> password)
    {
        int userBytesCount = Encoding.UTF8.GetByteCount(userName);
        int passBytes = Encoding.UTF8.GetByteCount(password);
        int totalBytes = userBytesCount + 1 + passBytes;

        const int stackThreshold = 512;
        byte[]? rentedBuffer = null;

        Span<byte> utf8Buffer = totalBytes <= stackThreshold
            ? stackalloc byte[stackThreshold]
            : (rentedBuffer = ArrayPool<byte>.Shared.Rent(totalBytes));

        try
        {
            int written = Encoding.UTF8.GetBytes(userName, utf8Buffer);
            utf8Buffer[written++] = (byte)':';
            written += Encoding.UTF8.GetBytes(password, utf8Buffer[written..]);

            int base64Length = ((written + 2) / 3) * 4;
            char[]? rentedBase64 = null;

            Span<char> base64Buffer = base64Length <= stackThreshold
                ? stackalloc char[stackThreshold]
                : (rentedBase64 = ArrayPool<char>.Shared.Rent(base64Length));

            try
            {
                Convert.TryToBase64Chars(utf8Buffer[..written], base64Buffer, out int charsWritten);
                return new string(base64Buffer[..charsWritten]);
            }
            finally
            {
                if (rentedBase64 is not null)
                {
                    base64Buffer[..base64Length].Clear();
                    ArrayPool<char>.Shared.Return(rentedBase64);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8Buffer[..totalBytes]);
            if (rentedBuffer is not null)
                ArrayPool<byte>.Shared.Return(rentedBuffer);
        }
    }

    /// <summary>
    /// Encodes credentials to a caller-provided span. Zero Heap allocations
    /// </summary>
    public static bool TryEncodeBasicAuth(
        ReadOnlySpan<char> userName,
        ReadOnlySpan<char> password,
        Span<char> destination,
        out int charsWritten)
    {
        charsWritten = 0;

        int userBytes = Encoding.UTF8.GetByteCount(userName);
        int passBytes = Encoding.UTF8.GetByteCount(password);
        int totalBytes = userBytes + 1 + passBytes;

        Span<byte> utf8Buffer = stackalloc byte[Math.Min(totalBytes, 1024)];
        if (totalBytes > utf8Buffer.Length)
            return false;

        try
        {
            int written = Encoding.UTF8.GetBytes(userName, utf8Buffer);
            utf8Buffer[written++] = (byte)':';
            written += Encoding.UTF8.GetBytes(password, utf8Buffer[written..]);

            return Convert.TryToBase64Chars(utf8Buffer[..written], destination, out charsWritten);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8Buffer);
        }

    }

    /// <summary>
    /// Computes HMAC-SHA256. Key buffer is zeroed after use.
    /// </summary>
    public static byte[] ComputeHmacSha256(ReadOnlySpan<char> secret, ReadOnlySpan<byte> data)
    {
        int keyByteCount = Encoding.UTF8.GetByteCount(secret);
        Span<byte> keyBytes = stackalloc byte[Math.Min(keyByteCount, 512)];

        if (keyByteCount > keyBytes.Length)
            throw new ArgumentException("Secret too large for stack allocation", nameof(secret));

        try
        {
            Encoding.UTF8.GetBytes(secret, keyBytes);
            Span<byte> hash = stackalloc byte[32];
            HMACSHA256.HashData(keyBytes[..keyByteCount], data, hash);
            return hash.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    /// <summary>
    /// Computes HMAC-SHA256 to a destination span. Zero allocations.
    /// </summary>
    public static bool TryComputeHmacSha256(
        ReadOnlySpan<char> secret,
        ReadOnlySpan<byte> data,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = 0;
        if (destination.Length < 32)
            return false;

        int keyByteCount = Encoding.UTF8.GetByteCount(secret);
        Span<byte> keyBytes = stackalloc byte[Math.Min(keyByteCount, 512)];

        if (keyByteCount > keyBytes.Length)
            return false;

        try
        {
            Encoding.UTF8.GetBytes(secret, keyBytes);
            bytesWritten = HMACSHA256.HashData(keyBytes[..keyByteCount], data, destination);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }
}