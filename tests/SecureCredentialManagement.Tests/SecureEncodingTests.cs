/* SPDX - License - Identifier: Apache - 2.0 
 * Copyright(c) 2025 Stefan Ploch */

using SecureCredentialManagement;
using Shouldly;
using Xunit;

namespace CredentialManagement.Tests;

public class SecureEncodingTests
{
    [Fact]
    public void CreateBasicAuthHeader_ValidCredentials_ReturnsBase64EncodedString()
    {
        // Arrange
        var userName = "user";
        var password = "pass";

        // Act
        var header = SecureEncoding.CreateBasicAuthHeader(userName, password);

        // Assert
        header.ShouldBe("dXNlcjpwYXNz"); // Base64 of "user:pass"
    }

    [Fact]
    public void TryEncodeBasicAuth_ValidCredentials_WritesToDestination()
    {
        // Arrange
        Span<char> buffer = stackalloc char[64];

        // Act
        var success = SecureEncoding.TryEncodeBasicAuth("user", "pass", buffer, out var written);

        // Assert
        success.ShouldBeTrue();
        written.ShouldBe(12);
        new string(buffer[..written]).ShouldBe("dXNlcjpwYXNz");
    }

    [Fact]
    public void TryEncodeBasicAuth_BufferTooSmall_ReturnsFalse()
    {
        // Arrange
        Span<char> buffer = stackalloc char[4]; // Too small

        // Act
        var success = SecureEncoding.TryEncodeBasicAuth("user", "pass", buffer, out _);

        // Assert
        success.ShouldBeFalse();
    }

    [Fact]
    public void ComputeHmacSha256_ReturnsCorrectHash()
    {
        // Arrange
        var secret = "secret";
        var data = "Hello, World!"u8.ToArray();

        // Act
        var hash = SecureEncoding.ComputeHmacSha256(secret, data);

        // Assert
        // HMAC-SHA256("secret", "Hello, World!") verified against standard implementations
        hash.Length.ShouldBe(32);
        Convert.ToHexString(hash).ShouldBe(
            "FCFAFFA7FEF86515C7BEB6B62D779FA4CCF092F2E61C164376054271252821FF",
            StringCompareShould.IgnoreCase);
    }

    [Fact]
    public void TryComputeHmacSha256_WritesToDestination()
    {
        // Arrange
        Span<byte> destination = stackalloc byte[32];

        // Act
        var success = SecureEncoding.TryComputeHmacSha256("secret", "data"u8, destination, out var written);

        // Assert
        success.ShouldBeTrue();
        written.ShouldBe(32);
    }

    [Fact]
    public void TryComputeHmacSha256_DestinationTooSmall_ReturnsFalse()
    {
        // Arrange
        Span<byte> destination = stackalloc byte[16]; // Too small

        // Act
        var success = SecureEncoding.TryComputeHmacSha256("secret", "data"u8, destination, out _);

        // Assert
        success.ShouldBeFalse();
    }
}