/* SPDX - License - Identifier: Apache - 2.0 
 * Copyright(c) 2025 Stefan Ploch */

using SecureCredentialManagement;
using Shouldly;
using Xunit;

namespace SecureCredentialManagement.Tests;

/// <summary>
/// Integration tests for CredentialManager.
/// These tests interact with the real Windows Credential Manager.
/// </summary>
public class CredentialManagerTests : IDisposable
{
    private const string TestTargetPrefix = "CredentialManagement.Tests:";
    private readonly List<string> _createdCredentials = [];

    [Fact]
    public void WriteCredential_ThenReadCredential_ReturnsMatchingCredential()
    {
        // Arrange
        var target = CreateTestTarget();
        var userName = "testuser@example.com";
        var password = "TestPassword123!";

        // Act
        CredentialManager.WriteCredential(target, userName, password, CredentialPersistence.Session);
        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.TargetName.ShouldBe(target);
        credential.UserName.ShouldBe(userName);
        credential.Password.ShouldBe(password);
        credential.CredentialType.ShouldBe(CredentialType.Generic);
    }

    [Fact]
    public void ReadCredential_NonExistent_ReturnsNull()
    {
        // Act
        var credential = CredentialManager.ReadCredential("NonExistent:Target:12345");

        // Assert
        credential.ShouldBeNull();
    }

    [Fact]
    public void DeleteCredential_ExistingCredential_ReturnsTrue()
    {
        // Arrange
        var target = CreateTestTarget();
        CredentialManager.WriteCredential(target, "user", "pass", CredentialPersistence.Session);

        // Act
        var deleted = CredentialManager.DeleteCredential(target);

        // Assert
        deleted.ShouldBeTrue();
        CredentialManager.ReadCredential(target).ShouldBeNull();
        _createdCredentials.Remove(target); // Already deleted
    }

    [Fact]
    public void DeleteCredential_NonExistent_ReturnsFalse()
    {
        // Act
        var deleted = CredentialManager.DeleteCredential("NonExistent:Target:12345");

        // Assert
        deleted.ShouldBeFalse();
    }

    [Fact]
    public void EnumerateCredentials_WithFilter_ReturnsMatchingCredentials()
    {
        // Arrange
        var target1 = CreateTestTarget("A");
        var target2 = CreateTestTarget("B");
        CredentialManager.WriteCredential(target1, "user1", "pass1", CredentialPersistence.Session);
        CredentialManager.WriteCredential(target2, "user2", "pass2", CredentialPersistence.Session);

        // Act
        var credentials = CredentialManager.EnumerateCredentials($"{TestTargetPrefix}*");

        // Assert
        credentials.Count.ShouldBeGreaterThanOrEqualTo(2);
        credentials.ShouldContain(c => c.TargetName == target1);
        credentials.ShouldContain(c => c.TargetName == target2);
    }

    [Fact]
    public void TryReadCredentialSecure_InvokesCallbackWithSecret()
    {
        // Arrange
        var target = CreateTestTarget();
        var expectedPassword = "SecurePassword!";
        CredentialManager.WriteCredential(target, "user", expectedPassword, CredentialPersistence.Session);
        string? capturedSecret = null;

        // Act
        var found = CredentialManager.TryReadCredentialSecure(target, out var userName,
            (secret, _) => capturedSecret = new string(secret), null);

        // Assert
        found.ShouldBeTrue();
        userName.ShouldBe("user");
        capturedSecret.ShouldBe(expectedPassword);
    }

    [Fact]
    public void TryUseCredential_ProvidesUserNameAndSecret()
    {
        // Arrange
        var target = CreateTestTarget();
        CredentialManager.WriteCredential(target, "testuser", "testpass", CredentialPersistence.Session);
        string? capturedUser = null;
        string? capturedSecret = null;

        // Act
        var found = CredentialManager.TryUseCredential<object?>(target,
            (secret, ctx) =>
            {
                capturedUser = ctx.userName;
                capturedSecret = new string(secret);
            }, null);

        // Assert
        found.ShouldBeTrue();
        capturedUser.ShouldBe("testuser");
        capturedSecret.ShouldBe("testpass");
    }

    // Cleanup
    public void Dispose()
    {
        foreach (var target in _createdCredentials)
        {
            try { CredentialManager.DeleteCredential(target); }
            catch { /* ignore cleanup errors */ }
        }
    }

    private string CreateTestTarget(string? suffix = null)
    {
        var target = $"{TestTargetPrefix}{Guid.NewGuid():N}{suffix}";
        _createdCredentials.Add(target);
        return target;
    }
}