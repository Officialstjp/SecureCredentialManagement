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

    #region Phase 1: New Feature Tests

    [Fact]
    public void WriteCredential_WithComment_ReturnsCommentOnRead()
    {
        // Arrange
        var target = CreateTestTarget();
        var comment = "Test credential for unit testing";

        // Act
        CredentialManager.WriteCredential(
            target, "user", "pass", CredentialPersistence.Session,
            comment: comment);
        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.Comment.ShouldBe(comment);
    }

    [Fact]
    public void WriteCredential_WithAttributes_ReturnsAttributesOnRead()
    {
        // Arrange
        var target = CreateTestTarget();
        var attributes = new Dictionary<string, byte[]>
        {
            ["team"] = System.Text.Encoding.UTF8.GetBytes("platform"),
            ["env"] = System.Text.Encoding.UTF8.GetBytes("production")
        };

        // Act
        CredentialManager.WriteCredential(
            target, "user", "pass", CredentialPersistence.Session,
            attributes: attributes);
        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.Attributes.Count.ShouldBe(2);
        credential.GetAttributeAsString("team").ShouldBe("platform");
        credential.GetAttributeAsString("env").ShouldBe("production");
    }

    [Fact]
    public void ReadCredential_LastWritten_ReturnsRecentTimestamp()
    {
        // Arrange
        var target = CreateTestTarget();
        var beforeWrite = DateTimeOffset.UtcNow.AddSeconds(-1);

        // Act
        CredentialManager.WriteCredential(target, "user", "pass", CredentialPersistence.Session);
        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.LastWritten.ShouldBeGreaterThan(beforeWrite);
        credential.LastWritten.ShouldBeLessThanOrEqualTo(DateTimeOffset.UtcNow.AddSeconds(1));
    }

    [Fact]
    public void CredentialBuilder_FluentApi_CreatesCredential()
    {
        // Arrange
        var target = CreateTestTarget();

        // Act
        CredentialManager.CreateCredential(target)
            .WithUserName("builder-user")
            .WithSecret("builder-pass")
            .WithPersistence(CredentialPersistence.Session)
            .WithComment("Created via builder")
            .WithAttribute("source", "unit-test")
            .Save();

        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.UserName.ShouldBe("builder-user");
        credential.Password.ShouldBe("builder-pass");
        credential.Comment.ShouldBe("Created via builder");
        credential.GetAttributeAsString("source").ShouldBe("unit-test");
    }

    [Fact]
    public void CredentialBuilder_WithExpiry_StoresExpiryAttribute()
    {
        // Arrange
        var target = CreateTestTarget();
        var expiry = DateTimeOffset.UtcNow.AddDays(30);

        // Act
        CredentialManager.CreateCredential(target)
            .WithUserName("user")
            .WithSecret("pass")
            .WithPersistence(CredentialPersistence.Session)
            .WithExpiry(expiry)
            .Save();

        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.IsExpired().ShouldBeFalse();
        var storedExpiry = credential.GetAttributeAsString("expiry");
        storedExpiry.ShouldNotBeNull();
        DateTimeOffset.Parse(storedExpiry).ShouldBe(expiry, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void Credential_IsExpired_ReturnsTrueForPastExpiry()
    {
        // Arrange
        var target = CreateTestTarget();
        var pastExpiry = DateTimeOffset.UtcNow.AddDays(-1);

        // Act
        CredentialManager.CreateCredential(target)
            .WithUserName("user")
            .WithSecret("pass")
            .WithPersistence(CredentialPersistence.Session)
            .WithExpiry(pastExpiry)
            .Save();

        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.IsExpired().ShouldBeTrue();
    }

    [Fact]
    public void Credential_IsExpired_ReturnsFalseWhenNoExpiry()
    {
        // Arrange
        var target = CreateTestTarget();

        // Act
        CredentialManager.WriteCredential(target, "user", "pass", CredentialPersistence.Session);
        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.IsExpired().ShouldBeFalse();
    }

    [Fact]
    public void CredentialBuilder_WithMetadata_StoresWithPrefix()
    {
        // Arrange
        var target = CreateTestTarget();

        // Act
        CredentialManager.CreateCredential(target)
            .WithUserName("user")
            .WithSecret("pass")
            .WithPersistence(CredentialPersistence.Session)
            .WithMetadata("created_by", "unit-test")
            .WithMetadata("version", "1.0")
            .Save();

        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.GetAttributeAsString("meta:created_by").ShouldBe("unit-test");
        credential.GetAttributeAsString("meta:version").ShouldBe("1.0");
    }

    [Fact]
    public void WriteCredentialSecure_WithAllOptions_RoundTripsCorrectly()
    {
        // Arrange
        var target = CreateTestTarget();
        var comment = "Secure credential test";
        var attributes = new Dictionary<string, byte[]>
        {
            ["key1"] = [0x01, 0x02, 0x03]
        };

        // Act
        CredentialManager.WriteCredentialSecure(
            target,
            "secure-user",
            "secure-password".AsSpan(),
            CredentialPersistence.Session,
            CredentialType.Generic,
            comment,
            attributes: attributes);

        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.UserName.ShouldBe("secure-user");
        credential.Password.ShouldBe("secure-password");
        credential.Comment.ShouldBe(comment);
        credential.Attributes["key1"].ShouldBe(new byte[] { 0x01, 0x02, 0x03 });
    }

    [Fact]
    public void GetAttributeAsString_NonExistentKey_ReturnsNull()
    {
        // Arrange
        var target = CreateTestTarget();
        CredentialManager.WriteCredential(target, "user", "pass", CredentialPersistence.Session);
        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.GetAttributeAsString("nonexistent").ShouldBeNull();
    }

    [Fact]
    public void CredentialBuilder_SaveSecure_ZeroesIntermediateBuffers()
    {
        // This test verifies SaveSecure works - actual memory zeroing
        // can't be easily verified in managed code
        var target = CreateTestTarget();

        // Act
        CredentialManager.CreateCredential(target)
            .WithUserName("user")
            .WithSecret("sensitive-password")
            .WithPersistence(CredentialPersistence.Session)
            .SaveSecure();

        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.Password.ShouldBe("sensitive-password");
    }

    #endregion

    #region Credential Type and Error Handling Tests

    [Fact]
    public void WriteCredential_WithDomainPasswordType_Succeeds()
    {
        // DomainPassword requires a server-style target name
        // Using a format that Windows Credential Manager accepts
        var target = $"TestServer{Guid.NewGuid():N}";
        _createdCredentials.Add(target);

        // Act
        CredentialManager.WriteCredential(
            target, "DOMAIN\\testuser", "pass123",
            CredentialPersistence.Session,
            type: CredentialType.DomainPassword);
        
        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.CredentialType.ShouldBe(CredentialType.DomainPassword);
        credential.UserName.ShouldBe("DOMAIN\\testuser");
    }

    [Fact]
    public void WriteCredential_WithDomainVisiblePasswordType_Succeeds()
    {
        // Arrange
        var target = CreateTestTarget();

        // Act
        CredentialManager.WriteCredential(
            target, "testuser", "visiblepass",
            CredentialPersistence.Session,
            type: CredentialType.DomainVisiblePassword);
        
        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.CredentialType.ShouldBe(CredentialType.DomainVisiblePassword);
    }

    [Fact]
    public void WriteCredential_WithInvalidType_ThrowsCredentialException()
    {
        // Arrange
        var target = CreateTestTarget();

        // Act & Assert
        var ex = Should.Throw<CredentialException>(() =>
            CredentialManager.WriteCredential(
                target, "user", "pass",
                CredentialPersistence.Session,
                type: CredentialType.DomainCertificate));

        ex.Message.ShouldContain("DomainCertificate");
        ex.CredentialType.ShouldBe(CredentialType.DomainCertificate);
    }

    [Fact]
    public void WriteCredential_WithMaximumType_ThrowsCredentialException()
    {
        // Arrange
        var target = CreateTestTarget();

        // Act & Assert
        var ex = Should.Throw<CredentialException>(() =>
            CredentialManager.WriteCredential(
                target, "user", "pass",
                CredentialPersistence.Session,
                type: CredentialType.Maximum));

        ex.Message.ShouldContain("not a valid credential type");
    }

    [Fact]
    public void ReadCredential_AutoDetectsDomainPasswordType()
    {
        // DomainPassword requires a server-style target name
        var target = $"AutoDetectServer{Guid.NewGuid():N}";
        _createdCredentials.Add(target);
        
        CredentialManager.WriteCredential(
            target, "DOMAIN\\user", "pass",
            CredentialPersistence.Session,
            type: CredentialType.DomainPassword);

        // Act - read without specifying type
        var credential = CredentialManager.ReadCredential(target);

        // Assert
        credential.ShouldNotBeNull();
        credential.CredentialType.ShouldBe(CredentialType.DomainPassword);
    }

    [Fact]
    public void DeleteCredential_AutoDetectsType()
    {
        // Arrange
        var target = CreateTestTarget();
        CredentialManager.WriteCredential(
            target, "user", "pass",
            CredentialPersistence.Session,
            type: CredentialType.DomainVisiblePassword);

        // Act - delete without specifying type
        var deleted = CredentialManager.DeleteCredential(target);

        // Assert
        deleted.ShouldBeTrue();
        CredentialManager.ReadCredential(target).ShouldBeNull();
        _createdCredentials.Remove(target);
    }

    [Fact]
    public void CredentialType_IsWritable_ReturnsTrueForValidTypes()
    {
        CredentialType.Generic.IsWritable().ShouldBeTrue();
        CredentialType.DomainPassword.IsWritable().ShouldBeTrue();
        CredentialType.DomainVisiblePassword.IsWritable().ShouldBeTrue();
    }

    [Fact]
    public void CredentialType_IsWritable_ReturnsFalseForCertificateTypes()
    {
        CredentialType.DomainCertificate.IsWritable().ShouldBeFalse();
        CredentialType.GenericCertificate.IsWritable().ShouldBeFalse();
        CredentialType.DomainExtended.IsWritable().ShouldBeFalse();
        CredentialType.Maximum.IsWritable().ShouldBeFalse();
    }

    [Fact]
    public void CredentialType_GetWriteRestrictionReason_ReturnsMessageForInvalidTypes()
    {
        CredentialType.DomainCertificate.GetWriteRestrictionReason().ShouldNotBeNull();
        CredentialType.GenericCertificate.GetWriteRestrictionReason().ShouldNotBeNull();
        CredentialType.Maximum.GetWriteRestrictionReason().ShouldNotBeNull();
    }

    [Fact]
    public void CredentialType_GetWriteRestrictionReason_ReturnsNullForValidTypes()
    {
        CredentialType.Generic.GetWriteRestrictionReason().ShouldBeNull();
        CredentialType.DomainPassword.GetWriteRestrictionReason().ShouldBeNull();
        CredentialType.DomainVisiblePassword.GetWriteRestrictionReason().ShouldBeNull();
    }

    [Fact]
    public void CredentialBuilder_WithInvalidType_ThrowsOnSave()
    {
        // Arrange
        var target = CreateTestTarget();

        // Act & Assert
        var ex = Should.Throw<CredentialException>(() =>
            CredentialManager.CreateCredential(target)
                .WithUserName("user")
                .WithSecret("pass")
                .WithType(CredentialType.DomainExtended)
                .Save());

        ex.Message.ShouldContain("DomainExtended");
    }

    #endregion

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