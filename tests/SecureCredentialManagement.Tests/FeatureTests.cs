/// <summary>
/// Tests for different features of the SecureCredentialManagement library.
/// </summary>
using SecureCredentialManagement;
using static SecureCredentialManagement.CredentialExport;
using System.Security.Cryptography;
using Shouldly;
using Xunit;

public class FeatureTests
{
    private static string? ResolvePassword(string? explicitPassword, string? envVarName, bool promptIfMissing)
    {
        if (!string.IsNullOrEmpty(explicitPassword))
            return explicitPassword;

        if (!string.IsNullOrEmpty(envVarName))
        {
            var envValue = Environment.GetEnvironmentVariable(envVarName);
            if (!string.IsNullOrEmpty(envValue))
                return envValue;
        }

        if (promptIfMissing)
        {
            Console.Write("Enter password: ");
            return Console.ReadLine();
        }

        return null;
    }

    [Fact]
    public void ResolvePassword_FromEnvironmentVariable_ReturnsValue()
    {
        Environment.SetEnvironmentVariable("TEST_SECRET", "env-password");
        try
        {
            var result = ResolvePassword(null, "TEST_SECRET", false);
            result.ShouldBe("env-password");
        }
        finally
        {
            Environment.SetEnvironmentVariable("TEST_SECRET", null);
        }
    }

    [Fact]
    public void ResolvePassword_ExplicitTakesPriority()
    {
        Environment.SetEnvironmentVariable("TEST_SECRET", "env-password");
        try
        {
            var result = ResolvePassword("explicit-password", "TEST_SECRET", false);
            result.ShouldBe("explicit-password");
        }
        finally
        {
            Environment.SetEnvironmentVariable("TEST_SECRET", null);
        }
    }

    [Fact]
    public void ExportImport_WithDpapi_RoundTrips()
    {
        var target = $"Test:ExportImport:{Guid.NewGuid():N}";
        try
        {
            CredentialManager.WriteCredential(target, "user", "secret123");

            var exported = CredentialExport.Export(filter: target, encryptionMethod: EncryptionMethod.Dpapi);
            exported.Credentials.Count.ShouldBe(1);
            exported.Encryption!.Method.ShouldBe("dpapi");

            CredentialManager.DeleteCredential(target);

            var results = CredentialExport.Import(exported, overwrite: true);
            results.Count.ShouldBe(1);
            if (!results[0].Success)
                throw new Exception($"Import failed: {results[0].Error}");

            var reimported = CredentialManager.ReadCredential(target);
            reimported.ShouldNotBeNull();
            reimported.Password.ShouldBe("secret123");
        }
        finally
        {
            CredentialManager.DeleteCredential(target);
        }
    }

    [Fact]
    public void ExportImport_WithPassword_RoundTrips()
    {
        var target = $"Test:ExportPassword:{Guid.NewGuid():N}";
        try
        {
            CredentialManager.WriteCredential(target, "user", "secret456");

            var exported = CredentialExport.Export(filter: target, encryptionMethod: EncryptionMethod.Password, password: "test-password");

            CredentialManager.DeleteCredential(target);

            var results = CredentialExport.Import(exported, "test-password", overwrite: true);
            if (!results[0].Success)
                throw new Exception($"Import failed: {results[0].Error}");

            var reimported = CredentialManager.ReadCredential(target);
            reimported!.Password.ShouldBe("secret456");
        }
        finally
        {
            CredentialManager.DeleteCredential(target);
        }
    }

    [Fact]
    public void Import_WrongPassword_FailsWithError()
    {
        var target = $"Test:WrongPassword:{Guid.NewGuid():N}";
        try
        {
            CredentialManager.WriteCredential(target, "user", "secret");

            var exported = CredentialExport.Export(filter: target, encryptionMethod: EncryptionMethod.Password, password: "correct-password");
            CredentialManager.DeleteCredential(target);

            // Import with wrong password should fail with error, not throw
            // (errors are captured in results for batch operations)
            var results = CredentialExport.Import(exported, "wrong-password");
            results.Count.ShouldBe(1);
            results[0].Success.ShouldBeFalse();
            results[0].Error.ShouldNotBeNullOrEmpty();
        }
        finally
        {
            CredentialManager.DeleteCredential(target);
        }
    }

    [Fact]
    public void Rotation_Success_UpdatesCredential()
    {
        var target = $"Test:Rotation:{Guid.NewGuid():N}";
        try
        {
            CredentialManager.WriteCredential(target, "user", "old-password");

            var rotation = new CredentialRotation(target);
            var result = rotation.Rotate("new-password");

            result.Success.ShouldBeTrue();
            result.PreviousCredential!.Password.ShouldBe("old-password");

            var updated = CredentialManager.ReadCredential(target);
            updated!.Password.ShouldBe("new-password");
        }
        finally
        {
            CredentialManager.DeleteCredential(target);
        }
    }

    [Fact]
    public void Rotation_ValidationFails_RollsBack()
    {
        var target = $"Test:RotationRollback:{Guid.NewGuid():N}";
        try
        {
            CredentialManager.WriteCredential(target, "user", "original-password");

            var rotation = new CredentialRotation(target);
            rotation.OnValidate += (s, e) =>
            {
                e.IsValid = false;
                e.ValidationError = "Simulated validation failure";
            };

            var result = rotation.Rotate("new-password", rollbackOnFailure: true);

            result.Success.ShouldBeFalse();
            result.WasRolledBack.ShouldBeTrue();

            var credential = CredentialManager.ReadCredential(target);
            credential!.Password.ShouldBe("original-password");
        }
        finally
        {
            CredentialManager.DeleteCredential(target);
        }
    }

    [Fact]
    public void Rotation_BeforeEventCancels_DoesNotRotate()
    {
        var target = $"Test:RotationCancel:{Guid.NewGuid():N}";
        try
        {
            CredentialManager.WriteCredential(target, "user", "original");

            var rotation = new CredentialRotation(target);
            rotation.OnBeforeRotate += (s, e) =>
            {
                e.Cancel = true;
                e.CancelReason = "Not allowed right now";
            };

            var result = rotation.Rotate("new-password");

            result.Success.ShouldBeFalse();
            result.WasCancelled.ShouldBeTrue();
            result.CancelReason.ShouldBe("Not allowed right now");

            var credential = CredentialManager.ReadCredential(target);
            credential!.Password.ShouldBe("original");
        }
        finally
        {
            CredentialManager.DeleteCredential(target);
        }
    }

    [Fact]
    public void Audit_WhenEnabled_FiresOnRead()
    {
        CredentialAudit.IsEnabled = true;
        var target = $"Test:Audit:{Guid.NewGuid():N}";
        var eventFired = false;

        void Handler(object? sender, CredentialAudit.CredentialAccessedEventArgs e)
        {
            if (e.TargetName == target)
                eventFired = true;
        }

        try
        {
            CredentialAudit.OnCredentialAccessed += Handler;
            CredentialManager.WriteCredential(target, "user", "secret");

            CredentialManager.ReadCredential(target);

            eventFired.ShouldBeTrue();
        }
        finally
        {
            CredentialAudit.OnCredentialAccessed -= Handler;
            CredentialAudit.IsEnabled = false;
            CredentialManager.DeleteCredential(target);
        }
    }

    [Fact]
    public void Audit_WhenDisabled_DoesNotFire()
    {
        CredentialAudit.IsEnabled = false;
        var target = $"Test:AuditDisabled:{Guid.NewGuid():N}";
        var eventFired = false;

        void Handler(object? sender, CredentialAudit.CredentialAccessedEventArgs e)
        {
            eventFired = true;
        }

        try
        {
            CredentialAudit.OnCredentialAccessed += Handler;
            CredentialManager.WriteCredential(target, "user", "secret");
            CredentialManager.ReadCredential(target);

            eventFired.ShouldBeFalse();
        }
        finally
        {
            CredentialAudit.OnCredentialAccessed -= Handler;
            CredentialManager.DeleteCredential(target);
        }
    }
}
