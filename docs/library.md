# Library Documentation

Complete guide to the `Stjp.SecureCredentialManagement` .NET library.

## Installation

```bash
dotnet add package Stjp.SecureCredentialManagement
```

## Requirements

- Windows 10/11 or Windows Server 2016+
- .NET 10.0 or later

---

## Basic Operations

```csharp
using SecureCredentialManagement;

// Write a credential
CredentialManager.WriteCredential(
    targetName: "MyApp:Production",
    userName: "admin@example.com", 
    secret: "MySecurePassword123",
    persistence: CredentialPersistence.LocalMachine);

// Read a credential
var credential = CredentialManager.ReadCredential("MyApp:Production");
if (credential is not null)
{
    Console.WriteLine($"User: {credential.UserName}");
    Console.WriteLine($"Password: {credential.Password}");
}

// Delete a credential
bool deleted = CredentialManager.DeleteCredential("MyApp:Production");

// Enumerate credentials
var allCreds = CredentialManager.EnumerateCredentials();
var filtered = CredentialManager.EnumerateCredentials("MyApp:*");
```

---

## Fluent Builder API (Recommended)

The builder API provides a clean, readable way to create credentials with full control over all options:

```csharp
// Simple credential
CredentialManager.CreateCredential("MyApp:Production")
    .WithUserName("admin@example.com")
    .WithSecret("MySecurePassword123")
    .Save();

// Full-featured credential with metadata
CredentialManager.CreateCredential("MyApp:Database")
    .WithUserName("sa")
    .WithSecret(passwordFromSecureSource)
    .WithPersistence(CredentialPersistence.LocalMachine)
    .WithType(CredentialType.Generic)
    .WithComment("Production DB - created by deployment pipeline")
    .WithExpiry(DateTimeOffset.UtcNow.AddDays(90))
    .WithMetadata("created_by", "deploy-bot")
    .WithMetadata("environment", "production")
    .WithAttribute("team", System.Text.Encoding.UTF8.GetBytes("platform"))
    .SaveSecure();  // Use SaveSecure() for zeroed intermediate buffers
```

---

## Reading Credential Metadata

```csharp
var credential = CredentialManager.ReadCredential("MyApp:Database");
if (credential is not null)
{
    Console.WriteLine($"Target: {credential.TargetName}");
    Console.WriteLine($"User: {credential.UserName}");
    Console.WriteLine($"Type: {credential.CredentialType}");
    Console.WriteLine($"Last Updated: {credential.LastWritten}");
    Console.WriteLine($"Comment: {credential.Comment}");
    
    // Check expiry
    if (credential.IsExpired())
        Console.WriteLine("[!] This credential has expired!");
    
    // Read string attributes
    var createdBy = credential.GetAttributeAsString("meta:created_by");
    Console.WriteLine($"Created by: {createdBy}");
    
    // Access raw byte attributes
    foreach (var attr in credential.Attributes)
        Console.WriteLine($"  {attr.Key}: {System.Text.Encoding.UTF8.GetString(attr.Value)}");
}
```

---

## Credential Rotation

Rotate secrets with validation hooks and automatic rollback on failure:

```csharp
using SecureCredentialManagement;

// Create a rotation handler for a credential
var rotation = new CredentialRotation("MyApp:Database");

// Hook into rotation events for validation
rotation.OnBeforeRotate += (sender, e) =>
{
    Console.WriteLine($"About to rotate: {e.TargetName}");
    // Cancel if needed: e.Cancel = true; e.CancelReason = "Maintenance window";
};

rotation.OnValidate += (sender, e) =>
{
    // Test the new credential before committing
    bool canConnect = TryConnectToDatabase(e.NewCredential);
    if (!canConnect)
    {
        e.IsValid = false;
        e.ValidationError = "Failed to connect with new credentials";
    }
};

rotation.OnAfterRotate += (sender, e) =>
{
    if (e.Success)
        Console.WriteLine($"Rotated {e.TargetName} successfully");
    else if (e.WasRolledBack)
        Console.WriteLine($"Rotation failed, rolled back to previous credential");
};

// Perform rotation with automatic rollback on validation failure
var result = rotation.Rotate(
    newSecret: GenerateNewPassword(),
    rollbackOnFailure: true,
    updateComment: true  // Appends "Rotated: <timestamp>" to comment
);

if (!result.Success)
    Console.Error.WriteLine($"Rotation failed: {result.Error?.Message ?? result.CancelReason}");
```

### Rotation Events

| Event | Description |
|-------|-------------|
| `OnBeforeRotate` | Called before rotation. Set `e.Cancel = true` to abort. |
| `OnValidate` | Called after writing new credential. Set `e.IsValid = false` to trigger rollback. |
| `OnAfterRotate` | Called after rotation completes (success or failure). |

### RotationResult Properties

| Property | Type | Description |
|----------|------|-------------|
| `Success` | `bool` | Whether rotation completed successfully |
| `NewCredential` | `Credential?` | The new credential (if successful) |
| `PreviousCredential` | `Credential?` | The original credential |
| `WasCancelled` | `bool` | Whether rotation was cancelled by BeforeRotate event |
| `CancelReason` | `string?` | Reason provided if cancelled |
| `WasRolledBack` | `bool` | Whether rollback occurred due to validation failure |
| `Error` | `Exception?` | Exception if rotation failed |

---

## Audit Events

Subscribe to credential access events for logging, SIEM integration, or compliance:

```csharp
using SecureCredentialManagement;

// Enable the audit system (disabled by default for performance)
CredentialAudit.IsEnabled = true;

// Subscribe to access events
CredentialAudit.OnCredentialAccessed += (sender, e) =>
{
    // Log to your preferred destination: file, EventLog, SIEM, etc.
    Log.Info($"[{e.Timestamp:u}] {e.UserName}@{e.MachineName} " +
             $"accessed '{e.TargetName}' ({e.Operation}, secret={e.SecretWasRetrieved})");
};

CredentialAudit.OnCredentialModified += (sender, e) =>
{
    Log.Info($"[{e.Timestamp:u}] {e.UserName} {e.Operation} '{e.TargetName}' " +
             $"(new={e.IsNewCredential})");
};

CredentialAudit.OnCredentialDeleted += (sender, e) =>
{
    Log.Warn($"[{e.Timestamp:u}] {e.UserName} deleted '{e.TargetName}'");
};

CredentialAudit.OnCredentialsEnumerated += (sender, e) =>
{
    Log.Info($"[{e.Timestamp:u}] {e.UserName} enumerated {e.CredentialCount} credentials " +
             $"(filter: {e.Filter ?? "all"})");
};
```

### Audit Event Properties

All audit events include:

| Property | Type | Description |
|----------|------|-------------|
| `Timestamp` | `DateTimeOffset` | UTC time of the operation |
| `UserName` | `string` | Windows user (e.g., `DOMAIN\user`) |
| `MachineName` | `string` | Computer name |
| `ProcessId` | `int` | Calling process ID |
| `ProcessName` | `string?` | Calling process name |

### Event-Specific Properties

**CredentialAccessedEventArgs:**
- `TargetName` - Credential that was accessed
- `CredentialType` - Type of the credential
- `Operation` - Read, ReadSecure, or UseCredential
- `SecretWasRetrieved` - Whether the password was accessed

**CredentialModifiedEventArgs:**
- `TargetName` - Credential that was modified
- `CredentialType` - Type of the credential
- `Operation` - Create, Update, or Rotate
- `IsNewCredential` - Whether this was a new credential

**CredentialDeletedEventArgs:**
- `TargetName` - Credential that was deleted
- `CredentialType` - Type of the credential

**CredentialEnumeratedEventArgs:**
- `Filter` - Filter pattern used (null for all)
- `CredentialCount` - Number of credentials returned

> **Note:** Audit is opt-in and disabled by default. Events are raised synchronously - keep handlers fast to avoid performance impact.

---

## Export/Import API

```csharp
using SecureCredentialManagement;
using System.Security.Cryptography;

// Export with DPAPI (current user)
CredentialExport.ExportToFile(
    filePath: "backup.json",
    filter: "MyApp:*",
    method: CredentialExport.EncryptionMethod.Dpapi,
    dpapiScope: DataProtectionScope.CurrentUser);

// Export with password (portable)
CredentialExport.ExportToFile(
    filePath: "backup.json",
    filter: "MyApp:*",
    method: CredentialExport.EncryptionMethod.Password,
    password: securePassword);

// Export specific targets
CredentialExport.ExportToFile(
    filePath: "backup.json",
    filter: null,
    targets: new[] { "MyApp:Prod", "MyApp:Dev" },
    method: CredentialExport.EncryptionMethod.Dpapi);

// Import credentials
var result = CredentialExport.ImportFromFile(
    filePath: "backup.json",
    password: decryptionPassword,  // null for DPAPI
    overwriteExisting: false);

Console.WriteLine($"Imported: {result.Imported}, Skipped: {result.Skipped}, Failed: {result.Failed}");
```

### Encryption Methods

| Method | Description | Portable? |
|--------|-------------|-----------|
| `Dpapi` | Windows Data Protection API | No - current user/machine only |
| `Password` | AES-GCM with PBKDF2 (100k iterations) | Yes - any machine with password |

---

## Credential Properties Reference

| Property | Type | Description |
|----------|------|-------------|
| `TargetName` | `string` | Unique identifier for the credential |
| `UserName` | `string?` | Username or key identifier |
| `Password` | `string?` | The secret value |
| `CredentialType` | `CredentialType` | Generic, DomainPassword, DomainCertificate, etc. |
| `Comment` | `string?` | Description or notes |
| `LastWritten` | `DateTimeOffset` | When the credential was last modified |
| `Attributes` | `IReadOnlyDictionary<string, byte[]>` | Custom key-value metadata |
| `TargetAlias` | `string?` | Alternative name for the credential |

### Credential Types

| Type | Value | Writable | Use Case |
|------|-------|----------|----------|
| `Generic` | 1 | ✅ | Application credentials (API keys, passwords) |
| `DomainPassword` | 2 | ✅ | Windows domain authentication |
| `DomainCertificate` | 3 | ❌ | Certificate-based auth (smartcards) - read-only |
| `DomainVisiblePassword` | 4 | ✅ | RDP saved credentials |
| `GenericCertificate` | 5 | ❌ | Application certificates - read-only |

> **Note:** Certificate types require marshaled certificate data and cannot be created with plain username/password through this library. They can be read if created by other applications.

### Helper Methods

| Method | Description |
|--------|-------------|
| `credential.GetAttributeAsString(key)` | Get attribute value as UTF-8 string |
| `credential.IsExpired()` | Check if "expiry" attribute is in the past |
| `credentialType.IsWritable()` | Check if type can be created with username/password |
| `credentialType.GetWriteRestrictionReason()` | Get explanation for read-only types |
| `CredentialBuilder.WithExpiry(date)` | Set expiration date |
| `CredentialBuilder.WithMetadata(key, value)` | Add `meta:` prefixed attribute |

---

## Error Handling

The library throws `CredentialException` with user-friendly messages for common errors:

```csharp
try
{
    CredentialManager.CreateCredential("MyApp:Token")
        .WithUserName("user")
        .WithSecret("secret")
        .WithType(CredentialType.DomainCertificate)  // Invalid for password-based creds
        .Save();
}
catch (CredentialException ex)
{
    Console.WriteLine(ex.Message);
    // "Cannot write credential: DomainCertificate requires marshaled certificate data..."
    
    if (ex.Win32ErrorCode.HasValue)
        Console.WriteLine($"Win32 Error: {ex.Win32ErrorCode}");
}
```

### Common Error Codes

| Code | Constant | Meaning |
|------|----------|---------|
| 87 | `ERROR_INVALID_PARAMETER` | Invalid credential type or malformed data |
| 1168 | `ERROR_NOT_FOUND` | Credential does not exist |
| 2202 | `ERROR_INVALID_USERNAME` | Username format wrong for credential type |
| 1312 | `ERROR_NO_SUCH_LOGON_SESSION` | Session-scoped credential from different session |

---

## See Also

- [Security Model](security.md) - Honest assessment of security guarantees
- [CLI Reference](cli.md) - Command-line tool documentation
- [CHANGELOG](../CHANGELOG.md) - Version history
