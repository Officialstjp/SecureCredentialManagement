# Stjp.SecureCredentialManagement

.NET library for Windows Credential Manager with encrypted storage (DPAPI), reduced memory exposure for secrets, and enterprise features.

## Installation

```bash
dotnet add package Stjp.SecureCredentialManagement
```

## Quick Start

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
Console.WriteLine($"User: {credential?.UserName}");

// Delete a credential
CredentialManager.DeleteCredential("MyApp:Production");
```

## Fluent Builder API

```csharp
CredentialManager.CreateCredential("MyApp:Database")
    .WithUserName("sa")
    .WithSecret(password)
    .WithComment("Production DB - rotate quarterly")
    .WithExpiry(DateTimeOffset.UtcNow.AddDays(90))
    .SaveSecure();  // Zeros intermediate buffers
```

## Features

- **Encrypted at rest** - Windows DPAPI via Credential Manager
- **Reduced memory exposure** - Span-based APIs minimize copies (see limitations)
- **Fluent builder** - Clean, readable credential creation
- **Metadata support** - Comments, attributes, expiry tracking
- **Credential rotation** - Rotate secrets with validation hooks and rollback
- **Audit events** - Hook into operations for SIEM/logging
- **Export/Import** - Backup with AES-GCM or DPAPI encryption
- **Auto-detection** - No need to specify credential type for read/delete

## Reduced-Exposure APIs

Minimize how long secrets exist in memory (we zero our buffer after the callback):

```csharp
// Our Span is zeroed after this callback
// But you still create a string - that's unavoidable with most .NET APIs
CredentialManager.TryUseCredential<SqlConnection>("MyApp:DB", (secret, conn) =>
{
    conn.ConnectionString = new SqlConnectionStringBuilder
    {
        DataSource = "server",
        Password = new string(secret)  // This string lives until GC
    }.ConnectionString;
}, connection);
```

> **Note:** See [security.md](https://github.com/Officialstjp/SecureCredentialManagement/blob/main/docs/security.md) for honest limitations.

## Documentation

Full documentation: https://github.com/Officialstjp/SecureCredentialManagement/blob/main/docs/library.md

## Related

- **CLI Tool**: [`wcred`](https://www.nuget.org/packages/wcred) - Command-line interface for Windows Credential Manager
