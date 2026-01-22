# SecureCredentialManagement

A .NET library and CLI tool for managing Windows Credential Manager credentials. Provides encrypted storage, reduced memory exposure for secrets, and enterprise features like rotation and audit.

[![.NET 10](https://img.shields.io/badge/.NET-10.0-blue)](https://dotnet.microsoft.com/)
[![NuGet](https://img.shields.io/nuget/v/Stjp.SecureCredentialManagement?label=NuGet%20Library)](https://www.nuget.org/packages/Stjp.SecureCredentialManagement)
[![NuGet](https://img.shields.io/nuget/v/wcred?label=NuGet%20CLI)](https://www.nuget.org/packages/wcred)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Stjp.SecureCredentialManagement?label=Downloads)](https://www.nuget.org/packages/Stjp.SecureCredentialManagement)

## What's New in v1.2

- **Automation-Friendly CLI** - `--password-stdin` and `--password-env` for scripts and CI/CD pipelines
- **Export/Import** - Backup and migrate credentials with AES-GCM or DPAPI encryption
- **Credential Rotation** - Rotate secrets with validation hooks and automatic rollback
- **Audit Events** - Subscribe to credential access/modify/delete events for SIEM integration

See [CHANGELOG.md](CHANGELOG.md) for full details.

## Features

- **Encrypted at rest** - Windows DPAPI encryption via Credential Manager
- **Reduced memory exposure** - Span-based APIs minimize secret copies
- **Full CRUD operations** - Create, read, update, delete credentials
- **CLI tool included** - Manage credentials from the command line
- **Export/Import** - Backup and migrate with AES-GCM or DPAPI encryption
- **Credential rotation** - Rotate secrets with validation hooks and rollback
- **Audit events** - Hook into credential operations for logging/SIEM
- **Metadata support** - Comments, attributes, and expiry tracking

## Installation

### NuGet Packages

**Library** (for .NET projects):
```bash
dotnet add package Stjp.SecureCredentialManagement
```

**CLI Tool** (global install):
```bash
dotnet tool install --global wcred
```

### Build from Source

```bash
git clone https://github.com/Officialstjp/SecureCredentialManagement.git
cd SecureCredentialManagement
dotnet build
dotnet test
```

## Requirements

- Windows 10/11 or Windows Server 2016+
- .NET 10.0 or later

---

## Quick Start: CLI

```bash
# List all credentials
wcred list

# Store a credential (prompts for password)
wcred set "MyApp:Production" "user@example.com"

# Store with automation (CI/CD)
wcred set "MyApp:Token" "api-key" --password-env MY_SECRET_VAR

# Read a credential
wcred get "MyApp:Production" --show-password

# Export credentials (encrypted)
wcred export --filter "MyApp:*" --output backup.json

# Import credentials
wcred import --file backup.json
```

📖 **[Full CLI Documentation](docs/cli.md)**

---

## Quick Start: Library

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

// Fluent builder with metadata
CredentialManager.CreateCredential("MyApp:Database")
    .WithUserName("sa")
    .WithSecret(password)
    .WithComment("Production DB - rotate quarterly")
    .WithExpiry(DateTimeOffset.UtcNow.AddDays(90))
    .SaveSecure();

// Reduced-exposure API - our buffer is zeroed after callback
CredentialManager.TryUseCredential<HttpClient>("API:Token", (secret, client) =>
{
    // You still create a string here - that's unavoidable with most .NET APIs
    client.DefaultRequestHeaders.Authorization = 
        new AuthenticationHeaderValue("Bearer", new string(secret));
}, httpClient);
```

📖 **[Full Library Documentation](docs/library.md)**

---

## Documentation

| Document | Description |
|----------|-------------|
| [CLI Reference](docs/cli.md) | Complete `wcred` command reference |
| [Library Guide](docs/library.md) | Full .NET library API documentation |
| [Security Deep-Dive](docs/security.md) | Honest assessment of security guarantees |
| [CHANGELOG](CHANGELOG.md) | Version history and release notes |

---

## Roadmap

**v1.3: PowerShell Module** - Native binary module for PSGallery, supporting PowerShell 5.1 and 7.x. See [CHANGELOG.md](CHANGELOG.md#roadmap) for details.

---

## License

[Apache 2.0](LICENSE)
