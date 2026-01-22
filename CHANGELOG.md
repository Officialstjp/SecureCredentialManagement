# Changelog

All notable changes to SecureCredentialManagement will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-01-22

### Added

- **Automation-Friendly CLI**
  - `--password-stdin` option reads password from standard input
  - `--password-env VAR` option reads password from environment variable by name (Note: PowerShell format `$env:variable` detection warns, as it might be expanded by the shell)
  - Works with `set`, `export`, and `import` commands

- **Credential Export/Import**
  - `wcred export` command exports credentials to encrypted JSON files
  - `wcred import` command restores credentials from exported files
  - **AES-GCM encryption** with password-based key derivation (PBKDF2, 100k iterations)
  - **DPAPI encryption** for Windows-native protection (user or machine scope)
  - `--filter` and `--targets` options to select credentials for export
  - `--dry-run` option to preview import without writing
  - Library API: `CredentialExport.ExportToFile()` and `CredentialExport.ImportFromFile()`

- **Credential Rotation API**
  - `CredentialRotation` class for managed secret rotation
  - `OnBeforeRotate` event with cancellation support
  - `OnValidate` event for testing new credentials before commit
  - `OnAfterRotate` event with success/failure notification
  - Automatic rollback on validation failure
  - `RotateAsync()` for async workflows
  - `updateComment` option appends rotation timestamp

- **Audit Events**
  - `CredentialAudit` static class with opt-in event firing
  - `OnCredentialAccessed` - fired on read/use operations
  - `OnCredentialModified` - fired on create/update/rotate
  - `OnCredentialDeleted` - fired on delete operations
  - `OnCredentialsEnumerated` - fired on list operations
  - Event args include: Timestamp, UserName, MachineName, ProcessId, ProcessName
  - `CredentialAudit.IsEnabled` toggle for performance

- **Documentation**
  - `docs\cli.md` - Full CLI reference guide
  - `docs\library.md` - Detailed library usage guide
  - `docs\security.md` - Deep-dive into security model and limitations
  - `docs\nuget-cli.md` - NuGet package page for CLI tool
  - `docs\nuget-library.md` - NuGet package page for library 

### Changed

- Added `System.Security.Cryptography.ProtectedData` package dependency

---

## Roadmap

### Planned: PowerShell Module (v1.3)

A native PowerShell binary module (`SecureCredentialManagement`) is planned for PSGallery.

**What this means for consumers:**

| Package | Impact |
|---------|--------|
| **wcred CLI** | None - stays .NET 10 only |
| **NuGet library** | None - existing apps get the same `net10.0` build |
| **PowerShell 7.4+** | Full feature parity via `net8.0` build |
| **PowerShell 5.1** | Functional parity, reduced memory security* |

*PowerShell 5.1 runs on .NET Framework 4.8, which lacks `CryptographicOperations.ZeroMemory`. Memory clearing will use `Array.Clear()` which may be optimized away by the JIT. For security-sensitive scenarios, PowerShell 7.x is recommended.

The core library will be multi-targeted (`net48`, `net8.0`, `net10.0`) with framework-specific implementations where needed. This is additive - no breaking changes for existing consumers.

---

## [1.1.0] - 2026-01-12

### Added

- **Fluent Builder API** - New `CredentialManager.CreateCredential()` returns a `CredentialBuilder` for clean, readable credential creation:
  ```csharp
  CredentialManager.CreateCredential("MyApp:Token")
      .WithUserName("api-key")
      .WithSecret("secret-value")
      .WithComment("Production API token")
      .WithExpiry(DateTimeOffset.UtcNow.AddDays(90))
      .WithMetadata("created_by", "deploy-bot")
      .Save();
  ```

- **Credential Metadata Support**
  - `Comment` property - Description or notes stored with the credential
  - `TargetAlias` property - Alternative name for the credential
  - `LastWritten` property - When the credential was last modified
  - `Attributes` property - Custom key-value metadata (`IReadOnlyDictionary<string, byte[]>`)
  - `GetAttributeAsString(key)` helper method for UTF-8 attribute values

- **Expiry Tracking**
  - `WithExpiry(DateTimeOffset)` on builder sets an "expiry" attribute
  - `credential.IsExpired()` checks if the credential has expired
  - CLI shows expiry warnings when displaying credentials

- **Auto-Detection for Credential Types**
  - `ReadCredential(targetName)` now tries all common types automatically
  - `DeleteCredential(targetName)` also supports auto-detection
  - No longer need to know the exact type to read or delete credentials

- **Custom Exception Type**
  - New `CredentialException` class with user-friendly error messages
  - `Win32ErrorCode` property for programmatic error handling
  - `CredentialType` property indicates which type caused the error
  - Translates common errors: invalid username format, invalid type, permission issues

- **Type Validation**
  - `CredentialType.IsWritable()` extension method
  - `CredentialType.GetWriteRestrictionReason()` explains why a type can't be written
  - Certificate types (DomainCertificate, GenericCertificate) are read-only through this library

- **CLI Enhancements**
  - `--comment` option for `set` command
  - `--type` option restricted to writable types only
  - `get` command shows LastWritten, Comment, Attributes, and expiry warnings
  - `list --wide` format includes timestamps and comments
  - Improved help text with examples and descriptions

### Changed

- `DeleteCredential()` type parameter is now optional (defaults to auto-detect)
- Error handling uses `CredentialException` instead of raw `Win32Exception`
- XML documentation on `CredentialType` enum values

### Fixed

- Memory leak in attribute parsing (keyword pointers not freed)
- Type parameter was ignored in `WriteCredential` (always used Generic)

## [1.0.0] - 2025-12-01

### Added

- Initial release
- Secure memory handling with `CryptographicOperations.ZeroMemory()`
- Zero-allocation APIs with `Span<char>` support
- Full CRUD operations for Windows Credential Manager
- `TryUseCredential` and `TryReadCredentialSecure` for secure secret handling
- `SecureEncoding` utilities (BasicAuth, HMAC-SHA256)
- CLI tool (`wcred`) for command-line credential management
- P/Invoke to Windows Credential Manager APIs (advapi32.dll)
