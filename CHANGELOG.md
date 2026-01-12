# Changelog

All notable changes to SecureCredentialManagement will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
