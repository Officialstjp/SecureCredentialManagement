# Security Model & Limitations

This document provides an overview of what this library protects against and what it doesn't.

## TL;DR

- Credentials are encrypted at rest by Windows Credential Manager (DPAPI)
- We reduce memory copies of secrets, but can't eliminate them entirely
- Most .NET APIs require strings, so you'll still create at least one copy
- This helps against casual inspection, not determined attackers with memory access

We provide **defense-in-depth**, not bulletproof security. Use these APIs as one layer among many.

---

## How Windows Credential Manager Works

```
┌─────────────────────────────────────────────────────────────────┐
│ Disk: Credentials encrypted with DPAPI (user's login key)       │
│ → Secure at rest +                                              │
└─────────────────────────────────────────────────────────────────┘
                              ↓ CredRead()
┌─────────────────────────────────────────────────────────────────┐
│ Unmanaged memory: CREDENTIAL struct with password bytes         │
│ → Exists until we call CredFree()                               │
└─────────────────────────────────────────────────────────────────┘
                              ↓ Our library
┌─────────────────────────────────────────────────────────────────┐
│ Managed memory: We decode to Span<char>, then zero it           │
│ → We control this, we zero it +                                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓ Your code
┌─────────────────────────────────────────────────────────────────┐
│ code might: new string(secret) for HttpClient, SqlConnection    │
│ → Lives until GC, we can't control this !                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## What We Protect Against

| Threat | Protection Level | Notes |
|--------|------------------|-------|
| Credentials stolen from disk | ✅ Strong | Windows DPAPI encryption |
| Casual memory inspection | ⚠️ Partial | Fewer copies = fewer places to look |
| Memory pressure / GC churn | ✅ Good | Less garbage containing secrets |
| Accidental logging | ⚠️ Partial | Span can't be accidentally ToString()'d |

## What We DON'T Protect Against

| Threat | Why Not |
|--------|---------|
| Memory dump while secret in use | The `new string(secret)` lives in memory |
| Debugger attached to process | Can read any memory |
| Determined attacker with memory access | Will find the string eventually |
| Crash at the wrong moment | String may not be GC'd yet |

---

## Reduced-Exposure APIs

### The Problem

```csharp
// Standard pattern - multiple copies
var cred = CredentialManager.ReadCredential("MyApp:DB");
string password = cred.Password;           // Copy 1: Property returns new string
string connStr = $"...Password={password}"; // Copy 2: String interpolation
// Both live until garbage collected (unpredictable timing)
```

### What We Offer

```csharp
// Reduced-exposure pattern
CredentialManager.TryUseCredential<SqlConnection>("MyApp:DB", (secret, conn) =>
{
    // 'secret' is a Span<char> that we will zero after this callback
    conn.ConnectionString = new SqlConnectionStringBuilder
    {
        Password = new string(secret)  // Still need to create ONE string
    }.ConnectionString;
}, connection);
// Our Span is now zeroed, but SqlConnection holds a string internally
```

### What We Actually Achieve

- **Reduced copies**: From N copies to 1 copy
- **Controlled lifetime for our buffer**: We zero it immediately
- **No accidental retention**: Span can't be stored in a field

### What We Can't Achieve

- **Zero copies**: Almost all .NET APIs require strings
- **Control over downstream**: HttpClient, SqlConnection, etc. keep their own copies
- **Guaranteed cleanup**: The one string you create lives until GC

---

## Reduced-Exposure API Reference

### TryUseCredential

Read a credential and use the secret in a callback. Our buffer is zeroed after callback completes.

```csharp
bool found = CredentialManager.TryUseCredential<TContext>(
    string targetName,
    Action<ReadOnlySpan<char>, TContext> useSecret,
    TContext context);
```

**Example:**

```csharp
CredentialManager.TryUseCredential<HttpClient>("API:Token", (secret, client) =>
{
    // We zero 'secret' after this callback returns
    // But the string you create here lives until GC
    client.DefaultRequestHeaders.Authorization = 
        new AuthenticationHeaderValue("Bearer", new string(secret));
}, httpClient);
```

### TryReadCredentialSecure

Same idea, with separate username access:

```csharp
bool found = CredentialManager.TryReadCredentialSecure(
    string targetName,
    out string? userName,
    Action<ReadOnlySpan<char>, object?> usePassword,
    object? state);
```

### SaveSecure (Builder)

Zeros our intermediate buffers during credential creation:

```csharp
CredentialManager.CreateCredential("MyApp:Token")
    .WithUserName("api-key")
    .WithSecret(apiKey)
    .SaveSecure();  // We zero our buffers, not the 'apiKey' string you passed
```

---

## SecureEncoding Utilities

These helpers zero their intermediate buffers:

### CreateBasicAuthHeader

```csharp
string authHeader = SecureEncoding.CreateBasicAuthHeader(userName, password);
// We zero the intermediate UTF-8 buffer
// The returned base64 string lives until GC (but it's meant to be transmitted anyway)
```

### ComputeHmacSha256

```csharp
byte[] hash = SecureEncoding.ComputeHmacSha256(secretKey, dataToSign);
// We zero the key buffer after computing
```

---

## Practical Recommendations

### Do Use These APIs When:

- You want to minimize copies (reduces attack surface slightly)
- You want to avoid accidentally logging/storing secrets
- You're already doing defense-in-depth

### Don't Rely On These APIs When:

- You need protection against memory forensics
- An attacker has debugging access to your process
- You're handling extremely sensitive secrets (use HSM/TPM instead)

### Better Alternatives for High-Security Scenarios:

| Scenario | Better Approach |
|----------|-----------------|
| Database credentials | Use Windows Integrated Auth (no password in memory) |
| API keys | Use managed identity (Azure, AWS IAM roles) |
| Signing keys | Use HSM or cloud KMS |
| Encryption keys | Use `SecureString` with `ProtectedMemory` (limited, but better) |

---

## Audit Events

The library provides audit events for compliance and monitoring:

```csharp
CredentialAudit.IsEnabled = true;

CredentialAudit.OnCredentialAccessed += (sender, e) =>
{
    Log.Info($"{e.UserName} accessed '{e.TargetName}' at {e.Timestamp}");
};
```

**CLI Audit:** Set `WCRED_AUDIT_LOG` environment variable to a file path to log CLI operations.

---

## See Also

- [Library Documentation](library.md) - Full API reference
- [CLI Reference](cli.md) - Command-line tool documentation
