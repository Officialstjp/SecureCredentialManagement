# SecureCredentialManagement

A secure .NET library and CLI tool for managing Windows Credential Manager credentials. Features secure memory handling, zero-allocation APIs, and proper cleanup of sensitive data.

[![.NET 10](https://img.shields.io/badge/.NET-10.0-blue)](https://dotnet.microsoft.com/)

## What's New in v1.1

- **Fluent Builder API** - Clean, readable credential creation with `CredentialManager.CreateCredential()`
- **Metadata Support** - Comments, attributes, expiry tracking, and `LastWritten` timestamps
- **Auto-Detection** - No need to specify credential type when reading or deleting
- **Better Errors** - `CredentialException` with user-friendly messages instead of raw Win32 codes
- **Type Validation** - Early validation prevents invalid operations on certificate types

See [CHANGELOG.md](CHANGELOG.md) for full details.

## Features

- **Secure by default** - Passwords are zeroed from memory after use
- **Zero-allocation APIs** - Span-based methods for performance-critical scenarios  
- **Full CRUD operations** - Create, read, update, delete credentials
- **CLI tool included** - Manage credentials from the command line
- **Native interop** - Direct P/Invoke to Windows Credential Manager APIs
- **Metadata support** - Comments, attributes, and expiry tracking
- **Fluent builder API** - Clean, readable credential creation
- **Multiple credential types** - Generic, DomainPassword, DomainCertificate, and more

## Installation

Install by building from source:

```bash
git clone https://github.com/yourusername/SecureCredentialManagement.git
cd SecureCredentialManagement
dotnet build
dotnet test
```

Or by grabbing the latest Github Release.

## Requirements

- Windows 10/11 or Windows Server 2016+
- .NET 10.0 or later

```bash
dotnet build -c Release
# Executable at: build/wcred.exe
```

---

## CLI Usage

The `wcred` command-line tool provides quick access to Windows Credential Manager.

### List Credentials

```bash
# List all credentials (table format)
wcred list

# Filter by pattern (wildcards supported)
wcred list "git:*"
wcred list "MyApp:*"

# Wide format: full details including timestamps and comments
wcred list --wide
wcred list "MyApp:*" -w

# Adjust column width for long target names
wcred list --columns 80
```

### Get a Credential

```bash
# Show credential (password masked) with all metadata
wcred get "MyApp:Production"

# Show password in plain text
wcred get "MyApp:Production" --show-password
wcred get "MyApp:Production" -s
```

**Output includes:** Target, User, Password (masked), Type, Last Updated, Comment (if set), Attributes, and expiry warnings.

> **Note:** Target names are case-sensitive. Use `wcred list` to find exact names.

### Store a Credential

```bash
# Interactive (prompts for password securely - recommended)
wcred set "MyApp:Production" "user@example.com"

# With persistence level
wcred set "MyApp:Token" "api-key" --persist Session

# With a comment/description
wcred set "MyApp:DB" "sa" --comment "Production database - rotate quarterly"

# Specify credential type (for Windows domain scenarios)
wcred set "MyApp:Domain" "DOMAIN\\user" --type DomainPassword

# Non-interactive (for scripts - password visible in history!)
wcred set "MyApp:CI" "service-account" --password "secret123"
```

**Persistence levels:**
- `Session` - Credential exists only for current login session
- `LocalMachine` - Persists across reboots on this machine (default)
- `Enterprise` - Roams with domain profile

**Credential types:**
- `Generic` - Application credentials (default, most common)
- `DomainPassword` - Windows domain authentication
- `DomainCertificate` - Certificate-based auth (smartcards, PIV)

### Delete a Credential

```bash
# With confirmation prompt
wcred delete "MyApp:Production"

# Skip confirmation
wcred delete "MyApp:Production" --force
wcred delete "MyApp:Production" -f
```

### Help

```bash
wcred --help
wcred list --help
wcred set --help
```

---

## Library Usage

### Basic Operations

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

### Fluent Builder API (Recommended)

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

### Reading Credential Metadata

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
        Console.WriteLine("⚠ This credential has expired!");
    
    // Read string attributes
    var createdBy = credential.GetAttributeAsString("meta:created_by");
    Console.WriteLine($"Created by: {createdBy}");
    
    // Access raw byte attributes
    foreach (var attr in credential.Attributes)
        Console.WriteLine($"  {attr.Key}: {System.Text.Encoding.UTF8.GetString(attr.Value)}");
}
```

### Secure APIs (Recommended)

The secure APIs solve a specific problem: **minimizing how long secrets exist in memory**.

#### Why This Matters

```csharp
// INSECURE PATTERN - secrets linger in memory
var cred = CredentialManager.ReadCredential("MyApp:DB");
string password = cred.Password;  // This string lives until GC runs (unpredictable!)
string connString = $"Server=db;Password={password}";  // Another copy!
// If your app crashes, memory dumps contain these passwords in plain text
// Memory-scanning malware can find them too
```

```csharp
// SECURE PATTERN - secrets are zeroed immediately after use
CredentialManager.TryUseCredential<SqlConnection>("MyApp:DB", (secret, ctx) =>
{
    var (userName, conn) = ctx;
    // Build connection string using the secret directly
    var builder = new SqlConnectionStringBuilder
    {
        DataSource = "server",
        UserID = userName,
        Password = new string(secret)  // Only copy we make
    };
    conn.ConnectionString = builder.ConnectionString;
}, (userName: "dbuser", conn: connection));
// The 'secret' span is now ZEROED - cannot be recovered from memory
```

#### Real-World Examples

**Example 1: HTTP API Authentication**

```csharp
using System.Net.Http.Headers;

public class SecureApiClient
{
    private readonly HttpClient _client = new();
    
    public async Task<string> CallSecureApiAsync()
    {
        // Credential is read, used, and zeroed in one operation
        bool found = CredentialManager.TryUseCredential<HttpClient>(
            "API:MyService",
            (secret, client) =>
            {
                // Set Bearer token - we must create a string for the header,
                // but it's the ONLY copy and we do it at the last moment
                client.DefaultRequestHeaders.Authorization = 
                    new AuthenticationHeaderValue("Bearer", new string(secret));
            },
            _client);
        
        if (!found)
            throw new InvalidOperationException("API credential not configured");
        
        return await _client.GetStringAsync("https://api.example.com/data");
    }
}
```

**Example 2: Basic Auth Header (Zero Extra Allocations)**

```csharp
public class BasicAuthExample
{
    public async Task<HttpResponseMessage> CallWithBasicAuthAsync(string url)
    {
        using var client = new HttpClient();
        
        // Read credential and build auth header securely
        bool found = CredentialManager.TryReadCredentialSecure(
            "MyApp:BasicAuth",
            out string? userName,
            (password, state) =>
            {
                var (user, httpClient) = ((string, HttpClient))state!;
                
                // SecureEncoding.CreateBasicAuthHeader:
                // 1. Encodes user:password to UTF-8 in a temporary buffer
                // 2. Base64 encodes it
                // 3. Zeros the UTF-8 buffer before returning
                // Result: only the final base64 string remains (which is safe to transmit)
                string base64 = SecureEncoding.CreateBasicAuthHeader(user, password);
                httpClient.DefaultRequestHeaders.Authorization = 
                    new AuthenticationHeaderValue("Basic", base64);
            },
            (userName ?? "", client));
        
        if (!found)
            throw new InvalidOperationException("Credential not found");
        
        return await client.GetAsync(url);
    }
}
```

**Example 3: Database Connection**

```csharp
public class SecureDatabaseConnection
{
    public SqlConnection CreateConnection()
    {
        var connection = new SqlConnection();
        
        bool found = CredentialManager.TryReadCredentialSecure(
            "MyApp:Database",
            out string? userName,
            (password, state) =>
            {
                var (user, conn) = ((string?, SqlConnection))state!;
                
                // Build connection string with password
                // The password span is zeroed after this callback
                conn.ConnectionString = new SqlConnectionStringBuilder
                {
                    DataSource = "myserver.database.windows.net",
                    InitialCatalog = "mydb",
                    UserID = user,
                    Password = new string(password),
                    Encrypt = true
                }.ConnectionString;
            },
            (userName, connection));
        
        if (!found)
            throw new InvalidOperationException("Database credential not configured");
        
        return connection;
    }
}
```

**Example 4: HMAC Signing for Webhooks**

```csharp
public class WebhookVerifier
{
    public bool VerifyWebhookSignature(byte[] payload, string receivedSignature)
    {
        // Read the signing secret and compute HMAC
        // The secret is zeroed from memory after ComputeHmacSha256 returns
        var credential = CredentialManager.ReadCredential("Webhook:SigningSecret");
        if (credential?.Password is null)
            return false;
        
        // ComputeHmacSha256 internally:
        // 1. Converts secret to UTF-8 bytes in a pinned buffer
        // 2. Computes HMAC
        // 3. Zeros the key buffer before returning
        byte[] expectedHash = SecureEncoding.ComputeHmacSha256(
            credential.Password, 
            payload);
        
        string expectedSignature = Convert.ToHexString(expectedHash);
        return string.Equals(expectedSignature, receivedSignature, 
            StringComparison.OrdinalIgnoreCase);
    }
}
```

**Example 5: Storing Credentials from User Input**

```csharp
public class CredentialSetupWizard
{
    public void ConfigureApiCredential()
    {
        Console.Write("API Key: ");
        
        // Read password without echoing, storing in StringBuilder
        var input = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            input.Append(key.KeyChar);
            Console.Write('*');
        }
        Console.WriteLine();
        
        // Convert to string, then immediately use and clear
        string apiKey = input.ToString();
        try
        {
            // WriteCredentialSecure accepts string, converts to span internally,
            // and zeros the intermediate buffers
            CredentialManager.WriteCredentialSecure(
                "MyApp:ApiKey",
                "api-key",
                apiKey,
                CredentialPersistence.LocalMachine);
            
            Console.WriteLine("API key saved securely.");
        }
        finally
        {
            // Clear the StringBuilder (input is still in memory as a string though)
            input.Clear();
            // Note: We can't truly clear 'apiKey' string - that's a .NET limitation
            // But WriteCredentialSecure ensures its internal copies are zeroed
        }
    }
}
```

### The Tradeoff: Practical Security

**What the secure APIs guarantee:**
- Internal buffers used for encoding/copying are zeroed
- The secret span you receive in callbacks is zeroed after the callback
- Intermediate UTF-8/byte representations are cleared

**What they can't prevent:**
- If you call `new string(secret)`, that string lives until GC
- The final destination (HTTP header, connection string) may keep a copy

**The value:** You reduce the number of copies from many to one, and you control exactly when that one copy is created. This significantly shrinks the attack window for memory-scanning threats.

### Helper Utilities

```csharp
// Create Basic Auth header (intermediate buffers zeroed)
string authHeader = SecureEncoding.CreateBasicAuthHeader(userName, password);
// Returns: "dXNlcm5hbWU6cGFzc3dvcmQ="

// Zero-allocation version for high-performance scenarios
Span<char> buffer = stackalloc char[256];
if (SecureEncoding.TryEncodeBasicAuth(userName, password, buffer, out int written))
{
    ReadOnlySpan<char> encoded = buffer[..written];
    // Use encoded directly without any heap allocation
    // Stack memory is automatically "cleaned" when method returns
}

// HMAC-SHA256 with secure key handling (key buffer zeroed after use)
byte[] hash = SecureEncoding.ComputeHmacSha256(secretKey, dataToSign);
```

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
