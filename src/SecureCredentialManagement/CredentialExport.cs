using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

#pragma warning disable CA1416 // Windows-specific API

namespace SecureCredentialManagement;

/// <summary>
/// Handles secure export and import of credentials
/// </summary>
public static class CredentialExport
{
    private const int SaltSize = 16;
    private const int KeySize = 32; // 256 bits
    private const int Iterations = 100_000;
    private static readonly HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;

    /// <summary>
    /// Represents a List with Metadata around exported credentials.
    /// </summary>
    public sealed class ExportedCredentialSet
    {
        /// <summary>
        /// Export format version.
        /// </summary>
        [JsonPropertyName("version")]
        public int Version { get; set; } = 1;

        /// <summary>
        /// Timestamp of the export.
        /// </summary>

        [JsonPropertyName("exportedAt")]
        public DateTime ExportedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Information about the encryption used for the exported credentials.
        /// </summary>

        [JsonPropertyName("encryption")]
        public EncryptionInfo? Encryption { get; set; }

        /// <summary>
        /// List of the exported credentials.
        /// </summary>
        [JsonPropertyName("credentials")]
        public List<ExportedCredential> Credentials { get; set; } = new List<ExportedCredential>();
    }

    /// <summary>
    /// Information about the encryption method used in the export.
    /// </summary>
    public sealed class EncryptionInfo
    {
        /// <summary>
        /// Encryption method: "none", "dpapi", or "password"
        /// Password utilizes AES-GCM with a derived key.
        /// </summary>
        [JsonPropertyName("method")]
        public string Method { get; set; } = "none"; // "none", "dpapi", "password"

        /// <summary>
        /// Salt used for password-based encryption (base64).
        /// </summary>
        [JsonPropertyName("salt")]
        public string? Salt { get; set; } // base64, for password-based encryption

        /// <summary>
        /// Scope used for DPAPI encryption: "user" or "machine"
        /// </summary>
        [JsonPropertyName("scope")]
        public string? Scope { get; set; } // "user" or "machine" for dpapi
    }

    /// <summary>
    /// Represents a single exported credential.
    /// </summary>
    public sealed class ExportedCredential
    {
        /// <summary>
        /// Target name of the credential.
        /// </summary>
        [JsonPropertyName("targetName")]
        public required string TargetName { get; set; }

        /// <summary>
        /// Username associated with the credential.
        /// </summary>
        [JsonPropertyName("userName")]        
        public string? UserName { get; set; }

        /// <summary>
        /// Encrypted or plain base64-encoded secret.
        /// </summary>
        [JsonPropertyName("secret")]
        public string Secret { get; set; } = string.Empty; // Encrypted or plain b64

        /// <summary>
        /// Credential type, <see cref="CredentialType"/>.
        /// </summary>
        [JsonPropertyName("type")]
        public CredentialType Type { get; set; }

        /// <summary>
        /// Persistence type, <see cref="CredentialPersistence"/>.
        /// </summary>
        [JsonPropertyName("persistence")]
        public CredentialPersistence Persistence { get; set; }

        /// <summary>
        /// Optional comment associated with the credential.
        /// </summary>
        [JsonPropertyName("comment")]
        public string? Comment { get; set; }

        /// <summary>
        /// Optional attributes associated with the credential (base64 values).
        /// </summary>
        [JsonPropertyName("attributes")]
        public Dictionary<string, string>? Attributes { get; set; } // base64 values
    }

    public enum EncryptionMethod
    {
        None,
        Dpapi,
        Password
    }

    #region Export

    /// <summary>
    /// Exports credentials matching the filter to an encrypted file.
    /// </summary>
    public static ExportedCredentialSet Export(
        string? filter = null,
        string[]? targets = null,
        EncryptionMethod encryptionMethod = EncryptionMethod.Dpapi,
        string? password = null,
        DataProtectionScope dpapiScope = DataProtectionScope.CurrentUser)
    {
        var credentials = (targets is null || targets.Length == 0)
            ? (string.IsNullOrEmpty(filter)
                ? CredentialManager.EnumerateCredentials()
                : CredentialManager.EnumerateCredentials(filter))
            : CredentialManager.EnumerateCredentials()
                .Where(c => targets.Contains(c.TargetName, StringComparer.Ordinal))
                .ToList();

        var export = new ExportedCredentialSet();

        // Setup encryption info
        byte[]? encryptionKey = null;
        byte[]? salt = null;

        switch (encryptionMethod)
        {
            case EncryptionMethod.Password:
                if (string.IsNullOrEmpty(password))
                    throw new ArgumentException("Password must be provided for password-based encryption.", nameof(password));

                salt = RandomNumberGenerator.GetBytes(SaltSize);
                encryptionKey = DeriveKey(password, salt);
                export.Encryption = new EncryptionInfo
                {
                    Method = "password",
                    Salt = Convert.ToBase64String(salt)
                };
                break;

            case EncryptionMethod.Dpapi:
                export.Encryption = new EncryptionInfo
                {
                    Method = "dpapi",
                    Scope = dpapiScope == DataProtectionScope.CurrentUser ? "user" : "machine"
                };
                break;

            default:
                export.Encryption = new EncryptionInfo
                {
                    Method = "none"
                };
                break;
        }

        foreach (var cred in credentials)
        {
            var exported = new ExportedCredential
            {
                TargetName = cred.TargetName,
                UserName = cred.UserName,
                Type = cred.CredentialType,
                Comment = cred.Comment,
                Persistence = CredentialPersistence.LocalMachine // Default, as Windows doesn't expose this on read
            };

            // Encrypt
            if (!string.IsNullOrEmpty(cred.Password))
            {
                byte[] secretBytes = Encoding.UTF8.GetBytes(cred.Password);

                byte[] encryptedBytes = encryptionMethod switch
                {
                    EncryptionMethod.Password => EncryptAesGcm(secretBytes, encryptionKey!),
                    EncryptionMethod.Dpapi => ProtectedData.Protect(secretBytes, null,
                        dpapiScope == DataProtectionScope.CurrentUser
                            ? DataProtectionScope.CurrentUser
                            : DataProtectionScope.LocalMachine),
                    _ => secretBytes
                };

                exported.Secret = Convert.ToBase64String(encryptedBytes);

                CryptographicOperations.ZeroMemory(secretBytes);
            }

            // Attributes exported as base64
            if (cred.Attributes.Count > 0)
            {
                exported.Attributes = cred.Attributes.ToDictionary(
                    kvp => kvp.Key,
                    kvp => Convert.ToBase64String(kvp.Value));
            }

            export.Credentials.Add(exported);
        }

        if (encryptionKey is not null)
            CryptographicOperations.ZeroMemory(encryptionKey);

        return export;
    }

     /// <summary>
    /// Exports credentials to a JSON file.
    /// </summary>
    public static void ExportToFile(
        string filePath,
        string? filter = null,
        string[]? targets = null,
        EncryptionMethod encryption = EncryptionMethod.Dpapi,
        string? password = null,
        DataProtectionScope dpapiScope = DataProtectionScope.CurrentUser)
    {
        var export = Export(filter, targets, encryption, password, dpapiScope);
        var json = JsonSerializer.Serialize(export, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
        File.WriteAllText(filePath, json);
    }

    #endregion

    #region Import

    /// <summary>
    /// Import result for a single credential.
    /// </summary>
    public sealed class ImportResult
    {
        /// <summary>
        /// Target name of the imported credential.
        /// </summary>
        public required string TargetName { get; init; }

        /// <summary>
        /// Indicates if the import was successful.
        /// </summary>
        public bool Success { get; init; }

        /// <summary>
        /// Error message if the import failed.
        /// </summary>
        public string? Error { get; init; }

        /// <summary>
        /// Indicates if the import was skipped due to existing credential.
        /// </summary>
        public bool Skipped { get; init; }
    }

    /// <summary>
    /// Imports credentials from an exported set.
    /// </summary>
    public static List<ImportResult> Import(
        ExportedCredentialSet exportSet,
        string? password = null,
        bool overwrite = false)
    {
        var results = new List<ImportResult>();

        // Derive decryption key if password-encrypted
        byte[]? decryptionKey = null;
        if (exportSet.Encryption?.Method == "password")
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password required to decrypt this export.", nameof(password));
            if (string.IsNullOrEmpty(exportSet.Encryption.Salt))
                throw new InvalidOperationException("Export file is corrupted: missing salt.");

            var salt = Convert.FromBase64String(exportSet.Encryption.Salt);
            decryptionKey = DeriveKey(password, salt);
        }

        var dpapiScope = exportSet.Encryption?.Scope == "machine"
            ? DataProtectionScope.LocalMachine
            : DataProtectionScope.CurrentUser;

        foreach (var exported in exportSet.Credentials)
        {
            try
            {
                // Check if exists
                var existing = CredentialManager.ReadCredential(exported.TargetName, exported.Type);
                if (existing is not null && !overwrite)
                {
                    results.Add(new ImportResult
                    {
                        TargetName = exported.TargetName,
                        Success = false,
                        Skipped = true,
                        Error = "Already exists (use --overwrite to replace)"
                    });
                    continue;
                }

                // Decrypt secret
                string? secret = null;
                if (!string.IsNullOrEmpty(exported.Secret))
                {
                    var encryptedBytes = Convert.FromBase64String(exported.Secret);
                    byte[] decryptedBytes = exportSet.Encryption?.Method switch
                    {
                        "password" => DecryptAesGcm(encryptedBytes, decryptionKey!),
                        "dpapi" => ProtectedData.Unprotect(encryptedBytes, null, dpapiScope),
                        _ => encryptedBytes
                    };
                    secret = Encoding.UTF8.GetString(decryptedBytes);
                    CryptographicOperations.ZeroMemory(decryptedBytes);
                }

                // Build and save credential
                var builder = CredentialManager.CreateCredential(exported.TargetName)
                    .WithUserName(exported.UserName ?? "")
                    .WithType(exported.Type)
                    .WithPersistence(exported.Persistence);

                if (!string.IsNullOrEmpty(secret))
                    builder.WithSecret(secret);

                if (!string.IsNullOrEmpty(exported.Comment))
                    builder.WithComment(exported.Comment);

                if (exported.Attributes is not null)
                {
                    foreach (var (key, value) in exported.Attributes)
                        builder.WithAttribute(key, Convert.FromBase64String(value));
                }

                builder.SaveSecure();

                results.Add(new ImportResult
                {
                    TargetName = exported.TargetName,
                    Success = true
                });
            }
            catch (Exception ex)
            {
                results.Add(new ImportResult
                {
                    TargetName = exported.TargetName,
                    Success = false,
                    Error = ex.Message
                });
            }
        }

        // Zero the decryption key
        if (decryptionKey is not null)
            CryptographicOperations.ZeroMemory(decryptionKey);

        return results;
    }

    /// <summary>
    /// Imports credentials from a JSON file.
    /// </summary>
    public static List<ImportResult> ImportFromFile(
        string filePath,
        string? password = null,
        bool overwrite = false)
    {
        var json = File.ReadAllText(filePath);
        var exportSet = JsonSerializer.Deserialize<ExportedCredentialSet>(json)
            ?? throw new InvalidOperationException("Invalid export file format.");
        return Import(exportSet, password, overwrite);
    }

    #endregion

    #region Encryption Helpers

    private static byte[] DeriveKey(string password, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Iterations,
            hashAlgorithm,
            KeySize);
    }

    private static byte[] EncryptAesGcm(byte[] plaintext, byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        var ciphertext = new byte[plaintext.Length];

        using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        // Format: nonce || tag || ciphertext
        var result = new byte[nonce.Length + tag.Length + ciphertext.Length];
        nonce.CopyTo(result, 0);
        tag.CopyTo(result, nonce.Length);
        ciphertext.CopyTo(result, nonce.Length + tag.Length);

        return result;
    }

    private static byte[] DecryptAesGcm(byte[] encrypted, byte[] key)
    {
        var nonceSize = AesGcm.NonceByteSizes.MaxSize;
        var tagSize = AesGcm.TagByteSizes.MaxSize;

        var nonce = encrypted[..nonceSize];
        var tag = encrypted[nonceSize..(nonceSize + tagSize)];
        var ciphertext = encrypted[(nonceSize + tagSize)..];

        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, tagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }

    #endregion
}

#pragma warning restore CA1416 // Windows-specific API
