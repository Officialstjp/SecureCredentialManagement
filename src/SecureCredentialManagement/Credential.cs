/* SPDX - License - Identifier: Apache - 2.0 
 * Copyright(c) 2025 Stefan Ploch */

namespace SecureCredentialManagement;

#region Public Types

/// <summary>
/// Represents a Windows credential.
/// </summary>
public sealed class Credential
{
    public CredentialType CredentialType { get; }
    public string TargetName { get; }
    public string? UserName { get; }
    public string? Password { get; }

    public string? Comment { get; }
    public string? TargetAlias { get; }
    public DateTimeOffset LastWritten { get; }
    public IReadOnlyDictionary<string, byte[]> Attributes { get;}

    internal Credential(
        CredentialType credentialType, 
        string targetName, 
        string? userName, 
        string? password,
        string? comment,
        string? targetAlias,
        DateTimeOffset lastWritten,
        IReadOnlyDictionary<string, byte[]> attributes)
    {
        CredentialType = credentialType;
        TargetName = targetName;
        UserName = userName;
        Password = password;
        Comment = comment;
        TargetAlias = targetAlias;
        LastWritten = lastWritten;
        Attributes = attributes ?? new Dictionary<string, byte[]>();
    }

    /// <summary>
    /// Returns a string representation of the credential. (No sensitive data)
    /// </summary>
    public override string ToString() =>
        $"TargetName: {TargetName}, UserName: {UserName}, Type: {CredentialType}";

    public string? GetAttributeAsString(string key)
    {
        return Attributes.TryGetValue(key, out var bytes)
            ? System.Text.Encoding.UTF8.GetString(bytes)
            : null;
    }

    /// <summary>
    /// Checks if the credential has expired based on a stored "expiry" attribute.
    /// The "expiry" attribute is expected to be a UTF-8 string representing a UTC DateTime.
    /// </summary>
    public bool IsExpired()
    {
        var expiryString = GetAttributeAsString("expiry");
        return expiryString is not null
            && DateTimeOffset.TryParse(expiryString, out var expiryDate)
            && DateTimeOffset.UtcNow > expiryDate;
    }
}

/// <summary>
/// Windows Credential Manager credential types.
/// </summary>
public enum CredentialType : uint
{
    /// <summary>
    /// Generic credentials for application use. Most common type.
    /// </summary>
    Generic = 1,

    /// <summary>
    /// Domain password credentials for Windows authentication (NTLM, Kerberos).
    /// Username should be in DOMAIN\user or user@domain format.
    /// </summary>
    DomainPassword = 2,

    /// <summary>
    /// Domain certificate credentials (smartcard, PKI). 
    /// Requires marshaled certificate data - cannot be created with plain username/password.
    /// </summary>
    DomainCertificate = 3,

    /// <summary>
    /// Domain password that can be read back. Used by RDP "save my credentials" feature.
    /// </summary>
    DomainVisiblePassword = 4,

    /// <summary>
    /// Generic certificate credentials for application use.
    /// Requires marshaled certificate data - cannot be created with plain username/password.
    /// </summary>
    GenericCertificate = 5,

    /// <summary>
    /// Extended domain credentials. Reserved for system use.
    /// </summary>
    DomainExtended = 6,

    /// <summary>
    /// Maximum valid credential type value. Not a valid type for credentials.
    /// </summary>
    Maximum = 7,

    /// <summary>
    /// Extended maximum value. Not a valid type for credentials.
    /// </summary>
    MaximumEx = Maximum + 1000
}

/// <summary>
/// Defines which credential types can be created/modified by users via CLI or the builder API.
/// Certificate types require special handling and are read-only through this library.
/// </summary>
public static class CredentialTypeExtensions
{
    /// <summary>
    /// Credential types that can be created with username/password via this library.
    /// </summary>
    public static readonly CredentialType[] WritableTypes =
    [
        CredentialType.Generic,
        CredentialType.DomainPassword,
        CredentialType.DomainVisiblePassword
    ];

    /// <summary>
    /// Checks if a credential type can be created with plain username/password.
    /// </summary>
    public static bool IsWritable(this CredentialType type) => type switch
    {
        CredentialType.Generic => true,
        CredentialType.DomainPassword => true,
        CredentialType.DomainVisiblePassword => true,
        _ => false
    };

    /// <summary>
    /// Gets a user-friendly description of why a type cannot be written.
    /// </summary>
    public static string? GetWriteRestrictionReason(this CredentialType type) => type switch
    {
        CredentialType.DomainCertificate => "DomainCertificate requires marshaled certificate data, not a username/password.",
        CredentialType.GenericCertificate => "GenericCertificate requires marshaled certificate data, not a username/password.",
        CredentialType.DomainExtended => "DomainExtended is reserved for system use.",
        CredentialType.Maximum => "Maximum is not a valid credential type (boundary value).",
        CredentialType.MaximumEx => "MaximumEx is not a valid credential type (boundary value).",
        _ => null
    };
}

public enum CredentialPersistence : uint
{
    /// <summary>
    /// Credential persists for the life of the logon session.
    /// </summary>
    Session = 1,

    /// <summary>
    /// Credential persists for all subsequent logon sessions on this machine.
    /// </summary>
    LocalMachine = 2,

    /// <summary>
    /// Credential persists for all computers in the domain.
    /// </summary>
    Enterprise = 3
}


#endregion