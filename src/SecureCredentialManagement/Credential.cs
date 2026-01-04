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

    internal Credential(CredentialType credentialType, string targetName, string? userName, string? password)
    {
        CredentialType = credentialType;
        TargetName = targetName;
        UserName = userName;
        Password = password;
    }

    public override string ToString() =>
        $"TargetName: {TargetName}, UserName: {UserName}, Type: {CredentialType}";
}

public enum CredentialType : uint
{
    Generic = 1,
    DomainPassword = 2,
    DomainCertificate = 3,
    DomainVisiblePassword = 4,
    GenericCertificate = 5,
    DomainExtended = 6,
    Maximum = 7,
    MaximumEx = Maximum + 1000
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