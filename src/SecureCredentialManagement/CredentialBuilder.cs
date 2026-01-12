using System.Text;

namespace SecureCredentialManagement;

/// <summary>
/// Fluent builder for creating and saving credentials.
/// </summary>
public sealed class CredentialBuilder
{
    private readonly string _targetName;
    private string? _userName;
    private string? _secret;
    private CredentialPersistence _persistence = CredentialPersistence.LocalMachine;
    private CredentialType _type = CredentialType.Generic;
    private string? _comment;
    private string? _targetAlias;
    private readonly Dictionary<string, byte[]> _attributes = new(StringComparer.OrdinalIgnoreCase);

    private CredentialBuilder(string targetName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);
        _targetName = targetName;
    }

    public static CredentialBuilder Create(string targetName) => new(targetName);

    public CredentialBuilder WithUserName(string userName)
    {
        _userName = userName;
        return this;
    }

    public CredentialBuilder WithSecret(string secret)
    {
        _secret = secret;
        return this;
    }

    public CredentialBuilder WithSecret(ReadOnlySpan<char> secret)
    {
        _secret = new string(secret);
        return this;
    }

    public CredentialBuilder WithPersistence(CredentialPersistence persistence)
    {
        _persistence = persistence;
        return this;
    }

    public CredentialBuilder WithType(CredentialType type)
    {
        _type = type;
        return this;
    }

    public CredentialBuilder WithComment(string comment)
    {
        _comment = comment;
        return this;
    }

    public CredentialBuilder WithTargetAlias(string alias)
    {
        _targetAlias = alias;
        return this;
    }

    public CredentialBuilder WithAttribute(string key, byte[] value)
    {
        _attributes[key] = value;
        return this;
    }

    public CredentialBuilder WithAttribute(string key, string value)
    {
        _attributes[key] = Encoding.UTF8.GetBytes(value);
        return this;
    }

    public CredentialBuilder WithExpiry(DateTimeOffset expiry)
    {
        return WithAttribute("expiry", expiry.ToString("O"));
    }

    public CredentialBuilder WithMetadata(string key, string value)
    {
        return WithAttribute($"meta:{key}", value);
    }

    public void Save()
    {
        ArgumentNullException.ThrowIfNull(_secret, "Secret must be set before saving");

        CredentialManager.WriteCredential(
            _targetName,
            _userName ?? Environment.UserName,
            _secret,
            _persistence,
            _type,
            _comment,
            _targetAlias,
            _attributes.Count > 0 ? _attributes : null);
    }

    /// <summary>
    /// Saves using secure memory handling for the secret.
    /// </summary>
    public void SaveSecure()
    {
        ArgumentNullException.ThrowIfNull(_secret, "Secret must be set before saving");

        CredentialManager.WriteCredentialSecure(
            _targetName,
            _userName ?? Environment.UserName,
            _secret.AsSpan(),
            _persistence,
            _type,
            _comment,
            _targetAlias,
            _attributes.Count > 0 ? _attributes : null);
    }
}