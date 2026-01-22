using System.Security.Principal;

namespace SecureCredentialManagement;

#pragma warning disable CA1416 // Windows-specific API

/// <summary>
/// Provides audit events for credential operations.
/// </summary>
public static class CredentialAudit
{
    /// <summary>
    /// Enable or disable audit event firing. Disabled by default.
    /// </summary>
    public static bool IsEnabled { get; set; } = false;

    #region Events

    public static event EventHandler<CredentialAccessedEventArgs>? OnCredentialAccessed;
    public static event EventHandler<CredentialModifiedEventArgs>? OnCredentialModified;
    public static event EventHandler<CredentialDeletedEventArgs>? OnCredentialDeleted;
    public static event EventHandler<CredentialEnumeratedEventArgs>? OnCredentialsEnumerated;

    #endregion

    #region Event Args

    public abstract class CredentialAuditEventArgs : EventArgs
    {
        public DateTimeOffset Timestamp { get; } = DateTimeOffset.UtcNow;
        public string UserName { get; } = GetCurrentUserName();
        public string MachineName { get; } = Environment.MachineName;
        public int ProcessId { get; } = Environment.ProcessId;
        public string? ProcessName { get; } = GetProcessName();

        private static string GetCurrentUserName()
        {
            try
            {
                return WindowsIdentity.GetCurrent().Name;
            }
            catch
            {
                return Environment.UserName;
            }
        }

        private static string? GetProcessName()
        {
            try
            {
                return System.Diagnostics.Process.GetCurrentProcess().ProcessName;
            }
            catch
            {
                return null;
            }
        }
    }

    public sealed class CredentialAccessedEventArgs : CredentialAuditEventArgs
    {
        public required string TargetName { get; init; }
        public CredentialType CredentialType { get; init; }
        public CredentialAccessOperation Operation { get; init; }
        public bool SecretWasRetrieved { get; init; }
    }

    public sealed class CredentialModifiedEventArgs : CredentialAuditEventArgs
    {
        public required string TargetName { get; init; }
        public CredentialType CredentialType { get; init; }
        public CredentialModifyOperation Operation { get; init; }
        public bool IsNewCredential { get; init; }
    }

    public sealed class CredentialDeletedEventArgs : CredentialAuditEventArgs
    {
        public required string TargetName { get; init; }
        public CredentialType CredentialType { get; init; }
    }

    public sealed class CredentialEnumeratedEventArgs : CredentialAuditEventArgs
    {
        public string? Filter { get; init; }
        public int CredentialCount { get; init; }
    }

    public enum CredentialAccessOperation
    {
        Read,
        ReadSecure,
        UseCredential
    }

    public enum CredentialModifyOperation
    {
        Create,
        Update,
        Rotate
    }

    #endregion

    #region Internal Raise Methods (called from CredentialManager)

    internal static void RaiseAccessed(
        string targetName,
        CredentialType type,
        CredentialAccessOperation operation,
        bool secretRetrieved)
    {
        if (!IsEnabled || OnCredentialAccessed is null) return;

        OnCredentialAccessed.Invoke(null, new CredentialAccessedEventArgs
        {
            TargetName = targetName,
            CredentialType = type,
            Operation = operation,
            SecretWasRetrieved = secretRetrieved
        });
    }

    internal static void RaiseModified(
        string targetName,
        CredentialType type,
        CredentialModifyOperation operation,
        bool isNew)
    {
        if (!IsEnabled || OnCredentialModified is null) return;

        OnCredentialModified.Invoke(null, new CredentialModifiedEventArgs
        {
            TargetName = targetName,
            CredentialType = type,
            Operation = operation,
            IsNewCredential = isNew
        });
    }

    internal static void RaiseDeleted(string targetName, CredentialType type)
    {
        if (!IsEnabled || OnCredentialDeleted is null) return;

        OnCredentialDeleted.Invoke(null, new CredentialDeletedEventArgs
        {
            TargetName = targetName,
            CredentialType = type
        });
    }

    internal static void RaiseEnumerated(string? filter, int count)
    {
        if (!IsEnabled || OnCredentialsEnumerated is null) return;

        OnCredentialsEnumerated.Invoke(null, new CredentialEnumeratedEventArgs
        {
            Filter = filter,
            CredentialCount = count
        });
    }

    #endregion
}

#pragma warning restore CA1416 // Windows-specific API
