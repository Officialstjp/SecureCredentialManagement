namespace SecureCredentialManagement;

/// <summary>
/// Manages credential rotation with validation and rollback support.
/// </summary>
public sealed class CredentialRotation
{
    private readonly string _targetName;
    private readonly CredentialType _type;

    public CredentialRotation(string targetName, CredentialType type = CredentialType.Generic)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);
        _targetName = targetName;
        _type = type;
    }

    #region Events

    public event EventHandler<BeforeRotateEventArgs>? OnBeforeRotate;
    public event EventHandler<AfterRotateEventArgs>? OnAfterRotate;
    public event EventHandler<ValidateCredentialEventArgs>? OnValidate;

    public sealed class BeforeRotateEventArgs : EventArgs
    {
        public required string TargetName { get; init; }
        public Credential? CurrentCredential { get; init; }
        public bool Cancel { get; set; }
        public string? CancelReason { get; set; }
    }

    public sealed class AfterRotateEventArgs : EventArgs
    {
        public required string TargetName { get; init; }
        public bool Success { get; init; }
        public Credential? NewCredential { get; init; }
        public Credential? PreviousCredential { get; init; }
        public Exception? Error { get; init; }
        public bool WasRolledBack { get; init; }
    }

    public sealed class ValidateCredentialEventArgs : EventArgs
    {
        public required string TargetName { get; init; }
        public required Credential NewCredential { get; init; }
        public bool IsValid { get; set; } = true;
        public string? ValidationError { get; set; }
    }

    #endregion

    #region Rotation Result

    public sealed class RotationResult
    {
        public bool Success { get; init; }
        public Credential? NewCredential { get; init; }
        public Credential? PreviousCredential { get; init; }
        public bool WasCancelled { get; init; }
        public string? CancelReason { get; init; }
        public bool WasRolledBack { get; init; }
        public Exception? Error { get; init; }
    }

    #endregion

    /// <summary>
    /// Rotates the credential with the new secret.
    /// </summary>
    /// <param name="newSecret">The new secret value.</param>
    /// <param name="newUserName">Optional new username (keeps existing if null).</param>
    /// <param name="rollbackOnFailure">If true, restores the old credential if validation fails.</param>
    /// <param name="updateComment">If true, updates the comment with rotation timestamp.</param>
    public RotationResult Rotate(
        string newSecret,
        string? newUserName = null,
        bool rollbackOnFailure = true,
        bool updateComment = true)
    {
        // Read current credential
        var current = CredentialManager.ReadCredential(_targetName, _type);

        // Fire BeforeRotate event
        var beforeArgs = new BeforeRotateEventArgs
        {
            TargetName = _targetName,
            CurrentCredential = current
        };
        OnBeforeRotate?.Invoke(this, beforeArgs);

        if (beforeArgs.Cancel)
        {
            return new RotationResult
            {
                Success = false,
                WasCancelled = true,
                CancelReason = beforeArgs.CancelReason ?? "Cancelled by handler",
                PreviousCredential = current
            };
        }

        // Store backup for rollback
        var backupSecret = current?.Password;
        var backupUserName = current?.UserName;

        try
        {
            // Write new credential
            var builder = CredentialManager.CreateCredential(_targetName)
                .WithUserName(newUserName ?? current?.UserName ?? "")
                .WithSecret(newSecret)
                .WithType(_type);

            if (updateComment)
            {
                var rotationNote = $"Rotated: {DateTimeOffset.UtcNow:u}";
                var existingComment = current?.Comment;
                builder.WithComment(string.IsNullOrEmpty(existingComment)
                    ? rotationNote
                    : $"{existingComment} | {rotationNote}");
            }
            else if (!string.IsNullOrEmpty(current?.Comment))
            {
                builder.WithComment(current.Comment);
            }

            // Preserve attributes
            if (current?.Attributes is not null)
            {
                foreach (var (key, value) in current.Attributes)
                {
                    if (key != "expiry") // Don't preserve old expiry
                        builder.WithAttribute(key, value);
                }
            }

            builder.SaveSecure();

            // Read back the new credential for validation
            var newCredential = CredentialManager.ReadCredential(_targetName, _type);

            // Fire Validate event
            if (OnValidate is not null && newCredential is not null)
            {
                var validateArgs = new ValidateCredentialEventArgs
                {
                    TargetName = _targetName,
                    NewCredential = newCredential
                };
                OnValidate.Invoke(this, validateArgs);

                if (!validateArgs.IsValid)
                {
                    if (rollbackOnFailure && backupSecret is not null)
                    {
                        // Rollback
                        CredentialManager.CreateCredential(_targetName)
                            .WithUserName(backupUserName ?? "")
                            .WithSecret(backupSecret)
                            .WithType(_type)
                            .WithComment(current?.Comment ?? "")
                            .SaveSecure();

                        var rolledBackResult = new RotationResult
                        {
                            Success = false,
                            WasRolledBack = true,
                            PreviousCredential = current,
                            Error = new CredentialException(
                                validateArgs.ValidationError ?? "Validation failed")
                        };

                        OnAfterRotate?.Invoke(this, new AfterRotateEventArgs
                        {
                            TargetName = _targetName,
                            Success = false,
                            WasRolledBack = true,
                            PreviousCredential = current,
                            Error = rolledBackResult.Error
                        });

                        return rolledBackResult;
                    }

                    throw new CredentialException(
                        validateArgs.ValidationError ?? "Credential validation failed after rotation");
                }
            }

            // Success
            var successResult = new RotationResult
            {
                Success = true,
                NewCredential = newCredential,
                PreviousCredential = current
            };

            OnAfterRotate?.Invoke(this, new AfterRotateEventArgs
            {
                TargetName = _targetName,
                Success = true,
                NewCredential = newCredential,
                PreviousCredential = current
            });

            return successResult;
        }
        catch (Exception ex)
        {
            // Attempt rollback on any exception
            if (rollbackOnFailure && backupSecret is not null)
            {
                try
                {
                    CredentialManager.CreateCredential(_targetName)
                        .WithUserName(backupUserName ?? "")
                        .WithSecret(backupSecret)
                        .WithType(_type)
                        .SaveSecure();
                }
                catch
                {
                    // Rollback failed - credential may be in inconsistent state
                }
            }

            var errorResult = new RotationResult
            {
                Success = false,
                PreviousCredential = current,
                WasRolledBack = rollbackOnFailure && backupSecret is not null,
                Error = ex
            };

            OnAfterRotate?.Invoke(this, new AfterRotateEventArgs
            {
                TargetName = _targetName,
                Success = false,
                PreviousCredential = current,
                WasRolledBack = errorResult.WasRolledBack,
                Error = ex
            });

            return errorResult;
        }
    }

    /// <summary>
    /// Rotates the credential asynchronously (wraps sync method).
    /// </summary>
    public Task<RotationResult> RotateAsync(
        string newSecret,
        string? newUserName = null,
        bool rollbackOnFailure = true,
        bool updateComment = true,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => Rotate(newSecret, newUserName, rollbackOnFailure, updateComment), cancellationToken);
    }
}