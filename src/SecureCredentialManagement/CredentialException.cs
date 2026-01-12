/* SPDX - License - Identifier: Apache - 2.0 
 * Copyright(c) 2025 Stefan Ploch */

using System.ComponentModel;

namespace SecureCredentialManagement;

/// <summary>
/// Exception thrown when a credential operation fails.
/// Provides user-friendly error messages for common Windows Credential Manager errors.
/// </summary>
public class CredentialException : Exception
{
    /// <summary>
    /// The Win32 error code if this exception wraps a Windows error.
    /// </summary>
    public int? Win32ErrorCode { get; }

    /// <summary>
    /// The credential type involved in the failed operation, if applicable.
    /// </summary>
    public CredentialType? CredentialType { get; }

    public CredentialException(string message) : base(message) { }

    public CredentialException(string message, Exception innerException) 
        : base(message, innerException) { }

    public CredentialException(string message, int win32ErrorCode, CredentialType? credentialType = null)
        : base(message)
    {
        Win32ErrorCode = win32ErrorCode;
        CredentialType = credentialType;
    }

    public CredentialException(string message, Win32Exception innerException, CredentialType? credentialType = null)
        : base(message, innerException)
    {
        Win32ErrorCode = innerException.NativeErrorCode;
        CredentialType = credentialType;
    }

    /// <summary>
    /// Known Windows error codes for credential operations.
    /// </summary>
    public static class ErrorCodes
    {
        public const int ERROR_NOT_FOUND = 1168;
        public const int ERROR_INVALID_PARAMETER = 87;
        public const int ERROR_INVALID_USERNAME = 2202;
        public const int ERROR_NO_SUCH_LOGON_SESSION = 1312;
        public const int ERROR_INVALID_FLAGS = 1004;
    }

    /// <summary>
    /// Creates a CredentialException from a Win32Exception with a user-friendly message.
    /// </summary>
    internal static CredentialException FromWin32Exception(
        Win32Exception ex, 
        string operation,
        CredentialType? credentialType = null)
    {
        string message = ex.NativeErrorCode switch
        {
            ErrorCodes.ERROR_INVALID_USERNAME when credentialType == SecureCredentialManagement.CredentialType.DomainCertificate =>
                $"Cannot {operation}: DomainCertificate credentials require a marshaled certificate reference as the username, not a plain string. " +
                "Use Generic or DomainPassword type for password-based credentials.",

            ErrorCodes.ERROR_INVALID_USERNAME =>
                $"Cannot {operation}: The username format is invalid for credential type '{credentialType}'. " +
                "For domain credentials, use 'DOMAIN\\username' format.",

            ErrorCodes.ERROR_INVALID_PARAMETER when credentialType is 
                SecureCredentialManagement.CredentialType.Maximum or 
                SecureCredentialManagement.CredentialType.MaximumEx or
                SecureCredentialManagement.CredentialType.DomainExtended =>
                $"Cannot {operation}: Credential type '{credentialType}' is not a valid type for this operation. " +
                "Use Generic, DomainPassword, or DomainVisiblePassword instead.",

            ErrorCodes.ERROR_INVALID_PARAMETER =>
                $"Cannot {operation}: Invalid parameter. The credential type '{credentialType}' may require specific data formats.",

            ErrorCodes.ERROR_NO_SUCH_LOGON_SESSION =>
                $"Cannot {operation}: No logon session exists. Session-scoped credentials require an active logon session.",

            ErrorCodes.ERROR_INVALID_FLAGS =>
                $"Cannot {operation}: Invalid flags specified for this credential type.",

            _ => $"Cannot {operation}: {ex.Message} (Win32 error {ex.NativeErrorCode})"
        };

        return new CredentialException(message, ex, credentialType);
    }
}
