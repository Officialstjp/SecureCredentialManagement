/* SPDX - License - Identifier: Apache - 2.0 
 * Copyright(c) 2025 Stefan Ploch */

using System.CommandLine;
using SecureCredentialManagement;
using static SecureCredentialManagement.CredentialExport;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;

var rootCommand = new RootCommand("Windows Credential Manager CLI Tool");

#pragma warning disable CA1416 // Windows-specific API

// Enable audit logging if WCRED_AUDIT_LOG environment variable is set
var auditLogPath = Environment.GetEnvironmentVariable("WCRED_AUDIT_LOG");
if (!string.IsNullOrEmpty(auditLogPath))
{
    CredentialAudit.IsEnabled = true;
    
    CredentialAudit.OnCredentialAccessed += (_, e) =>
        AppendAuditLog(auditLogPath, $"ACCESSED: {e.TargetName} | Op: {e.Operation} | Secret: {e.SecretWasRetrieved} | User: {e.UserName} | Machine: {e.MachineName}");
    
    CredentialAudit.OnCredentialModified += (_, e) =>
        AppendAuditLog(auditLogPath, $"MODIFIED: {e.TargetName} | Op: {e.Operation} | New: {e.IsNewCredential} | User: {e.UserName}");
    
    CredentialAudit.OnCredentialDeleted += (_, e) =>
        AppendAuditLog(auditLogPath, $"DELETED: {e.TargetName} | User: {e.UserName}");
    
    CredentialAudit.OnCredentialsEnumerated += (_, e) =>
        AppendAuditLog(auditLogPath, $"ENUMERATED: Filter: {e.Filter ?? "(all)"} | Count: {e.CredentialCount} | User: {e.UserName}");
}

static void AppendAuditLog(string path, string message)
{
    try
    {
        File.AppendAllText(path, $"[{DateTimeOffset.UtcNow:u}] {message}{Environment.NewLine}");
    }
    catch
    {
        // Silently ignore audit logging failures - don't break the CLI
    }
}

#region LIST


var listCommand = new Command("list", "List stored credentials matching an optional filter. Shows target, user, type, and timestamps.");

var listFilterArg = new Argument<string?>("filter") 
{ 
    Arity = ArgumentArity.ZeroOrOne, 
    Description = "Wildcard filter pattern (e.g., 'git:*', 'MyApp:*'). Omit to list all credentials." 
};

var wideOpt = new Option<bool>("--wide", "-w")
{
    Description = "Show full details: target, user, type, last updated, and comment (if set)"
};

var columnsOpt = new Option<int>("--columns", "-c")
{
    Description = "Target column width in table mode (default: 50)",
    DefaultValueFactory = _ => 50
};

listCommand.Add(listFilterArg);
listCommand.Add(wideOpt);
listCommand.Add(columnsOpt);
listCommand.SetAction(parseResult =>
{
    var filter = parseResult.GetValue(listFilterArg);
    var wide = parseResult.GetValue(wideOpt);
    var targetWidth = Math.Clamp(parseResult.GetValue(columnsOpt), 20, 200);
    var creds = CredentialManager.EnumerateCredentials(filter);
    if (creds.Count == 0)
    {
        Console.WriteLine(filter is null 
            ? "No credentials found." 
            : $"No credentials matching '{filter}'.");
        return 0;
    }

    if (wide)
    {
        // Wide format: one credential per block, full values
        foreach (var c in creds)
        {
            Console.WriteLine($"Target: {c.TargetName}");
            Console.WriteLine($"User:   {c.UserName}");
            Console.WriteLine($"Type:   {c.CredentialType}");
            Console.WriteLine($"Updated: {c.LastWritten:g}");
            if (c.Comment is not null)
                Console.WriteLine($"Comment: {c.Comment}");
            Console.WriteLine();
        }
    }
    else
    {
        // Table format: configurable column widths
        var userWidth = Math.Max(15, targetWidth / 2);
        var totalWidth = targetWidth + userWidth + 12;
        
        Console.WriteLine($"{"Target".PadRight(targetWidth)} {"User".PadRight(userWidth)} Type");
        Console.WriteLine(new string('─', totalWidth));
        foreach (var c in creds)
            Console.WriteLine($"{Truncate(c.TargetName, targetWidth).PadRight(targetWidth)} {Truncate(c.UserName, userWidth).PadRight(userWidth)} {c.CredentialType}");
    }
    
    Console.WriteLine($"\n{creds.Count} credential(s) found.");
    return 0;
});


#endregion LIST


#region GET


var getCommand = new Command("get", "Retrieve and display a stored credential with all metadata");

var targetArg = new Argument<string>("target") 
{ 
    Description = "Credential target name (case-sensitive)" 
};

var showPasswordOpt = new Option<bool>("--show-password", "-s") 
{ 
    Description = "Display the password in plain text (use with caution)" 
};

getCommand.Add(targetArg);
getCommand.Add(showPasswordOpt);
getCommand.SetAction(parseResult =>
{
    var target = parseResult.GetValue(targetArg);
    var showPassword = parseResult.GetValue(showPasswordOpt);
    
    var cred = CredentialManager.ReadCredential(target);
    if (cred is null)
    {
        Console.Error.WriteLine($"Credential '{target}' not found.");
        Console.Error.WriteLine("Tip: Target names are case-sensitive. Use 'list' to find exact names.");
        return 1;
    }

    Console.WriteLine($"Target:   {cred.TargetName}");
    Console.WriteLine($"User:     {cred.UserName}");
    Console.WriteLine($"Password: {(showPassword ? cred.Password : new string('*', cred.Password?.Length ?? 0))}");
    Console.WriteLine($"Type:     {cred.CredentialType}");
    Console.WriteLine($"Updated:  {cred.LastWritten:g}");
    if (cred.Comment is not null)
        Console.WriteLine($"Comment:  {cred.Comment}");

    if (cred.Attributes.Count > 0)
    {
        Console.WriteLine($"Attributes:");
        foreach (var attr in cred.Attributes)
            Console.WriteLine($"  {attr.Key}: {System.Text.Encoding.UTF8.GetString(attr.Value)}");
    }

    if (cred.IsExpired())
        Console.WriteLine($"[WARNING]: This credential has expired!");
    
    return 0;
});


#endregion GET


#region SET


var setCommand = new Command("set", "Store or update a credential in Windows Credential Manager with optional metadata");

var setTargetArg = new Argument<string>("target") 
{ 
    Description = "Unique identifier for the credential (e.g., 'MyApp:Production', 'API:GitHub')" 
};

var userArg = new Argument<string>("user") 
{ 
    Description = "Username or identifier (e.g., 'user@example.com', 'api-key', 'service-account')" 
};

var passwordOpt = new Option<string?>("--password", "-pw")
{
    Description = "Password/secret value. If omitted, prompts interactively (recommended). Warning: command-line values are visible in shell history!"
};

var persistOpt = new Option<CredentialPersistence>("--persist", "-p")
{
    Description = "Storage persistence: Session (until logoff), LocalMachine (survives reboot, default), Enterprise (roams with domain profile)",
    DefaultValueFactory = _ => CredentialPersistence.LocalMachine
};

var commentOpt = new Option<string?>("--comment", "-m")
{
    Description = "Description or note (e.g., 'Production DB - rotate quarterly', 'Created by CI pipeline')"
};

// Only expose writable credential types in CLI
var typeOpt = new Option<CredentialType>("--type", "-t")
{
    Description = "Credential type: Generic (default, for apps), DomainPassword (Windows/NTLM auth), DomainVisiblePassword (RDP-style)",
    DefaultValueFactory = _ => CredentialType.Generic
};

typeOpt.AcceptOnlyFromAmong(
    CredentialType.Generic.ToString(),
    CredentialType.DomainPassword.ToString(),
    CredentialType.DomainVisiblePassword.ToString()
);

var passwordEnvOption = new Option<string?>("--password-env", "-pwe")
{
    Description = "Name of an environment variable containing the password. " +
        "Pass the NAME only, not the value (e.g., '--password-env MY_SECRET', not '--password-env $Env:MY_SECRET').",
    DefaultValueFactory = _ => null
};

var passwordStdinOption = new Option<bool>("--password-stdin", "-pws")
{
    Description = "Read the password/secret value from standard input. Prefer this over --password for better security."
};

setCommand.Add(setTargetArg);
setCommand.Add(userArg);
setCommand.Add(passwordOpt);
setCommand.Add(persistOpt);
setCommand.Add(commentOpt);
setCommand.Add(typeOpt);
setCommand.Add(passwordEnvOption);
setCommand.Add(passwordStdinOption);

setCommand.SetAction(parseResult =>
{
    var target = parseResult.GetValue(setTargetArg);
    var user = parseResult.GetValue(userArg);
    var password = parseResult.GetValue(passwordOpt);
    var persist = parseResult.GetValue(persistOpt);
    var comment = parseResult.GetValue(commentOpt);
    var type = parseResult.GetValue(typeOpt);
    var passwordEnv = parseResult.GetValue(passwordEnvOption);
    var passwordStdin = parseResult.GetValue(passwordStdinOption);

    if (string.IsNullOrWhiteSpace(user))
    {
        Console.Error.WriteLine("Username cannot be empty.");
        return 1;
    }

    if (string.IsNullOrWhiteSpace(target))
    {
        Console.Error.WriteLine("Target name cannot be empty.");
        return 1;
    }

    var resolvedPassword = ResolvePassword(password, passwordEnv, passwordStdin);
    if (resolvedPassword is null)
        return 1;

    try
    {
        var builder = CredentialManager.CreateCredential(target)
            .WithUserName(user)
            .WithSecret(resolvedPassword)
            .WithPersistence(persist)
            .WithType(type);
    
        if (!string.IsNullOrWhiteSpace(comment))
            builder.WithComment(comment);

        builder.SaveSecure();
        Console.WriteLine($"Credential '{target}' saved (Type: {type}, Persist: {persist}).");
    }
    catch (CredentialException ex)
    {
        Console.Error.WriteLine($"Failed to save credential '{target}': {ex.Message}");
        return 1;
    }
    return 0;
});


#endregion SET


#region DELETE


var deleteCommand = new Command("delete", "Permanently remove a credential from Windows Credential Manager");

var delTargetArg = new Argument<string>("target") 
{ 
    Description = "Target name of the credential to delete (case-sensitive, use 'list' to find exact names)" 
};

var forceOpt = new Option<bool>("--force", "-f") 
{ 
    Description = "Skip confirmation prompt (use in scripts)" 
};

deleteCommand.Add(delTargetArg);
deleteCommand.Add(forceOpt);
deleteCommand.SetAction(parseResult =>
{
    var target = parseResult.GetValue(delTargetArg);
    var force = parseResult.GetValue(forceOpt);

    if (string.IsNullOrWhiteSpace(target))
    {
        Console.Error.WriteLine("Target name cannot be empty.");
        return 1;
    }
    
    if (!force)
    {
        Console.Write($"Delete credential '{target}'? [y/N]: ");
        if (Console.ReadLine()?.Trim().ToLowerInvariant() != "y")
        {
            Console.WriteLine("Cancelled.");
            return 0;
        }
    }

    if (CredentialManager.DeleteCredential(target))
    {
        Console.WriteLine($"Credential '{target}' deleted.");
        return 0;
    }
    
    Console.Error.WriteLine($"Credential '{target}' not found.");
    return 1;
});


#endregion DELETE

#region EXPORT

var exportCommand = new Command("export", "Export credentials to a JSON file with optional encryption. Useful for backup or migration.");

var exportFilterArg = new Option<string?>("--filter", "-f")
{
    Description = "Wildcard filter pattern to select credentials (e.g., 'git:*', 'MyApp:*'). One of --filter or --targets is required."
};

var exportTargetsArg = new Option<string[]>("--targets", "-t")
{
    Description = "List of specific credential target names to export. One of --filter or --targets is required."
};

var exportOutputArg = new Option<string>("--output", "-o")
{
    Description = "Output file path for the exported JSON data.",
};

var exportEncryptOpt = new Option<bool>("--encrypt", "-e")
{
    Description = "Encrypt the exported credentials using password-based encryption. Without this, uses DPAPI encryption (current user only).",
    DefaultValueFactory = _ => false
};

var exportPasswordOpt = new Option<string?>("--password", "-p")
{
    Description = "Password for encrypting the exported data. Required if --encrypt is set. Warning: command-line values are visible in shell history!"
};

var exportPasswordEnvOpt = new Option<string?>("--password-env", "-pe")
{
    Description = "Name of an environment variable containing the encryption password. Prefer this over --password for better security.",
    DefaultValueFactory = _ => null
};

var exportPasswordStdinOpt = new Option<bool>("--password-stdin", "-ps")
{
    Description = "Read the encryption password from standard input. Prefer this over --password for better security."
};

var exportDpapiMachineOpt = new Option<bool>("--machine-scope", "-m")
{
    Description = "When using DPAPI encryption, use machine scope (accessible by all users on this machine). Default is user scope.",
    DefaultValueFactory = _ => false
};

exportCommand.Add(exportFilterArg);
exportCommand.Add(exportTargetsArg);
exportCommand.Add(exportOutputArg);
exportCommand.Add(exportEncryptOpt);
exportCommand.Add(exportPasswordOpt);
exportCommand.Add(exportPasswordEnvOpt);
exportCommand.Add(exportPasswordStdinOpt);
exportCommand.Add(exportDpapiMachineOpt);
exportCommand.SetAction(parseResult =>
{
    var filter = parseResult.GetValue(exportFilterArg);
    var targets = parseResult.GetValue(exportTargetsArg);
    var outputPath = parseResult.GetValue(exportOutputArg);
    var pwEncrypt = parseResult.GetValue(exportEncryptOpt);
    var password = parseResult.GetValue(exportPasswordOpt);
    var passwordEnv = parseResult.GetValue(exportPasswordEnvOpt);
    var passwordStdin = parseResult.GetValue(exportPasswordStdinOpt);
    var dpapiMachineScope = parseResult.GetValue(exportDpapiMachineOpt);

    if (string.IsNullOrWhiteSpace(outputPath))
    {
        Console.Error.WriteLine("Output file path is required.");
        return 1;
    }

    if (filter is null && (targets is null || targets.Length == 0))
    {
        Console.Error.WriteLine("Either --filter or --targets must be specified to select credentials for export.");
        return 1;
    }

    EncryptionMethod method;

    string? encryptionPassword = null;
    if (pwEncrypt)
    {
        method = EncryptionMethod.Password;
        encryptionPassword = ResolvePassword(password, passwordEnv, passwordStdin);
        if (encryptionPassword is null)
        {
            Console.Error.WriteLine("Encryption password is required when --encrypt is specified.");
            return 1;
        }
    } else
    {
        method = EncryptionMethod.Dpapi;
    }

    try
    {
       var scope = dpapiMachineScope
            ? DataProtectionScope.LocalMachine
            : DataProtectionScope.CurrentUser;

        CredentialExport.ExportToFile(outputPath, filter, targets, method, encryptionPassword, scope);

        var creds = string.IsNullOrEmpty(filter)
            ? CredentialManager.EnumerateCredentials()
            : CredentialManager.EnumerateCredentials(filter);

        Console.WriteLine($"Exported {creds.Count()} credentials to {outputPath}");
        Console.WriteLine($"Encryption: {(method == EncryptionMethod.Password ? "Password (AES-GCM)" : "DPAPI")}");

        if (method == EncryptionMethod.Dpapi)
        {
            Console.WriteLine(dpapiMachineScope
                ? "Note: Any user on this machine can decrypt this file."
                : "Note: Only your user account can decrypt this file.");
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Error: {ex.Message}");
        Environment.ExitCode = 1;
    }

    return 0;
});

#endregion EXPORT

#region IMPORT

var importCommand = new Command("import", "Import credentials from a JSON file exported by this tool.");
var importFileArg = new Option<string>("file", "-f")
{
    Description = "Path to the JSON file containing exported credentials."
};

var importForceOpt = new Option<bool>("--force", "-F")
{
    Description = "Overwrite existing credentials with the same target name.",
    DefaultValueFactory = _ => false
};

var importPasswordOpt = new Option<string?>("--password", "-p")
{
    Description = "Password for decrypting the imported data if it was password-encrypted. Warning: command-line values are visible in shell history!"
};

var importPasswordEnvOpt = new Option<string?>("--password-env", "-pe")
{
    Description = "Name of an environment variable containing the decryption password. Prefer this over --password for better security.",
    DefaultValueFactory = _ => null
};

var importPasswordStdinOpt = new Option<bool>("--password-stdin", "-ps")
{
    Description = "Read the decryption password from standard input. Prefer this over --password for better security."
};

var importDryRunOpt = new Option<bool>("--dry-run", "-d")
{
    Description = "Simulate the import without actually writing any credentials.",
    DefaultValueFactory = _ => false
};

importCommand.Add(importFileArg);
importCommand.Add(importForceOpt);
importCommand.Add(importPasswordOpt);
importCommand.Add(importPasswordEnvOpt);
importCommand.Add(importPasswordStdinOpt);
importCommand.Add(importDryRunOpt);
importCommand.SetAction(parseResult =>
{
    var filePath = parseResult.GetValue(importFileArg);
    var force = parseResult.GetValue(importForceOpt);
    var password = parseResult.GetValue(importPasswordOpt);
    var passwordEnv = parseResult.GetValue(importPasswordEnvOpt);
    var passwordStdin = parseResult.GetValue(importPasswordStdinOpt);
    var dryRun = parseResult.GetValue(importDryRunOpt);

    try
    {
        if (!File.Exists(filePath))
        {
            Console.Error.WriteLine($"Error: File not found: {filePath}");
            Environment.ExitCode = 1;
            return;
        }

        var json = File.ReadAllText(filePath);
        var exportSet = JsonSerializer.Deserialize<ExportedCredentialSet>(json);

        if (exportSet is null)
        {
            Console.Error.WriteLine("Error: Invalid export file format.");
            Environment.ExitCode = 1;
            return;
        }
        string? decryptionPassword = null;
        if (exportSet.Encryption?.Method == "password")
        {
            decryptionPassword = ResolvePassword(password, passwordEnv, passwordStdin);
            if (decryptionPassword is null)
            {
                Console.Error.WriteLine("Decryption password is required for password-encrypted data.");
                Environment.ExitCode = 1;
                return;
            }
        }

        if (dryRun)
        {
            Console.WriteLine($"Would import {exportSet.Credentials.Count} credentials:");
            foreach (var cred in exportSet.Credentials)
            {
                var existing = CredentialManager.ReadCredential(cred.TargetName);
                var status = existing is not null
                    ? (force ? "[FORCE]" : "[SKIP - exists]")
                    : "[NEW]";
                Console.WriteLine($"  {status} {cred.TargetName} ({cred.Type})");
            }
            return;
        }

        var results = CredentialExport.Import(exportSet, decryptionPassword, force);

        var succeeded = results.Count(r => r.Success);
        var skipped = results.Count(r => r.Skipped);
        var failed = results.Count(r => !r.Success && !r.Skipped);

        Console.WriteLine($"Import complete: {succeeded} succeeded, {skipped} skipped, {failed} failed");

        if (failed > 0)
        {
            Console.WriteLine("\nFailed:");
            foreach (var result in results.Where(r => !r.Success && !r.Skipped))
                Console.WriteLine($"  {result.TargetName}: {result.Error}");
        }

        if (skipped > 0 && !force)
            Console.WriteLine("\nUse --force to replace existing credentials.");

        Environment.ExitCode = failed > 0 ? 1 : 0;
        }
        catch (CryptographicException)
        {
            Console.Error.WriteLine("Error: Decryption failed. Wrong password or corrupted file.");
            Environment.ExitCode = 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            Environment.ExitCode = 1;
        }
});

#endregion IMPORT

rootCommand.Add(listCommand);
rootCommand.Add(getCommand);
rootCommand.Add(setCommand);
rootCommand.Add(deleteCommand);
rootCommand.Add(exportCommand);
rootCommand.Add(importCommand);

return await rootCommand.Parse(args).InvokeAsync();

static string? ResolvePassword(
    string? ExplicitPassword,
    string? passwordEnvVar,
    bool ReadFromStdin)
{
    /// Priority: Explicit > Env Var > Stdin > Prompt
    if (!string.IsNullOrEmpty(ExplicitPassword))
        return ExplicitPassword;

    if (!string.IsNullOrEmpty(passwordEnvVar))
    {
        // Detect common mistake: user passed $Env:VAR or %VAR% instead of just VAR
        if (passwordEnvVar.Contains(' ') || passwordEnvVar.Contains('=') || 
            passwordEnvVar.Length > 100 || passwordEnvVar.Any(c => !char.IsLetterOrDigit(c) && c != '_'))
        {
            Console.Error.WriteLine($"Warning: '{passwordEnvVar}' doesn't look like an environment variable name.");
            Console.Error.WriteLine("Did you accidentally pass the VALUE instead of the NAME?");
            Console.Error.WriteLine("Correct usage: --password-env SECRET (not --password-env $Env:SECRET)");
            Console.Error.WriteLine();
        }

        var envValue = Environment.GetEnvironmentVariable(passwordEnvVar);
        if (string.IsNullOrEmpty(envValue))
        {
            Console.Error.WriteLine($"Environment variable '{passwordEnvVar}' is not set or empty.");
            Console.Error.WriteLine("Tip: Use '--password-env SECRET' with the variable NAME, not '$Env:SECRET'.");
            return null;
        }
        return envValue;
    }

    if (ReadFromStdin)
    {
        if (Console.IsInputRedirected)
        {
            var input = Console.In.ReadLine();
            if (string.IsNullOrEmpty(input))
            {
                Console.Error.WriteLine("No input received from standard input.");
                return null;
            }
            return input;
        }
        else
        {
            Console.Error.WriteLine("Error: --password-stdin requires input to be piped. " +
            "Use: echo 'secret' | wcred set... / $secret | wcred set...");
            return null;
        }
    }

    if (!Console.IsInputRedirected && !Console.IsOutputRedirected)
    {
        Console.Write("Password: ");
        var password = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            if (key.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password.Length--;
                Console.Write("\b \b");
            }
            else if (!char.IsControl(key.KeyChar))
            {
                password.Append(key.KeyChar);
                Console.Write("*");
            }
        }
        return password.ToString();
    }

    Console.Error.WriteLine("Error: No password provided. Use --password-env, --password-stdin or interactive options.");
        return null;
}


#region Helpers


static string Truncate(string? value, int maxLength) =>
    value is null ? "" : value.Length <= maxLength ? value : value[..(maxLength - 3)] + "...";


#endregion Helpers


#pragma warning restore CA1416 // Windows-specific API