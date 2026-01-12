/* SPDX - License - Identifier: Apache - 2.0 
 * Copyright(c) 2025 Stefan Ploch */

using System.CommandLine;
using SecureCredentialManagement;

var rootCommand = new RootCommand("Windows Credential Manager CLI Tool");

// LIST
var listCommand = new Command("list", "List stored credentials matching an optional filter. Shows target, user, type, and timestamps.");
var filterArg = new Argument<string?>("filter") 
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
listCommand.Add(filterArg);
listCommand.Add(wideOpt);
listCommand.Add(columnsOpt);
listCommand.SetAction(parseResult =>
{
    var filter = parseResult.GetValue(filterArg);
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

// GET
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
        Console.WriteLine($"⚠ WARNING: This credential has expired!");
    
    return 0;
});

// SET
var setCommand = new Command("set", "Store or update a credential in Windows Credential Manager with optional metadata");
var setTargetArg = new Argument<string>("target") 
{ 
    Description = "Unique identifier for the credential (e.g., 'MyApp:Production', 'API:GitHub')" 
};
var userArg = new Argument<string>("user") 
{ 
    Description = "Username or identifier (e.g., 'user@example.com', 'api-key', 'service-account')" 
};
var passwordOpt = new Option<string?>("--password")
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
setCommand.Add(setTargetArg);
setCommand.Add(userArg);
setCommand.Add(passwordOpt);
setCommand.Add(persistOpt);
setCommand.Add(commentOpt);
setCommand.Add(typeOpt);
setCommand.SetAction(parseResult =>
{
    var target = parseResult.GetValue(setTargetArg);
    var user = parseResult.GetValue(userArg);
    var password = parseResult.GetValue(passwordOpt);
    var persist = parseResult.GetValue(persistOpt);
    var comment = parseResult.GetValue(commentOpt);
    var type = parseResult.GetValue(typeOpt);
    
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

    if (password is null)
    {
        Console.Write("Password: ");
        password = ReadPasswordMasked();
        Console.WriteLine();
    }

    if (password.Length == 0)
    {
        Console.Error.WriteLine("Password cannot be empty.");
        return 1;
    }

    var builder = CredentialManager.CreateCredential(target)
        .WithUserName(user)
        .WithSecret(password)
        .WithPersistence(persist)
        .WithType(type);
    
    if (!string.IsNullOrWhiteSpace(comment))
        builder.WithComment(comment);
    
    try
    {
        builder.SaveSecure();
        Console.WriteLine($"Credential '{target}' saved (Type: {type}, Persist: {persist}).");
    }
    catch (CredentialException ex)
    {
        Console.Error.WriteLine($"Error: {ex.Message}");
        return 1;
    }
    
    return 0;
});

// DELETE
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

rootCommand.Add(listCommand);
rootCommand.Add(getCommand);
rootCommand.Add(setCommand);
rootCommand.Add(deleteCommand);

return await rootCommand.Parse(args).InvokeAsync();

// Helpers
static string ReadPasswordMasked()
{
    var password = new System.Text.StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace && password.Length > 0)
        {
            password.Length--;
            Console.Write("\b \b");
        }
        else if (!char.IsControl(key.KeyChar))
        {
            password.Append(key.KeyChar);
            Console.Write('*');
        }
    }
    return password.ToString();
}

static string Truncate(string? value, int maxLength) =>
    value is null ? "" : value.Length <= maxLength ? value : value[..(maxLength - 3)] + "...";