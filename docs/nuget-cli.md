# wcred - Windows Credential Manager CLI

Command-line tool for managing Windows Credential Manager credentials. Supports automation with stdin/environment variables, encrypted export/import, and more.

## Installation

```bash
dotnet tool install --global wcred
```

## Commands

### List Credentials

```bash
wcred list                    # List all credentials
wcred list "MyApp:*"          # Filter by pattern
wcred list --wide             # Full details with timestamps
```

### Get a Credential

```bash
wcred get "MyApp:Production"              # Show credential (password masked)
wcred get "MyApp:Production" -s           # Show password in plain text
```

### Store a Credential

```bash
# Interactive (prompts securely)
wcred set "MyApp:Token" "api-key"

# With comment
wcred set "MyApp:DB" "sa" --comment "Production database"

# From environment variable (CI/CD)
wcred set "MyApp:Token" "api-key" --password-env MY_SECRET

# From stdin (scripts)
echo "password" | wcred set "MyApp:Token" "api-key" --password-stdin
```

### Delete a Credential

```bash
wcred delete "MyApp:Production"           # With confirmation
wcred delete "MyApp:Production" --force   # Skip confirmation
```

### Export Credentials

```bash
# DPAPI encryption (current user)
wcred export --filter "MyApp:*" --output backup.json

# Password encryption (portable)
wcred export --filter "MyApp:*" --output backup.json --encrypt --password-env EXPORT_PW
```

### Import Credentials

```bash
wcred import --file backup.json                          # DPAPI-encrypted
wcred import --file backup.json --password-env IMPORT_PW # Password-encrypted
wcred import --file backup.json --dry-run                # Preview only
```

## Automation

For CI/CD pipelines, use `--password-env` or `--password-stdin` to avoid exposing secrets in command history:

```bash
# GitHub Actions 
# env: DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
wcred set "MyApp:DB" "sa" --password-env DB_PASSWORD
```

## Audit Logging

Set `WCRED_AUDIT_LOG` environment variable to log all operations:

```bash
$env:WCRED_AUDIT_LOG = "C:\logs\wcred.log"
wcred get "MyApp:Production"
# Logs: [2026-01-22 14:30:00Z] ACCESSED: MyApp:Production | Op: Read | ...
```

## Documentation

Full documentation: https://github.com/Officialstjp/SecureCredentialManagement/blob/main/docs/cli.md

## Related

- **Library**: [`Stjp.SecureCredentialManagement`](https://www.nuget.org/packages/Stjp.SecureCredentialManagement) - .NET library for programmatic access
