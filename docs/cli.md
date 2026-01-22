# CLI Reference

Complete guide to the `wcred` command-line tool for Windows Credential Manager.

## Installation

```bash
dotnet tool install --global wcred
```

## Requirements

- Windows 10/11 or Windows Server 2016+
- .NET 10.0 runtime

---

## Commands

| Command | Description |
|---------|-------------|
| `list` | List stored credentials matching an optional filter |
| `get` | Retrieve and display a stored credential |
| `set` | Store or update a credential |
| `delete` | Permanently remove a credential |
| `export` | Export credentials to encrypted JSON |
| `import` | Import credentials from exported file |

---

## list

List stored credentials matching an optional filter.

```bash
wcred list [filter] [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `filter` | Wildcard filter pattern (e.g., `git:*`, `MyApp:*`). Omit to list all. |

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--wide` | `-w` | Show full details: target, user, type, last updated, comment |
| `--columns` | `-c` | Target column width in table mode (default: 50) |

### Examples

```bash
# List all credentials (table format)
wcred list

# Filter by pattern (wildcards supported)
wcred list "git:*"
wcred list "MyApp:*"

# Wide format: full details including timestamps and comments
wcred list --wide
wcred list "MyApp:*" -w

# Adjust column width for long target names
wcred list --columns 80
```

---

## get

Retrieve and display a stored credential with all metadata.

```bash
wcred get <target> [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `target` | Credential target name (case-sensitive) |

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--show-password` | `-s` | Display the password in plain text |

### Examples

```bash
# Show credential (password masked) with all metadata
wcred get "MyApp:Production"

# Show password in plain text
wcred get "MyApp:Production" --show-password
wcred get "MyApp:Production" -s
```

**Output includes:** Target, User, Password (masked), Type, Last Updated, Comment (if set), Attributes, and expiry warnings.

> **Note:** Target names are case-sensitive. Use `wcred list` to find exact names.

---

## set

Store or update a credential in Windows Credential Manager.

```bash
wcred set <target> <user> [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `target` | Unique identifier for the credential (e.g., `MyApp:Production`) |
| `user` | Username or identifier (e.g., `user@example.com`, `api-key`) |

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--password` | `-pw` | Password/secret value. If omitted, prompts interactively. |
| `--password-env` | `-pwe` | Name of environment variable containing the password |
| `--password-stdin` | `-pws` | Read password from standard input |
| `--persist` | `-p` | Storage persistence: `Session`, `LocalMachine` (default), `Enterprise` |
| `--comment` | `-m` | Description or note |
| `--type` | `-t` | Credential type: `Generic` (default), `DomainPassword`, `DomainVisiblePassword` |

### Password Resolution Priority

1. `--password` (explicit value)
2. `--password-env` (from environment variable)
3. `--password-stdin` (from stdin)
4. Interactive prompt (if terminal available)

### Examples

```bash
# Interactive (prompts for password securely - recommended)
wcred set "MyApp:Production" "user@example.com"

# With persistence level
wcred set "MyApp:Token" "api-key" --persist Session

# With a comment/description
wcred set "MyApp:DB" "sa" --comment "Production database - rotate quarterly"

# Specify credential type (for Windows domain scenarios)
wcred set "MyApp:Domain" "DOMAIN\\user" --type DomainPassword

# Non-interactive (for scripts - password visible in history!)
wcred set "MyApp:CI" "service-account" --password "secret123"
```

### Persistence Levels

| Level | Description |
|-------|-------------|
| `Session` | Credential exists only for current login session |
| `LocalMachine` | Persists across reboots on this machine (default) |
| `Enterprise` | Roams with domain profile |

### Credential Types

| Type | Use Case |
|------|----------|
| `Generic` | Application credentials (default, most common) |
| `DomainPassword` | Windows domain authentication |
| `DomainVisiblePassword` | RDP saved credentials |

---

## delete

Permanently remove a credential from Windows Credential Manager.

```bash
wcred delete <target> [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `target` | Target name of the credential to delete (case-sensitive) |

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--force` | `-f` | Skip confirmation prompt |

### Examples

```bash
# With confirmation prompt
wcred delete "MyApp:Production"

# Skip confirmation
wcred delete "MyApp:Production" --force
wcred delete "MyApp:Production" -f
```

---

## export

Export credentials to a JSON file with optional encryption.

```bash
wcred export [options]
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--filter` | `-f` | Wildcard filter pattern (e.g., `MyApp:*`) |
| `--targets` | `-t` | List of specific credential target names |
| `--output` | `-o` | Output file path (required) |
| `--encrypt` | `-e` | Use password-based encryption (AES-GCM) |
| `--password` | `-p` | Encryption password |
| `--password-env` | `-pe` | Environment variable containing password |
| `--password-stdin` | `-ps` | Read password from stdin |
| `--machine-scope` | `-m` | Use DPAPI machine scope (default: user) |

> **Note:** One of `--filter` or `--targets` is required.

### Encryption Methods

| Method | When Used | Portability |
|--------|-----------|-------------|
| DPAPI | Default (no `--encrypt`) | Current user/machine only |
| Password (AES-GCM) | With `--encrypt` | Any machine with password |

### Examples

```bash
# Export with DPAPI (current user only, no password needed)
wcred export --filter "MyApp:*" --output backup.json

# Export with DPAPI for any user on this machine
wcred export --filter "MyApp:*" --output backup.json --machine-scope

# Export with password encryption (portable across machines)
wcred export --filter "MyApp:*" --output backup.json --encrypt --password-env EXPORT_PASSWORD

# Export specific targets
wcred export --targets "MyApp:Prod" "MyApp:Dev" --output backup.json
```

---

## import

Import credentials from a JSON file exported by this tool.

```bash
wcred import [options]
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--file` | `-f` | Path to the exported JSON file (required) |
| `--force` | `-F` | Overwrite existing credentials |
| `--password` | `-p` | Decryption password |
| `--password-env` | `-pe` | Environment variable containing password |
| `--password-stdin` | `-ps` | Read password from stdin |
| `--dry-run` | `-d` | Preview without writing |

### Examples

```bash
# Import from DPAPI-encrypted file
wcred import --file backup.json

# Import with password decryption
wcred import --file backup.json --password-env IMPORT_PASSWORD

# Overwrite existing credentials
wcred import --file backup.json --force

# Preview what would be imported
wcred import --file backup.json --dry-run
```

---

## Automation (Scripts & CI/CD)

For automated scenarios, avoid putting passwords on the command line (visible in shell history).

### Environment Variables

```bash
# Pass the variable NAME, not the value
wcred set "MyApp:Token" "api-key" --password-env MY_SECRET_VAR
```

> **Warning:** Pass the variable NAME only (e.g., `MY_SECRET`), not the expanded value (`$Env:MY_SECRET`).

### Standard Input

```bash
# From stdin (RECOMMENDED for scripts)
echo "my-password" | wcred set "MyApp:Token" "api-key" --password-stdin

# PowerShell example with secure pipeline
$secret | wcred set "MyApp:Token" "api-key" --password-stdin
```

### GitHub Actions Example

```yaml
jobs:
  deploy:
    runs-on: windows-latest
    steps:
      - name: Store credential
        env:
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
        run: wcred set "MyApp:DB" "sa" --password-env DB_PASSWORD
```

### Azure DevOps Example

```yaml
steps:
  - powershell: |
      wcred set "MyApp:API" "service" --password-env API_KEY
    env:
      API_KEY: $(ApiKeySecret)
```

---

## Audit Logging

Set the `WCRED_AUDIT_LOG` environment variable to enable audit logging:

```bash
# PowerShell
$env:WCRED_AUDIT_LOG = "C:\logs\wcred-audit.log"
wcred get "MyApp:Production"

# Bash / CI
export WCRED_AUDIT_LOG=/var/log/wcred-audit.log
wcred list
```

**Log format:**
```
[2026-01-22 14:30:00Z] ACCESSED: MyApp:Production | Op: Read | Secret: True | User: DOMAIN\user | Machine: WORKSTATION
[2026-01-22 14:30:05Z] ENUMERATED: Filter: (all) | Count: 12 | User: DOMAIN\user
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (credential not found, invalid arguments, etc.) |

---

## See Also

- [Library Documentation](library.md) - .NET library for programmatic access
- [Security Model](security.md) - Honest assessment of security guarantees
- [CHANGELOG](../CHANGELOG.md) - Version history
