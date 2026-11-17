# =============================================================================
# PowerShell Helper script to generate initial high-entropy secrets for SentinelAgent
# =============================================================================
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SecretsDir = Join-Path (Split-Path -Parent $ScriptDir) "secrets"

if (-not (Test-Path $SecretsDir)) {
    New-Item -ItemType Directory -Path $SecretsDir | Out-Null
}

function New-RandomPassword {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    return [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

# 1. PostgreSQL Admin Password
$adminPassFile = Join-Path $SecretsDir "postgres_admin_password.txt"
if (-not (Test-Path $adminPassFile)) {
    $adminPass = New-RandomPassword
    [System.IO.File]::WriteAllText($adminPassFile, $adminPass)
    Write-Host "Generated postgres_admin_password.txt"
}

# 2. Migration Role Password & DSN
$migPassFile = Join-Path $SecretsDir "migration_password.txt"
$migDsnFile = Join-Path $SecretsDir "migration_database_url.txt"
if (-not (Test-Path $migPassFile)) {
    $migPass = New-RandomPassword
    [System.IO.File]::WriteAllText($migPassFile, $migPass)
    [System.IO.File]::WriteAllText($migDsnFile, "postgresql+psycopg://sentinel_migration_role:${migPass}@db:5432/sentinelagent")
    Write-Host "Generated migration_password.txt and migration_database_url.txt"
}

# 3. Application Role Password & DSN
$appPassFile = Join-Path $SecretsDir "app_password.txt"
$appDsnFile = Join-Path $SecretsDir "app_database_url.txt"
if (-not (Test-Path $appPassFile)) {
    $appPass = New-RandomPassword
    [System.IO.File]::WriteAllText($appPassFile, $appPass)
    [System.IO.File]::WriteAllText($appDsnFile, "postgresql+psycopg://sentinel_app_role:${appPass}@db:5432/sentinelagent")
    Write-Host "Generated app_password.txt and app_database_url.txt"
}

# 4. Operator Credentials Template
$opCredsFile = Join-Path $SecretsDir "operator_credentials.json"
if (-not (Test-Path $opCredsFile)) {
    $opJson = @'
[
  {
    "operator_id": "op-analyst-01",
    "role": "analyst",
    "key_sha256": "c04fb597231c134cb36ab30d09e7bcfb0b030d8431813982b1cb1c55e10bc7ff"
  },
  {
    "operator_id": "op-approver-01",
    "role": "approver",
    "key_sha256": "1674ad86283e3eb9b6965b72c250e020da6bf456f6992bbdf97a805ed30abede"
  },
  {
    "operator_id": "op-admin-01",
    "role": "admin",
    "key_sha256": "07cc606494fc364c3f41e2c519de30a46b3eef4db3c2629aa5e06ed85270e738"
  }
]
'@
    [System.IO.File]::WriteAllText($opCredsFile, $opJson)
    Write-Host "Created operator_credentials.json template"
}

# 5. Gemini API Key Placeholder
$geminiFile = Join-Path $SecretsDir "gemini_api_key.txt"
if (-not (Test-Path $geminiFile)) {
    [System.IO.File]::WriteAllText($geminiFile, "")
    Write-Host "Created gemini_api_key.txt placeholder"
}

# -----------------------------------------------------------------------------
# Windows NTFS Access Control & Docker Desktop Mechanics
# -----------------------------------------------------------------------------
# Unlike Linux POSIX mode bits (e.g. 0700 / 0644), Windows NTFS permissions are
# governed by Access Control Lists (ACLs) with Access Control Entries (ACEs).
#
# When Docker Desktop (WSL2 / Hyper-V virtiofs) bind-mounts Windows host paths
# into Linux containers, the drvfs translation layer projects Windows filesystem
# objects as virtual inodes owned by root:root with mode 0755/0777. This virtualization
# allows non-root container processes (UID 10001 / UID 70) to read mounted secrets
# during local Windows development without triggering POSIX DAC EACCES errors.
#
# Inspect directory NTFS ACL:
$acl = Get-Acl $SecretsDir
Write-Host "Secrets directory NTFS Owner: $($acl.Owner)"
Write-Host "Secrets directory ACL inheritance: $(if ($acl.AreAccessRulesProtected) { 'Protected (Explicit)' } else { 'Inherited' })"
Write-Host "Secret provisioning completed in $SecretsDir."
