# =============================================================================
# PowerShell script to provision database roles against an already-running SentinelAgent database
# =============================================================================
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BaseDir = Split-Path -Parent $ScriptDir
$SecretsDir = Join-Path $BaseDir "secrets"

$adminPassFile = Join-Path $SecretsDir "postgres_admin_password.txt"
$migPassFile = Join-Path $SecretsDir "migration_password.txt"
$appPassFile = Join-Path $SecretsDir "app_password.txt"

if (-not (Test-Path $adminPassFile)) {
    Write-Error "Secret file $adminPassFile does not exist."
}

$adminPass = (Get-Content $adminPassFile).Trim()
$migPass = (Get-Content $migPassFile).Trim()
$appPass = (Get-Content $appPassFile).Trim()

Write-Host "Executing role provisioning against sentinelagent-db container..."

$composeFile = Join-Path $BaseDir "compose.yaml"
docker compose -f $composeFile exec -T db env `
    PGPASSWORD="$adminPass" `
    MIGRATION_PASSWORD="$migPass" `
    APP_PASSWORD="$appPass" `
    sh -c "/docker-entrypoint-initdb.d/01-init-roles.sh"

Write-Host "Role provisioning complete."
