<#
.SYNOPSIS
    Controlled bootstrap script to preload Gemma 3 4B into the dedicated Ollama model volume.

.DESCRIPTION
    Executes a controlled, temporary Ollama server container attached to the default Docker bridge
    to fetch and verify the Gemma 3 4B model weights into the 'sentinelagent-ollama-models' volume.
    The container publishes no host ports and mounts zero application data or secrets.
    Upon completion or failure, the temporary bootstrap container is cleanly destroyed, leaving
    the preloaded volume ready for the strictly isolated Option B runtime environment.

.NOTES
    Architecture Contract: Task 9F.7 (Option B)
    Pinned Ollama Image: ollama/ollama@sha256:910d0d8107b538fb0894e63163eb195de0cc7aefcbc666dc62d3b18f71124592
    Target Model: gemma3:4b
    Target Volume: sentinelagent-ollama-models
    SAFETY: This script is prepared for manual controlled execution. DO NOT run without operator authorization.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ModelTag = "gemma3:4b",

    [Parameter(Mandatory = $false)]
    [string]$VolumeName = "sentinelagent-ollama-models",

    [Parameter(Mandatory = $false)]
    [string]$PinnedImage = "ollama/ollama@sha256:910d0d8107b538fb0894e63163eb195de0cc7aefcbc666dc62d3b18f71124592",

    [Parameter(Mandatory = $false)]
    [string]$BootstrapContainerName = "sentinelagent-ollama-bootstrap",

    [Parameter(Mandatory = $false)]
    [int]$ReadinessTimeoutSeconds = 45,

    [Parameter(Mandatory = $false)]
    [switch]$ForceOverwrite
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param ([string]$Message)
    Write-Host "`n[STEP] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param ([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-WarnMsg {
    param ([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Find-DockerCli {
    $dockerCmd = Get-Command "docker" -ErrorAction SilentlyContinue
    if ($dockerCmd) {
        return $dockerCmd.Source
    }

    $candidates = @(
        "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin\docker.exe",
        "$env:ProgramFiles\Docker\Docker\resources\bin\docker.exe",
        "$env:ProgramFiles\Docker\Docker\docker.exe"
    )

    foreach ($path in $candidates) {
        if (Test-Path $path) {
            return $path
        }
    }

    throw "Docker executable could not be located in PATH or standard installation directories."
}

# -----------------------------------------------------------------------------
# 1. Verify Docker Engine Availability
# -----------------------------------------------------------------------------
Write-Step "1/10: Verifying Docker Engine connectivity..."
$dockerBin = Find-DockerCli
Write-Host "Using Docker CLI binary: $dockerBin"

# Ensure Docker Desktop helper binaries (e.g. docker-credential-desktop) are resolvable in PATH
$dockerBinDir = Split-Path -Parent $dockerBin
$env:PATH = "$dockerBinDir;$env:PATH"

$dockerPing = & $dockerBin info 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Docker daemon is unreachable. Please ensure Docker Desktop is running. Output: $dockerPing"
}
Write-Success "Docker Engine is active and responding."

# -----------------------------------------------------------------------------
# 2. Verify Pinned Ollama Image Exists Locally
# -----------------------------------------------------------------------------
Write-Step "2/10: Verifying local availability of pinned Ollama image..."
Write-Host "Target Image: $PinnedImage"

$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
$null = & $dockerBin image inspect $PinnedImage 2>$null
$imageMissing = ($LASTEXITCODE -ne 0)
$ErrorActionPreference = $prevEAP

if ($imageMissing) {
    Write-WarnMsg "Pinned Ollama image is not cached locally. Pulling pinned digest from Docker Hub..."
    & $dockerBin pull --platform=linux/amd64 $PinnedImage
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to pull pinned image '$PinnedImage'."
    }
    Write-Success "Pinned image pulled successfully."
} else {
    Write-Success "Pinned image is verified present in local Docker cache."
}

# -----------------------------------------------------------------------------
# 3 & 4. Inspect Dedicated Model Volume and Create Only When Appropriate
# -----------------------------------------------------------------------------
Write-Step "3/10: Inspecting dedicated model volume '$VolumeName'..."
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
$null = & $dockerBin volume inspect $VolumeName 2>$null
$volumeExisted = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = $prevEAP

if ($volumeExisted) {
    Write-Host "Volume '$VolumeName' already exists. Will inspect and cryptographically verify all model blobs."
    if ($ForceOverwrite) {
        Write-WarnMsg "-ForceOverwrite specified. Existing model files will be refreshed."
    }
} else {
    Write-Step "4/10: Creating dedicated model volume '$VolumeName'..."
    & $dockerBin volume create $VolumeName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create Docker volume '$VolumeName'."
    }
    Write-Success "Dedicated volume '$VolumeName' created."
}

# -----------------------------------------------------------------------------
# 5, 6, 7, 8. Launch Ephemeral Bootstrap Server Container
# -----------------------------------------------------------------------------
Write-Step "5/10: Launching temporary bootstrap container '$BootstrapContainerName'..."
Write-Host "Mounting exclusively: $VolumeName -> /root/.ollama"
Write-Host "Network: default bridge (outbound access enabled for pull; zero published ports)"

# Ensure no orphaned container with the same name exists
& $dockerBin rm -f $BootstrapContainerName 2>$null | Out-Null

$containerCreated = $false
try {
    # Run Ollama in server mode (default CMD 'serve' under entrypoint '/bin/ollama')
    $containerId = & $dockerBin run -d `
        --platform=linux/amd64 `
        --name $BootstrapContainerName `
        -v "${VolumeName}:/root/.ollama" `
        -e OLLAMA_HOST=0.0.0.0:11434 `
        -e OLLAMA_NOPRUNE=true `
        $PinnedImage

    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerId)) {
        throw "Failed to launch bootstrap container '$BootstrapContainerName'."
    }
    $containerCreated = $true
    Write-Success "Bootstrap container started (ID: $($containerId.Substring(0, 12)))."

    # -------------------------------------------------------------------------
    # 9. Wait for Ollama Server Readiness
    # -------------------------------------------------------------------------
    Write-Step "6/10: Waiting for bootstrap Ollama daemon readiness (timeout: ${ReadinessTimeoutSeconds}s)..."
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $isReady = $false

    while ($timer.Elapsed.TotalSeconds -lt $ReadinessTimeoutSeconds) {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
        $null = & $dockerBin exec $BootstrapContainerName /bin/ollama list 2>$null
        $probeExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEAP
        if ($probeExit -eq 0) {
            $isReady = $true
            break
        }
        Start-Sleep -Seconds 2
    }

    if (-not $isReady) {
        $logs = & $dockerBin logs --tail 25 $BootstrapContainerName 2>&1
        throw "Ollama daemon failed to achieve readiness within ${ReadinessTimeoutSeconds} seconds. Logs:`n$logs"
    }
    Write-Success "Ollama daemon is active and responding on internal loopback in $($timer.Elapsed.TotalSeconds.ToString('F1'))s."

    # -------------------------------------------------------------------------
    # 10. Execute Model Pull via docker exec
    # -------------------------------------------------------------------------
    Write-Step "7/10: Executing 'ollama pull $ModelTag' inside bootstrap container..."
    Write-Host "Downloading weights and layers into volume '$VolumeName'..."

    & $dockerBin exec $BootstrapContainerName /bin/ollama pull $ModelTag
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to pull model '$ModelTag' via bootstrap container."
    }
    Write-Success "Model '$ModelTag' successfully acquired."

    # -------------------------------------------------------------------------
    # 11 & 12. Verify Model & Cryptographically Validate All Manifest Blobs
    # -------------------------------------------------------------------------
    Write-Step "8/10: Cryptographically verifying model manifest and SHA-256 blob descriptors..."

    Write-Host "`n--- Ollama Model Details ---"
    & $dockerBin exec $BootstrapContainerName /bin/ollama show $ModelTag

    # Resolve manifest path inside container
    $tagParts = $ModelTag -split ":"
    $modelBase = $tagParts[0]
    $tagSub = if ($tagParts.Length -gt 1) { $tagParts[1] } else { "latest" }

    $manifestPathCandidates = @(
        "/root/.ollama/models/manifests/registry.ollama.ai/library/$modelBase/$tagSub",
        "/root/.ollama/models/manifests/registry.ollama.ai/library/$modelBase/latest",
        "/root/.ollama/models/manifests/registry.ollama.ai/library/$modelBase/4b"
    )

    $manifestContent = $null
    $resolvedManifestPath = $null
    foreach ($cand in $manifestPathCandidates) {
        $raw = & $dockerBin exec $BootstrapContainerName cat $cand 2>$null
        if ($LASTEXITCODE -eq 0 -and (-not [string]::IsNullOrWhiteSpace($raw))) {
            $manifestContent = $raw -join "`n"
            $resolvedManifestPath = $cand
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace($manifestContent)) {
        throw "Failed to locate model manifest for '$ModelTag' in container."
    }

    Write-Host "Resolved Manifest: $resolvedManifestPath"
    $manifestObj = $manifestContent | ConvertFrom-Json

    $descriptors = @()
    if ($manifestObj.config -and $manifestObj.config.digest) {
        $descriptors += [PSCustomObject]@{
            Role = "config"
            Digest = $manifestObj.config.digest
            Size = $manifestObj.config.size
        }
    }
    if ($manifestObj.layers) {
        foreach ($layer in $manifestObj.layers) {
            $descriptors += [PSCustomObject]@{
                Role = "layer"
                Digest = $layer.digest
                Size = $layer.size
            }
        }
    }

    if ($descriptors.Count -eq 0) {
        throw "Model manifest contains zero valid descriptors for verification."
    }

    Write-Host "Verifying $($descriptors.Count) model descriptors against disk blobs..."

    foreach ($desc in $descriptors) {
        $expectedDigest = [string]$desc.Digest
        if ($expectedDigest -notmatch "^sha256:([a-f0-9]{64})$") {
            throw "Descriptor has invalid digest format: '$expectedDigest'"
        }
        $expectedHash = $Matches[1]

        # Ollama stores blobs replacing ':' with '-'
        $blobFileName = "sha256-$expectedHash"
        $blobContainerPath = "/root/.ollama/models/blobs/$blobFileName"

        # 1. Verify file exists
        & $dockerBin exec $BootstrapContainerName test -f $blobContainerPath
        if ($LASTEXITCODE -ne 0) {
            throw "Descriptor blob file '$blobFileName' is MISSING in volume '$VolumeName'!"
        }

        # 2. Calculate actual SHA-256 hash using sha256sum
        $hashOutput = & $dockerBin exec $BootstrapContainerName sha256sum $blobContainerPath
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($hashOutput)) {
            throw "Failed to compute sha256sum for '$blobContainerPath'!"
        }

        $calcTokens = ($hashOutput.Trim() -split "\s+")
        $calculatedHash = $calcTokens[0].ToLowerInvariant()

        # 3. Compare calculated hash with descriptor digest
        if ($calculatedHash -ne $expectedHash.ToLowerInvariant()) {
            throw "SHA-256 mismatch for blob '$blobFileName'! Expected: $expectedHash, Calculated: $calculatedHash"
        }

        Write-Host "  [VERIFIED] $($desc.Role.ToUpper()) Blob $blobFileName ($($desc.Size) bytes)" -ForegroundColor Green
    }

    Write-Success "All $($descriptors.Count) model blob descriptors cryptographically verified against disk contents."

} catch {
    Write-Host "`n[FATAL ERROR] Model bootstrap and verification failed: $_" -ForegroundColor Red
    Write-WarnMsg "Persistent volume '$VolumeName' may contain partial, unverified, or corrupted model data."
    Write-WarnMsg "EVIDENCE PRESERVATION: The volume has NOT been automatically deleted to allow inspection."
    Write-WarnMsg "RUNTIME PERMISSION DENIED: The deployment is NOT ready. Do NOT start 'sentinelagent-ollama' with this unverified volume."
    throw $_
} finally {
    # -------------------------------------------------------------------------
    # 13 & 14. Stop and Remove Temporary Bootstrap Container
    # -------------------------------------------------------------------------
    if ($containerCreated) {
        Write-Step "9/10: Cleaning up temporary bootstrap container '$BootstrapContainerName'..."
        & $dockerBin stop $BootstrapContainerName 2>$null | Out-Null
        & $dockerBin rm $BootstrapContainerName 2>$null | Out-Null
        Write-Success "Bootstrap container stopped and removed."
    }
}

Write-Step "10/10: Pre-deployment model bootstrap complete!"
Write-Host "Volume '$VolumeName' preloading complete. Model verified for isolated Option B runtime attachment." -ForegroundColor Green

