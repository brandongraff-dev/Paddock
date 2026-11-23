# Paddock one-line installer for Windows (single-node "lite" stack).
# Mirrors scripts/install.sh. Needs Docker Desktop; nothing else (no make, no git).
#
#   irm https://raw.githubusercontent.com/brandongraff-dev/paddock/main/scripts/install.ps1 | iex
#
# With options (a piped script cannot take parameters, so wrap it):
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/brandongraff-dev/paddock/main/scripts/install.ps1))) -Dir D:\paddock -Active
#
# Or from a clone:   powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -DryRun
#
# What it does: checks Docker Desktop (and starts it if it is installed but off),
# downloads Paddock, generates strong secrets into .env (never overwriting ones
# you already have), starts the lite stack, waits until it is healthy and prints
# the URL and the admin credentials. Safe to re-run: existing .env values,
# containers and data are kept.
#
# Prebuilt vs from source: the copy attached to a GitHub release is stamped with
# its version and pulls the signed, prebuilt images from GHCR (1-2 minutes).
# A copy taken from a branch has no version and builds from source (15+
# minutes), unless you pass -Version. Get the release copy with:
#   irm https://github.com/brandongraff-dev/paddock/releases/latest/download/install.ps1 | iex
# or download the release zip and double-click install.bat.
#
# Options:
#   -Dir DIR        install directory            (default: %USERPROFILE%\paddock, or $env:PADDOCK_HOME)
#   -Version X.Y.Z  release to install (prebuilt images; default: the version this
#                   script was stamped with, else the one in .env, else build from source)
#   -Ref REF        git branch or tag to install (default: v<version>, else main, or $env:PADDOCK_REF)
#   -Repo OWNER/R   GitHub repository            (default: brandongraff-dev/paddock, or $env:PADDOCK_REPO)
#   -Active         also start the active worker (polite HTTP/TLS/port probing)
#   -Upgrade        re-download the sources even if the directory already has them
#   -NoStart        prepare files and secrets, do not start containers
#   -Wait SECONDS   how long to wait for health (default 300)
#   -DryRun         print what would happen; change nothing, no network
#   -Uninstall      stop and remove the containers (data volume and .env are kept)
#   -Purge          with -Uninstall: also delete the data volume and the install directory
#   -Yes            do not ask for confirmation (required for -Purge without a terminal)
#
# Environment for testing / air-gapped use: PADDOCK_SRC_DIR (copy sources from a
# local directory instead of downloading), PADDOCK_API_URL, PADDOCK_UI_URL,
# PADDOCK_SHA256 (pin the downloaded archive), PADDOCK_VERSION (= -Version),
# PADDOCK_REGISTRY (image registry/namespace, default ghcr.io/brandongraff-dev).
# When this script sits next to docker-compose.lite.yml (the release zip), those
# files are used instead of downloading anything.
#
# Keep this file ASCII-only: Windows PowerShell 5.1 reads BOM-less files as ANSI.
[CmdletBinding()]
param(
    [string]$Dir      = $(if ($env:PADDOCK_HOME) { $env:PADDOCK_HOME } else { Join-Path $env:USERPROFILE 'paddock' }),
    [string]$Ref      = $(if ($env:PADDOCK_REF)  { $env:PADDOCK_REF }  else { '' }),
    [string]$Version  = $(if ($env:PADDOCK_VERSION) { $env:PADDOCK_VERSION } else { '' }),
    [string]$Repo     = $(if ($env:PADDOCK_REPO) { $env:PADDOCK_REPO } else { 'brandongraff-dev/paddock' }),
    [int]$Wait        = 300,
    [switch]$Active,
    [switch]$Upgrade,
    [switch]$NoStart,
    [switch]$DryRun,
    [switch]$Uninstall,
    [switch]$Purge,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # Invoke-WebRequest is very slow with the progress bar
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# Stamped with the release version by scripts/make_release_bundle.py. Empty in a
# checkout: then the stack is built from source.
$StampedVersion = ''

$Registry     = if ($env:PADDOCK_REGISTRY) { $env:PADDOCK_REGISTRY } else { 'ghcr.io/brandongraff-dev' }
$ApiUrl       = if ($env:PADDOCK_API_URL) { $env:PADDOCK_API_URL } else { 'http://127.0.0.1:8080' }
$UiUrl        = if ($env:PADDOCK_UI_URL)  { $env:PADDOCK_UI_URL }  else { 'http://localhost:3000' }
$ComposeFile  = 'docker-compose.lite.yml'
$OverrideFile = 'docker-compose.install.yml'
$Project      = 'paddock-lite'

function Say($m)  { Write-Host $m }
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "warning: $m" -ForegroundColor Yellow }
function Plan($m) { Write-Host "[dry-run] $m" }
function Die($m)  { Write-Host "error: $m" -ForegroundColor Red; throw "paddock-install: $m" }

# ---------------------------------------------------------------------------
# argument checks
# ---------------------------------------------------------------------------
if ($Repo -notmatch '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$') { Die '-Repo must look like OWNER/NAME' }
if ($Ref  -ne '' -and $Ref -notmatch '^[A-Za-z0-9._/-]+$') { Die '-Ref contains unexpected characters' }
if ($Version -ne '' -and $Version -notmatch '^[A-Za-z0-9._-]+$') { Die '-Version contains unexpected characters' }
if ($Purge -and -not $Uninstall)                           { Die '-Purge only makes sense with -Uninstall' }

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
# Run a native command without PowerShell turning its stderr into an error.
# Returns the exit code; output is optionally captured into $script:Out.
function Native([scriptblock]$Cmd, [switch]$Quiet) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        # Out-Host keeps the command's output on screen and OUT of this function's
        # return value, which must be the exit code and nothing else.
        if ($Quiet) { $script:Out = & $Cmd 2>&1 | Out-String } else { & $Cmd | Out-Host }
        return $LASTEXITCODE
    } finally { $ErrorActionPreference = $prev }
}

function Test-Cmd($name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# Random alphanumeric string (safe in URLs, shells and compose files).
function New-Pw([int]$len = 24) {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
    $bytes = New-Object byte[] ($len * 2)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $sb = New-Object Text.StringBuilder
    foreach ($b in $bytes) {
        if ($b -lt 248) { [void]$sb.Append($chars[$b % 62]) }   # 248 = 62*4, no modulo bias
        if ($sb.Length -ge $len) { break }
    }
    while ($sb.Length -lt $len) { [void]$sb.Append($chars[(Get-Random -Maximum 62)]) }
    return $sb.ToString()
}

# 32 random bytes as urlsafe base64 (the format PADDOCK_SECRET_KEY expects).
function New-Key {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ([Convert]::ToBase64String($bytes)).Replace('+', '-').Replace('/', '_')
}

$Utf8NoBom = New-Object Text.UTF8Encoding($false)
$EnvPath   = Join-Path $Dir '.env'

# .env is read by Docker Compose: UTF-8 without BOM, LF endings.
function Read-EnvLines { if (Test-Path $EnvPath) { return [IO.File]::ReadAllText($EnvPath) -split "`r?`n" } else { return @() } }
function Write-EnvLines($lines) {
    $text = (($lines | Where-Object { $_ -ne $null }) -join "`n").TrimEnd("`n") + "`n"
    [IO.File]::WriteAllText($EnvPath, $text, $Utf8NoBom)
}
function Get-EnvValue($key) {
    $v = ''
    foreach ($l in (Read-EnvLines)) { if ($l -match ('^' + [regex]::Escape($key) + '=(.*)$')) { $v = $Matches[1] } }
    return $v
}

# Set KEY only when it is missing, empty or still the placeholder from
# .env.example. An existing real value is never touched.
function Ensure-Env($key, [scriptblock]$gen) {
    $cur = Get-EnvValue $key
    if ($cur -eq '' -or $cur -like 'change-me*') {
        $val = & $gen
        $lines = @(Read-EnvLines)
        $found = $false
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match ('^' + [regex]::Escape($key) + '=')) { $lines[$i] = "$key=$val"; $found = $true }
        }
        if (-not $found) { $lines += "$key=$val" }
        Write-EnvLines $lines
        Say "   generated $key"
    } else {
        Say "   kept existing $key"
    }
}

# Set KEY unconditionally (for non-secret settings such as the version).
function Set-EnvValue($key, $val) {
    $lines = @(Read-EnvLines)
    $found = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match ('^' + [regex]::Escape($key) + '=')) { $lines[$i] = "$key=$val"; $found = $true }
    }
    if (-not $found) { $lines += "$key=$val" }
    Write-EnvLines $lines
}

# Version to install: -Version / $env:PADDOCK_VERSION > stamped into this script >
# already recorded in .env > none (build from source). A leading "v" is dropped
# (image tags are 1.2.3, git tags are v1.2.3).
function Resolve-Version {
    if (-not $script:Version) { $script:Version = $StampedVersion }
    if (-not $script:Version) { $script:Version = Get-EnvValue 'PADDOCK_VERSION' }
    $script:Version = ([string]$script:Version).TrimStart('v')
    if ($script:Version -eq 'dev') { $script:Version = '' }     # "dev" is the from-source tag
    if (-not $script:Ref) { $script:Ref = if ($script:Version) { "v$($script:Version)" } else { 'main' } }
}

# Folder holding a release zip's files (compose file next to this script), or $null.
function Get-BundleDir {
    if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot $ComposeFile))) { return $PSScriptRoot }
    return $null
}

# Copy a folder's contents including dotfiles (.env.example), which '*' skips on some PowerShell versions.
function Copy-Tree($from, $to) {
    New-Item -ItemType Directory -Force -Path $to | Out-Null
    Copy-Item -Path (Join-Path $from '*') -Destination $to -Recurse -Force
    Get-ChildItem -Path $from -Force -File -Filter '.*' | ForEach-Object { Copy-Item -Path $_.FullName -Destination $to -Force }
}

function Compose {
    $a = @('compose', '-p', $Project, '--project-directory', $Dir, '-f', (Join-Path $Dir $ComposeFile), '-f', (Join-Path $Dir $OverrideFile))
    if ($Active) { $a += @('--profile', 'active') }
    $a += $args
    return (Native { docker @a })
}

function Test-Install { return (Test-Path (Join-Path $Dir $ComposeFile)) }

function Test-Port([int]$port) {
    try {
        $c = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction Stop
        return [bool]$c
    } catch { return $false }
}

function Find-DockerDesktop {
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, "$env:LOCALAPPDATA\Programs")) {
        if (-not $base) { continue }
        $p = Join-Path $base 'Docker\Docker\Docker Desktop.exe'
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Test-Engine { return ((Native { docker info } -Quiet) -eq 0) }

function Check-Docker {
    if (-not (Test-Cmd 'docker')) {
        Say ''
        Say 'Docker is not installed. Paddock runs in Docker Desktop:'
        Say '   1. Install it from https://www.docker.com/products/docker-desktop/ (choose the WSL 2 backend)'
        Say '   2. Reboot if the installer asks, start Docker Desktop, wait for "Engine running"'
        Say '   3. Run this installer again'
        Die 'Docker is not installed.'
    }
    if ((Native { docker compose version } -Quiet) -ne 0) {
        Die "'docker compose' (Compose v2) is required. Update Docker Desktop: https://docs.docker.com/compose/install/"
    }
    if (-not (Test-Engine)) {
        $exe = Find-DockerDesktop
        if ($exe) {
            Say '   Docker Desktop is installed but its engine is not running; starting it ...'
            Start-Process -FilePath $exe | Out-Null
            $deadline = (Get-Date).AddSeconds(180)
            while ((Get-Date) -lt $deadline) {
                Start-Sleep -Seconds 5
                if (Test-Engine) { break }
            }
        }
        if (-not (Test-Engine)) {
            Say ''
            Say 'The Docker engine is not reachable. Common fixes:'
            Say '   - Open Docker Desktop and wait for "Engine running" (first start takes a few minutes)'
            Say '   - Run "wsl --update" in an admin PowerShell, then restart Docker Desktop'
            Say '   - Check that virtualization is enabled (Task Manager > Performance > CPU)'
            Say '   - If it still fails: Docker Desktop > Troubleshoot > Restart, or reboot Windows'
            Die 'cannot talk to the Docker engine.'
        }
    }
    $ver = ''
    if ((Native { docker version --format '{{.Server.Version}}' } -Quiet) -eq 0) { $ver = $script:Out.Trim() }
    Say "   docker $ver, compose ok"
    if ((Native { docker info --format '{{.OSType}}' } -Quiet) -eq 0 -and $script:Out.Trim() -ne 'linux') {
        Die 'Docker is in Windows-containers mode. Right-click the Docker tray icon and choose "Switch to Linux containers".'
    }
}

function Fetch-Sources {
    $src = if ($env:PADDOCK_SRC_DIR) { $env:PADDOCK_SRC_DIR } else { Get-BundleDir }
    if ($src) {
        if (-not (Test-Path (Join-Path $src $ComposeFile))) { Die "PADDOCK_SRC_DIR has no $ComposeFile" }
        New-Item -ItemType Directory -Force -Path $Dir | Out-Null
        if ([IO.Path]::GetFullPath($src).TrimEnd('\') -ne [IO.Path]::GetFullPath($Dir).TrimEnd('\')) { Copy-Tree $src $Dir }
        # a release zip keeps the installers at its top level; keep them under scripts\ like a checkout
        if (Test-Path (Join-Path $Dir 'install.ps1')) {
            New-Item -ItemType Directory -Force -Path (Join-Path $Dir 'scripts') | Out-Null
            foreach ($f in 'install.ps1', 'install.sh', 'install.bat') {
                $from = Join-Path $Dir $f
                if (Test-Path $from) { Move-Item -Force -Path $from -Destination (Join-Path (Join-Path $Dir 'scripts') $f) }
            }
        }
        return
    }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('paddock-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        $url = "https://codeload.github.com/$Repo/zip/$Ref"
        $zip = Join-Path $tmp 'src.zip'
        Say "   downloading $url"
        try { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip } catch { Die "download failed: $url ($($_.Exception.Message))" }
        if ($env:PADDOCK_SHA256) {
            $got = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLower()
            if ($got -ne $env:PADDOCK_SHA256.ToLower()) { Die "checksum mismatch (expected $($env:PADDOCK_SHA256), got $got)" }
        }
        $x = Join-Path $tmp 'x'
        Expand-Archive -Path $zip -DestinationPath $x -Force
        $root = Get-ChildItem -Path $x -Directory | Select-Object -First 1
        if (-not $root -or -not (Test-Path (Join-Path $root.FullName $ComposeFile))) {
            Die "the download does not contain $ComposeFile (wrong -Repo/-Ref?)"
        }
        Copy-Tree $root.FullName $Dir
    } finally {
        Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
    }
}

function Write-Override {
    # Wires the secrets the lite compose file does not pass through by itself.
    $yaml = @'
# Written by scripts/install.ps1. Passes the generated secrets (and the release
# version, shown on Settings > System) to the orchestrator.
services:
  orchestrator:
    environment:
      JWT_SECRET: ${JWT_SECRET:?run scripts/install.sh to generate secrets}
      PADDOCK_SECRET_KEY: ${PADDOCK_SECRET_KEY:?run scripts/install.sh to generate secrets}
      AUDIT_HMAC_KEY: ${AUDIT_HMAC_KEY:?run scripts/install.sh to generate secrets}
      PADDOCK_VERSION: ${PADDOCK_VERSION:-}
'@
    [IO.File]::WriteAllText((Join-Path $Dir $OverrideFile), ($yaml -replace "`r`n", "`n") + "`n", $Utf8NoBom)
}

function Wait-Healthy {
    Step "waiting for Paddock to become healthy (up to ${Wait}s)"
    $i = 0
    while ($i -lt $Wait) {
        try {
            $r1 = Invoke-WebRequest -UseBasicParsing -Uri "$ApiUrl/healthz" -TimeoutSec 3
            $r2 = Invoke-WebRequest -UseBasicParsing -Uri "$UiUrl/" -TimeoutSec 3
            if ($r1.StatusCode -lt 400 -and $r2.StatusCode -lt 400) { Say "   healthy after ${i}s"; return $true }
        } catch { }
        Start-Sleep -Seconds 3
        $i += 3
    }
    Warn "not healthy after ${Wait}s. Inspect with: docker compose -p $Project -f `"$Dir\$ComposeFile`" logs --tail=100"
    return $false
}

# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------
if ($Uninstall) {
    Step "uninstalling Paddock from $Dir"
    if ($DryRun) {
        if ($Purge) {
            Plan "docker compose -p $Project down -v (deletes the database volume)"
            Plan "Remove-Item -Recurse $Dir (after confirmation)"
        } else {
            Plan "docker compose -p $Project down (keeps the data volume and $Dir\.env)"
        }
        return
    }
    if (-not (Test-Install)) { Die "$Dir does not look like a Paddock install (no $ComposeFile); nothing done" }
    if (-not (Test-Cmd 'docker')) { Die 'docker not found' }
    if (-not (Test-Path (Join-Path $Dir $OverrideFile))) { Write-Override }
    if (-not (Test-Path $EnvPath)) {   # compose still interpolates required vars on `down`
        foreach ($k in 'POSTGRES_PASSWORD', 'JWT_SECRET', 'PADDOCK_SECRET_KEY', 'AUDIT_HMAC_KEY') { Set-Item -Path "Env:$k" -Value 'unused' }
    }
    if ($Purge) {
        if (-not $Yes) {
            if (-not [Environment]::UserInteractive) { Die '-Purge deletes ALL Paddock data; re-run with -Yes to confirm' }
            $ans = Read-Host "This permanently deletes the Paddock database volume and $Dir. Type 'delete' to continue"
            if ($ans -ne 'delete') { Die 'aborted' }
        }
        [void](Compose down -v --remove-orphans)
        $full = [IO.Path]::GetFullPath($Dir).TrimEnd('\')
        if ($full -eq [IO.Path]::GetPathRoot($full).TrimEnd('\') -or $full -eq $env:USERPROFILE.TrimEnd('\')) { Die "refusing to delete '$Dir'" }
        Remove-Item -Recurse -Force -Path $Dir
        Say "removed containers, data volume and $Dir"
    } else {
        [void](Compose down --remove-orphans)
        Say "stopped. Data volume and $Dir\.env are kept; re-run the installer to start again."
    }
    return
}

# ---------------------------------------------------------------------------
# install / re-run
# ---------------------------------------------------------------------------
Step 'checking prerequisites'
if ($DryRun) {
    Plan "check: docker, 'docker compose' v2, reachable engine (starts Docker Desktop if it is off), Linux-containers mode"
} else {
    Check-Docker
    foreach ($p in 3000, 8080) {
        if (Test-Port $p) { Warn "port $p is already in use; Paddock may fail to start (stop the other program or re-run after freeing it)" }
    }
}

$InstalledVersion = Get-EnvValue 'PADDOCK_VERSION'
Resolve-Version
# New release than the one on disk: the compose file may have changed too.
if ($Version -and $Version -ne $InstalledVersion -and (Test-Install)) { $Upgrade = $true }
$Bundle = Get-BundleDir

Step "installing into $Dir"
if ($Version) { Say "   release $Version (prebuilt images from $Registry)" } else { Say '   no release version: images will be built from source' }
if ($DryRun) {
    if ((Test-Path (Join-Path $Dir $ComposeFile)) -and -not $Upgrade) {
        Plan "sources already present in ${Dir}: keep them (use -Upgrade to refresh)"
    } elseif ($env:PADDOCK_SRC_DIR) {
        Plan "copy sources from $($env:PADDOCK_SRC_DIR) to $Dir"
    } elseif ($Bundle) {
        Plan "copy the release files from $Bundle to $Dir (no download)"
    } else {
        Plan "download https://codeload.github.com/$Repo/zip/$Ref and unpack into $Dir"
    }
    Plan "create $Dir\.env from .env.example if missing"
    foreach ($k in 'POSTGRES_PASSWORD', 'PADDOCK_APP_DB_PASSWORD', 'ADMIN_BOOTSTRAP_PASSWORD', 'SERVICE_API_KEY', 'JWT_SECRET', 'PADDOCK_SECRET_KEY', 'AUDIT_HMAC_KEY') {
        Plan "generate $k only if it is not already set"
    }
    if ($Version) { Plan "set PADDOCK_VERSION=$Version in $Dir\.env" }
    Plan "write $Dir\$OverrideFile (passes JWT_SECRET, PADDOCK_SECRET_KEY, AUDIT_HMAC_KEY, PADDOCK_VERSION to the orchestrator)"
    if ($NoStart) {
        Plan '(-NoStart) stop here'
    } else {
        $prof = if ($Active) { ' --profile active' } else { '' }
        if ($Version) {
            Plan "docker compose -p $Project -f $ComposeFile -f $OverrideFile$prof pull"
            Plan "docker compose -p $Project -f $ComposeFile -f $OverrideFile$prof up -d --no-build"
        } else {
            Plan "docker compose -p $Project -f $ComposeFile -f $OverrideFile$prof up -d --build"
        }
        Plan "wait for $ApiUrl/healthz and $UiUrl/ (up to ${Wait}s)"
        Plan 'print the URL and the admin credentials'
    }
    return
}

if ((Test-Install) -and -not $Upgrade) {
    Say '   sources already present (use -Upgrade to refresh them)'
} else {
    Fetch-Sources
}
if (-not (Test-Install)) { Die "$Dir has no $ComposeFile after install" }

# A database volume without its .env means the old passwords are lost: Postgres
# would keep the old one and the stack could never connect.
if (-not (Test-Path $EnvPath)) {
    if ((Native { docker volume ls -q } -Quiet) -eq 0 -and (($script:Out -split "`r?`n") -contains "${Project}_pg_data")) {
        Die "a Paddock database volume exists but $EnvPath is missing, so its passwords are unknown. Restore the .env, or remove the old data with: install.ps1 -Uninstall -Purge -Dir $Dir"
    }
}

Step 'generating secrets (existing values are never overwritten)'
if (-not (Test-Path $EnvPath)) {
    $example = Join-Path $Dir '.env.example'
    if (Test-Path $example) { Write-EnvLines ([IO.File]::ReadAllText($example) -split "`r?`n") } else { Write-EnvLines @() }
}
Ensure-Env 'POSTGRES_PASSWORD'        { New-Pw }
Ensure-Env 'PADDOCK_APP_DB_PASSWORD'  { New-Pw }
Ensure-Env 'ADMIN_BOOTSTRAP_PASSWORD' { New-Pw }
Ensure-Env 'SERVICE_API_KEY'          { New-Key }
Ensure-Env 'JWT_SECRET'              { New-Key }
Ensure-Env 'PADDOCK_SECRET_KEY'       { New-Key }
Ensure-Env 'AUDIT_HMAC_KEY'           { New-Key }
if ($Version) { Set-EnvValue 'PADDOCK_VERSION' $Version; Say "   PADDOCK_VERSION=$Version" }
Write-Override

if ($NoStart) {
    Say "prepared $Dir (not started). Start with:"
    if ($Version) {
        Say "   cd $Dir; docker compose -p $Project -f $ComposeFile -f $OverrideFile pull; docker compose -p $Project -f $ComposeFile -f $OverrideFile up -d --no-build"
    } else {
        Say "   cd $Dir; docker compose -p $Project -f $ComposeFile -f $OverrideFile up -d --build"
    }
    return
}

if ($Version) {
    Step "downloading the Paddock images (release $Version, about 1-2 minutes)"
    if ((Compose pull) -eq 0) {
        Step 'starting Paddock'
        if ((Compose up -d --no-build) -ne 0) { Die 'docker compose up failed (see the output above)' }
    } elseif (Test-Path (Join-Path $Dir 'orchestrator\Dockerfile')) {
        Warn 'could not download the prebuilt images; building from source instead (15+ minutes)'
        if ((Compose up -d --build) -ne 0) { Die 'docker compose up failed (see the output above)' }
    } else {
        Die "could not download the Paddock images for release $Version from $Registry. Check your internet connection (and any proxy or firewall), then re-run this installer. If the release is brand new, its images may still be publishing: wait a few minutes and try again."
    }
} else {
    Step 'starting Paddock (first run builds the images; this can take several minutes)'
    if ((Compose up -d --build) -ne 0) { Die 'docker compose up failed (see the output above)' }
}

$healthy = Wait-Healthy
$adminPw = Get-EnvValue 'ADMIN_BOOTSTRAP_PASSWORD'
Say ''
if ($healthy) { Write-Host 'Paddock is running.' -ForegroundColor Green } else { Write-Host 'Paddock started but is not healthy yet.' -ForegroundColor Yellow }
Say ''
Say "   URL:       $UiUrl"
Say '   Username:  admin'
Say "   Password:  $adminPw"
Say ''
Say "   The password is stored in $EnvPath (ADMIN_BOOTSTRAP_PASSWORD). After you sign in, the"
Say '   first-run wizard (/setup) walks you through adding a domain and a first scan.'
Say '   Connect your tools:  Integrations > Connect anything  (docs/CONNECT.md)'
Say "   Stop:      powershell -File `"$Dir\scripts\install.ps1`" -Uninstall -Dir `"$Dir`""
if ($Version) {
    Say '   Upgrade:   run the installer from the latest release again:'
    Say "              irm https://github.com/$Repo/releases/latest/download/install.ps1 | iex"
} else {
    Say "   Upgrade:   powershell -File `"$Dir\scripts\install.ps1`" -Upgrade -Dir `"$Dir`""
}
if (-not $healthy) { throw 'paddock-install: not healthy' }
