param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string]$Repository,
    [string]$SecretKeyPath = "$HOME\.quantus-release-signing\quantus-release.key"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$PublicKeyPath = Join-Path $RepoRoot "release-signing-public-key.pub"
$RepositoryPath = Join-Path $RepoRoot "release-update-repository.txt"

$Minisign = Get-Command minisign -ErrorAction SilentlyContinue
if (-not $Minisign) {
    throw "minisign was not found in PATH. Install the official minisign CLI, then run this script again."
}

if (Test-Path -LiteralPath $SecretKeyPath) {
    throw "Refusing to overwrite existing release signing key: $SecretKeyPath"
}

if (Test-Path -LiteralPath $PublicKeyPath) {
    $existing = Get-Content -Raw -LiteralPath $PublicKeyPath
    if ($existing -notmatch 'UNCONFIGURED') {
        throw "release-signing-public-key.pub is already configured. Key rotation must be explicit."
    }
}

$SecretDir = Split-Path -Parent $SecretKeyPath
New-Item -ItemType Directory -Force -Path $SecretDir | Out-Null

$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $SecretDir "/inheritance:r" "/grant:r" "${Identity}:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to harden signing-key directory ACL: $SecretDir" }

$TempPublic = Join-Path $env:TEMP ("quantus-release-" + [Guid]::NewGuid().ToString("N") + ".pub")
try {
    & $Minisign.Source -G -W -p $TempPublic -s $SecretKeyPath
    if ($LASTEXITCODE -ne 0) { throw "minisign key generation failed." }

    & icacls.exe $SecretKeyPath "/inheritance:r" "/grant:r" "${Identity}:F" "SYSTEM:F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to harden signing-key file ACL: $SecretKeyPath" }

    $pub = Get-Content -Raw -LiteralPath $TempPublic
    $keyLine = ($pub -split "`r?`n" |
        Where-Object { $_ -and -not $_.StartsWith("untrusted comment:") } |
        Select-Object -First 1).Trim()

    if ($keyLine -notmatch '^RW[A-Za-z0-9+/=]{50,}$') {
        throw "Generated minisign public key did not have the expected format."
    }

    [System.IO.File]::WriteAllText(
        $PublicKeyPath,
        "untrusted comment: Quantus hardened release signing public key`n$keyLine`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    [System.IO.File]::WriteAllText(
        $RepositoryPath,
        "$Repository`n",
        [System.Text.UTF8Encoding]::new($false)
    )
}
finally {
    Remove-Item -LiteralPath $TempPublic -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Signed-update trust configured." -ForegroundColor Green
Write-Host "Repository : $Repository"
Write-Host "Public key : $PublicKeyPath"
Write-Host "Secret key : $SecretKeyPath"
Write-Host ""
Write-Host "The secret key was NOT printed and was NOT uploaded anywhere." -ForegroundColor Yellow
Write-Host ""
Write-Host "Create a protected GitHub Environment named 'release', require approval,"
Write-Host "then add MINISIGN_SECRET_KEY to that environment."
Write-Host ""
Write-Host "GitHub CLI command:"
Write-Host "  Get-Content -Raw `"$SecretKeyPath`" | gh secret set MINISIGN_SECRET_KEY --env release --repo $Repository"
