<#
.SYNOPSIS
  Replace the public Wazuh lab defaults with generated passwords (PowerShell twin of rotate-passwords.sh).

.DESCRIPTION
  Rotates the indexer `admin` and `kibanaserver` users and the `wazuh-wui` API user.
  Writes (all git-ignored):
    stack/secrets/internal_users.yml  indexer users, bcrypt-hashed by the indexer's own hash.sh
    stack/secrets/wazuh.yml           dashboard -> Wazuh API connection
    .env                              the three passwords + the paths of the two files above
  The committed files under stack/config/ keep the documented upstream defaults.
  Procedure: SECURITY.md.

.EXAMPLE
  .\scripts\rotate-passwords.ps1           # fresh lab (no containers yet)
  .\scripts\rotate-passwords.ps1 -Apply    # running lab: also push the new passwords to it
#>
[CmdletBinding()]
param([switch]$Apply)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

$Secrets = 'stack/secrets'
$IndexerTools = '/usr/share/wazuh-indexer/plugins/opensearch-security/tools'
$IndexerCerts = '/usr/share/wazuh-indexer/config/certs'
$JavaHomeInImage = '/usr/share/wazuh-indexer/jdk'
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false

function Write-LfFile([string]$Path, [string[]]$Lines) {
    # LF endings, no BOM: these files are read by Linux containers and by compose.
    $full = Join-Path (Get-Location) $Path
    [System.IO.File]::WriteAllText($full, (($Lines -join "`n") + "`n"), $Utf8NoBom)
}

function Invoke-Native([scriptblock]$Command) {
    # docker writes progress to stderr; Windows PowerShell would turn that into errors
    # when output is redirected. Judge native commands by their exit code only.
    $ErrorActionPreference = 'Continue'
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "command failed (exit $LASTEXITCODE): $Command" }
}

function New-LabPassword {
    # 30 random alphanumerics as xxxxxxxxxx.xxxxxxxxxx-xxxxxxxxxx (~178 bits), same format as the .sh.
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] 1
    while ($true) {
        $chars = New-Object System.Text.StringBuilder
        while ($chars.Length -lt 30) {
            $rng.GetBytes($buf)
            if ($buf[0] -lt 248) { [void]$chars.Append($alphabet[$buf[0] % 62]) }   # 248 = 4 * 62: no modulo bias
        }
        $s = $chars.ToString()
        $p = '{0}.{1}-{2}' -f $s.Substring(0, 10), $s.Substring(10, 10), $s.Substring(20, 10)
        if ($p -cmatch '[A-Z]' -and $p -cmatch '[a-z]' -and $p -match '[0-9]') { return $p }
    }
}

function Get-IndexerHash([string]$Password, [string]$Image) {
    # The password reaches the container through the environment, never a command line.
    $env:PW = $Password
    $ErrorActionPreference = 'Continue'   # see Invoke-Native
    try {
        $out = & docker run --rm -e PW -e "OPENSEARCH_JAVA_HOME=$JavaHomeInImage" `
            --entrypoint bash $Image "$IndexerTools/hash.sh" -env PW
        if ($LASTEXITCODE -ne 0) { throw "hash.sh failed (exit $LASTEXITCODE)" }
    } finally {
        Remove-Item Env:PW -ErrorAction SilentlyContinue
    }
    $hash = (@($out) | Select-Object -Last 1).Trim()
    if ($hash -notmatch '^\$2[aby]\$') { throw 'hash.sh did not return a bcrypt hash' }
    return $hash
}

function Set-EnvValue([string[]]$Lines, [string]$Key, [string]$Value) {
    # Replace KEY=... (keeping its position) or append it.
    $found = $false
    $result = foreach ($line in $Lines) {
        if ($line.StartsWith("$Key=")) { "$Key=$Value"; $found = $true } else { $line }
    }
    if (-not $found) { $result = @($result) + "$Key=$Value" }
    return , @($result)
}

if (-not (Test-Path .env)) { Copy-Item .env.example .env }
$envLines = @(Get-Content .env -Encoding UTF8)
$version = ($envLines | Where-Object { $_ -match '^WAZUH_VERSION=' } | Select-Object -Last 1) -replace '^WAZUH_VERSION=', ''
if (-not $version) { $version = '4.14.9' }
$indexerImage = "wazuh/wazuh-indexer:$version"

if (-not $Apply) {
    # Windows PowerShell turns redirected native stderr into errors: relax for this probe only.
    $ErrorActionPreference = 'Continue'
    $running = & docker compose ps -q wazuh.indexer 2>$null
    $ErrorActionPreference = 'Stop'
    if ($running) { throw "The lab is running. Use -Apply to rotate it in place, or '.\scripts\lab.ps1 reset' first." }
}

Write-Host "Generating passwords and hashing them with $indexerImage ..."
$indexerPassword = New-LabPassword
$dashboardPassword = New-LabPassword
$apiPassword = New-LabPassword
$adminHash = Get-IndexerHash $indexerPassword $indexerImage
$dashboardHash = Get-IndexerHash $dashboardPassword $indexerImage

New-Item -ItemType Directory -Force $Secrets | Out-Null
# Only the two users the lab needs. The upstream demo users (kibanaro, logstash,
# readall, snapshotrestore) have public passwords and are left out on purpose.
Write-LfFile "$Secrets/internal_users.yml" @(
    '---'
    '# Generated by scripts/rotate-passwords.ps1. Git-ignored: never commit.'
    '_meta:'
    '  type: "internalusers"'
    '  config_version: 2'
    ''
    'admin:'
    ('  hash: "{0}"' -f $adminHash)
    '  reserved: true'
    '  backend_roles:'
    '  - "admin"'
    '  description: "Lab admin user"'
    ''
    'kibanaserver:'
    ('  hash: "{0}"' -f $dashboardHash)
    '  reserved: true'
    '  description: "Wazuh dashboard server user"'
)
Write-LfFile "$Secrets/wazuh.yml" @(
    '# Generated by scripts/rotate-passwords.ps1. Git-ignored: never commit.'
    'hosts:'
    '  - 1513629884013:'
    '      url: "https://wazuh.manager"'
    '      port: 55000'
    '      username: wazuh-wui'
    ('      password: "{0}"' -f $apiPassword)
    '      run_as: true'
)

$envLines = Set-EnvValue $envLines 'INDEXER_PASSWORD' $indexerPassword
$envLines = Set-EnvValue $envLines 'DASHBOARD_PASSWORD' $dashboardPassword
$envLines = Set-EnvValue $envLines 'API_PASSWORD' $apiPassword
$envLines = Set-EnvValue $envLines 'INDEXER_USERS_FILE' "./$Secrets/internal_users.yml"
$envLines = Set-EnvValue $envLines 'DASHBOARD_API_CONFIG' "./$Secrets/wazuh.yml"
Write-LfFile '.env' $envLines

Write-Host "Wrote $Secrets/internal_users.yml, $Secrets/wazuh.yml and .env"

if ($Apply) {
    # The indexer reads internal_users.yml only when its security index is first created;
    # on a running lab the new users are loaded with securityadmin (admin client certificate).
    Write-Host 'Recreating the indexer with the new users file ...'
    # --force-recreate: on a second rotation the mounted path is unchanged, so compose would not
    Invoke-Native { docker compose up -d --force-recreate --wait wazuh.indexer }
    Invoke-Native {
        docker compose exec -T -e "JAVA_HOME=$JavaHomeInImage" wazuh.indexer bash `
            "$IndexerTools/securityadmin.sh" -t internalusers `
            -f /usr/share/wazuh-indexer/config/opensearch-security/internal_users.yml `
            -cacert "$IndexerCerts/root-ca.pem" -cert "$IndexerCerts/admin.pem" -key "$IndexerCerts/admin-key.pem" `
            -h localhost -icl -nhnv
    }
    # The manager re-applies API_PASSWORD (wazuh-wui) and the Filebeat password at every
    # start; the dashboard rebuilds its keystore. Recreating them picks up the new .env.
    Write-Host 'Recreating the manager and the dashboard ...'
    Invoke-Native { docker compose up -d --wait }
    Write-Host 'Done. Check with: python scripts/lab_status.py'
} else {
    Write-Host 'Next: .\scripts\lab.ps1 up'
}
Write-Host 'Dashboard login: admin / the INDEXER_PASSWORD value in .env'
