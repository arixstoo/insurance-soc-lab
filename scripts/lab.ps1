<#
.SYNOPSIS
  Lab commands for Windows PowerShell - same verbs as the Makefile.

.EXAMPLE
  .\scripts\lab.ps1 up             # certs + passwords if missing, build, start, wait until healthy, retention
  .\scripts\lab.ps1 status
  .\scripts\lab.ps1 rotate -Apply  # new passwords on a running lab
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'certs', 'rotate', 'up', 'down', 'reset', 'status', 'test', 'lint')]
    [string]$Verb = 'help',
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:MSYS_NO_PATHCONV = '1'

function Invoke-Native([scriptblock]$Command) {
    # docker writes progress to stderr; Windows PowerShell would turn that into errors
    # when output is redirected. Judge native commands by their exit code only.
    $ErrorActionPreference = 'Continue'
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "command failed (exit $LASTEXITCODE): $Command" }
}

switch ($Verb) {
    'help' {
        @(
            '  certs    generate TLS certificates (once)'
            '  rotate   new passwords for a fresh lab; on a running lab: rotate -Apply'
            '  up       certs + passwords if missing, build, start, wait until healthy, apply retention'
            '  down     stop the lab (data is kept)'
            '  reset    stop and DELETE all lab data (volumes)'
            '  status   containers, agents, passwords, retention, custom rules fired'
            '  test     unit tests + detection tests against the real engine'
            '  lint     ruff'
        ) | ForEach-Object { Write-Host $_ }
    }
    'certs' { Invoke-Native { docker compose -f stack/certs.compose.yml run --rm generator } }
    'rotate' { & "$PSScriptRoot\rotate-passwords.ps1" -Apply:$Apply }
    'up' {
        if (-not (Test-Path stack/certs)) { Invoke-Native { docker compose -f stack/certs.compose.yml run --rm generator } }
        if (-not (Test-Path .env)) { & "$PSScriptRoot\rotate-passwords.ps1" }
        if (-not (Select-String -Path .env -Pattern '^INDEXER_USERS_FILE=' -Quiet)) {
            Write-Warning '.env still has the public default passwords - run: lab.ps1 reset; lab.ps1 rotate; lab.ps1 up'
        }
        Invoke-Native { docker compose up -d --build --wait --wait-timeout 600 }
        Invoke-Native { python scripts/apply_ism.py }
    }
    'down' { Invoke-Native { docker compose down } }
    'reset' { Invoke-Native { docker compose down -v } }
    'status' { Invoke-Native { python scripts/lab_status.py } }
    'test' {
        Push-Location simulator
        try { Invoke-Native { python -m pytest -q } } finally { Pop-Location }
        Invoke-Native { python detection/tests/run_tests.py }
    }
    'lint' { Invoke-Native { ruff check simulator detection/tests scripts } }
}
