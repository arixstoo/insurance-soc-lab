<#
.SYNOPSIS
  Lab commands for Windows PowerShell - same verbs as the Makefile.

.EXAMPLE
  .\scripts\lab.ps1 up             # certs + passwords if missing, build, start, wait until healthy, retention, dashboards
  .\scripts\lab.ps1 up -Real       # + the real hosts (compose profile real, docs/real-services.md)
  .\scripts\lab.ps1 traffic        # scripted test traffic from the lab test client to the real hosts
  .\scripts\lab.ps1 status
  .\scripts\lab.ps1 response     # brute force -> alert -> webhook -> 10 min block -> expiry (-Real: real host too)
  .\scripts\lab.ps1 rotate -Apply  # new passwords on a running lab
  .\scripts\lab.ps1 ti             # refresh the threat-intel list (known-bad IPs), reload the manager
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'certs', 'rotate', 'up', 'down', 'reset', 'status', 'traffic', 'response', 'ti', 'test', 'lint', 'dashboards')]
    [string]$Verb = 'help',
    [switch]$Apply,
    [switch]$Real
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
            '  up       certs + passwords if missing, build, start, wait until healthy, retention, dashboards (-Real: + real hosts)'
            '  down     stop the lab (data is kept)'
            '  reset    stop and DELETE all lab data (volumes)'
            '  status   containers, agents, passwords, retention, response chain, custom rules fired'
            '  traffic  real hosts: scripted test traffic from the lab test client'
            '  response brute force -> alert -> webhook -> 10 min block -> expiry, ~11 min (-Real: real host too)'
            '  ti       threat intel: rebuild the known-bad IP list from the feed (cached; offline: sample), reload the manager'
            '  test     unit tests + detection tests against the real engine'
            '  lint     ruff'
            '  dashboards  (re)import dashboards/*.ndjson into the running lab'
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
        if ($Real) { Invoke-Native { docker compose --profile real up -d --build --wait --wait-timeout 600 } }
        else { Invoke-Native { docker compose up -d --build --wait --wait-timeout 600 } }
        Invoke-Native { python scripts/apply_ism.py }
        Invoke-Native { python scripts/import_dashboards.py }
    }
    'down' { Invoke-Native { docker compose --profile real down } }
    'reset' { Invoke-Native { docker compose --profile real down -v } }
    'status' { Invoke-Native { python scripts/lab_status.py } }
    'traffic' { Invoke-Native { docker compose --profile real exec real-client lab-traffic all } }
    'response' {
        $target = if ($Real) { 'both' } else { 'simulated' }
        Invoke-Native { python scripts/check_response.py --target $target }
    }
    'ti' {
        Invoke-Native { python scripts/update_ti.py }
        Invoke-Native { docker compose restart wazuh.manager }
    }
    'test' {
        Push-Location simulator
        try { Invoke-Native { python -m pytest -q } } finally { Pop-Location }
        Invoke-Native { python -m pytest -q detection/tests }
        Invoke-Native { python -m pytest -q response/tests }
        Invoke-Native { python scripts/gen_catalog.py --check }
        Invoke-Native { python scripts/gen_mitre_layer.py --check }
        Invoke-Native { python scripts/update_ti.py --sample --check }
        Invoke-Native { python detection/tests/run_tests.py }
    }
    'lint' { Invoke-Native { ruff check simulator detection/tests scripts real response } }
    'dashboards' { Invoke-Native { python scripts/import_dashboards.py } }
}
