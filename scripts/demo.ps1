$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    Write-Host "This resets this Compose project's databases and MinIO data volumes."
    Write-Host "It permanently deletes all app accounts, profiles, sessions, files, and benchmark records in those volumes."
    $answer = Read-Host 'Type RESET to remove the volumes and start a clean demo'
    if ($answer -cne 'RESET') {
        Write-Host 'Cancelled; no containers or volumes were changed.'
        return
    }

    docker compose down -v --remove-orphans
    if ($LASTEXITCODE -ne 0) { throw 'docker compose down failed' }
    docker compose up --build -d
    if ($LASTEXITCODE -ne 0) { throw 'docker compose up failed' }

    $healthUrl = 'http://localhost:' + $(if ($env:APP_PORT) { $env:APP_PORT } else { '8080' }) + '/healthz'
    $deadline = (Get-Date).AddMinutes(20)
    do {
        Start-Sleep -Seconds 5
        try {
            $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 5
            if ($health.status -eq 'ok') {
                Write-Host "App is healthy at $healthUrl"
                Write-Host 'Continue with the checklist in docs/demo.md.'
                return
            }
        } catch {
            # Services may still be starting, especially on the first MinIO build.
        }
    } while ((Get-Date) -lt $deadline)
    docker compose ps
    throw "App did not become healthy within 20 minutes. Check 'docker compose logs'."
} finally {
    Pop-Location
}

