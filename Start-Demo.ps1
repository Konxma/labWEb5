param(
    [int]$Port = 8080,
    [int]$DatabasePort = 55440,
    [string]$DataDir = (Join-Path $PSScriptRoot '.demo-db')
)
$ErrorActionPreference = 'Stop'
$base = "http://127.0.0.1:$Port"
try {
    $running = Invoke-RestMethod "$base/swagger/doc.json" -TimeoutSec 2
} catch {
    $running = $null
}
if ($running.info.title -eq 'Incident Tracker API') {
    Write-Host "Сервіс уже працює: $base/swagger/index.html"
    return
}

$pg = 'C:\Program Files\PostgreSQL\18\bin'
if (!(Test-Path "$pg\pg_ctl.exe")) { throw "PostgreSQL 18 не знайдено в $pg" }

$go = Get-Command go.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source
if (!$go) { $go = Join-Path $PSScriptRoot '..\..\work\sdk\go\bin\go.exe' }
if (!(Test-Path $go)) { throw 'Потрібен Go SDK. Інструкція є в README.md.' }

if (!(Test-Path (Join-Path $DataDir 'PG_VERSION'))) {
    # This cluster listens only on localhost and is used exclusively for the demo.
    & "$pg\initdb.exe" -D $DataDir -U tracker_demo -A trust --no-locale -E UTF8
    if ($LASTEXITCODE) { throw 'Не вдалося створити тестову базу PostgreSQL.' }
}

& "$pg\pg_ctl.exe" -D $DataDir status *> $null
$startedHere = $LASTEXITCODE -ne 0
if ($startedHere) {
    & "$pg\pg_ctl.exe" -D $DataDir -l (Join-Path $DataDir 'postgres.log') -o "-h 127.0.0.1 -p $DatabasePort" -w start
    if ($LASTEXITCODE) { throw 'Не вдалося запустити тестову базу PostgreSQL.' }
}

Push-Location $PSScriptRoot
try {
    $env:DATABASE_URL = "host=127.0.0.1 port=$DatabasePort user=tracker_demo dbname=postgres sslmode=disable"
    $env:JWT_SECRET = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
    $env:PORT = "$Port"
    $env:GIN_MODE = 'release'
    & $go run .
    if ($LASTEXITCODE) { throw 'Сервіс завершився з помилкою.' }
} finally {
    Pop-Location
    if ($startedHere) {
        & "$pg\pg_ctl.exe" -D $DataDir -m fast -w stop
    }
}
