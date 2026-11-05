param(
    [string]$Config = (Join-Path $PSScriptRoot 'config.toml'),
    [ValidateRange(1, 65535)][int]$Port = 8080
)

$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$projectPython = Join-Path $projectRoot '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $projectPython -PathType Leaf)) {
    throw 'Create the virtual environment with: py -3 -m venv .venv; then install with: .venv\Scripts\python.exe -m pip install -e .'
}

Push-Location -LiteralPath $projectRoot
try {
    & $projectPython -m sentinal --config $Config run --port $Port
    $sentinalExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $sentinalExitCode
