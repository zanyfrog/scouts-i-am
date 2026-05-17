Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repoRoot

Write-Host "Stopping scouts-landing Docker Compose stack..."
docker compose down

Write-Host "Rebuilding and starting scouts-landing Docker Compose stack..."
docker compose up -d --build

Write-Host "Current container status:"
docker compose ps
