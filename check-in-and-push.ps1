param(
  [string]$Message = "",
  [switch]$NoPush
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path ".git")) {
  throw "Run this script from the repository root."
}

if ([string]::IsNullOrWhiteSpace($Message)) {
  $Message = Read-Host "Commit message"
}

if ([string]::IsNullOrWhiteSpace($Message)) {
  throw "A commit message is required."
}

$branch = git rev-parse --abbrev-ref HEAD
if ([string]::IsNullOrWhiteSpace($branch)) {
  throw "Could not determine the current branch."
}

Write-Host "Repository: $(Split-Path -Leaf (Get-Location))"
Write-Host "Branch: $branch"
Write-Host ""
Write-Host "Current status:"
git status --short --branch

Write-Host ""
Write-Host "Staging all changes, including CSV, data, and untracked files..."
git add -A

$stagedChanges = git diff --cached --name-only
if ([string]::IsNullOrWhiteSpace(($stagedChanges -join ""))) {
  Write-Host "No staged changes to commit."
} else {
  Write-Host ""
  Write-Host "Files staged for commit:"
  $stagedChanges | ForEach-Object { Write-Host "  $_" }

  Write-Host ""
  git commit -m $Message
}

if ($NoPush) {
  Write-Host ""
  Write-Host "Skipping push because -NoPush was provided."
} else {
  Write-Host ""
  Write-Host "Pushing $branch to origin..."
  git push origin $branch
}

Write-Host ""
Write-Host "Final status:"
git status --short --branch
