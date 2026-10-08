[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
try {
    & (Join-Path $PSScriptRoot 'Prepare-ClaudeCode.ps1') -Finalize
    if($LASTEXITCODE -and $LASTEXITCODE -ne 0){throw 'Code finalization failed.'}
    Write-GuardJson (Get-GuardPath 'evidence\code-admin-stage.json') @{Time=(Get-Date -Format o);Success=$true}
} catch {
    Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
    Write-GuardJson (Get-GuardPath 'evidence\code-admin-stage.json') @{Time=(Get-Date -Format o);Success=$false;Reason=$_.Exception.Message}
    exit 1
}
