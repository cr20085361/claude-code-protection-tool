[CmdletBinding()]
param([switch]$PolicyOnly,[switch]$RepairCodeCache)
$ErrorActionPreference='Stop'
try {
    Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne (Get-GuardState).UserSid) { throw 'Elevation must use the same Windows account as the prepared installation.' }
    if (-not $PolicyOnly) { & (Join-Path $PSScriptRoot 'Install-ClaudeGuard.ps1') -FirewallOnly }
    & (Join-Path $PSScriptRoot 'Install-ClaudeGuard.ps1') -RepairCodeCache:$RepairCodeCache
    if (-not $PolicyOnly) { & (Join-Path $PSScriptRoot 'Test-ClaudeFirewall.ps1') } else { Assert-GuardFirewall -DesktopOnly; Assert-GuardPolicy }
} catch {
    Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
    Write-GuardJson (Get-GuardPath 'evidence\admin-stage.json') @{Time=(Get-Date -Format o);Success=$false;Reason=$_.Exception.Message}
    exit 1
}
Write-GuardJson (Get-GuardPath 'evidence\admin-stage.json') @{Time=(Get-Date -Format o);Success=$true}
