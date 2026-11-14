[CmdletBinding()]
param([switch]$SkipRiskGate)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-NetworkEnv.psm1') -Force
try {
    $null = Assert-NetworkEnvRiskGate -AllowOverride:$SkipRiskGate
    Start-GuardDesktop
} catch { Write-Error ('Startup refused: '+$_.Exception.Message); exit 1 }
