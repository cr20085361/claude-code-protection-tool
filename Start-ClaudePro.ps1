[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
try { Start-GuardDesktop } catch { Write-Error ('Startup refused: '+$_.Exception.Message); exit 1 }
