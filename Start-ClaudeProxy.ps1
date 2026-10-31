[CmdletBinding()]
param([switch]$Stop)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
if ($Stop) { Stop-GuardProxy } else { Start-GuardProxy; Test-GuardEgress }
