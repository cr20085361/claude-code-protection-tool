[CmdletBinding()]
param([switch]$CheckUpdates,[switch]$Force)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1')
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-VersionInfo.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-DesktopUpdate.psm1') -Force
$snapshot=Get-ClaudeVersionSnapshot $PSScriptRoot -CheckUpdates:$CheckUpdates -Force:$Force
try{$snapshot|Add-Member -NotePropertyName DesktopUpdate -NotePropertyValue (Get-ClaudeDesktopUpdateSnapshot $PSScriptRoot)}catch{}
$snapshot|ConvertTo-Json -Depth 10 -Compress
