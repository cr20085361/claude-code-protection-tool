[CmdletBinding()]
param([switch]$RoutingOnly)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$result=[ordered]@{Time=(Get-Date -Format o);Policy=$false;DesktopFirewall=$false;Firewall=$false;Egress=$null;OriginalCliUnchanged=$false;NetworkProtectionPrepared=$false;LocalCodeBasicAccepted=$false;FullLocalCodeAccepted=$false;Errors=@()}
try { Assert-GuardPolicy; $result.Policy=$true; $result.OriginalCliUnchanged=$true } catch { $result.Errors+=$_.Exception.Message }
try { Assert-GuardFirewall -DesktopOnly; $result.DesktopFirewall=$true } catch { $result.Errors+=$_.Exception.Message }
if (-not $RoutingOnly) { try { Assert-GuardFirewall; $result.Firewall=$true } catch { $result.Errors+=$_.Exception.Message } }
try { $result.Egress=Test-GuardEgress } catch { $result.Errors+=$_.Exception.Message }
$d=Get-GuardState
$result.LocalCodeBasicAccepted=((Test-GuardLocalCodeAcceptance) -and $result.Firewall -and $result.Errors.Count -eq 0)
# Basic normal-use acceptance does not certify untested IPv6, TUN changes, MCP or updates.
$result.FullLocalCodeAccepted=$false
$result.NetworkProtectionPrepared=($d.CodeCoverage -in @('prepared','verified') -and $result.Firewall -and $result.Errors.Count -eq 0)
Write-GuardJson (Get-GuardPath 'evidence\diagnostics.json') $result
$result | ConvertTo-Json -Depth 8
if ($result.Errors.Count) { exit 1 }
