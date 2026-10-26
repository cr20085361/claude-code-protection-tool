[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$checks=[Collections.Generic.List[string]]::new()
function Check($Name,[scriptblock]$Body){& $Body;$checks.Add($Name)}
function Refuse([scriptblock]$Body){$failed=$false;try{& $Body}catch{$failed=$true};if(-not $failed){throw 'Expected rejection.'}}
$nodes=@(foreach($i in 1,2){[pscustomobject]@{protocol='vless';settings=@{address="203.0.113.$i";port=443;id='00000000-0000-0000-0000-000000000001';encryption='none';flow='xtls-rprx-vision'};streamSettings=@{security='reality';network='raw';realitySettings=@{serverName='example.com';publicKey='fixture';shortId='ab'}}}})
$state=[pscustomobject]@{ProxyEngine='xray';ExpectedIp='203.0.113.1';ExpectedIps=@('203.0.113.1','203.0.113.2');InterfaceName='FixtureNIC'}
$pool=New-GuardXrayNodePool $nodes $state.InterfaceName
# Normalize as it will be read from disk, including strict property access.
$pool=$pool|ConvertTo-Json -Depth 40|ConvertFrom-Json
Check 'approved-pool-and-closed-fallback' {Assert-GuardXrayNodePool $pool $state;if($pool.routing.balancers[0].fallbackTag -ne 'block'){throw 'Open fallback'}}
Check 'legacy-single-egress' {if(@(Get-GuardExpectedIps ([pscustomobject]@{ExpectedIp='203.0.113.1'})).Count -ne 1){throw 'Legacy failed'}}
Check 'empty-egress-list-rejected' {Refuse {Get-GuardExpectedIps ([pscustomobject]@{ExpectedIps=@()})}}
Check 'unapproved-node-rejected' {$p=$pool|ConvertTo-Json -Depth 40|ConvertFrom-Json;$p.outbounds[0].settings.address='203.0.113.99';Refuse {Assert-GuardXrayNodePool $p $state}}
Check 'direct-fallback-rejected' {$p=$pool|ConvertTo-Json -Depth 40|ConvertFrom-Json;$p.outbounds[-1].protocol='freedom';Refuse {Assert-GuardXrayNodePool $p $state}}
Check 'foreign-interface-rejected' {$p=$pool|ConvertTo-Json -Depth 40|ConvertFrom-Json;$p.outbounds[0].streamSettings.sockopt.interface='OtherNIC';Refuse {Assert-GuardXrayNodePool $p $state}}
Check 'pool-preserved-by-version-maintenance' {$p=New-GuardIPv4Config $pool;if(($p|ConvertTo-Json -Depth 40 -Compress) -ne ($pool|ConvertTo-Json -Depth 40 -Compress)){throw 'Pool changed'}}
Check 'two-approved-egresses-during-switch' {$r=Resolve-GuardEgressProbes @{ExitCode=0;Body="ip=203.0.113.1`n"} @{ExitCode=0;Body='{"ip":"203.0.113.2"}'} $state.ExpectedIps;if($r.VerifiedProbeCount -ne 2){throw 'Switch proof failed'}}
Check 'unknown-egress-still-blocked' {Refuse {Resolve-GuardEgressProbes @{ExitCode=0;Body="ip=203.0.113.1`n"} @{ExitCode=0;Body='{"ip":"203.0.113.99"}'} $state.ExpectedIps}}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'ClaudeGuard-UiBridge.ps1'),[ref]$tokens,[ref]$errors)
if($errors){throw 'Bridge syntax error'}
$fn=$ast.Find({param($a)$a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq 'Assert-GuardUiRetryWindow'},$true)
. ([scriptblock]::Create($fn.Extent.Text))
$now=[datetimeoffset]::UtcNow
$snapshot=[pscustomobject]@{Ready=$false;Kind='UpstreamUnavailable';Health=[pscustomobject]@{ConsecutiveFailures=75;NextProbe=$now.AddMinutes(5).ToString('o')}}
Check 'backoff-fails-promptly' {$clock=[Diagnostics.Stopwatch]::StartNew();Refuse {Assert-GuardUiRetryWindow $snapshot $now};if($clock.Elapsed.TotalSeconds -gt 1){throw 'Unexpected wait'}}
Check 'periodic-check-does-not-hide-failure' {$snapshot.Kind='Checking';Refuse {Assert-GuardUiRetryWindow $snapshot $now}}
Check 'unverified-identity-not-misclassified' {$snapshot.Kind='SupervisorUnavailable';Assert-GuardUiRetryWindow $snapshot $now}
Check 'due-probe-can-complete' {$snapshot.Kind='UpstreamUnavailable';$snapshot.Health.NextProbe=$now.ToString('o');Assert-GuardUiRetryWindow $snapshot $now}
Write-GuardJson (Join-Path $PSScriptRoot 'evidence/node-pool-regression.json') @{Passed=$true;FixtureOnly=$true;Cases=@($checks);Time=(Get-Date -Format o)}
[pscustomobject]@{Passed=$true;CaseCount=$checks.Count}|ConvertTo-Json
