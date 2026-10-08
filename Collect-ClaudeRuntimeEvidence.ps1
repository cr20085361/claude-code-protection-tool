[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
Assert-GuardPolicy
Assert-GuardFirewall
Assert-GuardCore
$d=Get-GuardState
$last=Read-GuardJson (Get-GuardPath 'evidence\last-launch.json')
$desktop=@(Get-GuardDesktopProcesses)
$main=@($desktop|Where-Object ProcessId -eq $last.Pid)
if($main.Count -ne 1 -or (Get-Process -Id $last.Pid).StartTime.ToUniversalTime().Ticks -ne ([datetime]$last.ProcessStart).ToUniversalTime().Ticks){throw 'No matching protected Desktop instance.'}
$code=@(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -in @($d.CodePaths)})
$python=Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\python.exe'
$environments=@()
foreach($p in @($main)+@($code)) {
    $json=& $python (Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py') $p.ProcessId 2>$null
    if($LASTEXITCODE -ne 0){throw 'Read-only process environment verification unavailable.'}
    $environments+=($json|ConvertFrom-Json)
}
$all=@($desktop)+@($code)
$connections=@(Get-NetTCPConnection -ErrorAction SilentlyContinue|Where-Object {$_.OwningProcess -in @($all.ProcessId) -and $_.State -in 'Established','SynSent'}|Select-Object OwningProcess,@{n='State';e={$_.State.ToString()}},RemoteAddress,RemotePort)
$bad=@($connections|Where-Object {($_.RemoteAddress -ne '::1' -and $_.RemoteAddress -notlike '127.*') -or (($_.RemoteAddress -eq '::1' -or $_.RemoteAddress -like '127.*') -and $_.RemotePort -in @(10808,10813))})
$networkServices=@($desktop|Where-Object {$_.CommandLine -match 'network.mojom.NetworkService'})
$fixedConnections=@($connections|Where-Object {$_.OwningProcess -in @($networkServices.ProcessId) -and $_.RemoteAddress -eq '127.0.0.1' -and $_.RemotePort -eq 10818 -and $_.State -eq 'Established'})
$egress=Test-GuardEgress
$isolation=(@($environments|Where-Object {-not $_.ApprovedPath -or -not $_.ConfigDirMatches -or -not $_.HttpProxyMatches -or -not $_.HttpsProxyMatches -or -not $_.AllProxyMatches -or -not $_.NoProxyOnlyLoopback -or -not $_.AutoUpdaterDisabled -or -not $_.TlsVerificationEnabled -or @($_.UnexpectedTlsOverrideNames).Count -or @($_.UnexpectedProviderOverrideNames).Count}).Count -eq 0)
$codeIdentities=@($code|ForEach-Object {[ordered]@{Pid=$_.ProcessId;ParentPid=$_.ParentProcessId;Path=$_.ExecutablePath;Hash=(Get-GuardHash $_.ExecutablePath);Started=(Get-Process -Id $_.ProcessId).StartTime.ToUniversalTime().ToString('o');DedicatedProxyObserved=$false}})
foreach($identity in $codeIdentities){$identity.DedicatedProxyObserved=(@($connections|Where-Object {$_.OwningProcess -eq $identity.Pid -and $_.RemoteAddress -eq '127.0.0.1' -and $_.RemotePort -eq 10818 -and $_.State -eq 'Established'}).Count -gt 0)}
$result=[ordered]@{Time=(Get-Date -Format o);DesktopPid=$last.Pid;DesktopStart=$last.ProcessStart;DesktopFixedProxyArgument=($main[0].CommandLine -match '--proxy-server=http://127.0.0.1:10818');DesktopProxyConnectionObserved=($fixedConnections.Count -gt 0);UnexpectedConnectionCount=$bad.Count;RuntimeIsolationVerified=$isolation;Environments=$environments;Connections=$connections;CodeProcessCount=$code.Count;CodePaths=@($code|ForEach-Object {$_.ExecutablePath});CodeIdentities=$codeIdentities;CodeProxyConnectionsVerified=($code.Count -gt 0 -and @($codeIdentities|Where-Object {-not $_.DedicatedProxyObserved}).Count -eq 0);Egress=$egress;AuthenticatedCodeResponseVerified=$false;Scope='Process environment and TCP snapshot; user response and normal local Code session remain separate acceptance requirements.'}
Write-GuardJson (Get-GuardPath 'evidence\desktop-runtime.json') $result
$result|ConvertTo-Json -Depth 7
if($bad.Count){throw 'Unexpected network path observed; do not continue authentication.'}
if(-not $isolation){throw 'Runtime environment isolation mismatch; do not mark local Code accepted.'}
