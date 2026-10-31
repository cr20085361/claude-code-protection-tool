[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$d=Get-GuardState
$events=@()
foreach($file in @('private\supervisor-events.jsonl.previous','private\supervisor-events.jsonl')) {
    $path=Get-GuardPath $file
    if(Test-Path $path){foreach($line in Get-Content $path){try{$events+=($line|ConvertFrom-Json)}catch{}}}
}
$first=if($d.PSObject.Properties['Reliability']){[datetime]$d.Reliability.Installed}elseif($events.Count){[datetime]$events[0].Time}else{$null}
if($first){$events=@($events|Where-Object {[datetime]$_.Time -ge $first})}
$healthPath=Get-GuardPath 'private\supervisor-health.json'
$health=if(Test-Path $healthPath){Read-GuardJson $healthPath}else{$null}
$snapshot=Get-GuardSupervisorSnapshot
$hostEvents=@()
foreach($file in @('private\host-events.jsonl.previous','private\host-events.jsonl','private\supervisor-host-events.jsonl.previous','private\supervisor-host-events.jsonl')){
    $path=Get-GuardPath $file
    if(Test-Path -LiteralPath $path){foreach($line in Get-Content -LiteralPath $path){try{$hostEvents+=($line|ConvertFrom-Json)}catch{}}}
}
$result=[ordered]@{Time=(Get-Date -Format o);ApprovedDesktopVersion=$d.Desktop.Version;InstalledDesktopVersion=(Get-GuardDesktop).Version;CodeVersion=$d.CodeGate.Version;CurrentCodeSessionAccepted=(Test-GuardLocalCodeAcceptance);Supervisor=$health;HealthAgeSeconds=if($health){[Math]::Round(((Get-Date)-[datetime]$health.Time).TotalSeconds,1)}else{$null};ObservationStarted=if($first){$first.ToString('o')}else{$null};ElapsedHours=if($first){[Math]::Round(((Get-Date)-$first).TotalHours,2)}else{0};ProxyStarts=@($events|Where-Object Kind -eq 'ProxyStarted').Count;ObservedProxyExits=@($events|Where-Object Kind -eq 'ProxyExited').Count;EgressFailures=@($events|Where-Object Kind -eq 'EgressFailed').Count;VerifiedEgressChecks=@($events|Where-Object Kind -eq 'EgressVerified').Count;ResumeOrClockGaps=@($events|Where-Object Kind -eq 'ResumeOrClockGap').Count;SafetyStops=@($events|Where-Object Kind -eq 'SafetyStop').Count;ObservationElapsed24Hours=[bool]($first -and ((Get-Date)-$first).TotalHours -ge 24);LongRunObservationComplete=$false;SleepWakeVerified=$false;Scope='Elapsed wall-clock time and local records; sustained Code responses and actual sleep/wake are separate acceptance evidence.'}
$result['SupervisorVerified']=$snapshot.Ready;$result['SupervisorReason']=$snapshot.Reason
$result['HostWorkerExits']=@($hostEvents|Where-Object Kind -eq 'WorkerExited').Count
$result['HostWatchdogTimeouts']=@($hostEvents|Where-Object Kind -eq 'WatchdogExpired').Count
Write-GuardJson (Get-GuardPath 'evidence\reliability-observation.json') $result
$result|ConvertTo-Json -Depth 7
