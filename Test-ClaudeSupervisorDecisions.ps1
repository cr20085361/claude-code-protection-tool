[CmdletBinding()]
param([string]$ProjectRoot=$PSScriptRoot)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $ProjectRoot 'ClaudeGuard.psm1') -Force
Import-Module (Join-Path $ProjectRoot 'ClaudeGuard-Runtime.psm1')
$source=Get-Content (Join-Path $PSScriptRoot 'ClaudeGuard-Supervisor-v2.ps1') -Raw
$shell=(Get-Content (Get-GuardPath 'private\launcher-paths.txt') -Raw).Trim()
$results=@()
$newLine=[Environment]::NewLine
function Get-FixtureSource([string]$Text,[switch]$Worker) {
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$parseErrors)
    if($parseErrors.Count){throw ('Fixture source parse failed: '+($parseErrors.Message -join ';'))}
    $edits=@()
    if($ast.ParamBlock){
        $edits+=@{Start=$ast.ParamBlock.Extent.StartOffset;End=$ast.ParamBlock.Extent.EndOffset;Text=''}
        foreach($attribute in $ast.ParamBlock.Attributes){$edits+=@{Start=$attribute.Extent.StartOffset;End=$attribute.Extent.EndOffset;Text=''}}
    }
    foreach($command in $ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in @('Import-Module','Export-ModuleMember')},$true)){
        $edits+=@{Start=$command.Extent.StartOffset;End=$command.Extent.EndOffset;Text=''}
    }
    if($Worker){
        # 只修改经过 AST 确认的 worker 主循环条件，不全局替换 while 或状态赋值。
        $loop=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.WhileStatementAst] -and $n.Condition.Extent.Text -eq '$true'},$true))
        if($loop.Count -ne 1){throw 'Fixture requires exactly one worker cycle loop.'}
        $edits+=@{Start=$loop[0].Condition.Extent.StartOffset;End=$loop[0].Condition.Extent.EndOffset;Text='$script:FixtureTicks -lt $script:FixtureCycleLimit'}
        $mutexName=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -eq 'Local\ClaudeProGuardSupervisor-v1'},$true))
        if($mutexName.Count -ne 1){throw 'Fixture worker mutex was not located.'}
        $edits+=@{Start=$mutexName[0].Extent.StartOffset;End=$mutexName[0].Extent.EndOffset;Text="'Local\ClaudeGuardFixture-"+[guid]::NewGuid().ToString('N')+"'"}
    }
    foreach($edit in @($edits|Sort-Object Start -Descending)){$Text=$Text.Remove($edit.Start,$edit.End-$edit.Start).Insert($edit.Start,$edit.Text)}
    $Text
}
$body=Get-FixtureSource $source -Worker
foreach($scenario in @('egress-drift','runtime-unsafe','runtime-reader-recovered','runtime-reader-unavailable','runtime-timeout-persistent','runtime-timeout-recovers','runtime-timeout-existing-marker','runtime-timeout-inherited-proxy','runtime-timeout-mixed','runtime-timeout-listener-remains','runtime-timeout-proxy-process-remains','tls-disabled','active-code-probe-failure','idle-probe-failure','existing-safety-hold','healthy-current-run','new-version-available','maintenance-before-hash','persisted-restart-budget','failed-start-persisted','persisted-egress-backoff','persisted-egress-success','existing-proxy-during-restart-backoff','stale-health','slow-egress','fatal-recovery-state','slow-cycle-not-resume','resume-keeps-egress-backoff','periodic-check-retains-valid-result')) {
    $fixture=Get-GuardPath ('private\supervisor-fixture-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $fixture 'private') -Force|Out-Null
    $wrapper=Join-Path $fixture 'runner.ps1'
    try {
        $header=@'
param([string]$Fixture,[string]$Scenario,[switch]$SecondRun)
$RunId='fixture-current-run';$HostPid=42;$HostStarted=[datetime]::UtcNow.ToString('o')
$script:FixtureTicks=0
$script:FixtureCycleLimit=if($Scenario -eq 'runtime-timeout-recovers'){4}elseif($Scenario -eq 'runtime-timeout-persistent'){3}elseif($Scenario -in @('runtime-timeout-existing-marker','runtime-timeout-inherited-proxy','stale-health','slow-cycle-not-resume','resume-keeps-egress-backoff','periodic-check-retains-valid-result')){2}else{1}
$script:StoppedProxy=0;$script:StoppedRuntime=0;$script:StartedProxy=0;$script:EgressCalls=0;$script:PolicyCalls=0;$script:RuntimeCalls=0;$script:HealthSnapshots=@()
$script:FixtureProxyListening=$Scenario -notin @('runtime-timeout-existing-marker','runtime-timeout-inherited-proxy','persisted-restart-budget','failed-start-persisted')
$script:FixtureProxyAlive=$script:FixtureProxyListening -or $Scenario -eq 'runtime-timeout-inherited-proxy'
$script:FixtureProxyStarted=[datetime]::UtcNow
$script:StopsWithPendingMarker=0
function Get-GuardPath([string]$Name){Join-Path $Fixture $Name}
function Get-GuardHash([string]$Path){if($Scenario -eq 'maintenance-before-hash'){'changed-hash'}else{'fixture-hash'}}
function Read-GuardJson([string]$Path){Get-Content $Path -Raw|ConvertFrom-Json}
function Write-GuardJson([string]$Path,$Value){
    [IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 30))
    if($Path -eq (Get-GuardPath 'private\supervisor-health.json')){
        $healthSnapshot=$Value|ConvertTo-Json -Depth 30|ConvertFrom-Json
        $healthSnapshot|Add-Member NoteProperty PendingMarkerPresent (Test-Path -LiteralPath (Get-GuardPath 'private\runtime-evidence-pending.json'))
        $script:HealthSnapshots+=@($healthSnapshot)
    }
}
$script:FixtureState=[pscustomobject]@{Desktop=[pscustomobject]@{Version='fixture';Hash='fixture-hash';Path='fixture-desktop'};CodePaths=@('fixture-code');Reliability=[pscustomobject]@{SupervisorHash='fixture-hash';GuardHash='fixture-hash';CodeGateHash='fixture-hash';RuntimeHash='fixture-hash';EnvironmentReaderHash='fixture-hash';HealthScriptHash='fixture-hash';LifecycleScriptHash='fixture-hash'}}
function Get-GuardState{$script:FixtureState}
function Get-GuardListener{if($script:FixtureProxyListening){@([pscustomobject]@{OwningProcess=123})}}
function Get-GuardTcpListeners{if($script:FixtureProxyListening){[pscustomobject]@{OwningProcess=123;LocalPort=10818;LocalAddress='127.0.0.1'}}}
function Get-GuardCorePath{'fixture-proxy'}
function Assert-GuardCore{}
function Sync-GuardProxyProcess{if($Scenario -eq 'existing-proxy-during-restart-backoff'){$true}else{$false}}
function Assert-GuardPolicy{$script:PolicyCalls++;if($Scenario -eq 'tls-disabled'){throw 'TLS certificate verification is disabled in Code settings.'}}
function Assert-GuardFirewall{}
function Get-GuardDesktop{$script:FixtureState.Desktop}
function Get-Process{
    if($script:FixtureProxyAlive){
        $process=[pscustomobject]@{Id=123;Handle=1;StartTime=$script:FixtureProxyStarted;Path='fixture-proxy';ExitCode=0}
        $process|Add-Member ScriptProperty HasExited {-not $script:FixtureProxyAlive}
        $process|Add-Member ScriptMethod WaitForExit {param($Milliseconds) if($null -ne $Milliseconds){-not $script:FixtureProxyAlive}}
        $process|Add-Member ScriptMethod Dispose {}
        $process
    }
}
function Get-CimInstance{if($Scenario -eq 'active-code-probe-failure'){[pscustomobject]@{ExecutablePath='fixture-code'}}}
function Get-GuardRuntimeSafety{
    $script:RuntimeCalls++
    $timedOut=$Scenario -in @('runtime-timeout-persistent','runtime-timeout-mixed','runtime-timeout-listener-remains','runtime-timeout-proxy-process-remains') -or ($Scenario -eq 'runtime-timeout-recovers' -and $script:RuntimeCalls -eq 2)
    $readerFailures=@()
    if($timedOut -or $Scenario -eq 'runtime-reader-recovered'){
        $readerFailures+=@([pscustomobject]@{CandidateIndex=1;Round=1;ProcessId=123;Outcome='TimedOut';ElapsedMilliseconds=10000;ExitCode=124;NativeErrorCode=$null})
    }
    if($Scenario -eq 'runtime-reader-unavailable'){
        $readerFailures+=@([pscustomobject]@{CandidateIndex=1;Round=1;ProcessId=123;Outcome='NonZeroExit';ElapsedMilliseconds=80;ExitCode=1;NativeErrorCode=$null})
        $readerFailures+=@([pscustomobject]@{CandidateIndex=2;Round=1;ProcessId=123;Outcome='NonZeroExit';ElapsedMilliseconds=80;ExitCode=1;NativeErrorCode=$null})
    }
    [pscustomobject]@{
        Safe=(-not $timedOut -and $Scenario -notin @('runtime-unsafe','runtime-reader-unavailable'))
        Issues=@(
            if($timedOut -or $Scenario -eq 'runtime-reader-unavailable'){'RuntimeEnvironmentUnreadable'}
            if($Scenario -in @('runtime-unsafe','runtime-timeout-mixed')){'UnexpectedRuntimeNetworkPath'}
        )
        CodeProcessCount=if($timedOut -or $Scenario -in @('active-code-probe-failure','runtime-reader-recovered','runtime-reader-unavailable')){1}else{0}
        RuntimeEvidenceTimedOut=$timedOut
        RuntimeReaderFailures=$readerFailures
    }
}
function Stop-GuardUnsafeRuntime{$script:StoppedRuntime++}
function Stop-GuardProxy{$script:StoppedProxy++;$script:FixtureProxyListening=$false;$script:FixtureProxyAlive=$false}
function Stop-GuardProxyEmergency{
    $script:StoppedProxy++
    if(Test-Path -LiteralPath (Get-GuardPath 'private\runtime-evidence-pending.json')){$script:StopsWithPendingMarker++}
    if($Scenario -ne 'runtime-timeout-listener-remains'){$script:FixtureProxyListening=$false}
    if($Scenario -ne 'runtime-timeout-proxy-process-remains'){$script:FixtureProxyAlive=$false}
}
function Start-GuardProxy{
    $script:StartedProxy++
    if($Scenario -notin @('runtime-timeout-recovers','runtime-timeout-existing-marker','runtime-timeout-inherited-proxy')){throw 'Fixture proxy start failed.'}
    if(Test-Path -LiteralPath (Get-GuardPath 'private\runtime-evidence-pending.json')){throw 'Proxy started before timeout isolation could be safely cleared.'}
    $script:FixtureProxyListening=$true
    $script:FixtureProxyAlive=$true
    $script:FixtureProxyStarted=[datetime]::UtcNow
    Write-GuardJson (Get-GuardPath 'private\proxy-process.json') @{Pid=123;Started=$script:FixtureProxyStarted.ToString('o')}
}
function Start-Sleep{
    $script:FixtureTicks++
    if($Scenario -eq 'stale-health'){
        $script:lastSafetyCheck=[datetime]::UtcNow.AddSeconds(-121).ToString('o');$script:lastEgressCheck=[datetime]::UtcNow.AddSeconds(-121).ToString('o')
        $script:nextSafetyCheck=[datetime]::MaxValue;$script:nextProbe=[datetime]::MaxValue
    }
    if($Scenario -eq 'resume-keeps-egress-backoff'){$script:lastTick=[datetime]::UtcNow.AddSeconds(-65)}
    if($Scenario -eq 'periodic-check-retains-valid-result'){$script:nextSafetyCheck=[datetime]::MinValue}
    if($Scenario -eq 'runtime-timeout-recovers' -and $script:FixtureTicks -eq 1){$script:nextSafetyCheck=[datetime]::MinValue}
}
function Test-GuardEgress{
    $script:EgressCalls++
    if($Scenario -eq 'egress-drift'){throw 'Fixed egress mismatch; protected traffic must stop.'}
    if($Scenario -in @('active-code-probe-failure','idle-probe-failure')){throw 'Neutral egress probes failed; desktop startup refused.'}
    if($Scenario -eq 'slow-egress'){[Threading.Thread]::Sleep(200)}
    if($Scenario -eq 'slow-cycle-not-resume'){$script:lastTick=[datetime]::UtcNow.AddSeconds(-65)}
    [pscustomobject]@{Time=[datetime]::UtcNow.ToString('o');ProbeDegraded=$false;VerifiedProbeCount=2}
}
Write-GuardJson (Get-GuardPath 'private\proxy-process.json') @{Pid=123;Started=$script:FixtureProxyStarted.ToString('o')}
if($Scenario -in @('runtime-timeout-existing-marker','runtime-timeout-inherited-proxy')){Write-GuardJson (Get-GuardPath 'private\runtime-evidence-pending.json') @{Time=[datetime]::UtcNow.ToString('o');RunId='fixture-previous-run'}}
if($Scenario -eq 'new-version-available'){Write-GuardJson (Get-GuardPath 'private\version-update-status.json') @{SchemaVersion=1;Status='Checked';CheckedAt=[datetime]::UtcNow.ToString('o');LastSuccess=@{LatestDesktopVersion='99.0.0'}}}
if($Scenario -eq 'existing-safety-hold'){Write-GuardJson (Get-GuardPath 'private\safety-hold.json') @{Reason='previous-fixed-egress-mismatch'}}
if($Scenario -eq 'maintenance-before-hash'){Write-GuardJson (Get-GuardPath 'private\maintenance.json') @{Until=[datetime]::UtcNow.AddMinutes(2).ToString('o')}}
if(-not $SecondRun -and $Scenario -in @('active-code-probe-failure','idle-probe-failure','persisted-restart-budget','persisted-egress-backoff','persisted-egress-success','resume-keeps-egress-backoff')){
    $attempts=if($Scenario -eq 'persisted-restart-budget'){@([datetime]::UtcNow.AddSeconds(-3).ToString('o'),[datetime]::UtcNow.AddSeconds(-2).ToString('o'),[datetime]::UtcNow.AddSeconds(-1).ToString('o'))}else{@()}
    $next=if($Scenario -in @('persisted-egress-backoff','resume-keeps-egress-backoff')){[datetime]::UtcNow.AddSeconds(120)}else{[datetime]::UtcNow.AddSeconds(-1)}
    Write-GuardJson (Get-GuardPath 'private\proxy-recovery.json') @{SchemaVersion=1;RestartTimes=@($attempts|Where-Object {$_});NextRestart=[datetime]::UtcNow.AddSeconds(-1).ToString('o');ConsecutiveEgressFailures=if($Scenario -eq 'persisted-restart-budget'){0}else{2};NextProbe=$next.ToString('o')}
}
if($Scenario -eq 'fatal-recovery-state'){[IO.File]::WriteAllText((Get-GuardPath 'private\proxy-recovery.json'),'invalid-json')}
if($Scenario -eq 'existing-proxy-during-restart-backoff'){Write-GuardJson (Get-GuardPath 'private\proxy-recovery.json') @{SchemaVersion=1;RestartTimes=@([datetime]::UtcNow.ToString('o'));NextRestart=[datetime]::UtcNow.AddMinutes(5).ToString('o');ConsecutiveEgressFailures=0;NextProbe=[datetime]::UtcNow.AddSeconds(-1).ToString('o')}}
'@
        $footer=@'
}finally{Write-GuardJson (Get-GuardPath 'counts.json') @{StoppedProxy=$script:StoppedProxy;StoppedRuntime=$script:StoppedRuntime;StartedProxy=$script:StartedProxy;StopsWithPendingMarker=$script:StopsWithPendingMarker;EgressCalls=$script:EgressCalls;PolicyCalls=$script:PolicyCalls;RuntimeCalls=$script:RuntimeCalls;HealthSnapshots=$script:HealthSnapshots;NextSafetyUtc=$nextSafetyCheck.ToUniversalTime().ToString('o');SafetyStartTicks=if($safetyStarted){$safetyStarted.Ticks}else{0};NextSafetyTicks=$nextSafetyCheck.Ticks;NextProbeTicks=$nextProbe.Ticks}}
'@
        [IO.File]::WriteAllText($wrapper,$header+$newLine+'try{'+$newLine+$body+$newLine+$footer)
        $output=& $shell -NoProfile -File $wrapper -Fixture $fixture -Scenario $scenario 2>&1
        if($LASTEXITCODE -ne 0 -and $scenario -ne 'fatal-recovery-state'){throw ('Supervisor fixture execution failed: '+$scenario+' '+($output -join ' '))}
        $health=Read-GuardJson (Join-Path $fixture 'private\supervisor-health.json')
        $counts=Read-GuardJson (Join-Path $fixture 'counts.json')
        $held=Test-Path (Join-Path $fixture 'private\safety-hold.json')
        $pending=Test-Path (Join-Path $fixture 'private\runtime-evidence-pending.json')
        $events=@(Get-Content (Join-Path $fixture 'private\supervisor-events.jsonl')|ConvertFrom-Json)
        $readerEvents=@($events|Where-Object Kind -eq 'RuntimeEvidenceReadFailed')
        $safetyStops=@($events|Where-Object Kind -eq 'SafetyStop')
        $eventKinds=@($events|ForEach-Object Kind)
        $restoredIndex=[array]::IndexOf($eventKinds,'RuntimeEvidenceRestored')
        $proxyStartedIndex=[array]::IndexOf($eventKinds,'ProxyStarted')
        $lastEgressIndex=[array]::LastIndexOf($eventKinds,'EgressVerified')
        $recovery=if(Test-Path (Join-Path $fixture 'private\proxy-recovery.json')){if($scenario -ne 'fatal-recovery-state'){Read-GuardJson (Join-Path $fixture 'private\proxy-recovery.json')}}
        $passed=switch($scenario){
            'egress-drift' {$health.Status -eq 'SafetyHold' -and $held -and $counts.StoppedProxy -eq 1}
            'runtime-unsafe' {$health.Status -eq 'SafetyHold' -and $held -and $counts.StoppedRuntime -eq 1 -and $counts.StoppedProxy -eq 1}
            'runtime-reader-recovered' {
                $health.Status -eq 'Healthy' -and -not $held -and $counts.StoppedRuntime -eq 0 -and $counts.StoppedProxy -eq 0 -and
                $counts.EgressCalls -eq 1 -and $health.LastSafetyCheck -and $health.LastEgressCheck -and $safetyStops.Count -eq 0 -and
                $readerEvents.Count -eq 1 -and $readerEvents[0].Data.RunId -eq 'fixture-current-run' -and $readerEvents[0].Data.Recovered -eq $true -and
                @($readerEvents[0].Data.Attempts).Count -eq 1 -and $readerEvents[0].Data.Attempts[0].Outcome -eq 'TimedOut' -and
                $readerEvents[0].Data.Attempts[0].ProcessId -eq 123
            }
            'runtime-reader-unavailable' {
                $health.Status -eq 'SafetyHold' -and $held -and $counts.StoppedRuntime -eq 1 -and $counts.StoppedProxy -eq 1 -and
                $counts.EgressCalls -eq 0 -and -not $health.LastSafetyCheck -and $safetyStops.Count -eq 1 -and
                $safetyStops[0].Data.Reason -eq 'Runtime safety mismatch: RuntimeEnvironmentUnreadable' -and
                $readerEvents.Count -eq 1 -and $readerEvents[0].Data.RunId -eq 'fixture-current-run' -and $readerEvents[0].Data.Recovered -eq $false -and
                @($readerEvents[0].Data.Attempts).Count -eq 2 -and @($readerEvents[0].Data.Attempts|Where-Object Outcome -ne 'NonZeroExit').Count -eq 0 -and
                ($readerEvents[0].Data.Attempts.CandidateIndex -join ',') -eq '1,2'
            }
            'runtime-timeout-persistent' {
                $health.Status -eq 'RuntimeEvidencePending' -and $pending -and -not $held -and
                $counts.StopsWithPendingMarker -eq 1 -and $counts.StoppedProxy -eq 1 -and $counts.StoppedRuntime -eq 0 -and $counts.StartedProxy -eq 0 -and
                $counts.RuntimeCalls -eq 3 -and $counts.EgressCalls -eq 0 -and -not $health.LastSafetyCheck -and -not $health.LastEgressCheck -and
                'RuntimeEvidencePaused' -in $eventKinds -and $restoredIndex -eq -1 -and $safetyStops.Count -eq 0
            }
            'runtime-timeout-recovers' {
                $health.Status -eq 'Healthy' -and -not $pending -and -not $held -and $health.LastSafetyCheck -and $health.LastEgressCheck -and
                $counts.StopsWithPendingMarker -eq 1 -and $counts.StoppedProxy -eq 1 -and $counts.StoppedRuntime -eq 0 -and $counts.StartedProxy -eq 1 -and
                $counts.RuntimeCalls -ge 3 -and $counts.EgressCalls -eq 2 -and 'RuntimeEvidencePaused' -in $eventKinds -and
                $restoredIndex -gt 0 -and $restoredIndex -lt $proxyStartedIndex -and $proxyStartedIndex -lt $lastEgressIndex
            }
            {$_ -in @('runtime-timeout-existing-marker','runtime-timeout-inherited-proxy')} {
                $expectedStops=if($scenario -eq 'runtime-timeout-inherited-proxy'){1}else{0}
                $health.Status -eq 'Healthy' -and -not $pending -and -not $held -and $health.LastSafetyCheck -and $health.LastEgressCheck -and
                $counts.StoppedProxy -eq $expectedStops -and $counts.StopsWithPendingMarker -eq $expectedStops -and $counts.StoppedRuntime -eq 0 -and $counts.StartedProxy -eq 1 -and
                $counts.RuntimeCalls -ge 1 -and $counts.EgressCalls -eq 1 -and
                $restoredIndex -gt 0 -and $restoredIndex -lt $proxyStartedIndex -and $proxyStartedIndex -lt $lastEgressIndex
            }
            'runtime-timeout-mixed' {
                $health.Status -eq 'SafetyHold' -and $held -and -not $pending -and $counts.StoppedRuntime -eq 1 -and $counts.StoppedProxy -eq 1 -and
                $counts.EgressCalls -eq 0 -and $safetyStops.Count -eq 1 -and $safetyStops[0].Data.Reason -match 'UnexpectedRuntimeNetworkPath'
            }
            {$_ -in @('runtime-timeout-listener-remains','runtime-timeout-proxy-process-remains')} {
                $health.Status -eq 'SafetyHold' -and $held -and $counts.StoppedRuntime -eq 1 -and $counts.StopsWithPendingMarker -ge 1 -and
                $counts.StartedProxy -eq 0 -and $counts.EgressCalls -eq 0 -and $safetyStops.Count -eq 1
            }
            'tls-disabled' {$health.Status -eq 'SafetyHold' -and $held -and $counts.StoppedProxy -eq 1}
            'active-code-probe-failure' {$health.Status -eq 'UpstreamUnavailable' -and $counts.StoppedProxy -eq 0 -and -not $held -and $health.ConsecutiveFailures -eq 3}
            'idle-probe-failure' {$health.Status -eq 'UpstreamUnavailable' -and $counts.StoppedProxy -eq 1 -and -not $held -and $health.ConsecutiveFailures -eq 3}
            'existing-safety-hold' {$health.Status -eq 'SafetyHold' -and $held -and $counts.StoppedProxy -eq 0}
            'healthy-current-run' {$health.Status -eq 'Healthy' -and $counts.PolicyCalls -eq 1 -and $counts.EgressCalls -eq 1 -and $health.LastSafetyCheck -and $health.LastEgressCheck}
            'new-version-available' {$health.Status -eq 'Healthy' -and -not $held -and $counts.StoppedRuntime -eq 0 -and $counts.StoppedProxy -eq 0}
            'maintenance-before-hash' {$health.Status -eq 'Maintenance' -and -not $held -and $counts.StoppedProxy -eq 0 -and $counts.StartedProxy -eq 0 -and $counts.PolicyCalls -eq 0}
            'persisted-restart-budget' {$health.Status -eq 'Backoff' -and $counts.StartedProxy -eq 0 -and @($recovery.RestartTimes).Count -eq 3}
            'failed-start-persisted' {$health.Status -eq 'ProtectionError' -and $counts.StartedProxy -eq 1 -and @($recovery.RestartTimes).Count -eq 1}
            'persisted-egress-backoff' {$health.Status -eq 'UpstreamUnavailable' -and $counts.EgressCalls -eq 0 -and -not $health.LastEgressCheck -and $health.LastSafetyCheck -and $health.ConsecutiveFailures -eq 2}
            'persisted-egress-success' {$health.Status -eq 'Healthy' -and $counts.EgressCalls -eq 1 -and $health.ConsecutiveFailures -eq 0 -and $recovery.ConsecutiveEgressFailures -eq 0}
            'existing-proxy-during-restart-backoff' {$health.Status -eq 'Healthy' -and $counts.StartedProxy -eq 0 -and $counts.StoppedProxy -eq 0 -and @(Get-Content (Join-Path $fixture 'private\supervisor-events.jsonl')|ConvertFrom-Json|Where-Object Kind -eq 'ProxyTrackingRecovered').Count -eq 1}
            'stale-health' {$health.Status -eq 'Checking' -and $counts.EgressCalls -eq 1}
            'slow-egress' {$health.Status -eq 'Healthy' -and (([datetime]$health.LastEgressCheck)-([datetime]$health.LastEgressAttempt)).TotalMilliseconds -ge 190}
            'fatal-recovery-state' {$health.Status -eq 'ProtectionError' -and $health.Phase -eq 'Fatal' -and @(Get-Content (Join-Path $fixture 'private\supervisor-events.jsonl')|ConvertFrom-Json|Where-Object Kind -eq 'SupervisorFatal').Count -eq 1}
            'slow-cycle-not-resume' {$health.Status -eq 'Healthy' -and $counts.PolicyCalls -eq 1 -and $counts.EgressCalls -eq 1 -and @(Get-Content (Join-Path $fixture 'private\supervisor-events.jsonl')|ConvertFrom-Json|Where-Object Kind -eq 'ResumeOrClockGap').Count -eq 0}
            'resume-keeps-egress-backoff' {$health.Status -eq 'UpstreamUnavailable' -and $counts.EgressCalls -eq 0 -and $health.ConsecutiveFailures -eq 2 -and @(Get-Content (Join-Path $fixture 'private\supervisor-events.jsonl')|ConvertFrom-Json|Where-Object Kind -eq 'ResumeOrClockGap').Count -eq 1}
            'periodic-check-retains-valid-result' {$health.Status -eq 'Healthy' -and $counts.PolicyCalls -eq 2 -and @($counts.HealthSnapshots|Where-Object {$_.Phase -eq 'Firewall' -and $_.Status -eq 'Healthy'}).Count -gt 0}
        }
        $first=@($counts.HealthSnapshots)[0]
        $contract=$health.SchemaVersion -eq 2 -and $health.RunId -eq 'fixture-current-run' -and $health.HostPid -eq 42 -and $health.SupervisorStarted -and $first.Status -eq 'Starting' -and -not $first.LastSafetyCheck -and -not $first.LastEgressCheck
        $preparing=@($counts.HealthSnapshots|Where-Object {$_.Status -in @('Healthy','ProbeDegraded') -and (-not $_.LastSafetyCheck -or -not $_.LastEgressCheck -or ([datetime]$_.LastSafetyCheck).ToUniversalTime() -lt ([datetime]$_.SupervisorStarted).ToUniversalTime() -or ([datetime]$_.LastEgressCheck).ToUniversalTime() -lt ([datetime]$_.SupervisorStarted).ToUniversalTime())}).Count -eq 0
        $isolated=@($counts.HealthSnapshots|Where-Object {$_.PendingMarkerPresent -and $_.Status -in @('Healthy','ProbeDegraded')}).Count -eq 0
        if(-not $passed -or -not $contract -or -not $preparing -or -not $isolated){throw ('Supervisor decision regression failed: '+$scenario+' health='+($health|ConvertTo-Json -Compress)+' counts='+($counts|ConvertTo-Json -Compress -Depth 3))}
        if($scenario -in @('runtime-reader-recovered','runtime-reader-unavailable')){
            $runtimeEvidence=Read-GuardJson (Join-Path $fixture 'private\runtime-safety.json')
            if(@($runtimeEvidence.RuntimeReaderFailures).Count -ne @($readerEvents[0].Data.Attempts).Count -or
                ($runtimeEvidence.RuntimeReaderFailures|ConvertTo-Json -Depth 5 -Compress) -cne ($readerEvents[0].Data.Attempts|ConvertTo-Json -Depth 5 -Compress)){
                throw ('Runtime reader failure metadata was not preserved in runtime evidence and the worker event: '+$scenario)
            }
        }
        if($scenario -eq 'healthy-current-run'){
            if([long]$counts.NextSafetyTicks -ne ([long]$counts.SafetyStartTicks+[timespan]::FromSeconds(60).Ticks) -or [long]$counts.NextProbeTicks -ne ([datetimeoffset]$health.LastEgressCheck).UtcDateTime.AddSeconds(60).Ticks){throw 'UTC completion strings shifted the next check schedule into local clock ticks.'}
            $results+=@{Scenario='utc-next-check-schedule';Passed=$true;SafetyIntervalSeconds=60;EgressIntervalSeconds=60}
        }
        if($scenario -eq 'failed-start-persisted'){
            $null=& $shell -NoProfile -File $wrapper -Fixture $fixture -Scenario $scenario -SecondRun 2>&1
            if($LASTEXITCODE -ne 0){throw 'Second worker fixture failed.'}
            $health=Read-GuardJson (Join-Path $fixture 'private\supervisor-health.json');$counts=Read-GuardJson (Join-Path $fixture 'counts.json')
            $recovery=Read-GuardJson (Join-Path $fixture 'private\proxy-recovery.json')
            if($health.Status -ne 'Backoff' -or $counts.StartedProxy -ne 0 -or @($recovery.RestartTimes).Count -ne 1){throw 'Worker restart reset proxy startup recovery budget.'}
        }
        $results+=@{Scenario=$scenario;Passed=$true;Status=$health.Status;StopProxyCalls=$counts.StoppedProxy;StopRuntimeCalls=$counts.StoppedRuntime;StartProxyCalls=$counts.StartedProxy;EgressCalls=$counts.EgressCalls}
    }finally{
        foreach($name in @('private\version-update-status.json','private\proxy-process.json','private\supervisor-events.jsonl','private\supervisor-health.json','private\safety-hold.json','private\runtime-safety.json','private\runtime-evidence-pending.json','private\last-good-egress.json','private\maintenance.json','private\proxy-recovery.json','counts.json','runner.ps1')){Remove-Item -LiteralPath (Join-Path $fixture $name) -ErrorAction SilentlyContinue}
        Remove-Item -LiteralPath (Join-Path $fixture 'private'),$fixture -ErrorAction SilentlyContinue
    }
}
# 原生 reader 与 runtime 总证据预算均在隔离子进程验证，不读取或停止生产 Claude。
$fixture=Get-GuardPath ('private\supervisor-fixture-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture -Force|Out-Null
try {
    $runtimeBody=Get-FixtureSource (Get-Content (Join-Path $PSScriptRoot 'ClaudeGuard-Runtime.psm1') -Raw)
    $runtimeHeader=@'
$ErrorActionPreference='Stop'
function Get-GuardState{[pscustomobject]@{Desktop=[pscustomobject]@{Path='fixture-desktop'};CodePaths=@('fixture-code')}}
function Get-CimInstance{@([pscustomobject]@{ExecutablePath='fixture-desktop';CommandLine='--proxy-server=http://127.0.0.1:10818';ProcessId=101;ParentProcessId=1},[pscustomobject]@{ExecutablePath='fixture-code';CommandLine='';ProcessId=102;ParentProcessId=1},[pscustomobject]@{ExecutablePath='fixture-code';CommandLine='';ProcessId=103;ParentProcessId=1})}
function Get-NetTCPConnection{}
function Get-Process{[pscustomobject]@{StartTime=[datetime]::UtcNow}}
'@
    $runtimeFooter=@'
function Get-GuardTcpListeners{}
$python=Resolve-GuardReaderPython
$originalResolver=${function:Resolve-GuardReaderPython}
$script:FixtureReaderCandidates=@($python)
function Get-GuardReaderPythonCandidates{$script:FixtureReaderCandidates}
function Resolve-GuardReaderPython{throw 'The runtime snapshot must read evidence without a separate Python probe.'}
$info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$python;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
$info.ArgumentList.Add('-c');$info.ArgumentList.Add('import time; time.sleep(20)')
$sentinel=[Diagnostics.Process]::Start($info)
$cases=@()
try{
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $runtime=Get-GuardRuntimeSafety -EvidenceBudgetMilliseconds 200 -ReaderTimeoutMilliseconds 1000
    $passed=-not $runtime.Safe -and 'RuntimeEnvironmentUnreadable' -in $runtime.Issues -and $runtime.EvidenceDeadlineExceeded -and $runtime.RuntimeEvidenceTimedOut -and $clock.ElapsedMilliseconds -lt 2000 -and -not $sentinel.HasExited
    if(-not $passed){throw ('Runtime reader deadline failed: '+($runtime|ConvertTo-Json -Depth 10 -Compress))}
    $cases+=@{Scenario='runtime-reader-total-timeout';Passed=$true;ElapsedMilliseconds=$clock.ElapsedMilliseconds;UnrelatedFixtureProcessAlive=(-not $sentinel.HasExited)}
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py'),"print('{}')")
    $invalid=Get-GuardRuntimeSafety -EvidenceBudgetMilliseconds 3000 -ReaderTimeoutMilliseconds 1000
    if($invalid.Safe -or $invalid.RuntimeEvidenceTimedOut -or 'RuntimeEnvironmentUnreadable' -notin $invalid.Issues){throw 'Malformed reader evidence must remain unreadable and unsafe.'}
    $cases+=@{Scenario='runtime-reader-malformed-evidence';Passed=$true;Safe=$invalid.Safe}
    $validReader="import json, sys"+[Environment]::NewLine+"print(json.dumps(dict(Pid=int(sys.argv[1]),ApprovedPath=True,ConfigDirMatches=True,HttpProxyMatches=True,HttpsProxyMatches=True,AllProxyMatches=True,NoProxyOnlyLoopback=True,TlsVerificationEnabled=True,UnexpectedTlsOverrideNames=[],UnexpectedProviderOverrideNames=[])))"
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py'),$validReader)
    $valid=Get-GuardRuntimeSafety -EvidenceBudgetMilliseconds 3000 -ReaderTimeoutMilliseconds 1000
    if(-not $valid.Safe -or @($valid.Environments).Count -ne 3){throw 'Valid reader evidence did not retain existing safe approval.'}
    $cases+=@{Scenario='runtime-reader-valid-evidence';Passed=$true;Safe=$valid.Safe;EnvironmentCount=@($valid.Environments).Count}
    $slowReader="import sys, time"+[Environment]::NewLine+"if sys.argv[1] == '101': time.sleep(2.4)"+[Environment]::NewLine+$validReader
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py'),$slowReader)
    $slow=Get-GuardRuntimeSafety -EvidenceBudgetMilliseconds 8000 -ReaderTimeoutMilliseconds 6000
    if(-not $slow.Safe -or @($slow.Environments).Count -ne 3 -or $slow.EvidenceReaderElapsedMilliseconds -lt 2400){throw 'A slow interpreter that produced current valid evidence did not pass runtime verification.'}
    $cases+=@{Scenario='runtime-reader-slow-valid-evidence';Passed=$true;Safe=$slow.Safe;ElapsedMilliseconds=$slow.EvidenceReaderElapsedMilliseconds;EnvironmentCount=@($slow.Environments).Count}
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py'),$validReader)
    $script:FixtureReaderCandidates=@((Join-Path $PSScriptRoot 'incompatible\python.exe'),$python)
    $fallback=Get-GuardRuntimeSafety -EvidenceBudgetMilliseconds 8000 -ReaderTimeoutMilliseconds 3000
    $firstFailure=@($fallback.RuntimeReaderFailures)[0]
    if(-not $fallback.Safe -or @($fallback.Environments).Count -ne 3 -or $firstFailure.CandidateIndex -ne 1 -or $firstFailure.Outcome -ne 'StartFailed' -or $firstFailure.ProcessId -ne 101){throw 'Runtime verification did not recover from a failed interpreter with current evidence from the alternate.'}
    $cases+=@{Scenario='runtime-reader-native-fallback';Passed=$true;Safe=$fallback.Safe;FirstFailure=$firstFailure;EnvironmentCount=@($fallback.Environments).Count}
    $script:FixtureReaderCandidates=@($python)
    $retryOnce=@(
        'import pathlib, sys, time'
        "marker = pathlib.Path(__file__).with_name('attempted')"
        "if sys.argv[1] == '101' and not marker.exists():"
        '    marker.touch()'
        '    time.sleep(10)'
    ) -join [Environment]::NewLine
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py'),$retryOnce+[Environment]::NewLine+$validReader)
    $retried=Get-GuardRuntimeSafety -EvidenceBudgetMilliseconds 5000 -ReaderTimeoutMilliseconds 1000
    $attemptFailures=@($retried.RuntimeReaderFailures)
    if(-not $retried.Safe -or @($retried.Environments).Count -ne 3 -or $attemptFailures.Count -ne 1 -or
        $attemptFailures[0].Outcome -ne 'TimedOut' -or $attemptFailures[0].Round -ne 1){
        throw 'The second round did not recover a native reader startup timeout.'
    }
    $cases+=@{Scenario='runtime-reader-native-second-round';Passed=$true;Safe=$retried.Safe;FirstFailure=$attemptFailures[0]}
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py'),$validReader)
    $script:FixtureConnections=@();$script:FixtureListeners=@()
    function Get-NetTCPConnection{@($script:FixtureConnections)+@($script:FixtureListeners)}
    function Get-GuardTcpListeners{$script:FixtureListeners}
    foreach($case in @(
        @{Name='incident-localhost-8771-synsent';Address='127.0.0.1';Port=8771;State='SynSent';Safe=$true;Pending=1;Listener=$false},
        @{Name='ipv6-loopback-synsent';Address='::1';Port=8771;State='SynSent';Safe=$true;Pending=1;Listener=$false},
        @{Name='unknown-loopback-established';Address='127.0.0.1';Port=8771;State='Established';Safe=$false;Pending=0;Listener=$false},
        @{Name='shared-proxy-synsent';Address='127.0.0.1';Port=10808;State='SynSent';Safe=$false;Pending=0;Listener=$false},
        @{Name='shared-proxy-established';Address='::1';Port=10813;State='Established';Safe=$false;Pending=0;Listener=$false},
        @{Name='shared-proxy-owned-listener';Address='127.0.0.1';Port=10808;State='Established';Safe=$false;Pending=0;Listener=$true},
        @{Name='external-synsent';Address='203.0.113.10';Port=443;State='SynSent';Safe=$false;Pending=0;Listener=$false},
        @{Name='external-established';Address='203.0.113.10';Port=443;State='Established';Safe=$false;Pending=0;Listener=$false},
        @{Name='dedicated-proxy-established';Address='127.0.0.1';Port=10818;State='Established';Safe=$true;Pending=0;Listener=$false},
        @{Name='owned-local-service-established';Address='127.0.0.1';Port=8771;State='Established';Safe=$true;Pending=0;Listener=$true}
    )){
        $script:FixtureConnections=@([pscustomobject]@{OwningProcess=101;LocalAddress=if($case.Address -eq '::1'){'::1'}else{'127.0.0.1'};LocalPort=49152;RemoteAddress=$case.Address;RemotePort=$case.Port;State=$case.State})
        $script:FixtureListeners=if($case.Listener){@([pscustomobject]@{OwningProcess=102;LocalAddress='127.0.0.1';LocalPort=$case.Port;RemoteAddress='0.0.0.0';RemotePort=0;State='Listen'})}else{@()}
        $observed=Get-GuardRuntimeSafety -EvidenceBudgetMilliseconds 3000 -ReaderTimeoutMilliseconds 1000
        if($observed.Safe -ne $case.Safe -or @($observed.UnconfirmedLoopbackConnections).Count -ne $case.Pending -or (@($observed.UnexpectedConnections).Count -gt 0) -eq $case.Safe){throw ('Network decision fixture failed: '+$case.Name+' '+($observed|ConvertTo-Json -Depth 8 -Compress))}
        $cases+=@{Scenario=$case.Name;Passed=$true;Safe=$observed.Safe;UnconfirmedLoopbackCount=@($observed.UnconfirmedLoopbackConnections).Count}
    }
    # Exercise the launch contract against positive evidence for this exact
    # process, including the idle-safe snapshot that used to look like success.
    $knownStart=[datetime]::UtcNow.AddMinutes(-1)
    function Get-Process{[pscustomobject]@{StartTime=$knownStart}}
    function Get-GuardRuntimeSafety{
        [pscustomobject]@{Safe=$true;OwnedProcesses=@(@{Pid=101;Started=$knownStart});Environments=$launchEvidence}
    }
    $launchEvidence=@([pscustomobject]@{Pid=101;ApprovedPath=$true})
    Assert-GuardLaunchedRuntime 101 $knownStart ([datetime]::UtcNow.AddSeconds(5))
    foreach($mode in @('missing-main-evidence','wrong-pid','reused-pid')){
        $start=$knownStart
        $launchEvidence=@()
        if($mode -eq 'wrong-pid'){$launchEvidence=@([pscustomobject]@{Pid=999;ApprovedPath=$true})}
        if($mode -eq 'reused-pid'){$launchEvidence=@([pscustomobject]@{Pid=101;ApprovedPath=$true});$start=$knownStart.AddSeconds(1)}
        try{Assert-GuardLaunchedRuntime 101 $start ([datetime]::UtcNow.AddSeconds(5));throw 'Unexpected launch confirmation'}catch{if($_.Exception.Message -notlike 'RuntimeLaunchIdentityChanged:*'){throw}}
        $cases+=@{Scenario=$mode;Passed=$true}
    }
    Set-Item -Path Function:\Resolve-GuardReaderPython -Value $originalResolver
    function Get-GuardReaderPythonCandidates{@('python.exe','C:\WindowsApps\python.exe',(Join-Path $PSScriptRoot 'missing\python.exe'))}
    try{$null=Resolve-GuardReaderPython;throw 'Missing reader incorrectly accepted'}catch{if($_.Exception.Message -notlike 'RuntimeReaderUnavailable:*'){throw}}
    $missing=Get-GuardRuntimeSnapshot
    if($missing.Safe -or 'RuntimeReaderUnavailable' -notin $missing.Issues){throw 'Missing runtime reader must fail closed while Claude is running.'}
    $cases+=@{Scenario='missing-reader-fails-before-launch-and-in-runtime';Passed=$true}
    $cases|ConvertTo-Json
}finally{if(-not $sentinel.HasExited){$sentinel.Kill();$null=$sentinel.WaitForExit(1000)};$sentinel.Dispose()}
'@
    $incompatible=Join-Path $fixture 'incompatible'
    New-Item -ItemType Directory -Path $incompatible -Force|Out-Null
    [IO.File]::WriteAllText((Join-Path $incompatible 'python.exe'),'Invalid Windows image used only by this fixture.')
    [IO.File]::WriteAllText((Join-Path $fixture 'Read-ClaudeProcessEnvironment.py'),(@('import time','time.sleep(20)') -join $newLine))
    [IO.File]::WriteAllText((Join-Path $fixture 'runtime-runner.ps1'),$runtimeHeader+$newLine+$runtimeBody+$newLine+$runtimeFooter)
    $out=& $shell -NoProfile -File (Join-Path $fixture 'runtime-runner.ps1') 2>&1
    if($LASTEXITCODE -ne 0){throw ('Runtime timeout fixture failed: '+($out -join ' '))}
    $results+=@(($out -join $newLine)|ConvertFrom-Json)
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py') -Destination (Join-Path $fixture 'reader.py')
    $watchdog=@'
import pathlib, runpy, sys, time
pathlib.Path.read_text = lambda *a, **kw: time.sleep(20)
sys.argv = ['reader.py', '1', '--timeout-seconds', '0.2']
runpy.run_path(str(pathlib.Path(__file__).with_name('reader.py')), run_name='__main__')
'@
    [IO.File]::WriteAllText((Join-Path $fixture 'watchdog.py'),$watchdog)
    $python=Resolve-GuardReaderPython
    $timer=[Diagnostics.Stopwatch]::StartNew();$out=& $python (Join-Path $fixture 'watchdog.py') 2>&1
    if($LASTEXITCODE -ne 124 -or $out -or $timer.ElapsedMilliseconds -ge 2000){throw 'Python reader watchdog fixture failed.'}
    $results+=@{Scenario='python-reader-watchdog';Passed=$true;ExitCode=$LASTEXITCODE;ElapsedMilliseconds=$timer.ElapsedMilliseconds;EmittedEvidence=$false}
}finally{
    foreach($name in @('runtime-runner.ps1','Read-ClaudeProcessEnvironment.py','reader.py','watchdog.py','attempted','incompatible\python.exe','incompatible')){Remove-Item -LiteralPath (Join-Path $fixture $name) -ErrorAction SilentlyContinue}
    Remove-Item -LiteralPath $fixture -ErrorAction SilentlyContinue
}
$result=@{Time=[datetime]::UtcNow.ToString('o');Passed=$true;FixtureOnly=$true;ProductionProcessesTouched=$false;Cases=$results}
Write-GuardJson (Get-GuardPath 'evidence\supervisor-decision-regression.json') $result
$result|ConvertTo-Json -Depth 6
