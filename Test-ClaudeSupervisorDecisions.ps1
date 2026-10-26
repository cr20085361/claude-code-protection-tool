[CmdletBinding()]
param([string]$ProjectRoot=$PSScriptRoot)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $ProjectRoot 'ClaudeGuard.psm1') -Force
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
foreach($scenario in @('egress-drift','runtime-unsafe','tls-disabled','active-code-probe-failure','idle-probe-failure','existing-safety-hold','healthy-current-run','new-version-available','maintenance-before-hash','persisted-restart-budget','failed-start-persisted','persisted-egress-backoff','persisted-egress-success','stale-health','slow-egress','fatal-recovery-state','slow-cycle-not-resume','resume-keeps-egress-backoff','periodic-check-retains-valid-result')) {
    $fixture=Get-GuardPath ('private\supervisor-fixture-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $fixture 'private') -Force|Out-Null
    $wrapper=Join-Path $fixture 'runner.ps1'
    try {
        $header=@'
param([string]$Fixture,[string]$Scenario,[switch]$SecondRun)
$RunId='fixture-current-run';$HostPid=42;$HostStarted=[datetime]::UtcNow.ToString('o')
$script:FixtureTicks=0;$script:FixtureCycleLimit=if($Scenario -in @('stale-health','slow-cycle-not-resume','resume-keeps-egress-backoff','periodic-check-retains-valid-result')){2}else{1}
$script:StoppedProxy=0;$script:StoppedRuntime=0;$script:StartedProxy=0;$script:EgressCalls=0;$script:PolicyCalls=0;$script:HealthSnapshots=@()
function Get-GuardPath([string]$Name){Join-Path $Fixture $Name}
function Get-GuardHash([string]$Path){if($Scenario -eq 'maintenance-before-hash'){'changed-hash'}else{'fixture-hash'}}
function Read-GuardJson([string]$Path){Get-Content $Path -Raw|ConvertFrom-Json}
function Write-GuardJson([string]$Path,$Value){
    [IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 30))
    if($Path -eq (Get-GuardPath 'private\supervisor-health.json')){$script:HealthSnapshots+=@(($Value|ConvertTo-Json -Depth 30|ConvertFrom-Json))}
}
$script:FixtureState=[pscustomobject]@{Desktop=[pscustomobject]@{Version='fixture';Hash='fixture-hash';Path='fixture-desktop'};CodePaths=@('fixture-code');Reliability=[pscustomobject]@{SupervisorHash='fixture-hash';GuardHash='fixture-hash';CodeGateHash='fixture-hash';RuntimeHash='fixture-hash';EnvironmentReaderHash='fixture-hash';HealthScriptHash='fixture-hash';LifecycleScriptHash='fixture-hash'}}
function Get-GuardState{$script:FixtureState}
function Get-GuardListener{if($Scenario -notin @('persisted-restart-budget','failed-start-persisted')){@([pscustomobject]@{OwningProcess=123})}}
function Assert-GuardCore{}
function Assert-GuardPolicy{$script:PolicyCalls++;if($Scenario -eq 'tls-disabled'){throw 'TLS certificate verification is disabled in Code settings.'}}
function Assert-GuardFirewall{}
function Get-GuardDesktop{$script:FixtureState.Desktop}
function Get-Process{[pscustomobject]@{Id=123;Handle=1;HasExited=$false}}
function Get-CimInstance{if($Scenario -eq 'active-code-probe-failure'){[pscustomobject]@{ExecutablePath='fixture-code'}}}
function Get-GuardRuntimeSafety{[pscustomobject]@{Safe=($Scenario -ne 'runtime-unsafe');Issues=@('UnexpectedRuntimeNetworkPath');CodeProcessCount=if($Scenario -eq 'active-code-probe-failure'){1}else{0}}}
function Stop-GuardUnsafeRuntime{$script:StoppedRuntime++}
function Stop-GuardProxy{$script:StoppedProxy++}
function Stop-GuardProxyEmergency{$script:StoppedProxy++}
function Start-GuardProxy{$script:StartedProxy++;throw 'Fixture proxy start failed.'}
function Start-Sleep{
    $script:FixtureTicks++
    if($Scenario -eq 'stale-health'){
        $script:lastSafetyCheck=[datetime]::UtcNow.AddSeconds(-121).ToString('o');$script:lastEgressCheck=[datetime]::UtcNow.AddSeconds(-121).ToString('o')
        $script:nextSafetyCheck=[datetime]::MaxValue;$script:nextProbe=[datetime]::MaxValue
    }
    if($Scenario -eq 'resume-keeps-egress-backoff'){$script:lastTick=[datetime]::UtcNow.AddSeconds(-65)}
    if($Scenario -eq 'periodic-check-retains-valid-result'){$script:nextSafetyCheck=[datetime]::MinValue}
}
function Test-GuardEgress{
    $script:EgressCalls++
    if($Scenario -eq 'egress-drift'){throw 'Fixed egress mismatch; protected traffic must stop.'}
    if($Scenario -in @('active-code-probe-failure','idle-probe-failure')){throw 'Neutral egress probes failed; desktop startup refused.'}
    if($Scenario -eq 'slow-egress'){[Threading.Thread]::Sleep(200)}
    if($Scenario -eq 'slow-cycle-not-resume'){$script:lastTick=[datetime]::UtcNow.AddSeconds(-65)}
    [pscustomobject]@{Time=[datetime]::UtcNow.ToString('o');ProbeDegraded=$false;VerifiedProbeCount=2}
}
Write-GuardJson (Get-GuardPath 'private\proxy-process.json') @{Pid=123;Started=[datetime]::UtcNow.ToString('o')}
if($Scenario -eq 'new-version-available'){Write-GuardJson (Get-GuardPath 'private\version-update-status.json') @{SchemaVersion=1;Status='Checked';CheckedAt=[datetime]::UtcNow.ToString('o');LastSuccess=@{LatestDesktopVersion='99.0.0'}}}
if($Scenario -eq 'existing-safety-hold'){Write-GuardJson (Get-GuardPath 'private\safety-hold.json') @{Reason='previous-fixed-egress-mismatch'}}
if($Scenario -eq 'maintenance-before-hash'){Write-GuardJson (Get-GuardPath 'private\maintenance.json') @{Until=[datetime]::UtcNow.AddMinutes(2).ToString('o')}}
if(-not $SecondRun -and $Scenario -in @('active-code-probe-failure','idle-probe-failure','persisted-restart-budget','persisted-egress-backoff','persisted-egress-success','resume-keeps-egress-backoff')){
    $attempts=if($Scenario -eq 'persisted-restart-budget'){@([datetime]::UtcNow.AddSeconds(-3).ToString('o'),[datetime]::UtcNow.AddSeconds(-2).ToString('o'),[datetime]::UtcNow.AddSeconds(-1).ToString('o'))}else{@()}
    $next=if($Scenario -in @('persisted-egress-backoff','resume-keeps-egress-backoff')){[datetime]::UtcNow.AddSeconds(120)}else{[datetime]::UtcNow.AddSeconds(-1)}
    Write-GuardJson (Get-GuardPath 'private\proxy-recovery.json') @{SchemaVersion=1;RestartTimes=@($attempts|Where-Object {$_});NextRestart=[datetime]::UtcNow.AddSeconds(-1).ToString('o');ConsecutiveEgressFailures=if($Scenario -eq 'persisted-restart-budget'){0}else{2};NextProbe=$next.ToString('o')}
}
if($Scenario -eq 'fatal-recovery-state'){[IO.File]::WriteAllText((Get-GuardPath 'private\proxy-recovery.json'),'invalid-json')}
'@
        $footer=@'
}finally{Write-GuardJson (Get-GuardPath 'counts.json') @{StoppedProxy=$script:StoppedProxy;StoppedRuntime=$script:StoppedRuntime;StartedProxy=$script:StartedProxy;EgressCalls=$script:EgressCalls;PolicyCalls=$script:PolicyCalls;HealthSnapshots=$script:HealthSnapshots;NextSafetyUtc=$nextSafetyCheck.ToUniversalTime().ToString('o');NextSafetyTicks=$nextSafetyCheck.Ticks;NextProbeTicks=$nextProbe.Ticks}}
'@
        [IO.File]::WriteAllText($wrapper,$header+$newLine+'try{'+$newLine+$body+$newLine+$footer)
        $output=& $shell -NoProfile -File $wrapper -Fixture $fixture -Scenario $scenario 2>&1
        if($LASTEXITCODE -ne 0 -and $scenario -ne 'fatal-recovery-state'){throw ('Supervisor fixture execution failed: '+$scenario+' '+($output -join ' '))}
        $health=Read-GuardJson (Join-Path $fixture 'private\supervisor-health.json')
        $counts=Read-GuardJson (Join-Path $fixture 'counts.json')
        $held=Test-Path (Join-Path $fixture 'private\safety-hold.json')
        $recovery=if(Test-Path (Join-Path $fixture 'private\proxy-recovery.json')){if($scenario -ne 'fatal-recovery-state'){Read-GuardJson (Join-Path $fixture 'private\proxy-recovery.json')}}
        $passed=switch($scenario){
            'egress-drift' {$health.Status -eq 'SafetyHold' -and $held -and $counts.StoppedProxy -eq 1}
            'runtime-unsafe' {$health.Status -eq 'SafetyHold' -and $held -and $counts.StoppedRuntime -eq 1 -and $counts.StoppedProxy -eq 1}
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
        if(-not $passed -or -not $contract -or -not $preparing){throw ('Supervisor decision regression failed: '+$scenario+' health='+($health|ConvertTo-Json -Compress)+' counts='+($counts|ConvertTo-Json -Compress -Depth 3))}
        if($scenario -eq 'healthy-current-run'){
            if([long]$counts.NextSafetyTicks -ne ([datetimeoffset]$health.LastSafetyCheck).UtcDateTime.AddSeconds(60).Ticks -or [long]$counts.NextProbeTicks -ne ([datetimeoffset]$health.LastEgressCheck).UtcDateTime.AddSeconds(60).Ticks){throw 'UTC completion strings shifted the next check schedule into local clock ticks.'}
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
        foreach($name in @('private\version-update-status.json','private\proxy-process.json','private\supervisor-events.jsonl','private\supervisor-health.json','private\safety-hold.json','private\runtime-safety.json','private\last-good-egress.json','private\maintenance.json','private\proxy-recovery.json','counts.json','runner.ps1')){Remove-Item -LiteralPath (Join-Path $fixture $name) -ErrorAction SilentlyContinue}
        Remove-Item -LiteralPath (Join-Path $fixture 'private'),$fixture -ErrorAction SilentlyContinue
    }
}
# 原生 reader 与 runtime 总证据预算均在隔离子进程验证，不读取或停止生产 Claude。
$fixture=Get-GuardPath ('private\supervisor-fixture-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture -Force|Out-Null
try {
    $runtimeBody=Get-FixtureSource (Get-Content (Join-Path $PSScriptRoot 'ClaudeGuard-Runtime.psm1') -Raw)
    # Only the isolated runner uses PATH Python; production deployment retains its reviewed interpreter path.
    $runtimeBody=$runtimeBody.Replace("`$python=Join-Path `$env:LOCALAPPDATA 'Programs\Python\Python311\python.exe'","`$python=(Get-Command python -ErrorAction Stop).Source")
    $runtimeHeader=@'
$ErrorActionPreference='Stop'
function Get-GuardState{[pscustomobject]@{Desktop=[pscustomobject]@{Path='fixture-desktop'};CodePaths=@('fixture-code')}}
function Get-CimInstance{@([pscustomobject]@{ExecutablePath='fixture-desktop';CommandLine='--proxy-server=http://127.0.0.1:10818';ProcessId=101;ParentProcessId=1},[pscustomobject]@{ExecutablePath='fixture-code';CommandLine='';ProcessId=102;ParentProcessId=1},[pscustomobject]@{ExecutablePath='fixture-code';CommandLine='';ProcessId=103;ParentProcessId=1})}
function Get-NetTCPConnection{}
function Get-Process{[pscustomobject]@{StartTime=[datetime]::UtcNow}}
'@
    $runtimeFooter=@'
$python=(Get-Command python -ErrorAction Stop).Source
$info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$python;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
$info.ArgumentList.Add('-c');$info.ArgumentList.Add('import time; time.sleep(20)')
$sentinel=[Diagnostics.Process]::Start($info)
$cases=@()
try{
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $runtime=Get-GuardRuntimeSafety -EvidenceBudgetMilliseconds 200 -ReaderTimeoutMilliseconds 1000
    $passed=-not $runtime.Safe -and 'RuntimeEnvironmentUnreadable' -in $runtime.Issues -and $runtime.EvidenceDeadlineExceeded -and $clock.ElapsedMilliseconds -lt 2000 -and -not $sentinel.HasExited
    if(-not $passed){throw ('Runtime reader deadline failed: '+($runtime|ConvertTo-Json -Depth 10 -Compress))}
    $cases+=@{Scenario='runtime-reader-total-timeout';Passed=$true;ElapsedMilliseconds=$clock.ElapsedMilliseconds;UnrelatedFixtureProcessAlive=(-not $sentinel.HasExited)}
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py'),"print('{}')")
    $invalid=Get-GuardRuntimeSafety -EvidenceBudgetMilliseconds 3000 -ReaderTimeoutMilliseconds 1000
    if($invalid.Safe -or 'RuntimeEnvironmentUnreadable' -notin $invalid.Issues){throw 'Malformed reader evidence must remain unreadable and unsafe.'}
    $cases+=@{Scenario='runtime-reader-malformed-evidence';Passed=$true;Safe=$invalid.Safe}
    $validReader="import json, sys"+[Environment]::NewLine+"print(json.dumps(dict(Pid=int(sys.argv[1]),ApprovedPath=True,ConfigDirMatches=True,HttpProxyMatches=True,HttpsProxyMatches=True,AllProxyMatches=True,NoProxyOnlyLoopback=True,TlsVerificationEnabled=True,UnexpectedTlsOverrideNames=[],UnexpectedProviderOverrideNames=[])))"
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py'),$validReader)
    $valid=Get-GuardRuntimeSafety -EvidenceBudgetMilliseconds 3000 -ReaderTimeoutMilliseconds 1000
    if(-not $valid.Safe -or @($valid.Environments).Count -ne 3){throw 'Valid reader evidence did not retain existing safe approval.'}
    $cases+=@{Scenario='runtime-reader-valid-evidence';Passed=$true;Safe=$valid.Safe;EnvironmentCount=@($valid.Environments).Count}
    $script:FixtureConnections=@();$script:FixtureListeners=@()
    function Get-NetTCPConnection{param($State) if($State -eq 'Listen'){$script:FixtureListeners}else{$script:FixtureConnections}}
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
        $script:FixtureConnections=@([pscustomobject]@{OwningProcess=101;RemoteAddress=$case.Address;RemotePort=$case.Port;State=$case.State})
        $script:FixtureListeners=if($case.Listener){@([pscustomobject]@{OwningProcess=102;LocalPort=$case.Port})}else{@()}
        $observed=Get-GuardRuntimeSafety -EvidenceBudgetMilliseconds 3000 -ReaderTimeoutMilliseconds 1000
        if($observed.Safe -ne $case.Safe -or @($observed.UnconfirmedLoopbackConnections).Count -ne $case.Pending -or (@($observed.UnexpectedConnections).Count -gt 0) -eq $case.Safe){throw ('Network decision fixture failed: '+$case.Name+' '+($observed|ConvertTo-Json -Depth 8 -Compress))}
        $cases+=@{Scenario=$case.Name;Passed=$true;Safe=$observed.Safe;UnconfirmedLoopbackCount=@($observed.UnconfirmedLoopbackConnections).Count}
    }
    $cases|ConvertTo-Json
}finally{if(-not $sentinel.HasExited){$sentinel.Kill();$null=$sentinel.WaitForExit(1000)};$sentinel.Dispose()}
'@
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
    $python=(Get-Command python -ErrorAction Stop).Source
    $timer=[Diagnostics.Stopwatch]::StartNew();$out=& $python (Join-Path $fixture 'watchdog.py') 2>&1
    if($LASTEXITCODE -ne 124 -or $out -or $timer.ElapsedMilliseconds -ge 2000){throw 'Python reader watchdog fixture failed.'}
    $results+=@{Scenario='python-reader-watchdog';Passed=$true;ExitCode=$LASTEXITCODE;ElapsedMilliseconds=$timer.ElapsedMilliseconds;EmittedEvidence=$false}
}finally{
    foreach($name in @('runtime-runner.ps1','Read-ClaudeProcessEnvironment.py','reader.py','watchdog.py')){Remove-Item -LiteralPath (Join-Path $fixture $name) -ErrorAction SilentlyContinue}
    Remove-Item -LiteralPath $fixture -ErrorAction SilentlyContinue
}
$result=@{Time=[datetime]::UtcNow.ToString('o');Passed=$true;FixtureOnly=$true;ProductionProcessesTouched=$false;Cases=$results}
Write-GuardJson (Get-GuardPath 'evidence\supervisor-decision-regression.json') $result
$result|ConvertTo-Json -Depth 6
