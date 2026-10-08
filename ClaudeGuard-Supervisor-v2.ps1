[CmdletBinding()]
param([string]$RunId='',[int]$HostPid=0,[string]$HostStarted='')
$ErrorActionPreference='Stop'
$supervisorStarted=[Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToString('o')
try {
    Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-Runtime.psm1') -Force
}catch{
    # 模块初始化失败也保留可核查 fatal；不依赖尚未成功导入的函数。
    $fatalReason=$_.Exception.Message;$fatalTime=[datetime]::UtcNow.ToString('o')
    try{
        $fatalLog=Join-Path $PSScriptRoot 'private\supervisor-events.jsonl'
        [IO.File]::AppendAllText($fatalLog,(@{Time=$fatalTime;Kind='SupervisorFatal';Data=@{Pid=$PID;RunId=$RunId;Reason=$fatalReason}}|ConvertTo-Json -Compress)+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
        $fatalHealth=Join-Path $PSScriptRoot 'private\supervisor-health.json';$fatalTemp=$fatalHealth+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
        [IO.File]::WriteAllText($fatalTemp,(@{SchemaVersion=2;Time=$fatalTime;RunId=$RunId;HostPid=$HostPid;HostStarted=$HostStarted;SupervisorPid=$PID;SupervisorStarted=$supervisorStarted;Phase='Fatal';PhaseStarted=$fatalTime;Status='ProtectionError';Reason=$fatalReason;LastSafetyCheck=$null;LastEgressCheck=$null;LastEgressAttempt=$null;LastVerifiedEgress=$null;SafetyHold=(Test-Path -LiteralPath (Join-Path $PSScriptRoot 'private\safety-hold.json'));ProxyPid=$null;ConsecutiveFailures=0;NextProbe=$null;NextRestart=$null;ApprovedVersion=$null;ActiveCodeProcessCount=0}|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
        [IO.File]::Move($fatalTemp,$fatalHealth,$true)
    }catch{}
    throw
}
$mutex=[Threading.Mutex]::new($false,'Local\ClaudeProGuardSupervisor-v1')
$held=$false
try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
if(-not $held){$mutex.Dispose();exit 0}
$log=Get-GuardPath 'private\supervisor-events.jsonl'
$healthPath=Get-GuardPath 'private\supervisor-health.json'
$recoveryPath=Get-GuardPath 'private\proxy-recovery.json'
$owned=$null
$failures=0
$nextProbe=[datetime]::MinValue
$nextRestart=[datetime]::MinValue
$lastStatus=''
$nextVersionCheck=[datetime]::MinValue
$current=$null
$lastEgress=$null
$lastSafetyCheck=$null
$lastEgressCheck=$null
$lastEgressAttempt=$null
$safetyHold=$null
$holdPath=Get-GuardPath 'private\safety-hold.json'
$lastTick=[datetime]::UtcNow
$nextSafetyCheck=[datetime]::MinValue
$activeCodeCount=0
$restartTimes=[Collections.Generic.List[datetime]]::new()
$deployment=$null
$status='Starting'
$reason=$null
$proxyPid=$null
$phase='Starting'
$phaseStarted=[datetime]::UtcNow.ToString('o')
function Write-SupervisorEvent([string]$Kind,$Data) {
    if((Test-Path $log) -and (Get-Item $log).Length -gt 2097152){[IO.File]::Move($log,$log+'.previous',$true)}
    [IO.File]::AppendAllText($log,(@{Time=[datetime]::UtcNow.ToString('o');Kind=$Kind;Data=$Data}|ConvertTo-Json -Depth 6 -Compress)+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
}
function Write-SupervisorHealth {
    $health=[ordered]@{
        SchemaVersion=2;Time=[datetime]::UtcNow.ToString('o');RunId=$RunId;HostPid=$HostPid;HostStarted=$HostStarted
        SupervisorPid=$PID;SupervisorStarted=$supervisorStarted;Phase=$phase;PhaseStarted=$phaseStarted
        LastSafetyCheck=$lastSafetyCheck;LastEgressCheck=$lastEgressCheck;LastEgressAttempt=$lastEgressAttempt
        Status=$status;Reason=$reason;ProxyPid=$proxyPid;ConsecutiveFailures=$failures
        NextProbe=$nextProbe.ToUniversalTime().ToString('o');NextRestart=$nextRestart.ToUniversalTime().ToString('o')
        ApprovedVersion=if($deployment){$deployment.Desktop.Version}else{$null}
        ActiveCodeProcessCount=$activeCodeCount;LastVerifiedEgress=$lastEgress;SafetyHold=[bool]$safetyHold
    }
    Write-GuardJson $healthPath $health
    if($status -ne $lastStatus){Write-SupervisorEvent 'StatusChanged' $health;$script:lastStatus=$status}
}
function Set-SupervisorPhase([string]$Name) {
    $script:phase=$Name;$script:phaseStarted=[datetime]::UtcNow.ToString('o')
    # 周期检查期间只复用本次运行已经完成且仍有效的结果；首轮检查始终为 Checking。
    $checkNow=[datetime]::UtcNow
    $validSafety=$lastSafetyCheck -and ($checkNow-([datetime]$lastSafetyCheck).ToUniversalTime()).TotalSeconds -ge 0 -and ($checkNow-([datetime]$lastSafetyCheck).ToUniversalTime()).TotalSeconds -le 120
    $validEgress=$lastEgressCheck -and ($checkNow-([datetime]$lastEgressCheck).ToUniversalTime()).TotalSeconds -ge 0 -and ($checkNow-([datetime]$lastEgressCheck).ToUniversalTime()).TotalSeconds -le 120
    $script:status=if(-not $failures -and $validSafety -and $validEgress -and $lastEgress){if($lastEgress.ProbeDegraded){'ProbeDegraded'}else{'Healthy'}}else{'Checking'}
    Write-SupervisorEvent 'PhaseStarted' @{Phase=$Name;PhaseStarted=$phaseStarted}
    Write-SupervisorHealth
}
function Complete-SupervisorPhase {
    Write-SupervisorEvent 'PhaseCompleted' @{Phase=$phase;Completed=[datetime]::UtcNow.ToString('o')}
    Write-SupervisorHealth
}
function Save-SupervisorRecovery {
    Write-GuardJson $recoveryPath @{SchemaVersion=1;Updated=[datetime]::UtcNow.ToString('o');RestartTimes=@($restartTimes|ForEach-Object {$_.ToUniversalTime().ToString('o')});NextRestart=$nextRestart.ToUniversalTime().ToString('o');ConsecutiveEgressFailures=$failures;NextProbe=$nextProbe.ToUniversalTime().ToString('o')}
}
function Assert-SupervisorHashes {
    if(-not $deployment.PSObject.Properties['Reliability']){throw 'Supervisor deployment or script changed.'}
    $hashes=@{SupervisorHash=$PSCommandPath;GuardHash=(Get-GuardPath 'ClaudeGuard.psm1');CodeGateHash=(Get-GuardPath 'ClaudeCodeGate.psm1');RuntimeHash=(Get-GuardPath 'ClaudeGuard-Runtime.psm1');EnvironmentReaderHash=(Get-GuardPath 'Read-ClaudeProcessEnvironment.py')}
    foreach($entry in $hashes.GetEnumerator()){
        if(-not $deployment.Reliability.PSObject.Properties[$entry.Key] -or (Get-GuardHash $entry.Value) -ne $deployment.Reliability.($entry.Key)){throw 'Supervisor deployment or script changed.'}
    }
    foreach($entry in @(@{Name='HealthScriptHash';Path='ClaudeGuard-Health.ps1'},@{Name='LifecycleScriptHash';Path='ClaudeGuard-Lifecycle.ps1'})){
        if($deployment.Reliability.PSObject.Properties[$entry.Name] -and (Get-GuardHash (Get-GuardPath $entry.Path)) -ne $deployment.Reliability.($entry.Name)){throw 'Supervisor deployment or script changed.'}
    }
}
try {
    # 首次耗时检查前发布当前进程身份；历史健康与恢复状态都不能核准本次 worker。
    Write-SupervisorHealth
    Write-SupervisorEvent 'SupervisorStarted' @{Pid=$PID;Started=$supervisorStarted;RunId=$RunId;HostPid=$HostPid;HostStarted=$HostStarted}
    if(Test-Path $holdPath){$safetyHold=(Read-GuardJson $holdPath).Reason}
    if(Test-Path $recoveryPath){
        $saved=Read-GuardJson $recoveryPath
        if($saved.SchemaVersion -ne 1 -or [int]$saved.ConsecutiveEgressFailures -lt 0){throw 'Proxy recovery state is invalid; reviewed maintenance is required.'}
        $failures=[int]$saved.ConsecutiveEgressFailures
        $nextProbe=([datetime]$saved.NextProbe).ToUniversalTime();$nextRestart=([datetime]$saved.NextRestart).ToUniversalTime()
        foreach($stamp in @($saved.RestartTimes|Where-Object {$_})){$restartTimes.Add(([datetime]$stamp).ToUniversalTime())}
        Write-SupervisorEvent 'RecoveryStateLoaded' @{RestartAttemptCount=$restartTimes.Count;ConsecutiveEgressFailures=$failures;NextProbe=$nextProbe.ToString('o');NextRestart=$nextRestart.ToString('o')}
    }
    while($true) {
        $now=[datetime]::UtcNow
        if([Math]::Abs(($now-$lastTick).TotalSeconds) -gt 60){Write-SupervisorEvent 'ResumeOrClockGap' @{GapSeconds=[Math]::Round(($now-$lastTick).TotalSeconds,1)};if(-not $failures){$nextProbe=[datetime]::MinValue};$nextSafetyCheck=[datetime]::MinValue}
        $status='Checking';$reason=$null;$proxyPid=$null
        try {
            # 有效维护先于任何部署哈希检查或代理操作，以便受控替换组件。
            $maintenance=Get-GuardPath 'private\maintenance.json'
            if(Test-Path $maintenance){
                $m=Read-GuardJson $maintenance
                if(([datetime]$m.Until).ToUniversalTime() -gt $now -and ([datetime]$m.Until).ToUniversalTime() -lt $now.AddMinutes(10)){
                    $status='Maintenance';$phase='Maintenance';$phaseStarted=[datetime]::UtcNow.ToString('o');$reason='专用组件维护中';throw [OperationCanceledException]::new('maintenance')
                }
            }
            if($safetyHold){$status='SafetyHold';$phase='SafetyHold';$phaseStarted=[datetime]::UtcNow.ToString('o');$reason=$safetyHold;throw [OperationCanceledException]::new('safety-hold')}
            $deployment=Get-GuardState
            Set-SupervisorPhase 'Policy'
            Assert-SupervisorHashes
            if($owned -and $owned.HasExited){
                $owned.WaitForExit();Write-SupervisorEvent 'ProxyExited' @{Pid=$owned.Id;ExitCode=$owned.ExitCode;ObservedAt=[datetime]::UtcNow.ToString('o')}
                $owned.Dispose();$owned=$null
            }
            if(-not @(Get-GuardListener).Count){
                if($now -lt $nextRestart){$status='Backoff';$reason='等待有限重试';throw [OperationCanceledException]::new('backoff')}
                for($i=$restartTimes.Count-1;$i -ge 0;$i--){if($restartTimes[$i] -lt $now.AddMinutes(-5)){$restartTimes.RemoveAt($i)}}
                if($restartTimes.Count -ge 3){$nextRestart=$now.AddMinutes(5);Save-SupervisorRecovery;$status='Backoff';$reason='专用代理反复退出，五分钟后重试';throw [OperationCanceledException]::new('backoff')}
                # 先保存尝试次数，失败的启动与 worker 重启也占用同一个恢复预算。
                $restartTimes.Add($now);Save-SupervisorRecovery
                Start-GuardProxy -SupervisorWorker
                $tracked=Read-GuardJson (Get-GuardPath 'private\proxy-process.json')
                $owned=Get-Process -Id $tracked.Pid;$null=$owned.Handle
                Write-SupervisorEvent 'ProxyStarted' @{Pid=$tracked.Pid;ProcessStart=$tracked.Started}
                $nextProbe=[datetime]::MinValue;Save-SupervisorRecovery
            }
            Assert-GuardCore
            $proxyPid=(Read-GuardJson (Get-GuardPath 'private\proxy-process.json')).Pid
            if(-not $owned){$owned=Get-Process -Id $proxyPid;$null=$owned.Handle;Write-SupervisorEvent 'ProxyAdopted' @{Pid=$proxyPid}}
            if($now -ge $nextSafetyCheck -or -not $lastSafetyCheck){
                Assert-GuardPolicy -RuntimeOnly
                Complete-SupervisorPhase
                Set-SupervisorPhase 'Firewall';Assert-GuardFirewall;Complete-SupervisorPhase
                Set-SupervisorPhase 'Runtime'
                $runtime=Get-GuardRuntimeSafety;$activeCodeCount=$runtime.CodeProcessCount
                Write-GuardJson (Get-GuardPath 'private\runtime-safety.json') $runtime
                if(-not $runtime.Safe){Stop-GuardUnsafeRuntime $runtime;throw ('Runtime safety mismatch: '+($runtime.Issues -join ','))}
                $lastSafetyCheck=[datetime]::UtcNow.ToString('o');$nextSafetyCheck=([datetime]$lastSafetyCheck).ToUniversalTime().AddSeconds(60)
                Complete-SupervisorPhase
            }else{Complete-SupervisorPhase}
            if([datetime]::UtcNow -ge $nextProbe){
                Set-SupervisorPhase 'Egress';$lastEgressAttempt=[datetime]::UtcNow.ToString('o');Write-SupervisorHealth
                try {
                    $egress=Test-GuardEgress
                    $lastEgress=$egress;$lastEgressCheck=[datetime]::UtcNow.ToString('o')
                    Write-SupervisorEvent 'EgressVerified' @{Completed=$lastEgressCheck;VerifiedProbeCount=$egress.VerifiedProbeCount;ProbeDegraded=$egress.ProbeDegraded}
                    $failures=0;$nextProbe=([datetime]$lastEgressCheck).ToUniversalTime().AddSeconds(60);Save-SupervisorRecovery
                    Write-GuardJson (Get-GuardPath 'private\last-good-egress.json') $egress
                    Complete-SupervisorPhase
                }catch{
                    if($_.Exception.Message -match 'Fixed egress mismatch'){throw}
                    $failures++;$reason=$_.Exception.Message
                    $nextProbe=[datetime]::UtcNow.AddSeconds([Math]::Min(300,30*[Math]::Pow(2,[Math]::Min(4,$failures-1))));Save-SupervisorRecovery
                    Write-SupervisorEvent 'EgressFailed' @{Completed=[datetime]::UtcNow.ToString('o');ConsecutiveFailures=$failures;Reason=$reason}
                    $liveCode=@(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -in @($deployment.CodePaths)}).Count
                    if($failures -eq 3 -and $liveCode -eq 0){Stop-GuardProxy;Write-SupervisorEvent 'ProxyRefreshRequested' @{Reason='three-consecutive-egress-failures'}}
                    elseif($failures -eq 3){Write-SupervisorEvent 'ProxyRefreshDeferred' @{Reason='active-local-code-session';CodeProcessCount=$liveCode}}
                }
            }
            Set-SupervisorPhase 'Version'
            if(-not $current -or [datetime]::UtcNow -ge $nextVersionCheck){$current=Get-GuardDesktop;$nextVersionCheck=[datetime]::UtcNow.AddSeconds(60)}
            Complete-SupervisorPhase
            $safetyAge=if($lastSafetyCheck){([datetime]::UtcNow-([datetime]$lastSafetyCheck).ToUniversalTime()).TotalSeconds}else{-1}
            $egressAge=if($lastEgressCheck){([datetime]::UtcNow-([datetime]$lastEgressCheck).ToUniversalTime()).TotalSeconds}else{-1}
            $freshSafety=$lastSafetyCheck -and $safetyAge -ge 0 -and $safetyAge -le 120
            $freshEgress=$lastEgressCheck -and $egressAge -ge 0 -and $egressAge -le 120
            $status=if($failures){'UpstreamUnavailable'}elseif(-not $freshSafety -or -not $freshEgress){'Checking'}elseif($lastEgress.ProbeDegraded){'ProbeDegraded'}else{'Healthy'}
            if($current.Hash -ne $deployment.Desktop.Hash -or $current.Path -ne $deployment.Desktop.Path){$status='UpgradeRequired';$reason='Claude 已更新，需迁移防护后使用'}
            $phase='Idle';$phaseStarted=[datetime]::UtcNow.ToString('o')
        }catch [OperationCanceledException] {
        }catch{
            $reason=$_.Exception.Message
            if($reason -match 'Fixed egress mismatch|Runtime safety mismatch|changed|disabled|IPv4-only|Firewall rule|Shared proxy|policy|execution gate'){
                $safetyHold=$reason;Write-GuardJson $holdPath @{Time=[datetime]::UtcNow.ToString('o');Reason=$reason}
                Stop-GuardProxyEmergency;$status='SafetyHold';$phase='SafetyHold';$phaseStarted=[datetime]::UtcNow.ToString('o')
                Write-SupervisorEvent 'SafetyStop' @{Reason=$reason}
            }else{
                $status=if($reason -match 'interface unavailable'){'InterfaceUnavailable'}elseif($reason -match 'Desktop updated'){'UpgradeRequired'}else{'ProtectionError'}
                $nextRestart=[datetime]::UtcNow.AddSeconds(30);Save-SupervisorRecovery
            }
        }
        Write-SupervisorHealth
        # 只统计循环之间的空闲间隔，防火墙等检查自身的耗时不构成睡眠唤醒。
        $lastTick=[datetime]::UtcNow
        Start-Sleep -Seconds 5
    }
}catch{
    $reason=$_.Exception.Message;$status='ProtectionError';$phase='Fatal';$phaseStarted=[datetime]::UtcNow.ToString('o')
    try{Write-SupervisorEvent 'SupervisorFatal' @{Pid=$PID;RunId=$RunId;Reason=$reason};Write-SupervisorHealth}catch{}
    throw
}finally{
    try{Write-SupervisorEvent 'SupervisorStopped' @{Pid=$PID;RunId=$RunId}}finally{if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
}
