[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$mutex=[Threading.Mutex]::new($false,'Local\ClaudeProGuardSupervisor-v1')
$held=$false
try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
if(-not $held){$mutex.Dispose();exit 0}
$log=Get-GuardPath 'private\supervisor-events.jsonl'
$healthPath=Get-GuardPath 'private\supervisor-health.json'
$owned=$null
$failures=0
$nextProbe=[datetime]::MinValue
$nextRestart=[datetime]::MinValue
$lastStatus=''
$nextVersionCheck=[datetime]::MinValue
$current=$null
$restartTimes=[Collections.Generic.List[datetime]]::new()
function Write-SupervisorEvent([string]$Kind,$Data) {
    if((Test-Path $log) -and (Get-Item $log).Length -gt 2097152){[IO.File]::Move($log,$log+'.previous',$true)}
    [IO.File]::AppendAllText($log,(@{Time=(Get-Date -Format o);Kind=$Kind;Data=$Data}|ConvertTo-Json -Depth 6 -Compress)+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
}
Write-SupervisorEvent 'SupervisorStarted' @{Pid=$PID;ScriptHash=(Get-GuardHash $PSCommandPath)}
try {
    while($true) {
        $now=Get-Date
        $status='Checking'
        $reason=$null
        $egress=$null
        $proxyPid=$null
        $deployment=Get-GuardState
        try {
            if(-not $deployment.PSObject.Properties['Reliability'] -or (Get-GuardHash $PSCommandPath) -ne $deployment.Reliability.SupervisorHash){throw 'Supervisor deployment or script changed.'}
            if($owned -and $owned.HasExited) {
                $owned.WaitForExit()
                Write-SupervisorEvent 'ProxyExited' @{Pid=$owned.Id;ExitCode=$owned.ExitCode;ObservedAt=(Get-Date -Format o)}
                $owned.Dispose();$owned=$null
            }
            $maintenance=Get-GuardPath 'private\maintenance.json'
            if(Test-Path $maintenance) {
                $m=Read-GuardJson $maintenance
                if([datetime]$m.Until -gt $now -and [datetime]$m.Until -lt $now.AddMinutes(10)) {
                    $status='Maintenance';$reason='专用组件维护中';throw [OperationCanceledException]::new('maintenance')
                }
            }
            if(-not @(Get-GuardListener).Count) {
                if($now -lt $nextRestart){$status='Backoff';$reason='等待有限重试';throw [OperationCanceledException]::new('backoff')}
                # 至多五分钟内启动三次，随后退避五分钟；不触碰共用代理。
                for($i=$restartTimes.Count-1;$i -ge 0;$i--){if($restartTimes[$i] -lt $now.AddMinutes(-5)){$restartTimes.RemoveAt($i)}}
                if($restartTimes.Count -ge 3){$nextRestart=$now.AddMinutes(5);$status='Backoff';$reason='专用代理反复退出，五分钟后重试';throw [OperationCanceledException]::new('backoff')}
                Start-GuardProxy -SupervisorWorker
                $tracked=Read-GuardJson (Get-GuardPath 'private\proxy-process.json')
                $owned=Get-Process -Id $tracked.Pid
                $null=$owned.Handle
                $restartTimes.Add($now)
                Write-SupervisorEvent 'ProxyStarted' @{Pid=$tracked.Pid;ProcessStart=$tracked.Started}
                $nextProbe=[datetime]::MinValue
            }
            Assert-GuardCore
            $proxyPid=(Read-GuardJson (Get-GuardPath 'private\proxy-process.json')).Pid
            if(-not $owned){$owned=Get-Process -Id $proxyPid;$null=$owned.Handle;Write-SupervisorEvent 'ProxyAdopted' @{Pid=$proxyPid}}
            if($now -ge $nextProbe) {
                try {
                    $egress=Test-GuardEgress
                    $failures=0
                    $nextProbe=(Get-Date).AddSeconds(60)
                    Write-GuardJson (Get-GuardPath 'private\last-good-egress.json') $egress
                } catch {
                    $failures++
                    $reason=$_.Exception.Message
                    $nextProbe=(Get-Date).AddSeconds([Math]::Min(300,30*[Math]::Pow(2,[Math]::Min(4,$failures-1))))
                    Write-SupervisorEvent 'EgressFailed' @{ConsecutiveFailures=$failures;Reason=$reason}
                    # 仅第三次连续失败时刷新一次本组件；持续上游故障不无限重启。
                    if($failures -eq 3) {
                        Stop-GuardProxy
                        Write-SupervisorEvent 'ProxyRefreshRequested' @{Reason='three-consecutive-egress-failures'}
                    }
                }
            }
            $status=if($failures){'UpstreamUnavailable'}else{'Healthy'}
            if(-not $current -or $now -ge $nextVersionCheck){$current=Get-GuardDesktop;$nextVersionCheck=(Get-Date).AddSeconds(60)}
            if($current.Hash -ne $deployment.Desktop.Hash -or $current.Path -ne $deployment.Desktop.Path){$status='UpgradeRequired';$reason='Claude 已更新，需迁移防护后使用'}
        } catch [OperationCanceledException] {
        } catch {
            $status='ProtectionError';$reason=$_.Exception.Message
            $nextRestart=(Get-Date).AddSeconds(30)
        }
        $health=[ordered]@{Time=(Get-Date -Format o);SupervisorPid=$PID;Status=$status;Reason=$reason;ProxyPid=$proxyPid;ConsecutiveFailures=$failures;NextProbe=$nextProbe.ToString('o');NextRestart=$nextRestart.ToString('o');ApprovedVersion=$deployment.Desktop.Version}
        Write-GuardJson $healthPath $health
        if($status -ne $lastStatus){Write-SupervisorEvent 'StatusChanged' $health;$lastStatus=$status}
        Start-Sleep -Seconds 5
    }
} finally {
    Write-SupervisorEvent 'SupervisorStopped' @{Pid=$PID}
    if($held){$mutex.ReleaseMutex()};$mutex.Dispose()
}
