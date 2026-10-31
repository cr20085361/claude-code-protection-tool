[CmdletBinding()]
param([ValidateSet('Budget','Host','Hang')][string]$Mode='Budget')
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$state=Get-GuardState
$result=[ordered]@{Time=(Get-Date -Format o);Mode=$Mode;ActualScheduledTask=$true;Status='RUNNING';ClaudePreserved=$false;ProxyPreserved=$false;Error=$null;Steps=@()}
$path=Get-GuardPath ('evidence\supervisor-native-'+$Mode.ToLowerInvariant()+'.json')
function Save-NativeResult {$result|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $path -Encoding utf8}
function Read-HostRecovery {Read-GuardJson (Get-GuardPath 'private\supervisor-host-recovery.json')}
function Get-HostEvents {@(Get-Content -LiteralPath (Get-GuardPath 'private\host-events.jsonl')|ForEach-Object{try{$_|ConvertFrom-Json}catch{}})}
function Require-Ready([int]$Seconds=180){
    $end=[datetime]::UtcNow.AddSeconds($Seconds)
    do{$snapshot=Get-GuardSupervisorSnapshot;if($snapshot.Ready){return $snapshot.Health};if(Test-Path -LiteralPath (Get-GuardPath 'private\safety-hold.json')){throw 'SafetyHold appeared during native recovery.'};if([datetime]::UtcNow -ge $end){throw ('Native recovery timed out: '+$snapshot.Reason)};Start-Sleep -Seconds 2}while($true)
}
function Bind-Identity([int]$ProcessId,[string]$ExpectedPath,$Started){
    $process=Get-Process -Id $ProcessId -ErrorAction Stop;$null=$process.Handle
    if($process.Path -ne $ExpectedPath -or $process.StartTime.ToUniversalTime().Ticks -ne ([datetimeoffset]$Started).UtcTicks){$process.Dispose();throw 'Native fault target identity changed.'}
    return $process
}
function Check-Preserved {
    $p=Get-Process -Id $proxy.Id -ErrorAction Stop
    if($p.Path -ne $proxy.Path -or $p.StartTime.ToUniversalTime().Ticks -ne $proxy.StartedTicks){throw 'Dedicated proxy identity changed during guardian fault.'}
    if(-not @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 10818 -State Listen -ErrorAction Stop|Where-Object OwningProcess -eq $proxy.Id).Count){throw 'Dedicated proxy listener disappeared.'}
    foreach($desktop in $desktops){$p=Get-Process -Id $desktop.Id -ErrorAction Stop;if($p.StartTime.ToUniversalTime().Ticks -ne $desktop.StartedTicks -or $p.Path -ne $desktop.Path){throw 'Existing Claude desktop identity changed during guardian fault.'}}
    $result.ProxyPreserved=$true;$result.ClaudePreserved=($desktops.Count -gt 0)
}
function Wait-NewWorker([string]$PriorRunId,[int]$Seconds=150){
    $end=[datetime]::UtcNow.AddSeconds($Seconds)
    do{Check-Preserved;$identity=Read-GuardJson (Get-GuardPath 'private\supervisor-host-identity.json');if($identity.RunId -ne $PriorRunId){try{$p=Bind-Identity ([int]$identity.SupervisorPid) $state.Reliability.ShellPath $identity.SupervisorStarted;$p.Dispose();return $identity}catch{}};if([datetime]::UtcNow -ge $end){throw 'Periodic scheduled task did not create a new worker.'};Start-Sleep -Seconds 2}while($true)
}
try {
    if(@(Get-CimInstance Win32_Process|Where-Object ExecutablePath -eq (Get-GuardPath 'runtime\ClaudeProGuard.exe')).Count){throw 'Close the safety launcher window before native background recovery tests.'}
    $health=Require-Ready
    $trackedProxy=Read-GuardJson (Get-GuardPath 'private\proxy-process.json');$p=Bind-Identity ([int]$trackedProxy.Pid) (Get-GuardPath 'runtime\sing-box.exe') ((Get-Process -Id $trackedProxy.Pid).StartTime.ToUniversalTime().ToString('o'))
    $proxy=@{Id=$p.Id;Path=$p.Path;StartedTicks=$p.StartTime.ToUniversalTime().Ticks};$p.Dispose()
    $desktops=@(Get-GuardDesktopProcesses|Where-Object {$_.CommandLine -notmatch ' --type='}|ForEach-Object {$p=Get-Process -Id $_.ProcessId;@{Id=$p.Id;Path=$p.Path;StartedTicks=$p.StartTime.ToUniversalTime().Ticks}})
    if(-not $desktops.Count){throw 'Open protected Claude through the safety launcher before native preservation tests.'}
    $result['PreservedProxyIdentity']=$proxy
    $result['PreservedClaudeIdentities']=$desktops
    $result['InitialRunId']=$health.RunId
    Check-Preserved
    if($Mode -eq 'Budget'){
        $identity=Read-GuardJson (Get-GuardPath 'private\supervisor-host-identity.json')
        $start=[datetime]::UtcNow
        $initialBudget=Read-HostRecovery
        $initialCount=@($initialBudget.FailureTimes|Where-Object {([datetimeoffset]$_).UtcDateTime -ge $start.AddMinutes(-5)}).Count
        $attemptLimit=3-$initialCount
        if($attemptLimit -lt 1){throw 'Existing guardian backoff must recover before budget injection.'}
        $result['InitialFailureCount']=$initialCount
        for($attempt=1;$attempt -le $attemptLimit;$attempt++){
            $p=Bind-Identity ([int]$identity.SupervisorPid) $state.Reliability.ShellPath $identity.SupervisorStarted
            try{$p.Kill();if(-not $p.WaitForExit(10000)){throw 'Worker fault did not terminate the selected worker.'}}finally{$p.Dispose()}
            $result.Steps+=@{Kind='WorkerTerminated';Attempt=$attempt;RunId=$identity.RunId;WorkerPid=$identity.SupervisorPid;Time=[datetime]::UtcNow.ToString('o')};Save-NativeResult
            if($attempt -lt $attemptLimit){$identity=Wait-NewWorker $identity.RunId}
        }
        $end=[datetime]::UtcNow.AddSeconds(20)
        do{$budget=Read-HostRecovery;if(@($budget.FailureTimes).Count -ge 3 -and $budget.NextRestart -and ([datetimeoffset]$budget.NextRestart).UtcDateTime -gt [datetime]::UtcNow){break};if([datetime]::UtcNow -ge $end){throw 'Three real worker failures did not persist the recovery backoff.'};Start-Sleep -Seconds 1}while($true)
        $next=[datetimeoffset]$budget.NextRestart
        $workerStarts=@(Get-HostEvents|Where-Object {$_.Kind -eq 'WorkerStarted' -and ([datetimeoffset]$_.Time).UtcDateTime -ge $start}).Count
        $observeUntil=[datetime]::UtcNow.AddSeconds(75)
        do{Check-Preserved;Start-Sleep -Seconds 3}while([datetime]::UtcNow -lt $observeUntil)
        $after=Read-HostRecovery
        if(([datetimeoffset]$after.NextRestart).UtcTicks -ne $next.UtcTicks -or @($after.FailureTimes).Count -lt 3){throw 'Periodic host startup reset the persisted backoff.'}
        if(@(Get-HostEvents|Where-Object {$_.Kind -eq 'WorkerStarted' -and ([datetimeoffset]$_.Time).UtcDateTime -ge $start}).Count -ne $workerStarts){throw 'Periodic trigger started a worker before the backoff expired.'}
        if(-not @(Get-HostEvents|Where-Object {$_.Kind -eq 'BackoffSkipped' -and ([datetimeoffset]$_.Time).UtcDateTime -ge $start}).Count){throw 'No periodic trigger was observed during the backoff.'}
        $result.Steps+=@{Kind='PersistentBackoffConfirmed';FailureCount=@($after.FailureTimes).Count;NextRestart=$next.ToString('o');ObservedSeconds=75};Save-NativeResult
        $health=Require-Ready 440
        $result.Steps+=@{Kind='RecoveredAfterBackoff';RunId=$health.RunId;Time=[datetime]::UtcNow.ToString('o')}
    }elseif($Mode -eq 'Host'){
        $start=[datetime]::UtcNow;$oldWorker=Bind-Identity ([int]$health.SupervisorPid) $state.Reliability.ShellPath $health.SupervisorStarted
        $p=Bind-Identity ([int]$health.HostPid) $state.Reliability.HostPath $health.HostStarted
        try{$p.Kill();if(-not $p.WaitForExit(10000)){throw 'Selected host did not terminate.'};if(-not $oldWorker.WaitForExit(15000)){throw 'Host Job left its worker running.'}}finally{$p.Dispose();$oldWorker.Dispose()}
        Check-Preserved;$identity=Wait-NewWorker $health.RunId;$health=Require-Ready
        $result.Steps+=@{Kind='HostJobCleanupAndPeriodicRecovery';ElapsedSeconds=[math]::Round(([datetime]::UtcNow-$start).TotalSeconds,2);RunId=$health.RunId}
    }else{
        if(-not ('ClaudeGuardNativeSuspend' -as [type])){Add-Type 'using System;using System.Runtime.InteropServices;public static class ClaudeGuardNativeSuspend {[DllImport("ntdll.dll")]public static extern int NtSuspendProcess(IntPtr handle);[DllImport("ntdll.dll")]public static extern int NtResumeProcess(IntPtr handle);}'}
        $start=[datetime]::UtcNow;$oldWorker=Bind-Identity ([int]$health.SupervisorPid) $state.Reliability.ShellPath $health.SupervisorStarted
        try{
            $code=[ClaudeGuardNativeSuspend]::NtSuspendProcess($oldWorker.Handle);if($code -ne 0){throw ('Cannot suspend selected worker: '+$code)}
            $result.Steps+=@{Kind='WorkerSuspended';RunId=$health.RunId;WorkerPid=$health.SupervisorPid};Save-NativeResult
            $end=[datetime]::UtcNow.AddSeconds(150)
            do{Check-Preserved;if($oldWorker.HasExited){break};if([datetime]::UtcNow -ge $end){throw 'Host did not terminate a worker with stalled progress.'};Start-Sleep -Seconds 2}while($true)
            if(-not @(Get-HostEvents|Where-Object {$_.Kind -eq 'WatchdogExpired' -and $_.RunId -eq $health.RunId}).Count){throw 'Worker exited without a matching watchdog timeout event.'}
            $result.Steps+=@{Kind='WatchdogTerminatedStalledWorker';ElapsedSeconds=[math]::Round(([datetime]::UtcNow-$start).TotalSeconds,2)};Save-NativeResult
        }finally{if(-not $oldWorker.HasExited){$null=[ClaudeGuardNativeSuspend]::NtResumeProcess($oldWorker.Handle)};$oldWorker.Dispose()}
        $identity=Wait-NewWorker $health.RunId;$health=Require-Ready 180
        $result.Steps+=@{Kind='RecoveredAfterWatchdog';RunId=$health.RunId;Time=[datetime]::UtcNow.ToString('o')}
    }
    Check-Preserved;$result.Status='PASS';$result['FinalRunId']=$health.RunId
}catch{
    $result.Status='FAIL';$result.Error=$_.Exception.Message
    if($result.Contains('PreservedProxyIdentity')){
        try{Check-Preserved}catch{$result.ClaudePreserved=$false;$result.ProxyPreserved=$false;$result['PreservationError']=$_.Exception.Message}
    }
}
finally{Save-NativeResult}
$result|ConvertTo-Json -Depth 12
if($result.Status -ne 'PASS'){exit 1}
