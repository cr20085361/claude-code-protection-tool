[CmdletBinding()]
param([string]$ReportFile=(Join-Path $PSScriptRoot 'evidence\cache-repair-budget-regression.json'))
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-CacheRepair.psm1') -Force
$checks=[Collections.Generic.List[string]]::new()
function Require([bool]$Condition,[string]$Name){if(-not $Condition){throw ('Cache repair budget regression failed: '+$Name)};$checks.Add($Name)}
function Refuse([scriptblock]$Action,[string]$Name){$rejected=$false;try{$null=& $Action}catch{$rejected=$true};Require $rejected $Name}
$start=[datetimeoffset]'2026-11-15T00:00:00Z'
$id=[guid]::NewGuid().ToString('N');$hash='a'*64
$budget=New-GuardCacheRepairBudget -NowUtc $start -DeadlineUtc $start.AddSeconds(1000)
function New-Result([double]$CompletedSeconds=157,[bool]$Success=$true){
    [pscustomobject]@{SchemaVersion=1;OperationId=$id;ReviewedWorkerHash=$hash;StartedAt=$start.AddSeconds(1).ToString('o');CompletedAt=$start.AddSeconds($CompletedSeconds).ToString('o');ElapsedMilliseconds=($CompletedSeconds-1)*1000;Success=$Success;Reason=if($Success){$null}else{'fixture hash mismatch'}}
}
function New-Context($Result=$null,[double]$ResultAt=[double]::PositiveInfinity){
    @{Elapsed=0.0;NowUtc=$start;Result=$Result;ResultAt=$ResultAt;ReadDelay=0.0;ReadError=$false;ExitAt=[double]::PositiveInfinity;PublishOnExitProbe=$false;NeverStarts=$false;ObserveError=$false;Progress=[pscustomobject]@{OperationId=$id;ReviewedWorkerHash=$hash;Phase='Firewall';Time=$start.ToString('o');WorkerPid=123};Reads=0}
}
function Wait-Fixture($Context,$UseBudget=$budget){
    $now={$Context.NowUtc}.GetNewClosure();$elapsed={$Context.Elapsed}.GetNewClosure()
    $read={
        $Context.Reads++
        if($Context.ReadDelay){$Context.Elapsed+=$Context.ReadDelay;$Context.NowUtc=$Context.NowUtc.AddSeconds($Context.ReadDelay)}
        if($Context.ReadError){throw 'fixture unreadable result'}
        if($Context.Elapsed -ge $Context.ResultAt){return $Context.Result}
        return $null
    }.GetNewClosure()
    $progress={return $Context.Progress}.GetNewClosure()
    $state={if($Context.ObserveError){throw 'fixture task inaccessible'};if($Context.PublishOnExitProbe -and $Context.Elapsed -ge $Context.ExitAt){$Context.ResultAt=$Context.Elapsed};@{State=if($Context.NeverStarts -or $Context.Elapsed -ge $Context.ExitAt){3}else{4};LastTaskResult=if($Context.Elapsed -ge $Context.ExitAt){1}else{267009}}}.GetNewClosure()
    $delay={param($Milliseconds);$Context.Elapsed+=$Milliseconds/1000.0;$Context.NowUtc=$Context.NowUtc.AddMilliseconds($Milliseconds)}.GetNewClosure()
    Wait-GuardCacheRepairResult -Budget $UseBudget -OperationId $id -ReviewedWorkerHash $hash -ReadResult $read -ReadProgress $progress -GetTaskState $state -GetNowUtc $now -GetElapsedSeconds $elapsed -Delay $delay
}
try {
    Require ($budget.WaitTimeoutSeconds -eq 360) 'full-budget-allows-worker-longer-than-legacy-90-seconds'
    $taskLimit=[Xml.XmlConvert]::ToTimeSpan($budget.TaskExecutionTimeLimit).TotalSeconds
    Require ($taskLimit -eq 375 -and $taskLimit -gt $budget.WaitTimeoutSeconds) 'task-limit-includes-cancellation-and-result-reserve-after-wait'
    Require ($start.AddSeconds($taskLimit) -le [datetimeoffset]$budget.DeadlineUtc) 'task-limit-stays-within-caller-deadline'
    $short=New-GuardCacheRepairBudget -NowUtc $start -DeadlineUtc $start.AddSeconds(200)
    Require ($short.WaitTimeoutSeconds -eq 185 -and [Xml.XmlConvert]::ToTimeSpan($short.TaskExecutionTimeLimit).TotalSeconds -eq 200) 'remaining-caller-budget-caps-worker-and-task-together'
    Refuse {New-GuardCacheRepairBudget -NowUtc $start -DeadlineUtc $start.AddSeconds(44)} 'insufficient-budget-refuses-before-task-start'
    Refuse {New-GuardCacheRepairBudget -NowUtc $start -DeadlineUtc $start.AddSeconds(-1)} 'expired-caller-budget-refuses-before-task-start'

    $context=New-Context (New-Result) 157;$r=Wait-Fixture $context
    Require ($r.Success -and $r.Status -eq 'Completed' -and $r.ElapsedSeconds -ge 157 -and -not $r.NeedsCancellation) 'successful-157-second-worker-is-not-interrupted-at-90-or-120'
    Require ($r.Result.OperationId -eq $id -and $context.Reads -gt 500) 'success-comes-from-this-operation-final-result-after-repeated-observation'
    $roundtripResult=New-Result 2 | ConvertTo-Json | ConvertFrom-Json
    $roundtripBudget=$budget | ConvertTo-Json | ConvertFrom-Json
    $context=New-Context $roundtripResult 2;$r=Wait-Fixture $context $roundtripBudget
    Require $r.Success 'actual-json-reader-datetime-conversion-preserves-valid-result-and-budget'
    $context=New-Context (New-Result 3 $false) 3;$r=Wait-Fixture $context
    Require (-not $r.Success -and $r.FailureKind -eq 'CacheRepairWorkerFailed' -and $r.Reason.Contains('fixture hash mismatch')) 'explicit-worker-failure-remains-failed-with-original-reason'
    $context=New-Context;$r=Wait-Fixture $context
    Require (-not $r.Success -and $r.FailureKind -eq 'CacheRepairTimeout' -and $r.ElapsedSeconds -ge 360 -and $r.NeedsCancellation) 'missing-final-result-times-out-with-bounded-cancellation'
    Require ($r.LastProgress.Phase -eq 'Firewall' -and $r.Reason.Contains('Last phase: Firewall')) 'timeout-preserves-last-worker-phase-as-diagnostic-only'
    $context=New-Context;$context.ExitAt=2;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairTaskExited' -and $r.ElapsedSeconds -lt 3) 'worker-exit-without-final-result-is-not-misreported-as-full-timeout'
    Require ($r.LastTask.LastTaskResult -eq 1) 'worker-exit-retains-task-result-code'
    $context=New-Context (New-Result 2);$context.ExitAt=2;$context.PublishOnExitProbe=$true;$context.Progress=$null;$r=Wait-Fixture $context
    Require ($r.Success -and $r.Status -eq 'Completed') 'result-written-between-file-read-and-task-exit-observation-is-rechecked-and-accepted'
    $context=New-Context (New-Result 2 $false);$context.ExitAt=2;$context.PublishOnExitProbe=$true;$context.Progress=$null;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairWorkerFailed' -and $r.Result.Reason -eq 'fixture hash mismatch') 'failure-written-during-exit-race-retains-worker-failure-instead-of-missing-result'
    $context=New-Context;$context.NeverStarts=$true;$context.Progress=$null;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairTaskNotStarted' -and $r.ElapsedSeconds -ge 15 -and $r.ElapsedSeconds -lt 16) 'initial-ready-state-has-finite-startup-grace'
    $context=New-Context;$context.ReadError=$true;$context.ExitAt=2;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairResultUnreadable' -and $r.Reason.Contains('fixture unreadable')) 'unreadable-final-result-retains-cause-after-worker-exit'
    $context=New-Context;$context.ObserveError=$true;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairTaskObservationFailed' -and $r.NeedsCancellation) 'task-observation-error-fails-closed-and-requests-owned-task-cleanup'
    $context=New-Context (New-Result 361) 360;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairTimeout' -and $null -eq $r.Result) 'result-at-expired-deadline-cannot-be-accepted'
    $context=New-Context (New-Result 360) 0;$context.Elapsed=359;$context.NowUtc=$start.AddSeconds(359);$context.ReadDelay=2;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairTimeout' -and $null -eq $r.Result) 'blocking-result-read-crossing-deadline-cannot-turn-timeout-into-success'
    $context=New-Context (New-Result 3) 3;$context.NowUtc=$start.AddSeconds(361);$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairTimeout' -and $context.Reads -eq 0) 'absolute-deadline-cannot-be-bypassed-by-fresh-monotonic-clock'
    $context=New-Context (New-Result 3) 3;$context.Elapsed=361;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairTimeout' -and $context.Reads -eq 0) 'monotonic-deadline-cannot-be-bypassed-by-backward-wall-clock'
    $bad=New-Result 2;$bad.OperationId=[guid]::NewGuid().ToString('N');$context=New-Context $bad 2;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairResultIdentityMismatch') 'stale-other-operation-final-result-rejected'
    $bad=New-Result 2;$bad.ReviewedWorkerHash='b'*64;$context=New-Context $bad 2;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairResultIdentityMismatch') 'unreviewed-worker-result-rejected'
    $bad=New-Result 2;$bad.CompletedAt=$null;$context=New-Context $bad 2;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairResultInvalid') 'progress-like-success-without-terminal-timestamp-rejected'
    $bad=New-Result 2;$bad.StartedAt=$start.AddSeconds(-1).ToString('o');$context=New-Context $bad 2;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairResultTimeInvalid') 'result-started-before-this-task-budget-rejected'
    $bad=New-Result 361;$context=New-Context $bad 2;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairResultTimeInvalid') 'late-or-future-completion-timestamp-rejected-before-success'
    $bad=New-Result 2;$bad.CompletedAt='2026-11-15T00:00:02';$context=New-Context $bad 2;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairResultInvalid') 'terminal-timestamp-without-timezone-rejected'
    $bad=New-Result 2;$bad.CompletedAt=[datetime]::SpecifyKind([datetime]'2026-11-15T00:00:02',[DateTimeKind]::Unspecified);$context=New-Context $bad 2;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairResultInvalid') 'json-reader-unspecified-datetime-still-rejected'
    $bad=New-Result 2;$bad.ElapsedMilliseconds=[double]::NaN;$context=New-Context $bad 2;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairResultInvalid') 'nonfinite-worker-elapsed-time-rejected'
    $bad=New-Result 2;$bad.ElapsedMilliseconds='1000';$context=New-Context $bad 2;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairResultInvalid') 'string-worker-elapsed-time-rejected'
    $bad=New-Result 2 $false;$bad.Reason=$null;$context=New-Context $bad 2;$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairWorkerFailed' -and $r.Reason.Contains('未提供原因')) 'worker-failure-without-detail-still-has-clear-failure-reason'
    $context=New-Context;$context.Progress=[pscustomobject]@{OperationId=[guid]::NewGuid().ToString('N');ReviewedWorkerHash=$hash;Phase='Forged';WorkerPid=123};$r=Wait-Fixture $context
    Require ($r.FailureKind -eq 'CacheRepairTimeout' -and $null -eq $r.LastProgress -and -not $r.Reason.Contains('Forged')) 'unrelated-progress-does-not-become-completion-or-diagnostic-evidence'
    Refuse {Wait-GuardCacheRepairResult -Budget $budget -OperationId 'not-an-id' -ReviewedWorkerHash $hash -ReadResult {$null} -GetTaskState {4}} 'invalid-expected-operation-identity-refused'
    Refuse {Wait-GuardCacheRepairResult -Budget $budget -OperationId $id -ReviewedWorkerHash 'not-a-hash' -ReadResult {$null} -GetTaskState {4}} 'invalid-expected-reviewed-hash-refused'
    Refuse {Wait-GuardCacheRepairResult -Budget $budget -OperationId $id -ReviewedWorkerHash $hash -ReadResult {$null} -GetTaskState {4} -GetElapsedSeconds {[double]::NaN}} 'nonfinite-observer-monotonic-clock-refused'

    $report=[ordered]@{Time=(Get-Date -Format o);Passed=$true;FixtureOnly=$true;ProductionTouched=$false;SimulatedClock=$true;Count=$checks.Count;Checks=@($checks)}
    $ReportFile=[IO.Path]::GetFullPath($ReportFile)
    $null=New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($ReportFile)) -Force
    [IO.File]::WriteAllText($ReportFile,($report|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
    $report|ConvertTo-Json -Depth 5
}catch{throw}
