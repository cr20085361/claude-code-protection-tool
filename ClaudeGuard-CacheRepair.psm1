Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-CacheRepairValue($Value,[string]$Name,$Default=$null) {
    if($null -eq $Value){return $Default}
    if($Value -is [Collections.IDictionary]){if($Value.Contains($Name)){return $Value[$Name]};return $Default}
    if($Value.PSObject.Properties[$Name]){return $Value.$Name}
    $Default
}

function Get-CacheRepairTimestampText($Value) {
    # Read-GuardJson 的 ConvertFrom-Json 会将带时区 ISO 文本转成 DateTime。
    # 保留其 UTC/Local Kind；无时区文本产生的 Unspecified 不能作为终态时间。
    if($Value -is [datetimeoffset]){return $Value.ToString('o')}
    if($Value -is [datetime] -and $Value.Kind -ne [DateTimeKind]::Unspecified){return $Value.ToString('o')}
    [string]$Value
}

# 子任务预留取消与结果落盘时间；计划任务自身上限不得先于外层等待。
function New-GuardCacheRepairBudget {
    [CmdletBinding()]
    param(
        [datetimeoffset]$DeadlineUtc=[datetimeoffset]::UtcNow.AddSeconds(420),
        [datetimeoffset]$NowUtc=[datetimeoffset]::UtcNow,
        [ValidateRange(30,1800)][int]$MaxWorkerSeconds=360,
        [ValidateRange(5,120)][int]$CleanupReserveSeconds=15,
        [ValidateRange(1,180)][int]$MinimumWorkerSeconds=30
    )
    $available=[Math]::Floor(($DeadlineUtc-$NowUtc).TotalSeconds)-$CleanupReserveSeconds
    $seconds=[int][Math]::Min($MaxWorkerSeconds,$available)
    if($seconds -lt $MinimumWorkerSeconds){throw 'CacheRepairBudgetUnavailable: 缓存维护剩余预算不足，尚未启动任务。'}
    [pscustomobject]@{
        StartedAtUtc=$NowUtc.ToUniversalTime().ToString('o')
        DeadlineUtc=$DeadlineUtc.ToUniversalTime().ToString('o')
        WorkerDeadlineUtc=$NowUtc.AddSeconds($seconds).ToUniversalTime().ToString('o')
        WaitTimeoutSeconds=$seconds
        CancellationReserveSeconds=$CleanupReserveSeconds
        TaskExecutionTimeLimit=[Xml.XmlConvert]::ToString([timespan]::FromSeconds($seconds+$CleanupReserveSeconds))
    }
}

# 最终结果与本次随机操作身份、已审查脚本及完成时间绑定；进度文件不构成成功证据。
function Test-GuardCacheRepairResult {
    [CmdletBinding()]
    param($Result,$Budget,[string]$OperationId,[string]$ReviewedWorkerHash,[datetimeoffset]$NowUtc=[datetimeoffset]::UtcNow)
    $answer=[ordered]@{Valid=$false;FailureKind='CacheRepairResultInvalid';Reason='缓存维护最终结果无效。'}
    try {
        $id=[guid]::Empty
        if(-not [guid]::TryParseExact($OperationId,'N',[ref]$id) -or $ReviewedWorkerHash -notmatch '^[A-Fa-f0-9]{64}$'){throw '缓存维护预期身份无效。'}
        if((Get-CacheRepairValue $Result 'SchemaVersion') -ne 1 -or
           -not [string]::Equals([string](Get-CacheRepairValue $Result 'OperationId'),$OperationId,[StringComparison]::OrdinalIgnoreCase) -or
           -not [string]::Equals([string](Get-CacheRepairValue $Result 'ReviewedWorkerHash'),$ReviewedWorkerHash,[StringComparison]::OrdinalIgnoreCase)){
            $answer.FailureKind='CacheRepairResultIdentityMismatch';throw '缓存维护最终结果与本次操作身份不符。'
        }
        if((Get-CacheRepairValue $Result 'Success') -isnot [bool]){throw '缓存维护最终结果缺少明确的成功状态。'}
        $started=[datetimeoffset]::MinValue;$completed=[datetimeoffset]::MinValue
        $startedText=Get-CacheRepairTimestampText (Get-CacheRepairValue $Result 'StartedAt');$completedText=Get-CacheRepairTimestampText (Get-CacheRepairValue $Result 'CompletedAt')
        if($startedText -notmatch '(Z|[+-]\d{2}:\d{2})$' -or $completedText -notmatch '(Z|[+-]\d{2}:\d{2})$' -or
           -not [datetimeoffset]::TryParse($startedText,[ref]$started) -or -not [datetimeoffset]::TryParse($completedText,[ref]$completed)){
            throw '缓存维护最终结果缺少开始或完成时间。'
        }
        $elapsed=Get-CacheRepairValue $Result 'ElapsedMilliseconds'
        if($null -eq $elapsed -or $elapsed -is [string] -or $elapsed -is [bool] -or $elapsed -lt 0 -or
           [double]::IsNaN([double]$elapsed) -or [double]::IsInfinity([double]$elapsed)){throw '缓存维护最终结果缺少有效的单调计时。'}
        if($started -lt [datetimeoffset]$Budget.StartedAtUtc -or $completed -lt $started -or
           $completed -gt [datetimeoffset]$Budget.WorkerDeadlineUtc -or $completed -gt $NowUtc.AddSeconds(1) -or
           $elapsed -gt ([double]$Budget.WaitTimeoutSeconds*1000)){
            $answer.FailureKind='CacheRepairResultTimeInvalid';throw '缓存维护最终结果来自本次预算之外。'
        }
        $answer.Valid=$true;$answer.FailureKind=$null;$answer.Reason=$null
    }catch{$answer.Reason=$_.Exception.Message}
    [pscustomobject]$answer
}

function Wait-GuardCacheRepairResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Budget,
        [Parameter(Mandatory)][string]$OperationId,
        [Parameter(Mandatory)][string]$ReviewedWorkerHash,
        [Parameter(Mandatory)][scriptblock]$ReadResult,
        [scriptblock]$ReadProgress={return $null},
        [Parameter(Mandatory)][scriptblock]$GetTaskState,
        [scriptblock]$GetNowUtc={return [datetimeoffset]::UtcNow},
        [scriptblock]$GetElapsedSeconds,
        [scriptblock]$Delay={param($Milliseconds) [Threading.Thread]::Sleep($Milliseconds)},
        [ValidateRange(0,60)][int]$StartupGraceSeconds=15,
        [ValidateRange(10,1000)][int]$PollMilliseconds=200
    )
    $id=[guid]::Empty
    if(-not [guid]::TryParseExact($OperationId,'N',[ref]$id) -or $ReviewedWorkerHash -notmatch '^[A-Fa-f0-9]{64}$'){throw 'Invalid cache repair wait identity.'}
    $started=[datetimeoffset]$Budget.StartedAtUtc;$deadline=[datetimeoffset]$Budget.WorkerDeadlineUtc
    if($Budget.WaitTimeoutSeconds -le 0 -or $deadline -le $started -or $deadline -gt [datetimeoffset]$Budget.DeadlineUtc){throw 'Invalid cache repair wait budget.'}
    $watch=[Diagnostics.Stopwatch]::StartNew()
    if(-not $GetElapsedSeconds){$GetElapsedSeconds={$watch.Elapsed.TotalSeconds}.GetNewClosure()}
    $sawRunning=$false;$terminalRecheckPending=$false;$lastProgress=$null;$lastReadError=$null;$lastTask=$null;$status='';$failureKind=$null;$reason=$null;$result=$null;$cancel=$true;$elapsed=0.0
    while($true){
        $now=[datetimeoffset](& $GetNowUtc);$elapsed=[double](& $GetElapsedSeconds)
        if($elapsed -lt 0 -or [double]::IsNaN($elapsed) -or [double]::IsInfinity($elapsed)){throw 'Invalid cache repair monotonic clock.'}
        if($now -ge $deadline -or $elapsed -ge [double]$Budget.WaitTimeoutSeconds){$status='TimedOut';$failureKind='CacheRepairTimeout';$reason='Desktop cache repair timed out.';break}
        $result=$null
        try{$result=& $ReadResult;$lastReadError=$null}catch{$lastReadError=$_.Exception.Message}
        # 文件读取也可能阻塞；同一轮出现结果并越过 deadline 时仍然失败关闭。
        $now=[datetimeoffset](& $GetNowUtc);$elapsed=[double](& $GetElapsedSeconds)
        if($elapsed -lt 0 -or [double]::IsNaN($elapsed) -or [double]::IsInfinity($elapsed)){throw 'Invalid cache repair monotonic clock.'}
        if($now -ge $deadline -or $elapsed -ge [double]$Budget.WaitTimeoutSeconds){$status='TimedOut';$failureKind='CacheRepairTimeout';$reason='Desktop cache repair timed out.';$result=$null;break}
        if($null -ne $result){
            $valid=Test-GuardCacheRepairResult -Result $result -Budget $Budget -OperationId $OperationId -ReviewedWorkerHash $ReviewedWorkerHash -NowUtc $now
            if(-not $valid.Valid){$status='InvalidResult';$failureKind=$valid.FailureKind;$reason=$valid.Reason;break}
            $cancel=$false
            if($result.Success){$status='Completed'}else{$status='Failed';$failureKind='CacheRepairWorkerFailed';$reason=[string](Get-CacheRepairValue $result 'Reason');if([string]::IsNullOrWhiteSpace($reason)){$reason='缓存维护任务报告失败，未提供原因。'}}
            break
        }
        try{
            $progress=& $ReadProgress
            if($progress -and
               [string]::Equals([string](Get-CacheRepairValue $progress 'OperationId'),$OperationId,[StringComparison]::OrdinalIgnoreCase) -and
               [string]::Equals([string](Get-CacheRepairValue $progress 'ReviewedWorkerHash'),$ReviewedWorkerHash,[StringComparison]::OrdinalIgnoreCase)){
                $lastProgress=$progress
                if((Get-CacheRepairValue $progress 'WorkerPid' 0) -gt 0){$sawRunning=$true}
            }
        }catch{}
        try{$lastTask=& $GetTaskState}catch{$status='TaskObservationFailed';$failureKind='CacheRepairTaskObservationFailed';$reason=$_.Exception.Message;break}
        $taskState=[string](Get-CacheRepairValue $lastTask 'State' $lastTask)
        if($taskState -eq '4' -or $taskState -eq 'Running'){$sawRunning=$true;$terminalRecheckPending=$false}
        elseif($taskState -in @('','0','1','3','Unknown','Disabled','Ready','Completed','Stopped','Exited')){
            if($sawRunning -or $elapsed -ge $StartupGraceSeconds){
                # 最终结果可能在本轮先读文件、后读任务状态之间落盘。首次看到
                # 任务终态后，在同一 deadline 内再读一次，不能误报成功任务退出。
                if(-not $terminalRecheckPending){$terminalRecheckPending=$true;continue}
                $status=if($sawRunning){'TaskExited'}else{'TaskNotStarted'}
                $failureKind=if($lastReadError){'CacheRepairResultUnreadable'}elseif($sawRunning){'CacheRepairTaskExited'}else{'CacheRepairTaskNotStarted'}
                $reason=if($lastReadError){'缓存维护任务结束，但最终结果不可读：'+$lastReadError}elseif($sawRunning){'缓存维护任务已退出，未取得本次最终结果。'}else{'缓存维护任务未能启动，未取得本次最终结果。'}
                break
            }
        }
        $remaining=[Math]::Min(($deadline-([datetimeoffset](& $GetNowUtc))).TotalMilliseconds,([double]$Budget.WaitTimeoutSeconds-([double](& $GetElapsedSeconds)))*1000)
        if($remaining -gt 0){& $Delay ([int][Math]::Min($PollMilliseconds,[Math]::Max(1,$remaining)))}
    }
    if($failureKind -and $lastProgress){$phase=[string](Get-CacheRepairValue $lastProgress 'Phase');if($phase){$reason+=' Last phase: '+$phase+'.'}}
    [pscustomobject]@{
        SchemaVersion=1;OperationId=$OperationId;ReviewedWorkerHash=$ReviewedWorkerHash
        Status=$status;Success=($status -eq 'Completed');FailureKind=$failureKind;Reason=$reason
        Time=([datetimeoffset](& $GetNowUtc)).ToUniversalTime().ToString('o');ElapsedSeconds=[Math]::Round($elapsed,3)
        Result=$result;LastProgress=$lastProgress;LastTask=$lastTask;LastReadError=$lastReadError;NeedsCancellation=$cancel
    }
}

Export-ModuleMember -Function New-GuardCacheRepairBudget,Test-GuardCacheRepairResult,Wait-GuardCacheRepairResult
