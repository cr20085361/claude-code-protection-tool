# 所有入口使用同一就绪契约；旧健康文件或存活代理不能作为守护健康证据。
function Get-GuardHealthAssessment {
    param($Health,$State,[datetimeoffset]$NowUtc=[datetimeoffset]::UtcNow,[string]$TaskState='Unknown',[scriptblock]$IdentityVerifier)
    $answer=[ordered]@{Ready=$false;Kind='SupervisorUnavailable';Reason='后台守护尚未确认';Health=$Health;AgeSeconds=$null}
    try {
        if(Test-Path -LiteralPath (Get-GuardPath 'private\safety-hold.json')){$answer.Kind='SafetyHold';throw 'SafetyHold: 网络防护已暂停'}
        if(-not $Health -or -not $Health.PSObject.Properties['SchemaVersion'] -or $Health.SchemaVersion -ne 2){throw '旧版或缺失的守护状态'}
        foreach($name in @('Time','RunId','HostPid','HostStarted','SupervisorPid','SupervisorStarted','LastSafetyCheck','LastEgressCheck','Status')){if(-not $Health.PSObject.Properties[$name]){throw ('守护状态缺少字段：'+$name)}}
        $stamp=[datetimeoffset]$Health.Time
        $age=($NowUtc-$stamp).TotalSeconds;$answer.AgeSeconds=$age
        if($age -lt -5 -or $age -gt 120){throw '后台守护状态已过期或时钟异常'}
        if($TaskState -ne 'Running'){throw '后台守护任务未运行'}
        if([string]::IsNullOrEmpty($Health.RunId) -or -not $IdentityVerifier -or -not (& $IdentityVerifier $Health $State)){throw '后台守护进程身份未确认'}
        if($Health.Status -eq 'SafetyHold'){$answer.Kind='SafetyHold';throw 'SafetyHold: 网络防护已暂停'}
        if($Health.Status -notin @('Healthy','ProbeDegraded')){$answer.Kind=[string]$Health.Status;throw ('后台守护检查未完成：'+$Health.Status)}
        foreach($field in @('LastSafetyCheck','LastEgressCheck')){
            $checked=[datetimeoffset]$Health.$field;$checkAge=($NowUtc-$checked).TotalSeconds
            if($checkAge -lt -5 -or $checkAge -gt 120 -or $checked -lt [datetimeoffset]$Health.SupervisorStarted){throw ('本次守护检查过期或未完成：'+$field)}
        }
        if(-not $Health.PSObject.Properties['LastVerifiedEgress'] -or -not $Health.LastVerifiedEgress){throw '本次固定出口结果缺失'}
        $e=$Health.LastVerifiedEgress
        if([int]$e.VerifiedProbeCount -lt 1){throw '本次固定出口未确认'}
        foreach($name in @('CloudflareIp','IpifyIp')){if($e.PSObject.Properties[$name] -and $e.$name -and $e.$name -ne $State.ExpectedIp){$answer.Kind='SafetyHold';throw 'Fixed egress mismatch'}}
        if(-not (@($e.CloudflareIp,$e.IpifyIp) -contains $State.ExpectedIp)){throw '本次固定出口结果不匹配'}
        $answer.Ready=$true;$answer.Kind=[string]$Health.Status;$answer.Reason='后台守护已确认'
    } catch {$answer.Reason=$_.Exception.Message}
    [pscustomobject]$answer
}
function Test-GuardSupervisorIdentity($Health,$State) {
    try {
        $identity=Read-GuardJson (Get-GuardPath 'private\supervisor-host-identity.json')
        foreach($f in @('RunId','HostPid','HostStarted','SupervisorPid','SupervisorStarted')){if($identity.$f -ne $Health.$f){return $false}}
        if($identity.ShellPath -ne $State.Reliability.ShellPath -or $identity.ScriptPath -ne (Get-GuardSupervisorScript $State.Reliability)){return $false}
        foreach($entry in @(@{Pid=$Health.HostPid;Started=$Health.HostStarted;Path=$State.Reliability.HostPath},@{Pid=$Health.SupervisorPid;Started=$Health.SupervisorStarted;Path=$State.Reliability.ShellPath})){
            $p=Get-Process -Id $entry.Pid -ErrorAction Stop
            if($p.Path -ne $entry.Path -or $p.StartTime.ToUniversalTime().Ticks -ne ([datetimeoffset]$entry.Started).UtcTicks){return $false}
        }
        $worker=Get-CimInstance Win32_Process -Filter "ProcessId=$($Health.SupervisorPid)" -OperationTimeoutSec 5
        if(-not $worker -or $worker.CommandLine -notlike ('*'+$identity.ScriptPath+'*') -or $worker.CommandLine -notlike ('*'+$Health.RunId+'*')){return $false}
        return $true
    } catch {return $false}
}
function Get-GuardSupervisorSnapshot {
    $state=Get-GuardState;$health=$null
    try {
        $health=Read-GuardJson (Get-GuardPath 'private\supervisor-health.json')
        $task=Get-ScheduledTask -TaskName $state.Reliability.TaskName -ErrorAction Stop
        Assert-GuardSupervisorTask $task $state
        Get-GuardHealthAssessment -Health $health -State $state -TaskState $task.State.ToString() -IdentityVerifier ${function:Test-GuardSupervisorIdentity}
    } catch {[pscustomobject]@{Ready=$false;Kind='SupervisorUnavailable';Reason=$_.Exception.Message;Health=$health;AgeSeconds=$null}}
}
function Wait-GuardSupervisorReady {
    param([int]$TimeoutSeconds=90,[datetime]$DeadlineUtc=[datetime]::MaxValue)
    $end=[datetime]::UtcNow.AddSeconds($TimeoutSeconds)
    if($DeadlineUtc.ToUniversalTime() -lt $end){$end=$DeadlineUtc.ToUniversalTime()}
    do {
        $s=Get-GuardSupervisorSnapshot
        if($s.Ready){return $s.Health}
        if($s.Kind -eq 'SafetyHold' -or (Test-Path -LiteralPath (Get-GuardPath 'private\safety-hold.json'))){throw ('SafetyHold: '+$s.Reason)}
        if($s.Kind -in @('UpgradeRequired','ProtectionError')){throw ('SupervisorUnavailable: '+$s.Reason)}
        if([datetime]::UtcNow -ge $end){throw ('SupervisorUnavailable: '+$s.Reason+'；等待守护恢复超时')}
        Start-Sleep -Milliseconds 750
    } while($true)
}
function Get-GuardVerifiedEgress {
    $s=Get-GuardSupervisorSnapshot
    if(-not $s.Ready){throw ('SupervisorUnavailable: '+$s.Reason)}
    $s.Health.LastVerifiedEgress
}
