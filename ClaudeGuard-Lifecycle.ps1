# 计划任务、后台宿主和维护迁移共用的生命周期规则；仅由 ClaudeGuard.psm1 加载。
function Get-GuardLifecycleValue($Object,[string]$Name,$Default=$null) {
    if($null -eq $Object){return $Default}
    if($Object -is [Collections.IDictionary]){if($Object.Contains($Name)){return $Object[$Name]};return $Default}
    $p=$Object.PSObject.Properties[$Name]
    if($p){return $p.Value}
    $Default
}
function Resolve-GuardLifecycleSid([string]$Identity) {
    if($Identity -match '^S-1-'){return $Identity}
    if(-not $Identity){throw 'Supervisor task has no owner identity.'}
    $qualified=if($Identity -match '\\|@'){$Identity}else{$env:COMPUTERNAME+'\'+$Identity}
    ([Security.Principal.NTAccount]::new($qualified)).Translate([Security.Principal.SecurityIdentifier]).Value
}
function Get-GuardApprovedShellPath($Reliability=$null) {
    $record=Get-GuardPath 'private\launcher-paths.txt'
    if(-not (Test-Path -LiteralPath $record -PathType Leaf)){throw 'Approved PowerShell path is missing; review it before building or deploying.'}
    $path=(Get-Content -LiteralPath $record -Raw).Trim()
    if(-not [IO.Path]::IsPathFullyQualified($path) -or [IO.Path]::GetFileName($path) -ne 'pwsh.exe' -or -not (Test-Path -LiteralPath $path -PathType Leaf)){throw 'Approved PowerShell executable path is invalid.'}
    $path=[IO.Path]::GetFullPath($path)
    $expected=Get-GuardLifecycleValue $Reliability 'ShellPath'
    if($expected -and $path -ne $expected){throw 'Approved PowerShell path differs from the deployment manifest.'}
    $versionText=[Diagnostics.FileVersionInfo]::GetVersionInfo($path).ProductVersion
    $versionMatch=[regex]::Match($versionText,'^\d+\.\d+\.\d+')
    if(-not $versionMatch.Success -or [version]$versionMatch.Value -lt [version]'7.4'){throw 'Approved PowerShell must be version 7.4 or newer.'}
    $expectedHash=Get-GuardLifecycleValue $Reliability 'ShellHash'
    if($expectedHash -and (Get-GuardHash $path) -ne $expectedHash){throw 'Approved PowerShell executable hash changed.'}
    $path
}
function New-GuardReliability($Previous=$null) {
    $value=if($Previous){$Previous|ConvertTo-Json -Depth 40|ConvertFrom-Json -AsHashtable}else{@{}}
    $shell=Get-GuardApprovedShellPath
    $value.SchemaVersion=2
    $value.TaskName='ClaudeProGuard-Supervisor'
    $value.HostPath=Get-GuardPath 'runtime\ClaudeSupervisorHost.exe'
    $value.HostHash=Get-GuardHash $value.HostPath
    $value.ShellPath=$shell
    $value.ShellHash=Get-GuardHash $shell
    $value.SupervisorScript='ClaudeGuard-Supervisor-v2.ps1'
    $value.SupervisorHash=Get-GuardHash (Get-GuardSupervisorScript ([pscustomobject]$value))
    $value.GuardHash=Get-GuardHash (Get-GuardPath 'ClaudeGuard.psm1')
    $value.CodeGateHash=Get-GuardHash (Get-GuardPath 'ClaudeCodeGate.psm1')
    $value.RuntimeHash=Get-GuardHash (Get-GuardPath 'ClaudeGuard-Runtime.psm1')
    $value.EnvironmentReaderHash=Get-GuardHash (Get-GuardPath 'Read-ClaudeProcessEnvironment.py')
    $value.HealthScriptHash=Get-GuardHash (Get-GuardPath 'ClaudeGuard-Health.ps1')
    $value.LifecycleScriptHash=Get-GuardHash (Get-GuardPath 'ClaudeGuard-Lifecycle.ps1')
    $value.Installed=Get-Date -Format o
    if(-not $value.ContainsKey('ObservationStarted')){$value.ObservationStarted=$null}
    $value.Ipv4Only=$true
    [pscustomobject]$value
}
function Assert-GuardReliabilityFiles($State) {
    $r=$State.Reliability
    if([int](Get-GuardLifecycleValue $r 'SchemaVersion' 0) -ne 2){throw 'Supervisor reliability schema requires reviewed migration.'}
    if($r.TaskName -ne 'ClaudeProGuard-Supervisor' -or $r.HostPath -ne (Get-GuardPath 'runtime\ClaudeSupervisorHost.exe')){throw 'Supervisor host deployment path changed.'}
    $null=Get-GuardApprovedShellPath $r
    $files=@{
        HostHash=$r.HostPath;SupervisorHash=(Get-GuardSupervisorScript $r)
        GuardHash=(Get-GuardPath 'ClaudeGuard.psm1');CodeGateHash=(Get-GuardPath 'ClaudeCodeGate.psm1')
        RuntimeHash=(Get-GuardPath 'ClaudeGuard-Runtime.psm1');EnvironmentReaderHash=(Get-GuardPath 'Read-ClaudeProcessEnvironment.py')
        HealthScriptHash=(Get-GuardPath 'ClaudeGuard-Health.ps1');LifecycleScriptHash=(Get-GuardPath 'ClaudeGuard-Lifecycle.ps1')
    }
    foreach($name in $files.Keys){
        $approved=Get-GuardLifecycleValue $r $name
        if(-not $approved -or (Get-GuardHash $files[$name]) -ne $approved){throw ('Supervisor deployment hash changed: '+$name)}
    }
}
function Get-GuardSupervisorTaskXml($Task) {
    $embedded=Get-GuardLifecycleValue $Task 'Xml'
    if($embedded){return [xml]$embedded}
    [xml](Export-ScheduledTask -TaskName $Task.TaskName -TaskPath '\')
}
function Assert-GuardSupervisorTask($Task,$State) {
    if(-not $Task -or $Task.TaskName -ne $State.Reliability.TaskName -or $Task.TaskPath -ne '\'){throw 'Supervisor task identity changed.'}
    $r=$State.Reliability
    $schema=[int](Get-GuardLifecycleValue $r 'SchemaVersion' 0)
    if($schema -notin @(0,1,2)){throw 'Supervisor task reliability schema is unsupported.'}
    $v2=$schema -eq 2
    $shell=if($v2){Get-GuardApprovedShellPath $r}else{Get-GuardApprovedShellPath}
    $actions=@($Task.Actions)
    $expectedPath=if($v2){$r.HostPath}else{$shell}
    $expectedArgs=if($v2){''}else{'-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+(Get-GuardSupervisorScript $r)+'"'}
    if($actions.Count -ne 1 -or $actions[0].Execute -ne $expectedPath -or [string]$actions[0].Arguments -ne $expectedArgs -or $actions[0].WorkingDirectory -ne $script:Root -or (Resolve-GuardLifecycleSid ([string]$Task.Principal.UserId)) -ne $State.UserSid -or $Task.Principal.RunLevel.ToString() -ne 'Limited' -or $Task.Principal.LogonType.ToString() -ne 'Interactive'){throw 'Supervisor task policy changed.'}
    if(-not $v2){return}
    if($expectedPath -ne (Get-GuardPath 'runtime\ClaudeSupervisorHost.exe') -or (Get-GuardHash $expectedPath) -ne $r.HostHash){throw 'Supervisor task host executable changed.'}
    $xml=Get-GuardSupervisorTaskXml $Task
    $ns=[Xml.XmlNamespaceManager]::new($xml.NameTable);$ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
    $triggers=@($xml.SelectNodes('/t:Task/t:Triggers/*',$ns))
    $logon=@($triggers|Where-Object LocalName -eq 'LogonTrigger')
    $time=@($triggers|Where-Object LocalName -eq 'TimeTrigger')
    if($triggers.Count -ne 2 -or $logon.Count -ne 1 -or $time.Count -ne 1){throw 'Supervisor task recovery triggers changed.'}
    if((Resolve-GuardLifecycleSid $logon[0].SelectSingleNode('t:UserId',$ns).InnerText) -ne $State.UserSid){throw 'Supervisor task logon owner changed.'}
    foreach($trigger in $triggers){$enabled=$trigger.SelectSingleNode('t:Enabled',$ns);if($enabled -and $enabled.InnerText -ne 'true'){throw 'Supervisor recovery trigger was disabled.'}}
    $interval=$time[0].SelectSingleNode('t:Repetition/t:Interval',$ns)
    $duration=$time[0].SelectSingleNode('t:Repetition/t:Duration',$ns)
    $stop=$time[0].SelectSingleNode('t:Repetition/t:StopAtDurationEnd',$ns)
    $boundary=$time[0].SelectSingleNode('t:StartBoundary',$ns)
    if(-not $interval -or $interval.InnerText -ne 'PT1M' -or ($duration -and $duration.InnerText) -or ($stop -and $stop.InnerText -ne 'false') -or -not $boundary){throw 'Supervisor one-minute recovery repetition changed.'}
    $parsedBoundary=[datetime]::MinValue
    if(-not [datetime]::TryParse($boundary.InnerText,[ref]$parsedBoundary)){throw 'Supervisor recovery start boundary is invalid.'}
    $expectedSettings=@{
        MultipleInstancesPolicy='IgnoreNew';DisallowStartIfOnBatteries='false';StopIfGoingOnBatteries='false'
        ExecutionTimeLimit='PT0S';Hidden='true';StartWhenAvailable='true';WakeToRun='false';AllowStartOnDemand='true'
        'RestartOnFailure/Count'='3';'RestartOnFailure/Interval'='PT1M'
    }
    foreach($key in $expectedSettings.Keys){
        $xpath='/t:Task/t:Settings/'+(($key -split '/'|ForEach-Object {'t:'+$_}) -join '/')
        $node=$xml.SelectSingleNode($xpath,$ns)
        # Task Scheduler 不导出值等于系统默认的字段；缺失仅允许已知默认值。
        $defaults=@{WakeToRun='false';AllowStartOnDemand='true'}
        if(-not $node){if($defaults.ContainsKey($key) -and $defaults[$key] -eq $expectedSettings[$key]){continue};throw ('Supervisor task setting missing: '+$key)}
        if($node.InnerText -ne $expectedSettings[$key]){throw ('Supervisor task setting changed: '+$key)}
    }
}
function Register-GuardSupervisorTask {
    [CmdletBinding()]param([Parameter(Mandatory)]$State,$PreviousState,[switch]$AllowCreate)
    if(-not (Test-GuardAdmin) -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $State.UserSid){throw 'Same-account administrator context is required to register the supervisor task.'}
    Assert-GuardReliabilityFiles $State
    $prior=Get-ScheduledTask -TaskName $State.Reliability.TaskName -TaskPath '\' -ErrorAction SilentlyContinue
    if($prior){
        if(-not $PreviousState){$PreviousState=$State}
        Assert-GuardSupervisorTask $prior $PreviousState
        if($prior.State.ToString() -eq 'Running' -or $prior.Settings.Enabled){throw 'Suspend the owned supervisor task before replacing it.'}
    }elseif(-not $AllowCreate){throw 'Owned supervisor task is missing; creation requires explicit migration scope.'}
    $service=New-Object -ComObject 'Schedule.Service';$service.Connect();$folder=$service.GetFolder('\')
    $definition=$service.NewTask(0)
    $definition.RegistrationInfo.Description='Claude 专用代理：无窗口宿主、固定出口检查与每分钟后台恢复。'
    $definition.Principal.UserId=$State.UserSid;$definition.Principal.LogonType=3;$definition.Principal.RunLevel=0
    $settings=$definition.Settings
    $settings.Hidden=$true;$settings.Enabled=$true;$settings.AllowDemandStart=$true
    $settings.DisallowStartIfOnBatteries=$false;$settings.StopIfGoingOnBatteries=$false
    $settings.ExecutionTimeLimit='PT0S';$settings.MultipleInstances=2
    $settings.RestartCount=3;$settings.RestartInterval='PT1M';$settings.StartWhenAvailable=$true;$settings.WakeToRun=$false
    $trigger=$definition.Triggers.Create(9);$trigger.UserId=$State.UserSid;$trigger.Enabled=$true
    $recovery=$definition.Triggers.Create(1);$recovery.StartBoundary=(Get-Date).AddMinutes(1).ToString('yyyy-MM-ddTHH:mm:ss')
    $recovery.Enabled=$true;$recovery.Repetition.Interval='PT1M';$recovery.Repetition.StopAtDurationEnd=$false
    $action=$definition.Actions.Create(0);$action.Path=$State.Reliability.HostPath;$action.WorkingDirectory=$script:Root;$action.Arguments=''
    $null=$folder.RegisterTaskDefinition($State.Reliability.TaskName,$definition,6,$State.UserSid,$null,3,$null)
    Assert-GuardSupervisorTask (Get-ScheduledTask -TaskName $State.Reliability.TaskName -TaskPath '\') $State
}
function Get-GuardSupervisorProcessIdentities($State) {
    $r=$State.Reliability;$shell=Get-GuardApprovedShellPath
    $workerScript=Get-GuardSupervisorScript $r
    $legacyArguments='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+$workerScript+'"'
    $identityPath=Get-GuardPath 'private\supervisor-host-identity.json'
    $identity=if(Test-Path -LiteralPath $identityPath){try{Read-GuardJson $identityPath}catch{$null}}else{$null}
    $result=@()
    foreach($candidate in @(Get-CimInstance Win32_Process)){
        $kind=$null;$command=([string]$candidate.CommandLine).Trim()
        if($candidate.ExecutablePath -eq (Get-GuardPath 'runtime\ClaudeSupervisorHost.exe')){
            if($command -notin @(('"'+$candidate.ExecutablePath+'"'),$candidate.ExecutablePath)){throw 'Supervisor host command line changed; refusing process termination.'}
            $kind='Host'
        }elseif($candidate.ExecutablePath -eq $shell -and $command -in @(('"'+$shell+'" '+$legacyArguments),($shell+' '+$legacyArguments))){$kind='LegacyWorker'}
        elseif($candidate.ExecutablePath -eq $shell -and $command -like ('*"'+$workerScript+'"*')){
            # 新 worker 必须匹配宿主记录的全部启动参数，不能仅凭 PID 或脚本名结束进程。
            if(-not $identity){throw 'Supervisor worker has no host identity record; refusing process termination.'}
            if((Get-GuardLifecycleValue $identity 'ShellPath') -ne $shell -or (Get-GuardLifecycleValue $identity 'ScriptPath') -ne $workerScript){throw 'Supervisor worker host paths changed; refusing process termination.'}
            $runId=[guid](Get-GuardLifecycleValue $identity 'RunId')
            $hostPid=[int](Get-GuardLifecycleValue $identity 'HostPid')
            $hostStarted=[datetimeoffset](Get-GuardLifecycleValue $identity 'HostStarted')
            $base='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$workerScript+'" -RunId "'+$runId.ToString()+'" -HostPid '+$hostPid+' -HostStarted "'
            $matched=$false
            foreach($prefix in @(('"'+$shell+'" '+$base),($shell+' '+$base))){
                if(-not $command.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){continue}
                $tail=$command.Substring($prefix.Length)
                if($tail -notmatch '^[^"\r\n]+"$'){continue}
                $stamp=[datetimeoffset]::MinValue
                if([datetimeoffset]::TryParse($tail.TrimEnd('"'),[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$stamp) -and $stamp.UtcTicks -eq $hostStarted.UtcTicks){$matched=$true;break}
            }
            if(-not $matched){throw 'Supervisor worker startup identity changed; refusing process termination.'}
            $kind='Worker'
        }
        if(-not $kind){continue}
        $process=Get-Process -Id $candidate.ProcessId -ErrorAction SilentlyContinue
        if(-not $process){continue}
        $owner=Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid
        if($owner.ReturnValue -ne 0 -or $owner.Sid -ne $State.UserSid){throw 'Supervisor process owner changed; refusing process termination.'}
        $result+=[pscustomobject]@{Pid=[int]$candidate.ProcessId;Started=$process.StartTime.ToUniversalTime().ToString('o');Path=[string]$candidate.ExecutablePath;CommandLine=$command;Kind=$kind}
    }
    $result
}
function Test-GuardSupervisorProcessIdentity($Identity) {
    $live=Get-Process -Id $Identity.Pid -ErrorAction SilentlyContinue
    if(-not $live){return $false}
    if($live.StartTime.ToUniversalTime().Ticks -ne ([datetime]$Identity.Started).ToUniversalTime().Ticks){return $false}
    $cim=Get-CimInstance Win32_Process -Filter ('ProcessId='+$Identity.Pid) -ErrorAction SilentlyContinue
    ($cim -and $cim.ExecutablePath -eq $Identity.Path -and ([string]$cim.CommandLine).Trim() -eq $Identity.CommandLine)
}
function Stop-GuardSupervisorProcessIdentity($Identity) {
    $live=Get-Process -Id $Identity.Pid -ErrorAction SilentlyContinue
    if(-not $live){return}
    try {
        # 固定到内核进程句柄，再核验启动时间；PID 在核验与结束之间复用也不会终止新进程。
        $null=$live.Handle
        if($live.StartTime.ToUniversalTime().Ticks -ne ([datetime]$Identity.Started).ToUniversalTime().Ticks){return}
        $cim=Get-CimInstance Win32_Process -Filter ('ProcessId='+$Identity.Pid) -ErrorAction SilentlyContinue
        if(-not $cim -or $cim.ExecutablePath -ne $Identity.Path -or ([string]$cim.CommandLine).Trim() -ne $Identity.CommandLine){return}
        if(-not $live.HasExited){$live.Kill()}
    }finally{$live.Dispose()}
}
function Suspend-GuardSupervisorTask {
    [CmdletBinding()]param($State=(Get-GuardState),[int]$TimeoutSeconds=30)
    $task=Get-ScheduledTask -TaskName $State.Reliability.TaskName -TaskPath '\' -ErrorAction Stop
    Assert-GuardSupervisorTask $task $State
    $before=@(Get-GuardSupervisorProcessIdentities $State)
    $snapshot=[pscustomobject]@{TaskXml=(Export-ScheduledTask -TaskName $State.Reliability.TaskName -TaskPath '\');WasEnabled=[bool]$task.Settings.Enabled;WasRunning=($task.State.ToString() -eq 'Running');Processes=$before}
    $null=Disable-ScheduledTask -TaskName $State.Reliability.TaskName -TaskPath '\'
    if((Get-ScheduledTask -TaskName $State.Reliability.TaskName -TaskPath '\').Settings.Enabled){throw 'Supervisor task did not disable; maintenance refused.'}
    Stop-ScheduledTask -TaskName $State.Reliability.TaskName -TaskPath '\'
    $after=@(Get-GuardSupervisorProcessIdentities $State)
    $identities=@(@($before)+@($after)|Sort-Object Pid,Started -Unique)
    # 计划任务通常终止整棵树；残留仅按本次捕获的启动身份终止，避免旧健康 PID 复用。
    foreach($identity in $identities){Stop-GuardSupervisorProcessIdentity $identity}
    $watch=[Diagnostics.Stopwatch]::StartNew()
    do {
        $remaining=@($identities|Where-Object {Test-GuardSupervisorProcessIdentity $_})
        $discovered=@(Get-GuardSupervisorProcessIdentities $State)
        if(-not $remaining.Count -and -not $discovered.Count){break}
        if($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds){throw 'Supervisor host or worker did not stop; maintenance refused.'}
        Start-Sleep -Milliseconds 150
    }while($true)
    if((Get-ScheduledTask -TaskName $State.Reliability.TaskName -TaskPath '\').State.ToString() -eq 'Running'){throw 'Supervisor task remained running after process exit.'}
    $recoveryPath=Get-GuardPath 'private\supervisor-host-recovery.json'
    if(Test-Path -LiteralPath $recoveryPath){
        $recovery=Read-GuardJson $recoveryPath
        $activePid=Get-GuardLifecycleValue $recovery 'ActiveHostPid'
        $activeStarted=Get-GuardLifecycleValue $recovery 'ActiveHostStarted'
        $captured=@($identities|Where-Object {$_.Kind -eq 'Host' -and $_.Pid -eq $activePid -and $activeStarted -and ([datetime]$_.Started).ToUniversalTime().Ticks -eq ([datetime]$activeStarted).ToUniversalTime().Ticks})
        if($captured.Count -eq 1){
            foreach($name in @('ActiveRunId','ActiveHostPid','ActiveHostStarted')){$recovery|Add-Member -NotePropertyName $name -NotePropertyValue $null -Force}
            Write-GuardJson $recoveryPath $recovery
        }
    }
    $snapshot
}
function Resume-GuardSupervisorTask {
    [CmdletBinding()]param($State=(Get-GuardState),[switch]$Wait,[int]$TimeoutSeconds=90)
    Assert-GuardSupervisorTask (Get-ScheduledTask -TaskName $State.Reliability.TaskName -TaskPath '\') $State
    $null=Enable-ScheduledTask -TaskName $State.Reliability.TaskName -TaskPath '\'
    Start-ScheduledTask -TaskName $State.Reliability.TaskName -TaskPath '\'
    if($Wait){Wait-GuardSupervisorReady -TimeoutSeconds $TimeoutSeconds}
}


# 版本维护的观察状态不能代替守护就绪契约；操作记录只保存脱敏身份和路径。
function Get-GuardMaintenanceLock([string]$Purpose='Record') {
    $bytes=[Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFullPath((Get-GuardPath '')).ToLowerInvariant())
    $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).Substring(0,24)
    [Threading.Mutex]::new($false,('Local\ClaudeProGuardMaintenance-'+$hash+'-'+$Purpose))
}
function Invoke-GuardMaintenanceLocked([scriptblock]$Action) {
    $mutex=Get-GuardMaintenanceLock;$held=$false
    try {
        try{$held=$mutex.WaitOne(15000)}catch [Threading.AbandonedMutexException]{$held=$true}
        if(-not $held){throw 'MaintenanceBusy: 维护状态正在更新，请稍候。'}
        & $Action
    }finally{if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
}
function Get-GuardMaintenancePath([string]$OperationId) {
    if($OperationId -notmatch '^[0-9a-f]{32}$'){throw 'Invalid maintenance operation identity.'}
    Get-GuardPath ('private\maintenance-operation-'+$OperationId+'.json')
}
function Read-GuardMaintenanceOperation([string]$OperationId='') {
    $path=if($OperationId){Get-GuardMaintenancePath $OperationId}else{Get-GuardPath 'private\active-version-maintenance.json'}
    if(-not (Test-Path -LiteralPath $path)){return $null}
    $op=Read-GuardJson $path
    if(-not $OperationId -and $op.ActionId -match '^[0-9a-f]{32}$'){
        $canonical=Get-GuardMaintenancePath $op.ActionId
        if(Test-Path -LiteralPath $canonical){$op=Read-GuardJson $canonical}
    }
    if($op.SchemaVersion -ne 1 -or $op.ActionId -notmatch '^[0-9a-f]{32}$' -or ($OperationId -and $op.ActionId -ne $OperationId)){throw 'Invalid maintenance operation record.'}
    $op
}
function Test-GuardMaintenanceProcess([int]$ProcessId,$Started,[string]$Path) {
    if($ProcessId -le 0 -or -not $Started -or -not $Path){return $false}
    try {
        if(-not ('ClaudeMaintenanceProcessIdentity' -as [type])){
            Add-Type -TypeDefinition @"
using System;using System.Text;using System.Runtime.InteropServices;
public static class ClaudeMaintenanceProcessIdentity {
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder name,ref uint length);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr h,out long created,out long exited,out long kernel,out long user);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 public static bool Matches(int pid,DateTime started,string path){
  IntPtr h=OpenProcess(0x1000,false,pid);if(h==IntPtr.Zero)return false;
  try{long created,exited,kernel,user;uint length=32768;var name=new StringBuilder((int)length);
   return GetProcessTimes(h,out created,out exited,out kernel,out user)&&exited==0&&created==started.ToUniversalTime().ToFileTimeUtc()&&QueryFullProcessImageName(h,0,name,ref length)&&String.Equals(name.ToString(),path,StringComparison.OrdinalIgnoreCase);
  }finally{CloseHandle(h);}
 }
}
"@
        }
        [ClaudeMaintenanceProcessIdentity]::Matches($ProcessId,([datetimeoffset]$Started).UtcDateTime,$Path)
    }catch{$false}
}
function Get-GuardMaintenanceAssessment($Operation,[scriptblock]$ProcessVerifier=${function:Test-GuardMaintenanceProcess},[datetimeoffset]$NowUtc=[datetimeoffset]::UtcNow) {
    if(-not $Operation){return [pscustomobject]@{Operation=$null;Active=$false;Interrupted=$false;OverBudget=$false}}
    $terminal=$Operation.Status -in @('Completed','Failed','Interrupted')
    $live=$false
    if(-not $terminal){
        if($Operation.WorkerPid){$live=& $ProcessVerifier $Operation.WorkerPid $Operation.WorkerStarted $Operation.WorkerPath}
        else{$live=& $ProcessVerifier $Operation.CoordinatorPid $Operation.CoordinatorStarted $Operation.CoordinatorPath}
    }
    $interrupted=($Operation.Status -eq 'Interrupted') -or (-not $terminal -and -not $live)
    $budget=if($Operation.WorkerPid){600}else{660}
    $since=if($Operation.WorkerPid){$Operation.WorkerStarted}else{$Operation.StartedAt}
    $over=-not $terminal -and (($NowUtc-([datetimeoffset]$since)).TotalSeconds -gt $budget)
    [pscustomobject]@{Operation=$Operation;Active=([bool]$live);Interrupted=$interrupted;OverBudget=$over}
}
function Get-GuardMaintenanceSnapshot {
    Get-GuardMaintenanceAssessment (Read-GuardMaintenanceOperation)
}
function New-GuardMaintenanceOperation([string]$ActionId) {
    $null=Get-GuardMaintenancePath $ActionId
    Invoke-GuardMaintenanceLocked {
        $previous=Get-GuardMaintenanceSnapshot
        if($previous.Active){throw 'MaintenanceBusy: 版本维护正在进行，请接续观察。'}
        if($previous.Interrupted -or ($previous.Operation -and $previous.Operation.RecoveryRequired)){throw 'MaintenanceInterrupted: 维护中断，需要同账号管理员恢复。'}
        $self=[Diagnostics.Process]::GetCurrentProcess()
        $op=[ordered]@{SchemaVersion=1;ActionId=$ActionId;StageId=$null;StageFile=$null;StageHash=$null;ResultFile=$null;Status='Running';Phase='Preparing';StartedAt=[datetime]::UtcNow.ToString('o');UpdatedAt=[datetime]::UtcNow.ToString('o');CompletedAt=$null;CoordinatorPid=$PID;CoordinatorStarted=$self.StartTime.ToUniversalTime().ToString('o');CoordinatorPath=$self.MainModule.FileName;WorkerPid=0;WorkerStarted=$null;WorkerPath=$null;Reason=$null;FailureKind=$null;RecoveryRequired=$false;RollbackRestored=$false;BackupFile=$null;BackupHash=$null;TaskBackup=$null;TaskBackupHash=$null;ProxyBackup=$null;ProxyBackupHash=$null;SupervisorSuspended=$false;BaselineChanged=$false}
        Write-GuardJson (Get-GuardMaintenancePath $ActionId) $op
        Write-GuardJson (Get-GuardPath 'private\active-version-maintenance.json') $op
        [pscustomobject]$op
    }
}
function Set-GuardMaintenanceOperation([string]$OperationId,[Collections.IDictionary]$Changes,[switch]$Recovery) {
    Invoke-GuardMaintenanceLocked {
        $op=Read-GuardMaintenanceOperation $OperationId
        if(-not $op){throw 'Maintenance operation record is missing.'}
        if($op.Status -in @('Completed','Failed','Interrupted') -and -not $Recovery){return $op}
        foreach($key in $Changes.Keys){$op|Add-Member -NotePropertyName $key -NotePropertyValue $Changes[$key] -Force}
        $op.UpdatedAt=[datetime]::UtcNow.ToString('o')
        if($op.Status -in @('Completed','Failed','Interrupted')){
            $op.CompletedAt=$op.UpdatedAt
            # 终态作为最后发布的完成标记；先保存权威 UI 投影，再开放终态观察。
            $activeBefore=Read-GuardMaintenanceOperation
            $claimPath=Get-GuardPath 'private\active-ui-action.json';$claim=$null
            if(Test-Path -LiteralPath $claimPath){$claim=Read-GuardJson $claimPath}
            if($activeBefore -and $activeBefore.ActionId -eq $OperationId -and (-not $claim -or ($claim.Kind -eq 'Update' -and $claim.OperationId -eq $OperationId))){
                $projection=Get-GuardMaintenanceUiResult $op
                if($claim){$projection.ActionId=$claim.ActionId}
                Write-GuardJson (Get-GuardPath 'evidence\last-ui-result.json') $projection
                $errorPath=Get-GuardPath 'private\last-ui-error.json'
                if($projection.Success){if(Test-Path -LiteralPath $errorPath){Remove-Item -LiteralPath $errorPath}}
                elseif(-not $projection.Pending){Write-GuardJson $errorPath @{Time=[datetime]::UtcNow.ToString('o');ActionId=$OperationId;FailureKind=$projection.FailureKind;Detail=$projection.Message}}
            }
        }
        Write-GuardJson (Get-GuardMaintenancePath $OperationId) $op
        $active=Read-GuardMaintenanceOperation
        if($active -and $active.ActionId -eq $OperationId){Write-GuardJson (Get-GuardPath 'private\active-version-maintenance.json') $op}
        $op
    }
}
function Get-GuardMaintenanceUiResult($Operation) {
    $s=Get-GuardMaintenanceAssessment $Operation
    $result=[ordered]@{Success=$false;Pending=$s.Active;Message='维护仍在进行，暂未取得最终结果。';Started=$false;SessionVerified=$false;DesktopPid=$null;FailureKind=$null;ApprovedVersion=$null;InstalledVersion=$null;SupervisorStatus=$null;SupervisorVerified=$false;SupervisorTime=$null;SupervisorRunId=$null;ApiTransport=$null;ActionId=$Operation.ActionId;OperationId=$Operation.ActionId;Phase=$Operation.Phase}
    if($s.Interrupted -or $Operation.RecoveryRequired){$result.Pending=$false;$result.FailureKind='MaintenanceInterrupted';$result.Message='维护中断，需要恢复。请点击“维护版本”，通过同账号管理员授权恢复后再重试。'}
    elseif($Operation.Status -eq 'Failed'){$result.FailureKind=$Operation.FailureKind;$result.Message=if($Operation.Reason){$Operation.Reason}else{'版本维护失败，请查看维护记录。'}}
    elseif($Operation.Status -eq 'Completed'){
        $d=Get-GuardState;$health=Get-GuardSupervisorSnapshot
        $result.ApprovedVersion=$d.Desktop.Version;$result.InstalledVersion=(Get-GuardDesktop).Version
        if($health.Ready -and $Operation.ResultFile -and (Test-Path -LiteralPath $Operation.ResultFile)){
            $migration=Read-GuardJson $Operation.ResultFile
            if($migration.Success -and $migration.ActionId -eq $Operation.ActionId -and $migration.StageId -eq $Operation.StageId -and $migration.DesktopVersion -eq $d.Desktop.Version -and $migration.CodeVersion -eq $d.CodeGate.Version){
                $result.Success=$true;$result.SupervisorVerified=$true;$result.SupervisorStatus=$health.Kind;$result.SupervisorTime=$health.Health.Time;$result.SupervisorRunId=$health.Health.RunId;$result.SessionVerified=Test-GuardLocalCodeAcceptance
                $result.Message='版本维护完成。Desktop '+$d.Desktop.Version+' / Code '+$d.CodeGate.Version+'；后台守护及固定出口检查通过。点击“打开 Claude”继续。'
            }
        }
        if(-not $result.Success){$result.FailureKind='SupervisorUnavailable';$result.Message='版本迁移已完成，当前守护就绪尚未确认，请重新检查。'}
    }
    [pscustomobject]$result
}
function Register-GuardUiAction([string]$ActionId,[string]$Kind,[string]$OperationId='') {
    if($ActionId -notmatch '^[0-9a-f]{32}$'){throw 'Invalid UI action identity.'}
    Invoke-GuardMaintenanceLocked {
        Write-GuardJson (Get-GuardPath 'private\active-ui-action.json') @{ActionId=$ActionId;Kind=$Kind;OperationId=$OperationId;StartedAt=[datetime]::UtcNow.ToString('o')}
    }
}
function Set-GuardUiMaintenanceBinding([string]$ActionId,[string]$OperationId) {
    Invoke-GuardMaintenanceLocked {
        $path=Get-GuardPath 'private\active-ui-action.json'
        if(Test-Path -LiteralPath $path){$claim=Read-GuardJson $path;if($claim.ActionId -eq $ActionId -and $claim.Kind -eq 'Update'){$claim.OperationId=$OperationId;Write-GuardJson $path $claim}}
    }
}
function Sync-GuardMaintenanceUiResult([string]$OperationId) {
    Invoke-GuardMaintenanceLocked {
        $active=Read-GuardMaintenanceOperation
        if(-not $active -or $active.ActionId -ne $OperationId){return}
        $claimPath=Get-GuardPath 'private\active-ui-action.json'
        $claim=$null
        if(Test-Path -LiteralPath $claimPath){$claim=Read-GuardJson $claimPath;if($claim.Kind -ne 'Update' -or $claim.OperationId -ne $OperationId){return}}
        $result=Get-GuardMaintenanceUiResult $active
        if($claim){$result.ActionId=$claim.ActionId}
        Write-GuardJson (Get-GuardPath 'evidence\last-ui-result.json') $result
        $errorPath=Get-GuardPath 'private\last-ui-error.json'
        if($result.Success){if(Test-Path -LiteralPath $errorPath){Remove-Item -LiteralPath $errorPath}}
        elseif(-not $result.Pending){Write-GuardJson $errorPath @{Time=[datetime]::UtcNow.ToString('o');ActionId=$OperationId;FailureKind=$result.FailureKind;Detail=$result.Message}}
        $result
    }
}
function Restore-GuardCodeMigrationPermissions($Backup) {
    $current=Get-GuardState
    $candidatePaths=@(Get-GuardLifecycleValue $Backup 'CandidateCodePaths' @())
    foreach($path in $candidatePaths){
        if($path -notin @($current.CodePaths)){throw 'Maintenance rollback candidate ACL path is not approved.'}
        if($path -notin @($Backup.Deployment.CodePaths) -and (Test-Path -LiteralPath $path)){
            $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetAccessRuleProtection($false,$false)
            Set-CodeAccessOnlyAcl $path $acl
        }
    }
    foreach($entry in $Backup.CodeAcls){
        if($entry.Path -notin (@($Backup.Deployment.CodePaths)+$candidatePaths)){throw 'Maintenance rollback ACL path is not approved.'}
        if(Test-Path -LiteralPath $entry.Path){$acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm($entry.Sddl,[Security.AccessControl.AccessControlSections]::Access);Set-CodeAccessOnlyAcl $entry.Path $acl}
    }
    $gateBackup=Get-GuardLifecycleValue $Backup 'GateBackup'
    if($gateBackup){Write-GuardJson (Get-GuardPath 'private\code-gate-backup.json') $gateBackup}
}
function Restore-GuardMaintenanceBackup($Operation) {
    if(-not (Test-GuardAdmin)){throw 'Same-account administrator recovery is required.'}
    $d=Get-GuardState
    if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $d.UserSid){throw 'Maintenance recovery requires the original Windows account.'}
    if(-not $Operation.BackupFile){return}
    foreach($pair in @(@{Path=$Operation.BackupFile;Hash=$Operation.BackupHash;Pattern='^upgrade-backup-[0-9a-f]{32}\.json$'},@{Path=$Operation.TaskBackup;Hash=$Operation.TaskBackupHash;Pattern='^upgrade-task-[0-9a-f]{32}\.xml$'},@{Path=$Operation.ProxyBackup;Hash=$Operation.ProxyBackupHash;Pattern='^proxy-before-[0-9a-f]{32}\.json$'})){
        if(-not $pair.Path){continue}
        $full=[IO.Path]::GetFullPath($pair.Path)
        if([IO.Path]::GetDirectoryName($full) -ne (Get-GuardPath 'private') -or [IO.Path]::GetFileName($full) -notmatch $pair.Pattern -or (Get-GuardHash $full) -ne $pair.Hash){throw 'Maintenance recovery backup changed or escaped the private directory.'}
    }
    if(-not $Operation.SupervisorSuspended -and -not $Operation.BaselineChanged){return}
    $backup=Read-GuardJson $Operation.BackupFile
    if($backup.Deployment.UserSid -ne $d.UserSid -or $backup.Deployment.ProxyUrl -ne $d.ProxyUrl -or $backup.Deployment.ExpectedIp -ne $d.ExpectedIp){throw 'Maintenance recovery escaped the approved account/network boundary.'}
    if((Get-GuardLifecycleValue $backup.Deployment 'ProxyEngine' 'sing-box') -ne (Get-GuardLifecycleValue $d 'ProxyEngine' 'sing-box') -or ((Get-GuardExpectedIps $backup.Deployment|Sort-Object) -join ',') -ne ((Get-GuardExpectedIps $d|Sort-Object) -join ',')){throw 'Maintenance recovery changed the approved node pool.'}
    if($Operation.SupervisorSuspended){$null=Suspend-GuardSupervisorTask -State $d -TimeoutSeconds 30}
    Stop-GuardProxyEmergency
    Restore-GuardCodeMigrationPermissions $backup
    Write-GuardJson (Get-GuardPath 'private\deployment.json') $backup.Deployment
    if($Operation.ProxyBackup){Copy-Item -LiteralPath $Operation.ProxyBackup -Destination (Get-GuardPath 'private\proxy.json')}
    if($Operation.TaskBackup){$null=Register-ScheduledTask -TaskName $backup.Deployment.Reliability.TaskName -TaskPath '\' -Xml (Get-Content -LiteralPath $Operation.TaskBackup -Raw) -Force}
    if($Operation.BaselineChanged){Write-GuardJson (Get-GuardPath 'private\safety-hold.json') @{Time=[datetime]::UtcNow.ToString('o');Reason='Interrupted maintenance recovered; reviewed maintenance is required before protected launch.'}}
    $marker=Get-GuardPath 'private\maintenance.json'
    if(Test-Path -LiteralPath $marker){$m=Read-GuardJson $marker;if((Get-GuardLifecycleValue $m 'ActionId') -eq $Operation.ActionId){Remove-Item -LiteralPath $marker}}
    if($Operation.SupervisorSuspended -and $backup.WasEnabled){$null=Enable-ScheduledTask -TaskName $backup.Deployment.Reliability.TaskName -TaskPath '\';if($backup.WasRunning){Start-ScheduledTask -TaskName $backup.Deployment.Reliability.TaskName -TaskPath '\'}}
}

function Test-GuardMaintenanceAuthorizationCancelled($Exception) {
    $e=$Exception;while($e.InnerException){$e=$e.InnerException}
    ($e -is [ComponentModel.Win32Exception] -and $e.NativeErrorCode -eq 1223)
}

function Start-GuardMaintenanceAdministrator([string]$Shell,[string]$Arguments) {
    # PowerShell Start-Process 将 Win32Exception 转为不含原始错误码的通用异常。
    # ShellExecute 的原生结果保留 1223；观察超时不进入授权取消分支。
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$Shell
    $info.Arguments=$Arguments
    $info.WorkingDirectory=$PSScriptRoot
    $info.UseShellExecute=$true
    $info.Verb='runas'
    $info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
    [Diagnostics.Process]::Start($info)
}
