[CmdletBinding()]
param(
    [switch]$Worker,
    [string]$ResultFile,
    [string]$ReviewedWorkerHash,
    [datetimeoffset]$DeadlineUtc=[datetimeoffset]::MaxValue,
    [switch]$AdministratorContext
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ClaudeCodeGate.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-CacheRepair.psm1') -Force
$d=Get-GuardState
if(-not (Test-GuardAdmin) -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $d.UserSid){throw 'Same-account administrator context required.'}
if(@(Get-GuardDesktopProcesses).Count -or @(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -in @($d.CodePaths)}).Count){throw 'Exit Claude and Code before cache permissions repair.'}
if($Worker) {
    $ResultFile=[IO.Path]::GetFullPath($ResultFile)
    if([IO.Path]::GetDirectoryName($ResultFile) -ne (Get-GuardPath 'private') -or [IO.Path]::GetFileName($ResultFile) -notmatch '^cache-repair-[0-9a-f]{32}\.json$' -or (Get-GuardHash $PSCommandPath) -ne $ReviewedWorkerHash){throw 'Reviewed cache worker arguments changed.'}
    $cacheWorkerId=[IO.Path]::GetFileNameWithoutExtension($ResultFile).Substring(13)
    $cacheClock=[Diagnostics.Stopwatch]::StartNew()
    $cacheStarted=[datetimeoffset]::UtcNow
    $cacheDeadline=Get-Variable -Name DeadlineUtc -ValueOnly -ErrorAction SilentlyContinue
    if(-not $cacheDeadline -or $cacheDeadline -gt $cacheStarted.AddSeconds(300)){$cacheDeadline=$cacheStarted.AddSeconds(300)}
    $record=[ordered]@{SchemaVersion=1;OperationId=$cacheWorkerId;ReviewedWorkerHash=$ReviewedWorkerHash;Time=(Get-Date -Format o);StartedAt=$cacheStarted.ToString('o');CompletedAt=$null;ElapsedMilliseconds=0;Success=$false;Reason=$null;CurrentPhase=$null;Phases=@();ChangedPermissions=@();Candidates=@()}
    function Assert-CacheWorkerBudget {
        if([datetimeoffset]::UtcNow -ge $cacheDeadline -or $cacheClock.Elapsed.TotalSeconds -ge 300){throw ('Desktop cache repair timed out. Last phase: '+$record.CurrentPhase)}
    }
    function Set-CacheRepairPhase([string]$Name) {
        Assert-CacheWorkerBudget
        if($record.Phases.Count){$record.Phases[-1].CompletedAt=[datetimeoffset]::UtcNow.ToString('o');$record.Phases[-1].ElapsedMilliseconds=$cacheClock.ElapsedMilliseconds-$record.Phases[-1].StartedElapsedMilliseconds}
        $record.CurrentPhase=$Name
        $record.Phases+=@([ordered]@{Phase=$Name;StartedAt=[datetimeoffset]::UtcNow.ToString('o');StartedElapsedMilliseconds=$cacheClock.ElapsedMilliseconds;CompletedAt=$null;ElapsedMilliseconds=$null})
        Write-GuardJson ($ResultFile+'.progress.json') @{SchemaVersion=1;OperationId=$cacheWorkerId;ReviewedWorkerHash=$ReviewedWorkerHash;WorkerPid=$PID;Time=[datetimeoffset]::UtcNow.ToString('o');Phase=$Name;ElapsedMilliseconds=$cacheClock.ElapsedMilliseconds}
    }
    try {
        Set-CacheRepairPhase 'ValidateCacheRoots'
        foreach($root in $d.CodeGate.Roots) {
            Assert-CacheWorkerBudget
            if(Test-Path -LiteralPath $root){
                Assert-CodeCacheGate $root
                if((Get-Item -LiteralPath $root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint -or @(Get-ChildItem -LiteralPath $root -Recurse -Force|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'Code cache reparse point requires separate review.'}
            }
        }
        Set-CacheRepairPhase 'RestrictUnapprovedExecutables'
        foreach($root in $d.CodeGate.Roots) {
            # 缺失目录由下方受控修复创建；先收紧已有旧引擎，再执行完整门禁验收。
            Assert-CacheWorkerBudget
            if(-not (Test-Path -LiteralPath $root)){continue}
            Assert-CodeCacheGate $root
            if((Get-Item $root).Attributes -band [IO.FileAttributes]::ReparsePoint -or @(Get-ChildItem $root -Recurse -Force|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'Code cache reparse point requires separate review.'}
            foreach($file in Get-ChildItem $root -Recurse -Force -File -Filter *.exe) {
                Assert-CacheWorkerBudget
                $acl=Get-Acl -LiteralPath $file.FullName
                $approved=$file.FullName -in @($d.CodePaths)
                $entry=@{Path=$file.FullName;Hash=(Get-GuardHash $file.FullName);Approved=$approved;BeforeSddl=$acl.Sddl}
                $record.Candidates+=@($entry)
                if($approved) {
                    if($entry.Hash -ne $d.CodeGate.PayloadHash){throw 'Approved engine hash changed; permissions repair refused.'}
                } else {
                    $deny=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object {$_.IdentityReference.Value -eq $d.UserSid -and $_.AccessControlType.ToString() -eq 'Deny' -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ExecuteFile)})
                    if(-not $deny.Count){
                        Write-GuardJson ($ResultFile+'.acl-backup.json') $record
                        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($d.UserSid),'ExecuteFile','Deny'))
                        Set-CodeAccessOnlyAcl $file.FullName $acl
                        $record.ChangedPermissions+=@($file.FullName)
                    }
                }
            }
        }
        Set-CacheRepairPhase 'RepairDesktopCache'
        Repair-GuardDesktopCodeCache
        Set-CacheRepairPhase 'VerifyFirewall'
        Assert-GuardFirewall
        Set-CacheRepairPhase 'Completed'
        $record.Success=$true
    } catch {$record.Reason=$_.Exception.Message} finally {
        $record.CompletedAt=[datetimeoffset]::UtcNow.ToString('o');$record.ElapsedMilliseconds=$cacheClock.ElapsedMilliseconds
        if($record.Phases.Count){$record.Phases[-1].CompletedAt=$record.CompletedAt;$record.Phases[-1].ElapsedMilliseconds=$cacheClock.ElapsedMilliseconds-$record.Phases[-1].StartedElapsedMilliseconds}
        Write-GuardJson $ResultFile $record
    }
    if(-not $record.Success){exit 1}
    exit 0
}
if($ResultFile -or $ReviewedWorkerHash){throw 'Worker arguments require Worker mode.'}
if($DeadlineUtc -eq [datetimeoffset]::MaxValue){$DeadlineUtc=[datetimeoffset]::UtcNow.AddSeconds(315)}
$budget=New-GuardCacheRepairBudget -DeadlineUtc $DeadlineUtc -MaxWorkerSeconds 300 -CleanupReserveSeconds 15
$id=[guid]::NewGuid().ToString('N');$name='ClaudeProGuard-CacheRepair-'+$id
$resultPath=Get-GuardPath ('private\cache-repair-'+$id+'.json')
$workerHash=Get-GuardHash $PSCommandPath
$shellPath=(Get-Content (Get-GuardPath 'private\launcher-paths.txt') -Raw).Trim()
$workerArguments=@('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',$PSCommandPath,'-Worker','-ReviewedWorkerHash',$workerHash,'-ResultFile',$resultPath,'-DeadlineUtc',[string]$budget.WorkerDeadlineUtc)
$registered=$null;$workerProcess=$null;$waitResult=$null;$cleanupError=$null;$dispatchError=$null
$context=if($AdministratorContext){'Administrator'}else{'Desktop'}
try {
    if($AdministratorContext){
        # 同账号管理员检查也放到本次专属子进程，使阻塞调用受相同取消预算约束。
        $psi=[Diagnostics.ProcessStartInfo]::new($shellPath);$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.WorkingDirectory=$PSScriptRoot
        foreach($argument in $workerArguments){$psi.ArgumentList.Add($argument)}
        $workerProcess=[Diagnostics.Process]::Start($psi)
    }else{
        $service=New-Object -ComObject Schedule.Service;$service.Connect();$folder=$service.GetFolder('\')
        $definition=$service.NewTask(0)
        $definition.Principal.UserId=$d.UserSid;$definition.Principal.LogonType=3;$definition.Principal.RunLevel=1
        $definition.Settings.Hidden=$true;$definition.Settings.ExecutionTimeLimit=$budget.TaskExecutionTimeLimit;$definition.Settings.DisallowStartIfOnBatteries=$false;$definition.Settings.StopIfGoingOnBatteries=$false
        $action=$definition.Actions.Create(0);$action.Path=$shellPath;$action.WorkingDirectory=$PSScriptRoot
        $action.Arguments=($workerArguments|ForEach-Object {'"'+$_+'"'}) -join ' '
        $registered=$folder.RegisterTaskDefinition($name,$definition,6,$d.UserSid,$null,3,$null)
        $null=$registered.Run($null)
    }
    $waitResult=Wait-GuardCacheRepairResult -Budget $budget -OperationId $id -ReviewedWorkerHash $workerHash -ReadResult {if(Test-Path -LiteralPath $resultPath){Read-GuardJson $resultPath}} -ReadProgress {if(Test-Path -LiteralPath ($resultPath+'.progress.json')){Read-GuardJson ($resultPath+'.progress.json')}} -GetTaskState {
        if($workerProcess){if($workerProcess.HasExited){@{State='Ready';LastTaskResult=$workerProcess.ExitCode}}else{@{State='Running'}}}else{@{State=$registered.State;LastTaskResult=$registered.LastTaskResult}}
    }
    Write-GuardJson ($resultPath+'.wait.json') @{SchemaVersion=1;OperationId=$id;Context=$context;Budget=$budget;Wait=$waitResult;CompletedAt=[datetimeoffset]::UtcNow.ToString('o')}
    if(-not $waitResult.Success){throw $waitResult.Reason}
    Write-GuardJson (Get-GuardPath 'evidence\code-cache-context-repair.json') $waitResult.Result
}catch{$dispatchError=$_.Exception.Message;throw}finally{
    # 只取消本次创建且保留对象身份的worker，绝不按进程名或共享代理任务取消。
    try{
        $cleanupClock=[Diagnostics.Stopwatch]::StartNew()
        $cleanupMilliseconds=[int][Math]::Max(0,[Math]::Min($budget.CancellationReserveSeconds*1000,(([datetimeoffset]$budget.DeadlineUtc)-[datetimeoffset]::UtcNow).TotalMilliseconds))
        if($workerProcess -and -not $workerProcess.HasExited){
            $grace=if($waitResult -and $waitResult.Success){[Math]::Min(1000,$cleanupMilliseconds)}else{0}
            if(-not $workerProcess.WaitForExit($grace)){
                $workerProcess.Kill()
                $remaining=[int][Math]::Max(0,$cleanupMilliseconds-$cleanupClock.ElapsedMilliseconds)
                if(-not $workerProcess.WaitForExit($remaining)){throw 'Owned cache worker did not exit within cancellation budget.'}
            }
        }
        if($registered){
            if([int]$registered.State -in @(2,4)){$registered.Stop(0)}
            while([int]$registered.State -in @(2,4)){
                $remaining=$cleanupMilliseconds-$cleanupClock.ElapsedMilliseconds
                if($remaining -le 0){throw 'Owned cache task did not stop within cancellation budget.'}
                [Threading.Thread]::Sleep([int][Math]::Min(100,$remaining))
            }
            $folder.DeleteTask($name,0)
        }
    }catch{$cleanupError=$_.Exception.Message}
    if(-not $waitResult){Write-GuardJson ($resultPath+'.wait.json') @{SchemaVersion=1;OperationId=$id;Context=$context;Budget=$budget;FailureKind='CacheRepairDispatchFailed';Reason=$dispatchError;CompletedAt=[datetimeoffset]::UtcNow.ToString('o')}}
    Write-GuardJson ($resultPath+'.cleanup.json') @{SchemaVersion=1;OperationId=$id;Context=$context;CleanupError=$cleanupError;CompletedAt=[datetimeoffset]::UtcNow.ToString('o')}
    if($workerProcess){$workerProcess.Dispose()}
    if($cleanupError){throw ('Desktop cache worker cleanup failed: '+$cleanupError)}
}
[pscustomobject]@{OperationId=$id;Context=$context;ResultFile=$resultPath;ElapsedMilliseconds=$waitResult.Result.ElapsedMilliseconds;Success=$true}
exit 0
