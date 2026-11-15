[CmdletBinding()]
param(
    [string]$RepairScriptPath=(Join-Path $PSScriptRoot 'Repair-ClaudeCodeContext-Admin.ps1'),
    [string]$ReportFile=(Join-Path $PSScriptRoot 'evidence\cache-repair-context-regression.json')
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-CacheRepair.psm1') -Force
$checks=[Collections.Generic.List[string]]::new()
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeCacheContext-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path (Join-Path $fixture 'private'),(Join-Path $fixture 'evidence')
function Require([bool]$Condition,[string]$Name){if(-not $Condition){throw ('Cache context regression failed: '+$Name)};$checks.Add($Name)}
function Read-Ast([string]$Path){$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors);if($errors.Count){throw ($errors|Out-String)};$ast}
$RepairScriptPath=(Resolve-Path -LiteralPath $RepairScriptPath).ProviderPath
$repairAst=Read-Ast $RepairScriptPath
$coordinator=@($repairAst.EndBlock.Statements|Where-Object {$_.Extent.Text.StartsWith('if($ResultFile -or $ReviewedWorkerHash)')})
if($coordinator.Count -ne 1){throw 'Cache coordinator branch boundary not found.'}
$repairSource=Get-Content -LiteralPath $RepairScriptPath -Raw
$body=$repairSource.Substring($coordinator[0].Extent.StartOffset).Replace('$PSCommandPath','$CacheRepairScriptPath').Replace('$PSScriptRoot','$FixtureRoot').Replace('exit 0','return')
$coordinatorBody=[scriptblock]::Create($body)
# 使用工程真正的共享 JSON 读写代码；只向随机临时根目录写入。
$guardAst=Read-Ast (Join-Path $PSScriptRoot 'ClaudeGuard.psm1')
foreach($name in @('Read-GuardJson','Write-GuardJson')){
    $definition=@($guardAst.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true))
    if($definition.Count -ne 1){throw ('Shared JSON function missing: '+$name)}
    $text=$definition[0].Extent.Text
    if($name -eq 'Write-GuardJson'){$text=$text.Replace('function Write-GuardJson','function Write-FixtureGuardJson')}
    . ([scriptblock]::Create($text))
}
$script:cacheContext=$null
function Get-GuardPath([string]$Name){Join-Path $fixture $Name}
function Get-GuardHash([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
function Write-GuardJson([string]$Path,$Value){
    $full=[IO.Path]::GetFullPath($Path);$allowed=[IO.Path]::GetFullPath($fixture)+'\'
    if(-not $full.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture attempted a write outside its temporary root.'}
    Write-FixtureGuardJson $full $Value
    $script:cacheContext.Events.Add('write:'+([IO.Path]::GetFileName($Path)))
}
function Publish-FixtureResult($Context){
    if($Context.Published){return}
    $Context.Published=$true
    $id=$Context.OperationId;$hash=$Context.WorkerHash
    if($Context.Mode -eq 'WrongOperation'){$id=[guid]::NewGuid().ToString('N')}
    if($Context.Mode -eq 'WrongHash'){$hash='f'*64}
    $success=$Context.Mode -ne 'WorkerFailure'
    $result=@{SchemaVersion=1;OperationId=$id;ReviewedWorkerHash=$hash;StartedAt=$Context.StartUtc.AddSeconds(1).ToString('o');CompletedAt=$Context.StartUtc.AddSeconds($Context.Elapsed).ToString('o');ElapsedMilliseconds=($Context.Elapsed-1)*1000;Success=$success;Reason=if($success){$null}else{'fixture payload mismatch'};Phases=@(@{Phase='VerifyFirewall';ElapsedMilliseconds=1000})}
    Write-FixtureGuardJson $Context.ResultPath $result
    if($Context.Mode -notin @('WrongOperation','WrongHash')){$Context.TaskCompleted=$true}
}
function New-FakeScheduleService($Context){
    $publish=${function:Publish-FixtureResult};$write=${function:Write-FixtureGuardJson}
    $action=[pscustomobject]@{Path=$null;WorkingDirectory=$null;Arguments=$null}
    $actions=[pscustomobject]@{Action=$action};$actions|Add-Member ScriptMethod Create {param($kind);if($kind -ne 0){throw 'Unexpected task action type.'};$this.Action}
    $definition=[pscustomobject]@{Principal=[pscustomobject]@{UserId=$null;LogonType=0;RunLevel=0};Settings=[pscustomobject]@{Hidden=$false;ExecutionTimeLimit=$null;DisallowStartIfOnBatteries=$true;StopIfGoingOnBatteries=$true};Actions=$actions}
    $task=[pscustomobject]@{Context=$Context;LastTaskResult=0}
    $task|Add-Member ScriptProperty State {
        $c=$this.Context
        if($c.StopRequested){$c.StateReadsAfterStop++;if($c.Mode -ne 'StopNeverCompletes' -and $c.StateReadsAfterStop -ge 2){$c.TaskCompleted=$true}}
        if($c.Mode -eq 'ExitRace' -and $c.Elapsed -ge 2 -and -not $c.Published){& $publish $c}
        if($c.TaskCompleted -or $c.Mode -in @('NeverStarts','RunThrows')){return 3}
        return 4
    }.GetNewClosure()
    $task|Add-Member ScriptMethod Run {
        param($arguments)
        $c=$this.Context;$c.Events.Add('run:'+ $c.RegisteredName)
        $parts=@([regex]::Matches($c.Definition.Actions.Action.Arguments,'"([^"]*)"')|ForEach-Object {$_.Groups[1].Value})
        $c.Arguments=$parts;$c.ResultPath=$parts[[Array]::IndexOf($parts,'-ResultFile')+1];$c.WorkerHash=$parts[[Array]::IndexOf($parts,'-ReviewedWorkerHash')+1]
        $c.OperationId=[IO.Path]::GetFileNameWithoutExtension($c.ResultPath).Substring(13)
        if($c.Mode -eq 'RunThrows'){throw 'fixture scheduler dispatch failed'}
        if($c.Mode -ne 'NeverStarts'){& $write ($c.ResultPath+'.progress.json') @{OperationId=$c.OperationId;ReviewedWorkerHash=$c.WorkerHash;WorkerPid=123;Phase='VerifyFirewall';Time=$c.StartUtc.ToString('o')}}
    }.GetNewClosure()
    $task|Add-Member ScriptMethod Stop {param($flags);if($flags -ne 0){throw 'Unexpected stop flags.'};$this.Context.Events.Add('stop:'+ $this.Context.RegisteredName);$this.Context.StopRequested=$true}
    $folder=[pscustomobject]@{Context=$Context;Task=$task}
    $folder|Add-Member ScriptMethod RegisterTaskDefinition {
        param($name,$definition,$flags,$user,$password,$logon,$sddl)
        $c=$this.Context;if($name -notmatch '^ClaudeProGuard-CacheRepair-[a-f0-9]{32}$' -or $flags -ne 6 -or $logon -ne 3){throw 'Unexpected registered task identity.'}
        $c.RegisteredName=$name;$c.Definition=$definition;$c.Events.Add('register:'+ $name);$this.Task
    }
    $folder|Add-Member ScriptMethod DeleteTask {
        param($name,$flags)
        if($name -ne $this.Context.RegisteredName -or $flags -ne 0){throw 'Cleanup targeted another task.'}
        if($this.Task.State -in @(2,4)){throw 'Task deleted before stop was confirmed.'}
        $this.Context.Deleted=$true;$this.Context.Events.Add('delete:'+ $name)
    }
    $service=[pscustomobject]@{Context=$Context;Definition=$definition;Folder=$folder}
    $service|Add-Member ScriptMethod Connect {if($this.Context.Mode -eq 'ConnectThrows'){throw 'fixture scheduler unavailable'}}
    $service|Add-Member ScriptMethod NewTask {param($flags);$this.Definition}
    $service|Add-Member ScriptMethod GetFolder {param($path);if($path -ne '\'){throw 'Unexpected scheduler folder.'};$this.Folder}
    $service
}
function New-Object {param([string]$ComObject);if($ComObject -ne 'Schedule.Service'){throw 'Fixture refused an unexpected COM object.'};New-FakeScheduleService $script:cacheContext}
function New-GuardCacheRepairBudget {
    param($DeadlineUtc,$MaxWorkerSeconds,$CleanupReserveSeconds)
    $budget=ClaudeGuard-CacheRepair\New-GuardCacheRepairBudget -DeadlineUtc $DeadlineUtc -NowUtc $script:cacheContext.StartUtc -MaxWorkerSeconds $MaxWorkerSeconds -CleanupReserveSeconds $CleanupReserveSeconds
    if($script:cacheContext.Mode -eq 'StopNeverCompletes'){$budget.CancellationReserveSeconds=0.05}
    $script:cacheContext.Budget=$budget;$budget
}
function Wait-GuardCacheRepairResult {
    param($Budget,$OperationId,$ReviewedWorkerHash,[scriptblock]$ReadResult,[scriptblock]$ReadProgress,[scriptblock]$GetTaskState)
    $c=$script:cacheContext;$publish=${function:Publish-FixtureResult}
    $now={$c.StartUtc.AddSeconds($c.Elapsed)}.GetNewClosure();$elapsed={$c.Elapsed}.GetNewClosure()
    $delay={param($Milliseconds)
        $c.Elapsed+=$Milliseconds/1000.0
        if($c.Mode -in @('Success','WorkerFailure','WrongOperation','WrongHash') -and $c.Elapsed -ge $c.FinishAt){& $publish $c}
        if($c.Mode -eq 'EarlyExit' -and $c.Elapsed -ge 2){$c.TaskCompleted=$true}
    }.GetNewClosure()
    $r=ClaudeGuard-CacheRepair\Wait-GuardCacheRepairResult -Budget $Budget -OperationId $OperationId -ReviewedWorkerHash $ReviewedWorkerHash -ReadResult $ReadResult -ReadProgress $ReadProgress -GetTaskState $GetTaskState -GetNowUtc $now -GetElapsedSeconds $elapsed -Delay $delay
    $c.Wait=$r;$r
}
function Invoke-FixtureCoordinator([string]$Mode,[double]$FinishAt=2){
    foreach($file in Get-ChildItem -LiteralPath (Join-Path $fixture 'private') -File){Remove-Item -LiteralPath $file.FullName}
    [IO.File]::WriteAllText((Join-Path $fixture 'private\launcher-paths.txt'),[Environment]::ProcessPath)
    $script:cacheContext=@{Mode=$Mode;StartUtc=[datetimeoffset]::UtcNow;Elapsed=0.0;FinishAt=$FinishAt;Events=[Collections.Generic.List[string]]::new();TaskCompleted=$false;StopRequested=$false;StateReadsAfterStop=0;Deleted=$false;Published=$false;RegisteredName=$null;Definition=$null;Arguments=@();ResultPath=$null;OperationId=$null;WorkerHash=$null;Budget=$null;Wait=$null;Error=$null}
    $ResultFile=$null;$ReviewedWorkerHash=$null;$DeadlineUtc=$script:cacheContext.StartUtc.AddSeconds(500);$AdministratorContext=$false
    $d=[pscustomobject]@{UserSid='fixture-user'};$CacheRepairScriptPath=$RepairScriptPath;$FixtureRoot=$fixture
    try{$null=& $coordinatorBody}catch{$script:cacheContext.Error=$_.Exception.Message}
    $script:cacheContext
}
try {
    $c=Invoke-FixtureCoordinator 'Success' 157
    Require (-not $c.Error -and $c.Wait.Success) 'coordinator-accepts-successful-157-second-worker-through-real-json-reader'
    Require ($c.Wait.Result.StartedAt -is [datetime] -and $c.Wait.Result.CompletedAt -is [datetime]) 'coordinator-json-reader-reproduces-production-typed-timestamps'
    Require ([Xml.XmlConvert]::ToTimeSpan($c.Definition.Settings.ExecutionTimeLimit).TotalSeconds -eq 315 -and $c.Budget.WaitTimeoutSeconds -eq 300) 'scheduler-limit-and-wait-share-300-second-budget-plus-cleanup-reserve'
    $parts=$c.Arguments;$sentDeadline=$parts[[Array]::IndexOf($parts,'-DeadlineUtc')+1]
    Require (([datetimeoffset]$sentDeadline).UtcTicks -eq ([datetimeoffset]$c.Budget.WorkerDeadlineUtc).UtcTicks) 'worker-receives-budget-absolute-deadline-as-rfc3339-command-argument'
    Require ($parts[[Array]::IndexOf($parts,'-File')+1] -eq $RepairScriptPath -and $c.WorkerHash -eq (Get-GuardHash $RepairScriptPath)) 'worker-command-binds-reviewed-script-path-and-current-script-hash'
    Require ($c.Wait.OperationId -eq $c.OperationId -and $c.ResultPath.EndsWith('cache-repair-'+$c.OperationId+'.json')) 'random-task-result-and-wait-operation-identities-match'
    Require ($c.Deleted -and -not $c.StopRequested -and $c.Definition.Principal.UserId -eq 'fixture-user') 'completed-owned-task-is-removed-without-stopping-shared-or-unrelated-task'
    $waitName='write:'+([IO.Path]::GetFileName($c.ResultPath))+'.wait.json';$cleanupName='write:'+([IO.Path]::GetFileName($c.ResultPath))+'.cleanup.json'
    Require ($c.Events.IndexOf($waitName) -ge 0 -and $c.Events.IndexOf($waitName) -lt $c.Events.IndexOf('delete:'+ $c.RegisteredName) -and $c.Events.IndexOf($cleanupName) -gt $c.Events.IndexOf('delete:'+ $c.RegisteredName)) 'wait-evidence-persists-before-task-cleanup-and-cleanup-result-afterwards'
    $firstTask=$c.RegisteredName;$c=Invoke-FixtureCoordinator 'Success'
    Require ($c.RegisteredName -ne $firstTask) 'repeated-coordinators-own-distinct-random-task-identities'
    $c=Invoke-FixtureCoordinator 'ExitRace'
    Require (-not $c.Error -and $c.Wait.Success) 'coordinator-completion-between-file-read-and-exit-observation-is-not-lost'
    $c=Invoke-FixtureCoordinator 'EarlyExit'
    Require ($c.Wait.FailureKind -eq 'CacheRepairTaskExited' -and $c.Wait.ElapsedSeconds -lt 3 -and $c.Deleted) 'premature-task-exit-retains-failure-and-cleans-only-owned-task'
    $c=Invoke-FixtureCoordinator 'Timeout'
    Require ($c.Wait.FailureKind -eq 'CacheRepairTimeout' -and $c.Wait.LastProgress.Phase -eq 'VerifyFirewall') 'coordinator-timeout-retains-last-worker-phase-and-bounded-wait'
    Require ($c.StopRequested -and $c.StateReadsAfterStop -ge 2 -and $c.Deleted) 'timed-out-owned-task-stop-is-confirmed-before-deletion'
    Require ($c.Events.IndexOf('write:'+([IO.Path]::GetFileName($c.ResultPath))+'.wait.json') -lt $c.Events.IndexOf('stop:'+ $c.RegisteredName)) 'timeout-evidence-is-written-before-cancellation'
    foreach($mode in @('WrongOperation','WrongHash')){
        $c=Invoke-FixtureCoordinator $mode
        Require ($c.Wait.FailureKind -eq 'CacheRepairResultIdentityMismatch' -and $c.StopRequested -and $c.Deleted) ('coordinator-rejects-and-cancels-'+$mode)
    }
    $c=Invoke-FixtureCoordinator 'WorkerFailure'
    Require ($c.Wait.FailureKind -eq 'CacheRepairWorkerFailed' -and $c.Error.Contains('fixture payload mismatch') -and $c.Deleted) 'worker-explicit-failure-is-preserved-instead-of-generic-timeout'
    $c=Invoke-FixtureCoordinator 'NeverStarts'
    Require ($c.Wait.FailureKind -eq 'CacheRepairTaskNotStarted' -and $c.Wait.ElapsedSeconds -lt 16 -and $c.Deleted) 'registered-task-that-never-starts-fails-with-finite-grace'
    $c=Invoke-FixtureCoordinator 'RunThrows'
    $dispatch=Read-GuardJson ($c.ResultPath+'.wait.json')
    Require ($c.Error.Contains('fixture scheduler dispatch failed') -and $dispatch.FailureKind -eq 'CacheRepairDispatchFailed' -and $c.Deleted) 'dispatch-failure-is-recorded-and-created-task-is-cleaned'
    $c=Invoke-FixtureCoordinator 'ConnectThrows'
    Require ($c.Error.Contains('fixture scheduler unavailable') -and -not $c.Deleted -and -not $c.StopRequested) 'scheduler-connect-failure-does-not-cancel-any-existing-task'
    $c=Invoke-FixtureCoordinator 'StopNeverCompletes'
    $cleanup=Read-GuardJson ($c.ResultPath+'.cleanup.json')
    Require ($c.Error.Contains('cleanup failed') -and $cleanup.CleanupError.Contains('did not stop') -and -not $c.Deleted) 'unconfirmed-stop-retains-owned-task-and-clear-cleanup-failure'

    $report=[ordered]@{Time=(Get-Date -Format o);Passed=$true;FixtureOnly=$true;ProductionTouched=$false;RealSchedulerUsed=$false;RealWorkerStarted=$false;SimulatedClock=$true;RepairScript=$RepairScriptPath;RepairScriptHash=(Get-GuardHash $RepairScriptPath);Count=$checks.Count;Checks=@($checks)}
    $ReportFile=[IO.Path]::GetFullPath($ReportFile);$null=New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($ReportFile)) -Force
    [IO.File]::WriteAllText($ReportFile,($report|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false));$report|ConvertTo-Json -Depth 5
}finally{
    $full=[IO.Path]::GetFullPath($fixture);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if(-not $full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '^ClaudeCacheContext-[a-f0-9]{32}$'){throw 'Unsafe cache context fixture cleanup path.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
