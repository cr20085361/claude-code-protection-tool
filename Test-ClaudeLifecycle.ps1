[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$projectRoot=$PSScriptRoot
$script:Root='D:\fixture'
$global:LifecycleFixtureRoot=$script:Root
. (Join-Path $projectRoot 'ClaudeGuard-Lifecycle.ps1')
function Get-GuardPath([string]$Name){Join-Path $global:LifecycleFixtureRoot $Name}
function Get-GuardHash([string]$Path){'fixture-hash'}
function Get-GuardApprovedShellPath($Reliability=$null){'C:\approved\pwsh.exe'}
function Get-GuardSupervisorScript($Reliability){Get-GuardPath 'ClaudeGuard-Supervisor-v2.ps1'}
$checks=[Collections.Generic.List[string]]::new()
function Require-Rejection([string]$Name,[scriptblock]$Action){
    $rejected=$false;try{& $Action}catch{$rejected=$true}
    if(-not $rejected){throw ('Accepted invalid fixture: '+$Name)}
    $checks.Add($Name)
}
$baseline=New-GuardReliability ([pscustomobject]@{FutureField='preserved';ObservationStarted='historic-observation'})
if($baseline.SchemaVersion -ne 2 -or $baseline.FutureField -ne 'preserved' -or $baseline.ObservationStarted -ne 'historic-observation'){throw 'Reliability migration erased prior fields.'}
$checks.Add('manifest-preserves-prior-fields')
$state=[pscustomobject]@{UserSid='S-1-5-21-fixture';Reliability=$baseline}
$xml=@'
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Hidden>true</Hidden><StartWhenAvailable>true</StartWhenAvailable><WakeToRun>false</WakeToRun><AllowStartOnDemand>true</AllowStartOnDemand><RestartOnFailure><Count>3</Count><Interval>PT1M</Interval></RestartOnFailure></Settings><Triggers><LogonTrigger><UserId>S-1-5-21-fixture</UserId><Enabled>true</Enabled></LogonTrigger><TimeTrigger><StartBoundary>2026-10-06T12:00:00</StartBoundary><Enabled>true</Enabled><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></TimeTrigger></Triggers></Task>
'@
$task=[pscustomobject]@{TaskName='ClaudeProGuard-Supervisor';TaskPath='\';Actions=@([pscustomobject]@{Execute='D:\fixture\runtime\ClaudeSupervisorHost.exe';Arguments='';WorkingDirectory='D:\fixture'});Principal=[pscustomobject]@{UserId=$state.UserSid;RunLevel='Limited';LogonType='Interactive'};Xml=$xml}
function New-FixtureTask {$task|ConvertTo-Json -Depth 20|ConvertFrom-Json}
Assert-GuardSupervisorTask $task $state
$checks.Add('schema2-exact-task-accepted')
foreach($case in @('execute','arguments','working-directory','owner','elevated','noninteractive','task-folder','task-name')){
    $changed=New-FixtureTask
    switch($case){execute{$changed.Actions[0].Execute='C:\other.exe'} arguments{$changed.Actions[0].Arguments='--extra'} working-directory{$changed.Actions[0].WorkingDirectory='D:\other'} owner{$changed.Principal.UserId='S-1-5-21-other'} elevated{$changed.Principal.RunLevel='Highest'} noninteractive{$changed.Principal.LogonType='Password'} task-folder{$changed.TaskPath='\Other\'} task-name{$changed.TaskName='Other'}}
    Require-Rejection $case {Assert-GuardSupervisorTask $changed $state}
}
foreach($change in @(@{Name='finite-repeat';Old='<Interval>PT1M</Interval><StopAtDurationEnd>';New='<Interval>PT1M</Interval><Duration>PT1H</Duration><StopAtDurationEnd>'},@{Name='two-minute-repeat';Old='<Repetition><Interval>PT1M';New='<Repetition><Interval>PT2M'},@{Name='missing-recovery';Old='<TimeTrigger>';New='<CalendarTrigger>'},@{Name='wake';Old='<WakeToRun>false';New='<WakeToRun>true'},@{Name='no-catchup';Old='<StartWhenAvailable>true';New='<StartWhenAvailable>false'},@{Name='parallel-instances';Old='IgnoreNew';New='Parallel'},@{Name='restart-count';Old='<Count>3';New='<Count>9'},@{Name='disabled-trigger';Old='<Enabled>true';New='<Enabled>false'})){
    $changed=New-FixtureTask;$changed.Xml=$changed.Xml.Replace($change.Old,$change.New)
    Require-Rejection $change.Name {Assert-GuardSupervisorTask $changed $state}
}
$legacyState=[pscustomobject]@{UserSid=$state.UserSid;Reliability=[pscustomobject]@{TaskName='ClaudeProGuard-Supervisor';SupervisorScript='ClaudeGuard-Supervisor-v2.ps1'}}
$legacy=New-FixtureTask;$legacy.Actions[0].Execute='C:\approved\pwsh.exe';$legacy.Actions[0].Arguments='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "D:\fixture\ClaudeGuard-Supervisor-v2.ps1"'
Assert-GuardSupervisorTask $legacy $legacyState
$checks.Add('legacy-exact-task-accepted')
$legacy.Actions[0].Arguments+=' --unexpected'
Require-Rejection 'legacy-extra-argument' {Assert-GuardSupervisorTask $legacy $legacyState}
function Get-Process {param($Id,$ErrorAction);[pscustomobject]@{StartTime=[datetime]'2026-10-06T01:00:00Z'}}
function Get-CimInstance {throw 'PID reuse must reject before querying executable.'}
if(Test-GuardSupervisorProcessIdentity ([pscustomobject]@{Pid=123;Started='2026-10-06T00:00:00Z';Path='fixture';CommandLine='fixture'})){throw 'PID reuse accepted.'}
$checks.Add('pid-reuse-rejected')
$global:LifecycleIdentityFixture=[pscustomobject]@{RunId='01234567-89ab-cdef-0123-456789abcdef';HostPid=789;HostStarted=[datetime]'2026-10-06T01:02:03.1234567Z';ShellPath='C:\approved\pwsh.exe';ScriptPath='D:\fixture\ClaudeGuard-Supervisor-v2.ps1'}
$global:LifecycleWorkerCommand='"C:\approved\pwsh.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "D:\fixture\ClaudeGuard-Supervisor-v2.ps1" -RunId "01234567-89ab-cdef-0123-456789abcdef" -HostPid 789 -HostStarted "2026-10-06T01:02:03.1234567Z"'
function Read-GuardJson([string]$Path){$global:LifecycleIdentityFixture}
function Test-Path {param($LiteralPath,[string]$PathType);$LiteralPath -eq 'D:\fixture\private\supervisor-host-identity.json'}
function Get-CimInstance {param($ClassName,$Filter,$ErrorAction);[pscustomobject]@{ExecutablePath='C:\approved\pwsh.exe';CommandLine=$global:LifecycleWorkerCommand;ProcessId=456}}
function Get-Process {param($Id,$ErrorAction);[pscustomobject]@{StartTime=[datetime]'2026-10-06T01:02:04.7654321Z'}}
function Invoke-CimMethod {param($InputObject,$MethodName);[pscustomobject]@{ReturnValue=0;Sid='S-1-5-21-fixture'}}
$identified=@(Get-GuardSupervisorProcessIdentities $state)
if($identified.Count -ne 1 -or $identified[0].Kind -ne 'Worker'){throw 'Date-object identity with fractional command-line timestamp was not matched.'}
$checks.Add('worker-date-object-fractional-start-matched')
$global:LifecycleWorkerCommand=$global:LifecycleWorkerCommand.Replace('03.1234567Z','03.1234568Z')
Require-Rejection 'worker-start-ticks-mismatch' {Get-GuardSupervisorProcessIdentities $state}
$global:LifecycleWorkerCommand=$global:LifecycleWorkerCommand.Replace('03.1234568Z','03.1234567Z')+' --unexpected'
Require-Rejection 'worker-extra-argument' {Get-GuardSupervisorProcessIdentities $state}
Remove-Item -LiteralPath 'Function:\Test-Path'
function Assert-GuardSupervisorTask {}
$global:LifecycleFixtureEnabled=$true;$global:LifecycleFixtureCalls=[Collections.Generic.List[string]]::new()
function Get-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);[pscustomobject]@{Settings=[pscustomobject]@{Enabled=$global:LifecycleFixtureEnabled};State=if($global:LifecycleFixtureEnabled){'Running'}else{'Disabled'}}}
function Get-GuardSupervisorProcessIdentities {@()}
function Export-ScheduledTask {param($TaskName,$TaskPath);'<Task/>'}
function Disable-ScheduledTask {param($TaskName,$TaskPath);$global:LifecycleFixtureCalls.Add('disable');$global:LifecycleFixtureEnabled=$false}
function Stop-ScheduledTask {param($TaskName,$TaskPath);$global:LifecycleFixtureCalls.Add('stop')}
$snapshot=Suspend-GuardSupervisorTask -State $state
if(($global:LifecycleFixtureCalls -join ',') -ne 'disable,stop' -or -not $snapshot.WasEnabled -or -not $snapshot.WasRunning){throw 'Task suspension ordering or snapshot failed.'}
$checks.Add('disable-before-stop-and-snapshot')

# 运行维护脚本原 SupervisorOnly 分支；系统操作在隔离目录中替换为可审计 mock。
# 唯一文本适配是 exit -> return/throw，使测试能够检查结果并清理临时目录。
$repairSource=(Get-Content -LiteralPath (Join-Path $projectRoot 'Repair-ClaudeSupervisorContext-Admin.ps1') -Raw).Replace('exit 0','return').Replace('exit 1',"throw 'fixture-maintenance-failed'")
$scratch=Join-Path ([IO.Path]::GetTempPath()) ('claude-lifecycle-tests-'+[guid]::NewGuid().ToString('N'))
try {
    $global:LifecycleFixtureRoot=$scratch
    foreach($name in @('private','runtime','evidence')){New-Item -ItemType Directory -Path (Join-Path $scratch $name)|Out-Null}
    $repair=Join-Path $scratch 'Repair-Fixture.ps1'
    [IO.File]::WriteAllText($repair,$repairSource,[Text.UTF8Encoding]::new($false))
    function Import-Module {param($Name,[switch]$Force)}
    function Test-GuardAdmin {$true}
    function Read-GuardJson([string]$Path){Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json}
    function Get-GuardHash([string]$Path){if((Test-Path -LiteralPath $Path -PathType Leaf) -and [IO.Path]::GetFileName($Path) -in @('ClaudeGuard.psm1','ClaudeGuard-Supervisor-v2.ps1','ClaudeGuard-Runtime.psm1','Read-ClaudeProcessEnvironment.py') -and (Get-Content -LiteralPath $Path -Raw) -eq 'candidate'){'candidate-hash'}else{'fixture-hash'}}
    function Write-GuardJson([string]$Path,$Value){[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 40),[Text.UTF8Encoding]::new($false))}
    $global:LifecycleFixtureState=[pscustomobject]@{UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;ConfigDir=(Join-Path $scratch 'config');OriginalCli=[pscustomobject]@{Path=(Join-Path $scratch 'original-cli.json')};CodePaths=@();Reliability=[pscustomobject]@{TaskName='ClaudeProGuard-Supervisor';SupervisorScript='ClaudeGuard-Supervisor-v2.ps1';GuardHash='fixture-hash';SupervisorHash='fixture-hash';RuntimeHash='fixture-hash';EnvironmentReaderHash='fixture-hash';FutureField='preserved'}}
    function Get-GuardState {$global:LifecycleFixtureState}
    $backup=Join-Path $scratch 'private\supervisor-fix-backup-fixture';New-Item -ItemType Directory -Path $backup|Out-Null
    [IO.File]::WriteAllText((Get-GuardPath 'private\active-supervisor-fix-backup.txt'),$backup)
    foreach($name in @('ClaudeGuard.psm1','ClaudeGuard-Supervisor-v2.ps1','ClaudeGuard-Runtime.psm1','Read-ClaudeProcessEnvironment.py')){
        [IO.File]::WriteAllText((Get-GuardPath $name),'candidate')
        [IO.File]::WriteAllText((Join-Path $backup $name),'original')
    }
    Write-GuardJson (Get-GuardPath 'private\deployment.json') $global:LifecycleFixtureState
    function Assert-GuardReliabilityFiles {}
    function Assert-GuardPolicy {param([switch]$RuntimeOnly);$global:LifecycleFixtureCalls.Add('assert-policy')}
    function Assert-GuardFirewall {$global:LifecycleFixtureCalls.Add('assert-firewall')}
    function Assert-GuardCore {$global:LifecycleFixtureCalls.Add('assert-core')}
    function Register-GuardSupervisorTask {param($State,$PreviousState);$global:LifecycleFixtureCalls.Add('register-new')}
    function Resume-GuardSupervisorTask {param($State);$global:LifecycleFixtureCalls.Add('resume');$global:LifecycleFixtureEnabled=$true}
    $global:LifecycleFixtureFailReadiness=$false
    function Wait-GuardSupervisorReady {param($TimeoutSeconds);if($global:LifecycleFixtureFailReadiness){throw 'injected-readiness-failure'};[pscustomobject]@{RunId='fixture';Status='Healthy'}}
    function Register-ScheduledTask {param($TaskName,$TaskPath,$Xml,[switch]$Force);$global:LifecycleFixtureCalls.Add('restore-task')}
    function Enable-ScheduledTask {param($TaskName,$TaskPath);$global:LifecycleFixtureCalls.Add('enable');$global:LifecycleFixtureEnabled=$true}
    function Start-ScheduledTask {param($TaskName,$TaskPath);$global:LifecycleFixtureCalls.Add('start')}
    foreach($forbidden in @('Stop-GuardProxy','Stop-GuardProxyEmergency','Install-GuardDesktopUserPolicy','Install-GuardFirewall','Repair-GuardDesktopCodeCache')){Set-Item ('Function:'+ $forbidden) {throw 'SupervisorOnly touched a forbidden protected operation.'}}
    $global:LifecycleFixtureCalls.Clear();$global:LifecycleFixtureEnabled=$true
    $resultFile=Get-GuardPath ('private\supervisor-only-result-'+[guid]::NewGuid().ToString('N')+'.json')
    $null=& $repair -SupervisorOnly -ResultFile $resultFile
    $success=Read-GuardJson $resultFile
    if(-not $success.Success -or -not $success.SupervisorHealthy -or $success.Mode -ne 'SupervisorOnly' -or -not $success.BackupPath -or $success.Health.Status -ne 'Healthy'){throw 'SupervisorOnly success branch did not produce a complete result.'}
    $deployed=Read-GuardJson (Get-GuardPath 'private\deployment.json')
    if($deployed.Reliability.SchemaVersion -ne 2 -or $deployed.Reliability.FutureField -ne 'preserved'){throw 'SupervisorOnly lost reliability metadata.'}
    if(($global:LifecycleFixtureCalls -join ',') -ne 'disable,stop,assert-policy,assert-firewall,assert-core,register-new,resume'){throw ('Unexpected SupervisorOnly native branch sequence: '+($global:LifecycleFixtureCalls -join ','))}
    $checks.Add('supervisor-only-native-success-and-protected-boundary')
    # 重新放回旧 manifest，注入 readiness 失败；原脚本必须还原源文件/state/task。
    Write-GuardJson (Get-GuardPath 'private\deployment.json') $global:LifecycleFixtureState
    $global:LifecycleFixtureFailReadiness=$true;$global:LifecycleFixtureCalls.Clear();$global:LifecycleFixtureEnabled=$true
    $failedResult=Get-GuardPath ('private\supervisor-only-result-'+[guid]::NewGuid().ToString('N')+'.json')
    try{$null=& $repair -SupervisorOnly -ResultFile $failedResult}catch{}
    $failure=Read-GuardJson $failedResult
    if($failure.Success -or -not $failure.RolledBack -or $failure.Reason -ne 'injected-readiness-failure' -or $failure.RollbackError){throw ('SupervisorOnly did not recover after native branch failure: '+($failure|ConvertTo-Json -Compress))}
    foreach($name in @('ClaudeGuard.psm1','ClaudeGuard-Supervisor-v2.ps1','ClaudeGuard-Runtime.psm1','Read-ClaudeProcessEnvironment.py')){if((Get-Content -LiteralPath (Get-GuardPath $name) -Raw) -ne 'original'){throw 'SupervisorOnly source rollback failed.'}}
    $restored=Read-GuardJson (Get-GuardPath 'private\deployment.json')
    if($restored.Reliability.PSObject.Properties['SchemaVersion']){throw 'SupervisorOnly state rollback failed.'}
    if('restore-task' -notin $global:LifecycleFixtureCalls -or 'start' -notin $global:LifecycleFixtureCalls){throw 'SupervisorOnly did not restore the prior running task.'}
    $checks.Add('supervisor-only-native-failure-rolls-back-source-state-task')
    $global:LifecycleFixtureFailReadiness=$false;$global:LifecycleFixtureCalls.Clear()
    $newTaskResult=Get-GuardPath ('private\supervisor-only-result-'+[guid]::NewGuid().ToString('N')+'.json')
    $null=& $repair -SupervisorOnly -ResultFile $newTaskResult
    $fresh=Read-GuardJson $newTaskResult
    if(-not $fresh.Success -or (Test-Path -LiteralPath (Get-GuardPath 'private\maintenance.json'))){throw 'Already-approved source maintenance failed or left its maintenance marker.'}
    $checks.Add('approved-current-source-maintenance-and-marker-cleanup')
}finally{
    $resolved=[IO.Path]::GetFullPath($scratch)
    $temporaryRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if(-not $resolved.StartsWith($temporaryRoot,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notmatch '^claude-lifecycle-tests-[0-9a-f]{32}$'){throw 'Refusing unsafe fixture cleanup path.'}
    if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
[pscustomobject]@{Success=$true;Count=$checks.Count;Checks=$checks}|ConvertTo-Json -Depth 6
