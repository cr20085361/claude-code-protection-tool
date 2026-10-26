[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$project=$PSScriptRoot
Import-Module (Join-Path $project 'ClaudeGuard.psm1') -Force
Import-Module (Join-Path $project 'ClaudeCodeGate.psm1') -Force
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeMaintenanceTests-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $fixture,(Join-Path $fixture 'private'),(Join-Path $fixture 'evidence'),(Join-Path $fixture 'runtime')
$checks=[Collections.Generic.List[string]]::new()
$source=Get-Content -LiteralPath (Join-Path $project 'Update-ClaudeGuard.ps1') -Raw
$source=$source.Replace('exit 0','return').Replace('exit 1','return')
[IO.File]::WriteAllText((Join-Path $fixture 'Update-ClaudeGuard.ps1'),$source,[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $fixture 'Repair-ClaudeCodeContext-Admin.ps1'),'$global:LASTEXITCODE=0',[Text.UTF8Encoding]::new($false))
try {
& (Get-Module ClaudeGuard) {
param($Fixture,$Checks,$Project)
$previous=$script:Root;$script:Root=$Fixture
$global:MaintenanceFixtureRoot=$Fixture
function Get-GuardPath([string]$Name){Join-Path $global:MaintenanceFixtureRoot $Name}
$oldApp=$env:APPDATA;$oldLocal=$env:LOCALAPPDATA
$env:APPDATA=Join-Path $Fixture 'AppData';$env:LOCALAPPDATA=Join-Path $Fixture 'LocalData'
function Require([bool]$Ok,[string]$Name){if(-not $Ok){throw ('Maintenance fixture failed: '+$Name)};$Checks.Add($Name)}
function Import-Module {param($Name,[switch]$Force)}
function Test-GuardAdmin {$true}
function Get-GuardState {Read-GuardJson (Get-GuardPath 'private\deployment.json')}
function Get-GuardDesktop {[pscustomobject]@{Version='fixture-desktop';Path=(Get-GuardPath 'desktop.exe');Hash=(Get-GuardHash (Get-GuardPath 'desktop.exe'));Family='Claude_fixture'}}
function Get-GuardSupervisorSnapshot {[pscustomobject]@{Ready=$true;Kind='Healthy';Health=[pscustomobject]@{Time=[datetime]::UtcNow.ToString('o');RunId='fixture-run'}}}
function Test-GuardLocalCodeAcceptance {$false}
$global:MaintenanceFixtureCalls=[Collections.Generic.List[string]]::new()
function Get-ScheduledTask {[pscustomobject]@{State=$(if($global:MaintenanceFixtureDisabled){'Ready'}else{'Running'});Settings=[pscustomobject]@{Enabled=(-not $global:MaintenanceFixtureDisabled)}}}
function Assert-GuardSupervisorTask {}
function Export-ScheduledTask {'<fixture-task/>'}
function Suspend-GuardSupervisorTask {param($State,$TimeoutSeconds);$global:MaintenanceFixtureCalls.Add('suspend');[pscustomobject]@{WasEnabled=(-not $global:MaintenanceFixtureDisabled);WasRunning=(-not $global:MaintenanceFixtureDisabled)}}
function Resume-GuardSupervisorTask {param($State);$global:MaintenanceFixtureCalls.Add('resume')}
function Register-GuardSupervisorTask {$global:MaintenanceFixtureCalls.Add('register-new')}
function Register-ScheduledTask {$global:MaintenanceFixtureCalls.Add('restore-task')}
function Enable-ScheduledTask {$global:MaintenanceFixtureCalls.Add('enable')}
function Start-ScheduledTask {$global:MaintenanceFixtureCalls.Add('start')}
function Stop-GuardProxy {$global:MaintenanceFixtureCalls.Add('stop-proxy')}
function Stop-GuardProxyEmergency {$global:MaintenanceFixtureCalls.Add('emergency-stop')}
function Start-GuardProxy {param([switch]$SupervisorWorker);$global:MaintenanceFixtureCalls.Add($(if($SupervisorWorker){'start-proxy-worker'}else{'start-proxy'}))}
function New-GuardIPv4Config($Config){$Config}
function Get-GuardDesktopProcesses {}
function Get-CimInstance {}
function Get-AuthenticodeSignature {[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='O="Anthropic, PBC", C=US'}}}
function Assert-CodeCacheGate {param($Path);if(-not (Test-Path -LiteralPath $Path)){throw 'fixture-cache-root-missing'};if($global:MaintenanceFixtureFailure -eq 'cache-gate'){throw 'fixture-cache-gate-changed'}}
function Set-CodeCacheGate {param($Path);$global:MaintenanceFixtureCalls.Add('set-cache-gate')}
function Test-CodeCacheGate {}
function Protect-CodeBinary {}
function Set-CodeAccessOnlyAcl {$global:MaintenanceFixtureCalls.Add('restore-acl')}
function New-ItemProperty {}
function Assert-GuardPolicy {}
function Assert-GuardFirewall {}
function Install-GuardFirewall {if($global:MaintenanceFixtureFailure -eq 'firewall'){throw 'injected-firewall-failure'};Write-GuardJson (Get-GuardPath 'private\firewall.json') @{Rules=@()}}
function Install-GuardDesktopUserPolicy {if($global:MaintenanceFixtureFailure -eq 'policy'){throw 'injected-policy-failure'}}
function Test-GuardEgress {[pscustomobject]@{VerifiedProbeCount=2}}
function Wait-GuardSupervisorReady {if($global:MaintenanceFixtureFailure -eq 'readiness'){throw 'injected-readiness-failure'};[pscustomobject]@{Status='Healthy'}}
function Reset-State {
    $global:MaintenanceFixtureFailure='';$global:MaintenanceFixtureDisabled=$false;$global:MaintenanceFixtureCalls.Clear()
    foreach($name in @('active-version-maintenance.json','active-ui-action.json','safety-hold.json','maintenance.json')){$path=Get-GuardPath ('private\'+$name);if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path}}
    foreach($file in @('desktop.exe','archive.bin','payload.exe')){[IO.File]::WriteAllText((Get-GuardPath $file),'fixture-only')}
    Write-GuardJson (Get-GuardPath 'private\proxy.json') @{fixture='fixed'}
    Write-GuardJson (Get-GuardPath 'private\firewall.json') @{Rules=@()}
    $roots=@(Get-GuardCodeCacheRoots (Get-GuardDesktop))
    $paths=@($roots|ForEach-Object {Join-Path $_ 'fixture-code\0123456789ab\claude.exe'})
    foreach($path in $paths){$null=New-Item -ItemType Directory -Path (Split-Path $path) -Force;[IO.File]::WriteAllText($path,'fixture-only')}
    Write-GuardJson (Get-GuardPath 'private\code-gate-backup.json') @{Roots=@($roots|ForEach-Object {@{Path=$_;Existed=$true;Sddl=(Get-Acl -LiteralPath $_).Sddl}})}
    $d=@{UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;ProxyUrl='http://127.0.0.1:1';ExpectedIp='203.0.113.1';ConfigDir=$Fixture;CoreHash='fixture-core';ProxyConfigHash=(Get-GuardHash (Get-GuardPath 'private\proxy.json'));Desktop=(Get-GuardDesktop);CodePaths=$paths;CodeGate=@{Roots=$roots;Version='fixture-code';CompressedHash='0123456789abcdef';ArchivePath=(Get-GuardPath 'archive.bin');ArchiveHash=(Get-GuardHash (Get-GuardPath 'archive.bin'));PayloadHash=(Get-GuardHash (Get-GuardPath 'payload.exe')).ToLowerInvariant()};Reliability=@{TaskName='fixture-task';Installed='fixture'};UpdatePolicyBackup=@{Value=$null;Kind=$null}}
    Write-GuardJson (Get-GuardPath 'private\deployment.json') $d
    $d
}
function Prepare-FixtureInstall {
    $d=Reset-State;$id=[guid]::NewGuid().ToString('N');$op=New-GuardMaintenanceOperation $id;$stageId=[guid]::NewGuid().ToString('N')
    $config=Get-GuardPath ('private\proxy-stage-'+$stageId+'.json');Copy-Item -LiteralPath (Get-GuardPath 'private\proxy.json') -Destination $config
    $stage=Get-GuardPath ('private\upgrade-stage-'+$stageId+'.json')
    Write-GuardJson $stage @{Id=$stageId;Created=[datetime]::UtcNow.ToString('o');ScriptHashes=@();PreviousStateHash=(Get-GuardHash (Get-GuardPath 'private\deployment.json'));Candidate=$d;ConfigStage=$config;PayloadPath=(Get-GuardPath 'payload.exe')}
    $result=Get-GuardPath ('private\upgrade-result-'+$id+'.json')
    $null=Set-GuardMaintenanceOperation $id @{Phase='AwaitingAuthorization';StageId=$stageId;StageFile=$stage;StageHash=(Get-GuardHash $stage);ResultFile=$result}
    [pscustomobject]@{Id=$id;Stage=$stage;StageHash=(Get-GuardHash $stage);Result=$result;OldStateHash=(Get-GuardHash (Get-GuardPath 'private\deployment.json'))}
}
try {
$null=Reset-State
$id=[guid]::NewGuid().ToString('N');$op=New-GuardMaintenanceOperation $id
if(-not (Get-GuardMaintenanceSnapshot).Active){
    $p=Get-Process -Id $op.CoordinatorPid
    [pscustomobject]@{SavedPid=$op.CoordinatorPid;CurrentPid=$PID;SavedPath=$op.CoordinatorPath;CurrentPath=$p.Path;SavedStart=$op.CoordinatorStarted;CurrentStart=$p.StartTime.ToUniversalTime().ToString('o');Direct=(Test-GuardMaintenanceProcess $op.CoordinatorPid $op.CoordinatorStarted $op.CoordinatorPath)}|ConvertTo-Json
}
Require ((Get-GuardMaintenanceSnapshot).Active) 'preparation-current-owner-is-active'
$rejected=$false;try{$null=New-GuardMaintenanceOperation ([guid]::NewGuid().ToString('N'))}catch{$rejected=$_.Exception.Message -match 'MaintenanceBusy'}
Require $rejected 'duplicate-operation-refused'
$child=Join-Path $Fixture 'Duplicate.ps1'
$childCode=@'
param($Project,$Fixture)
Import-Module (Join-Path $Project 'ClaudeGuard.psm1') -Force
& (Get-Module ClaudeGuard) {param($Root);$script:Root=$Root;try{$null=New-GuardMaintenanceOperation ([guid]::NewGuid().ToString('N'));exit 2}catch{if($_.Exception.Message -match 'MaintenanceBusy'){exit 0};throw}} $Fixture
'@
[IO.File]::WriteAllText($child,$childCode,[Text.UTF8Encoding]::new($false))
$shell=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$childArgs='-NoProfile -File "'+$child+'" -Project "'+$Project+'" -Fixture "'+$Fixture+'"'
$childProcess=Start-Process -FilePath $shell -ArgumentList $childArgs -WindowStyle Hidden -PassThru
try{if(-not $childProcess.WaitForExit(10000)){throw 'Duplicate fixture subprocess timed out.'};Require ($childProcess.ExitCode -eq 0) 'duplicate-operation-refused-across-processes'}finally{$childProcess.Dispose()}
$op.StartedAt=[datetime]::UtcNow.AddSeconds(-163).ToString('o')
$a=Get-GuardMaintenanceAssessment $op {return $true}
Require ($a.Active -and -not $a.Interrupted -and -not $a.OverBudget) '163-seconds-does-not-imply-authorization-failure'
$op.StartedAt=[datetime]::UtcNow.AddSeconds(-661).ToString('o');$a=Get-GuardMaintenanceAssessment $op {return $true}
Require ($a.Active -and $a.OverBudget -and -not $a.Interrupted) 'live-preparation-over-budget-remains-pending'
$op.WorkerPid=123;$op.WorkerStarted=[datetime]::UtcNow.AddSeconds(-601).ToString('o');$a=Get-GuardMaintenanceAssessment $op {return $true}
Require ($a.Active -and $a.OverBudget -and -not $a.Interrupted) 'live-installer-over-budget-remains-pending'
$a=Get-GuardMaintenanceAssessment $op {return $false}
Require ($a.Interrupted -and -not $a.Active) 'dead-installer-without-result-needs-recovery'
$self=[Diagnostics.Process]::GetCurrentProcess()
Require (-not (Test-GuardMaintenanceProcess $PID $self.StartTime.ToUniversalTime().AddSeconds(-1).ToString('o') $self.MainModule.FileName)) 'reused-pid-or-start-time-mismatch-refused'
Require (Test-GuardMaintenanceAuthorizationCancelled ([ComponentModel.Win32Exception]::new(1223))) 'explicit-windows-cancellation-recognized'
Require (Test-GuardMaintenanceAuthorizationCancelled ([Management.Automation.MethodInvocationException]::new('native launch failed',[ComponentModel.Win32Exception]::new(1223)))) 'native-shell-wrapper-preserves-windows-cancellation'
Require (-not (Test-GuardMaintenanceAuthorizationCancelled ([TimeoutException]::new('still running')))) 'timeout-is-not-authorization-cancellation'
$null=Set-GuardMaintenanceOperation $id @{Status='Failed';Phase='Failed';FailureKind='AdministratorCancelled';Reason='授权已取消'}
$null=Set-GuardMaintenanceOperation $id @{Status='Running';Phase='Migrating'}
Require ((Read-GuardMaintenanceOperation $id).Status -eq 'Failed') 'terminal-record-cannot-be-reopened-by-late-progress'
$next=[guid]::NewGuid().ToString('N');$null=New-GuardMaintenanceOperation $next
Write-GuardJson (Get-GuardPath 'evidence\last-ui-result.json') @{ActionId=$next;Success=$false;Pending=$true}
$hash=Get-GuardHash (Get-GuardPath 'evidence\last-ui-result.json');$null=Sync-GuardMaintenanceUiResult $id
Require ((Get-GuardHash (Get-GuardPath 'evidence\last-ui-result.json')) -eq $hash) 'late-old-result-does-not-overwrite-current-operation'
$canonical=Read-GuardMaintenanceOperation $next
$null=Set-GuardMaintenanceOperation $next @{Status='Failed';Phase='Failed';Reason='fixture'}
Write-GuardJson (Get-GuardPath 'private\active-version-maintenance.json') $canonical
Require ((Read-GuardMaintenanceOperation).Status -eq 'Failed') 'canonical-record-survives-pointer-publication-interruption'
Register-GuardUiAction ([guid]::NewGuid().ToString('N')) 'Check'
$hash=Get-GuardHash (Get-GuardPath 'evidence\last-ui-result.json');$null=Sync-GuardMaintenanceUiResult $next
Require ((Get-GuardHash (Get-GuardPath 'evidence\last-ui-result.json')) -eq $hash) 'late-maintenance-result-does-not-overwrite-newer-check'
foreach($failure in @('','firewall','policy','readiness')){
    $f=Prepare-FixtureInstall;$global:MaintenanceFixtureFailure=$failure
    try{$null=& (Get-GuardPath 'Update-ClaudeGuard.ps1') -Install -StageFile $f.Stage -StageHash $f.StageHash -ResultFile $f.Result -OperationId $f.Id}catch{Write-Output $_.ScriptStackTrace;throw}
    $result=Read-GuardJson $f.Result;$final=Read-GuardMaintenanceOperation $f.Id
    if(-not $failure -and -not $result.Success){$result|ConvertTo-Json -Depth 4;@($global:MaintenanceFixtureCalls)|ConvertTo-Json}
    if(-not $failure){
        Require ($result.Success -and $final.Status -eq 'Completed' -and $result.StageId -eq $final.StageId -and $result.ActionId -eq $final.ActionId) 'real-install-branch-success-correlates-result-and-operation'
        Require ((Read-GuardJson (Get-GuardPath 'evidence\last-ui-result.json')).Success) 'real-install-terminal-ui-evidence-is-success'
        Require (-not (Test-Path -LiteralPath (Get-GuardPath 'private\maintenance.json'))) 'success-clears-own-maintenance-marker'
    }else{
        Require (-not $result.Success -and $result.RollbackRestored -and -not $result.RollbackError -and $final.Status -eq 'Failed') ('real-install-'+$failure+'-failure-rolls-back')
        Require (((Get-GuardHash (Get-GuardPath 'private\deployment.json')) -eq $f.OldStateHash) -and 'restore-task' -in $global:MaintenanceFixtureCalls -and 'start' -in $global:MaintenanceFixtureCalls) ('real-install-'+$failure+'-restores-baseline-and-task')
        Require (Test-Path -LiteralPath (Get-GuardPath 'private\safety-hold.json')) ('real-install-'+$failure+'-remains-fail-closed')
    }
}
$f=Prepare-FixtureInstall
$null=Set-GuardMaintenanceOperation $f.Id @{DesktopDownloadId=([guid]::NewGuid().ToString('N'))}
$null=& (Get-GuardPath 'Update-ClaudeGuard.ps1') -Install -StageFile $f.Stage -StageHash $f.StageHash -ResultFile $f.Result -OperationId $f.Id -ContinueDesktopUpdate
$continued=Read-GuardMaintenanceOperation $f.Id
Require ((Read-GuardJson $f.Result).Success -and $continued.Status -eq 'Running' -and $continued.Phase -eq 'PreparingInstall') 'pre-install-maintenance-success-keeps-update-running'
Require (-not (Get-GuardMaintenanceUiResult $continued).Success -and (Get-GuardMaintenanceUiResult $continued).Pending) 'pre-install-maintenance-does-not-publish-final-success'
$f=Prepare-FixtureInstall
$missingRoot=(Get-GuardState).CodeGate.Roots[1]
$fixtureFull=[IO.Path]::GetFullPath($Fixture).TrimEnd('\')+'\'
if(-not ([IO.Path]::GetFullPath($missingRoot)).StartsWith($fixtureFull,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe missing-cache fixture path.'}
Remove-Item -LiteralPath $missingRoot -Recurse -Force
$null=& (Get-GuardPath 'Update-ClaudeGuard.ps1') -Install -StageFile $f.Stage -StageHash $f.StageHash -ResultFile $f.Result -OperationId $f.Id
Require ((Read-GuardJson $f.Result).Success -and (Test-Path -LiteralPath (Get-GuardState).CodePaths[1])) 'maintenance-restores-missing-package-code-cache'
Require ($global:MaintenanceFixtureCalls.IndexOf('suspend') -lt $global:MaintenanceFixtureCalls.IndexOf('set-cache-gate') -and 'set-cache-gate' -in $global:MaintenanceFixtureCalls) 'missing-cache-gated-after-supervisor-suspension'
$f=Prepare-FixtureInstall
$newRoot=(Get-GuardState).CodeGate.Roots[2]
$stage=Read-GuardJson $f.Stage
$old=Get-GuardState;$old.CodePaths=@($old.CodePaths|Select-Object -First 2);$old.CodeGate.Roots=@($old.CodeGate.Roots|Select-Object -First 2)
Write-GuardJson (Get-GuardPath 'private\deployment.json') $old
$gateBackup=Read-GuardJson (Get-GuardPath 'private\code-gate-backup.json');$gateBackup.Roots=@($gateBackup.Roots|Select-Object -First 2);Write-GuardJson (Get-GuardPath 'private\code-gate-backup.json') $gateBackup
$stage.PreviousStateHash=Get-GuardHash (Get-GuardPath 'private\deployment.json');Write-GuardJson $f.Stage $stage;$f.StageHash=Get-GuardHash $f.Stage
$null=Set-GuardMaintenanceOperation $f.Id @{StageHash=$f.StageHash}
$null=& (Get-GuardPath 'Update-ClaudeGuard.ps1') -Install -StageFile $f.Stage -StageHash $f.StageHash -ResultFile $f.Result -OperationId $f.Id
Require ((Read-GuardJson $f.Result).Success -and $newRoot -in @((Get-GuardState).CodeGate.Roots)) 'legacy-deployment-migrates-to-claude-data-root'
Require ($newRoot -in @((Read-GuardJson (Get-GuardPath 'private\code-gate-backup.json')).Roots.Path)) 'new-root-rollback-acl-snapshot-preserved'
$f=Prepare-FixtureInstall;$global:MaintenanceFixtureFailure='cache-gate'
$null=& (Get-GuardPath 'Update-ClaudeGuard.ps1') -Install -StageFile $f.Stage -StageHash $f.StageHash -ResultFile $f.Result -OperationId $f.Id
Require (-not (Read-GuardJson $f.Result).Success -and $global:MaintenanceFixtureCalls.Count -eq 0) 'changed-existing-cache-gate-refused-before-mutation'
$f=Prepare-FixtureInstall
$null=& (Get-GuardPath 'Update-ClaudeGuard.ps1') -Install -StageFile $f.Stage -StageHash $f.StageHash -ResultFile $f.Result -OperationId $f.Id -ContinueDesktopUpdate
Require (-not (Read-GuardJson $f.Result).Success -and $global:MaintenanceFixtureCalls.Count -eq 0) 'ordinary-maintenance-cannot-request-update-continuation'
$f=Prepare-FixtureInstall;$global:MaintenanceFixtureDisabled=$true;$global:MaintenanceFixtureFailure='firewall'
$originalTask=Get-GuardPath ('private\upgrade-task-'+$f.Id+'.xml');[IO.File]::WriteAllText($originalTask,'<original-enabled-task/>')
$null=Set-GuardMaintenanceOperation $f.Id @{DesktopTaskSnapshot=@{Path=$originalTask;Hash=(Get-GuardHash $originalTask);WasEnabled=$true;WasRunning=$true}}
$null=& (Get-GuardPath 'Update-ClaudeGuard.ps1') -Install -StageFile $f.Stage -StageHash $f.StageHash -ResultFile $f.Result -OperationId $f.Id
$rolled=Read-GuardMaintenanceOperation $f.Id;$backup=Read-GuardJson $rolled.BackupFile
Require ($backup.WasEnabled -and $backup.WasRunning -and 'enable' -in $global:MaintenanceFixtureCalls -and 'start' -in $global:MaintenanceFixtureCalls) 'desktop-update-rolls-back-to-pre-msix-enabled-task'
Require ((Get-Content -LiteralPath $rolled.TaskBackup -Raw) -eq '<original-enabled-task/>') 'desktop-update-preserves-pre-msix-task-xml'
$f=Prepare-FixtureInstall;$global:MaintenanceFixtureDisabled=$true
$null=Set-GuardMaintenanceOperation $f.Id @{DesktopTaskSnapshot=@{Path=$originalTask;Hash='changed';WasEnabled=$true;WasRunning=$true}}
$null=& (Get-GuardPath 'Update-ClaudeGuard.ps1') -Install -StageFile $f.Stage -StageHash $f.StageHash -ResultFile $f.Result -OperationId $f.Id
Require (-not (Read-GuardJson $f.Result).Success -and $global:MaintenanceFixtureCalls.Count -eq 0) 'desktop-update-changed-original-task-snapshot-refused-before-mutation'
$f=Prepare-FixtureInstall
$before=Get-GuardHash (Get-GuardPath 'private\deployment.json')
$null=& (Get-GuardPath 'Update-ClaudeGuard.ps1') -Install -StageFile $f.Stage -StageHash 'tampered' -ResultFile $f.Result -OperationId $f.Id
Require (((Get-GuardHash (Get-GuardPath 'private\deployment.json')) -eq $before) -and (Read-GuardMaintenanceOperation $f.Id).Status -eq 'Running') 'unclaimed-invalid-stage-cannot-mutate-or-complete-operation'
$null=Set-GuardMaintenanceOperation $f.Id @{Status='Interrupted';Phase='Interrupted';RecoveryRequired=$true}
$null=& (Get-GuardPath 'Update-ClaudeGuard.ps1') -RecoverOperationId $f.Id
$recovered=Read-GuardMaintenanceOperation $f.Id
Require ($recovered.RollbackRestored -and -not $recovered.RecoveryRequired -and $recovered.Status -eq 'Failed') 'real-recovery-branch-clears-interrupted-pre-mutation-operation'
$null=New-GuardMaintenanceOperation ([guid]::NewGuid().ToString('N'))
Require $true 'reviewed-maintenance-can-retry-after-recovery'
$null=Reset-State
$prepareText=Get-Content -LiteralPath (Join-Path $Project 'Update-ClaudeGuard.ps1') -Raw
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($prepareText,[ref]$tokens,[ref]$errors)
$networkBranch=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.IfStatementAst] -and $node.Extent.Text.StartsWith('if(-not (Test-Path (Get-GuardPath ''private\safety-hold.json''))') -and $node.Extent.Text.Contains('DesktopTaskSnapshot')},$true))
Require ($networkBranch.Count -eq 1) 'desktop-update-preparation-network-branch-located'
$compressed=Get-GuardPath 'private\fixture-cached-code.zst'
$OperationId='fixture-update';$op=[pscustomobject]@{SupervisorSuspended=$true;DesktopTaskSnapshot=@{Path='fixture'}}
& ([scriptblock]::Create($networkBranch[0].Extent.Text))
Require ('start-proxy-worker' -in $global:MaintenanceFixtureCalls) 'desktop-update-preparation-does-not-start-disabled-supervisor-task'
$global:MaintenanceFixtureCalls.Clear();$op.SupervisorSuspended=$false
& ([scriptblock]::Create($networkBranch[0].Extent.Text))
Require ('start-proxy' -in $global:MaintenanceFixtureCalls) 'ordinary-maintenance-retains-supervisor-readiness-check'
$global:MaintenanceFixtureCalls.Clear();[IO.File]::WriteAllText($compressed,'fixture-cached-payload')
& ([scriptblock]::Create($networkBranch[0].Extent.Text))
Require ($global:MaintenanceFixtureCalls.Count -eq 0) 'cached-maintenance-preparation-does-not-wait-for-broken-supervisor'
Remove-Item -LiteralPath $compressed
$global:MaintenanceFixtureCalls.Clear();Write-GuardJson (Get-GuardPath 'private\safety-hold.json') @{Reason='fixture'}
& ([scriptblock]::Create($networkBranch[0].Extent.Text))
Require ($global:MaintenanceFixtureCalls.Count -eq 0) 'real-safety-hold-still-blocks-new-maintenance-network'
}finally{$env:APPDATA=$oldApp;$env:LOCALAPPDATA=$oldLocal;$script:Root=$previous}
} $fixture $checks $project
$runner=@'
using System;using Claude=ClaudeGuardWindow;
public class MaintenanceRunner {
 static void Require(bool ok,string name){if(!ok)throw new Exception(name);}
 public static void Main(){
  var now=DateTimeOffset.UtcNow;var m=new Claude.MaintenanceResult{SchemaVersion=1,ActionId=new string('a',32),Status="Running",Phase="Migrating",StartedAt=now.AddSeconds(-163).ToString("o"),WorkerPid=1,WorkerStarted=now.AddSeconds(-163).ToString("o")};
  var v=Claude.AssessMaintenance(m,now,true,false);Require(v.Observe&&v.BlockStart&&v.Message.Contains("暂时暂停"),"planned-pause-is-progress");
  v=Claude.AssessMaintenance(m,now,true,true);Require(v.Observe&&v.BlockStart&&!v.Held,"live-authorized-maintenance-observes-held-recovery");
  v=Claude.AssessMaintenance(m,now,false,true);Require(v.Held&&!v.Observe,"hold-without-live-maintenance-takes-priority");
  m.WorkerStarted=now.AddSeconds(-601).ToString("o");v=Claude.AssessMaintenance(m,now,true,false);Require(v.Observe&&!v.Recover&&v.Message.Contains("仍在进行"),"live-install-over-budget-is-pending");
  v=Claude.AssessMaintenance(m,now,false,false);Require(v.Recover&&v.BlockStart,"dead-worker-requires-recovery");
  m.Phase="AwaitingAuthorization";m.WorkerPid=0;m.StartedAt=now.ToString("o");v=Claude.AssessMaintenance(m,now,true,false);Require(v.Message.Contains("等待 Windows"),"awaiting-authorization-stage");
  m.Phase="Verifying";v=Claude.AssessMaintenance(m,now,true,false);Require(v.Message.Contains("恢复并核验"),"verifying-stage");
  m.Status="Completed";v=Claude.AssessMaintenance(m,now,false,false);Require(v.Completed&&!v.BlockStart,"completed-stops-blocking");
  m.Status="Failed";m.Reason="fixture failure";v=Claude.AssessMaintenance(m,now,false,false);Require(v.Failed&&!v.Completed,"failure-stays-distinct-from-health");
  m.RecoveryRequired=true;v=Claude.AssessMaintenance(m,now,false,false);Require(v.Recover&&v.BlockStart,"rollback-failure-blocks-launch");
  Console.WriteLine("C# maintenance view contract: 10 cases passed");
 }
}
'@
$source=Join-Path $fixture 'MaintenanceRunner.cs';[IO.File]::WriteAllText($source,$runner,[Text.UTF8Encoding]::new($false))
$csc=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$dll=Join-Path $fixture 'GuardUI.dll';$exe=Join-Path $fixture 'MaintenanceRunner.exe'
& $csc /nologo /target:library /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/out:'+$dll) (Join-Path $project 'ClaudeGuardLauncher.cs')
if($LASTEXITCODE){throw 'Maintenance UI compile failed.'}
& $csc /nologo /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll ('/reference:'+$dll) ('/out:'+$exe) $source
if($LASTEXITCODE){throw 'Maintenance view runner compile failed.'}
& $exe;if($LASTEXITCODE){throw 'Maintenance view contract failed.'}
$result=@{Time=(Get-Date -Format o);Passed=$true;FixtureOnly=$true;PowerShellCaseCount=$checks.Count;CSharpCaseCount=10;Checks=@($checks)}
Write-GuardJson (Join-Path $project 'evidence\maintenance-fixture-tests.json') $result
$result|ConvertTo-Json -Depth 4
}finally{
$full=[IO.Path]::GetFullPath($fixture);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
if(-not $full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '^ClaudeMaintenanceTests-[0-9a-f]{32}$'){throw 'Unsafe fixture cleanup path.'}
Remove-Item -LiteralPath $full -Recurse -Force
}
