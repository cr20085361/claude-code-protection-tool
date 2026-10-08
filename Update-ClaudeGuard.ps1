[CmdletBinding()]
param([switch]$Install,[string]$StageFile,[string]$StageHash,[string]$ResultFile,[string]$OperationId,[string]$RecoverOperationId)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ClaudeCodeGate.psm1') -Force
function Assert-PrivateFile([string]$Path,[string]$Pattern) {
    $full=[IO.Path]::GetFullPath($Path)
    if([IO.Path]::GetDirectoryName($full) -ne (Get-GuardPath 'private') -or [IO.Path]::GetFileName($full) -notmatch $Pattern){throw 'Invalid maintenance artifact path.'}
    $full
}
function Assert-AnthropicSignature([string]$Path) {
    $s=Get-AuthenticodeSignature -LiteralPath $Path
    if($s.Status.ToString() -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'O="?Anthropic, PBC"?[, ]'){throw 'Official Anthropic signature verification failed.'}
}
function Install-SupervisorTask($Candidate,$PreviousState) {
    Register-GuardSupervisorTask -State $Candidate -PreviousState $PreviousState -AllowCreate
}
$d=Get-GuardState
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $d.UserSid){throw 'Maintenance requires the original Windows account.'}
if($RecoverOperationId) {
    if(-not (Test-GuardAdmin)){throw 'Same-account administrator recovery is required.'}
    $op=Read-GuardMaintenanceOperation $RecoverOperationId
    if(-not $op -or $op.Status -eq 'Completed' -or (Get-GuardMaintenanceAssessment $op).Active){throw 'Maintenance recovery refused for a live or completed operation.'}
    $installer=Get-GuardMaintenanceLock 'Install';$held=$false
    try {
        try{$held=$installer.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
        if(-not $held){throw 'MaintenanceBusy: another installer is running.'}
        $self=[Diagnostics.Process]::GetCurrentProcess()
        $op=Set-GuardMaintenanceOperation $RecoverOperationId @{Status='Running';Phase='Recovering';WorkerPid=$PID;WorkerStarted=$self.StartTime.ToUniversalTime().ToString('o');WorkerPath=$self.MainModule.FileName} -Recovery
        Restore-GuardMaintenanceBackup $op
        $null=Set-GuardMaintenanceOperation $RecoverOperationId @{Status='Failed';Phase='Failed';RecoveryRequired=$false;RollbackRestored=$true;FailureKind='MaintenanceRecovered';Reason='维护中断已恢复。请点击“维护版本”重新核验，完成后再打开 Claude。'}
        $null=Sync-GuardMaintenanceUiResult $RecoverOperationId
    }catch{
        $null=Set-GuardMaintenanceOperation $RecoverOperationId @{Status='Interrupted';Phase='Interrupted';RecoveryRequired=$true;FailureKind='MaintenanceInterrupted';Reason=('维护恢复失败：'+$_.Exception.Message)} -Recovery
        $null=Sync-GuardMaintenanceUiResult $RecoverOperationId
        throw
    }finally{if($held){$installer.ReleaseMutex()};$installer.Dispose()}
    exit 0
}
if($Install) {
    if(-not (Test-GuardAdmin)){throw 'Administrator rights are required for reviewed version migration.'}
    $StageFile=Assert-PrivateFile $StageFile '^upgrade-stage-[0-9a-f]{32}\.json$'
    $ResultFile=Assert-PrivateFile $ResultFile '^upgrade-result-[0-9a-f]{32}\.json$'
    $result=[ordered]@{Time=(Get-Date -Format o);StartedAt=[datetime]::UtcNow.ToString('o');CompletedAt=$null;ActionId=$OperationId;StageId=$null;Success=$false;Reason=$null;DesktopVersion=$null;CodeVersion=$null;SupervisorInstalled=$false;UpdatePolicyInstalled=$false;RollbackRestored=$false;RollbackError=$null}
    $budgetEnd=[datetime]::UtcNow.AddSeconds(600)
    $installer=Get-GuardMaintenanceLock 'Install';$installerHeld=$false;$operationClaimed=$false
    function Assert-MigrationBudget {if([datetime]::UtcNow -ge $budgetEnd){throw 'MaintenanceTimeout: 管理员安装阶段超过 600 秒，已进入失败恢复。'}}
    $oldState=$d
    $baselineChanged=$false;$priorTaskXml=$null;$priorTaskSnapshot=$null;$configBackup=$null;$candidate=$null
    try {
        try{$installerHeld=$installer.WaitOne(0)}catch [Threading.AbandonedMutexException]{$installerHeld=$true}
        if(-not $installerHeld){throw 'MaintenanceBusy: another installer is running.'}
        if((Get-GuardHash $StageFile) -ne $StageHash){throw 'Reviewed maintenance stage changed.'}
        $stage=Read-GuardJson $StageFile
        $result.StageId=$stage.Id
        if($OperationId){
            $op=Read-GuardMaintenanceOperation $OperationId
            $active=Read-GuardMaintenanceOperation
            if(-not $op -or $op.Status -ne 'Running' -or $op.StageId -ne $stage.Id -or $op.StageHash -ne $StageHash -or $op.StageFile -ne $StageFile -or $op.ResultFile -ne $ResultFile -or -not $active -or $active.ActionId -ne $OperationId){throw 'Maintenance operation does not match the reviewed stage.'}
            $operationClaimed=$true
            $self=[Diagnostics.Process]::GetCurrentProcess()
            $null=Set-GuardMaintenanceOperation $OperationId @{Phase='Migrating';WorkerPid=$PID;WorkerStarted=$self.StartTime.ToUniversalTime().ToString('o');WorkerPath=$self.MainModule.FileName}
        }
        Assert-MigrationBudget
        if([datetimeoffset]::UtcNow -gt ([datetimeoffset]$stage.Created).AddHours(2)){throw 'Maintenance stage expired.'}
        foreach($file in $stage.ScriptHashes){if((Get-GuardHash (Get-GuardPath $file.Name)) -ne $file.Hash){throw 'Reviewed maintenance script changed.'}}
        if((Get-GuardHash (Get-GuardPath 'private\deployment.json')) -ne $stage.PreviousStateHash){throw 'Deployment changed after review.'}
        $candidate=$stage.Candidate
        if($candidate.UserSid -ne $d.UserSid -or $candidate.ProxyUrl -ne $d.ProxyUrl -or $candidate.ExpectedIp -ne $d.ExpectedIp -or $candidate.ConfigDir -ne $d.ConfigDir -or $candidate.CoreHash -ne $d.CoreHash){throw 'Migration escaped approved network boundaries.'}
        $configStage=Assert-PrivateFile $stage.ConfigStage '^proxy-stage-[0-9a-f]{32}\.json$'
        if((Get-GuardHash (Get-GuardPath 'private\proxy.json')) -ne $d.ProxyConfigHash -or (Get-GuardHash $configStage) -ne $candidate.ProxyConfigHash){throw 'Reviewed proxy configuration changed.'}
        $expectedConfig=New-GuardIPv4Config (Read-GuardJson (Get-GuardPath 'private\proxy.json'))
        if(($expectedConfig|ConvertTo-Json -Depth 40 -Compress) -ne ((Read-GuardJson $configStage)|ConvertTo-Json -Depth 40 -Compress)){throw 'Proxy change escaped IPv4-only hardening.'}
        $current=Get-GuardDesktop
        if($current.Path -ne $candidate.Desktop.Path -or $current.Hash -ne $candidate.Desktop.Hash -or $current.Family -ne $d.Desktop.Family){throw 'Desktop changed after review.'}
        Assert-AnthropicSignature $current.Path
        if(@(Get-GuardDesktopProcesses).Count -or @(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -eq $current.Path -or $_.ExecutablePath -in @($d.CodePaths)}).Count){throw 'Exit Claude and local Code before migration.'}
        if((Get-GuardHash $candidate.CodeGate.ArchivePath) -ne $candidate.CodeGate.ArchiveHash){throw 'Engine metadata changed after review.'}
        if((Get-GuardHash $stage.PayloadPath).ToLowerInvariant() -ne $candidate.CodeGate.PayloadHash.ToLowerInvariant()){throw 'Reviewed Code payload changed.'}
        Assert-AnthropicSignature $stage.PayloadPath
        $expectedRoots=@((Join-Path $env:APPDATA 'Claude\claude-code'),(Join-Path $env:LOCALAPPDATA ('Packages\'+$current.Family+'\LocalCache\Roaming\Claude\claude-code')))
        if(@(Compare-Object @($expectedRoots|Sort-Object) @($candidate.CodeGate.Roots|Sort-Object)).Count){throw 'Unexpected Code cache roots.'}
        $expectedPaths=@($expectedRoots|ForEach-Object {Join-Path $_ ($candidate.CodeGate.Version+'\'+$candidate.CodeGate.CompressedHash.Substring(0,12)+'\claude.exe')})
        if(@(Compare-Object @($expectedPaths|Sort-Object) @($candidate.CodePaths|Sort-Object)).Count){throw 'Unexpected Code binary paths.'}
        foreach($root in $expectedRoots){Assert-CodeCacheGate $root}
        foreach($path in $expectedPaths){if((Test-Path $path) -and (Get-GuardHash $path).ToLowerInvariant() -ne $candidate.CodeGate.PayloadHash.ToLowerInvariant()){throw 'Existing new Code cache differs from reviewed payload.'}}
        if(-not $candidate.PSObject.Properties['UpdatePolicyBackup']) {
            $policyKey=Get-Item 'HKCU:\SOFTWARE\Policies\Claude'
            $value=$policyKey.GetValue('disableAutoUpdates',$null)
            $candidate|Add-Member -NotePropertyName UpdatePolicyBackup -NotePropertyValue @{Value=$value;Kind=if($null -ne $value){$policyKey.GetValueKind('disableAutoUpdates').ToString()}else{$null}}
        }
        Assert-MigrationBudget
        Write-GuardJson (Get-GuardPath 'private\maintenance.json') @{Until=$budgetEnd.AddSeconds(120).ToString('o');Reason='reviewed-version-migration';ActionId=$OperationId;StageId=$stage.Id}
        $priorRules=Read-GuardJson (Get-GuardPath 'private\firewall.json')
        # 更新链已在 MSIX 安装前暂停守护；回滚必须恢复暂停前的任务状态。
        $desktopTaskRestore=if($OperationId){Get-GuardLifecycleValue (Read-GuardMaintenanceOperation $OperationId) 'DesktopTaskSnapshot'}else{$null}
        $backupEnabled=(Get-ScheduledTask -TaskName $d.Reliability.TaskName).Settings.Enabled
        $backupRunning=((Get-ScheduledTask -TaskName $d.Reliability.TaskName).State.ToString() -eq 'Running')
        if($desktopTaskRestore){
            $originalTask=Assert-PrivateFile $desktopTaskRestore.Path '^upgrade-task-[0-9a-f]{32}\.xml$'
            if((Get-GuardHash $originalTask) -ne $desktopTaskRestore.Hash -or $desktopTaskRestore.WasEnabled -isnot [bool] -or $desktopTaskRestore.WasRunning -isnot [bool]){throw 'Original desktop-update task snapshot changed.'}
            $backupEnabled=$desktopTaskRestore.WasEnabled;$backupRunning=$desktopTaskRestore.WasRunning
        }
        $rollback=Get-GuardPath ('private\upgrade-backup-'+$stage.Id+'.json')
        Write-GuardJson $rollback @{Deployment=$d;Firewall=$priorRules;WasEnabled=$backupEnabled;WasRunning=$backupRunning;CodeAcls=@($d.CodePaths|Where-Object {Test-Path $_}|ForEach-Object { @{Path=$_;Sddl=(Get-Acl $_).Sddl} });StageHash=$StageHash}
        $configBackup=Get-GuardPath ('private\proxy-before-'+$stage.Id+'.json')
        Copy-Item -LiteralPath (Get-GuardPath 'private\proxy.json') -Destination $configBackup
        if($OperationId){$null=Set-GuardMaintenanceOperation $OperationId @{BackupFile=$rollback;BackupHash=(Get-GuardHash $rollback);ProxyBackup=$configBackup;ProxyBackupHash=(Get-GuardHash $configBackup)}}
        if($d.PSObject.Properties['Reliability']){
            $priorTask=Get-ScheduledTask -TaskName $d.Reliability.TaskName
            Assert-GuardSupervisorTask $priorTask $d
            $priorTaskXml=if($desktopTaskRestore){Get-Content -LiteralPath $originalTask -Raw}else{Export-ScheduledTask -TaskName $d.Reliability.TaskName}
            $taskBackup=Get-GuardPath ('private\upgrade-task-'+$stage.Id+'.xml')
            [IO.File]::WriteAllText($taskBackup,$priorTaskXml,[Text.UTF8Encoding]::new($false))
            if($OperationId){$null=Set-GuardMaintenanceOperation $OperationId @{TaskBackup=$taskBackup;TaskBackupHash=(Get-GuardHash $taskBackup);SupervisorSuspended=$true}}
            $priorTaskSnapshot=Suspend-GuardSupervisorTask -State $d -TimeoutSeconds 30
            if($desktopTaskRestore){$priorTaskSnapshot.WasEnabled=$backupEnabled;$priorTaskSnapshot.WasRunning=$backupRunning}
        }
        Assert-MigrationBudget
        Stop-GuardProxy
        Copy-Item -LiteralPath $configStage -Destination (Get-GuardPath 'private\proxy.json')
        # 最终核准前先写入 prepared 状态；异常时恢复旧基线并保持拒绝启动。
        $candidate.Reliability.Installed=Get-Date -Format o
        if($OperationId){$null=Set-GuardMaintenanceOperation $OperationId @{BaselineChanged=$true}}
        $baselineChanged=$true;Write-GuardJson (Get-GuardPath 'private\deployment.json') $candidate
        Install-GuardFirewall
        $fresh=Read-GuardJson (Get-GuardPath 'private\firewall.json')
        $fresh.Rules=@($fresh.Rules)+@($priorRules.Rules|Where-Object {$_.Name -notin @($fresh.Rules.Name)})
        Write-GuardJson (Get-GuardPath 'private\firewall.json') $fresh
        foreach($path in $d.CodePaths) {
            if(Test-Path $path){$acl=[Security.AccessControl.FileSecurity]::new();$acl.SetAccessRuleProtection($false,$false);Set-CodeAccessOnlyAcl $path $acl}
        }
        foreach($path in $expectedPaths) {
            $folder=Split-Path $path -Parent;New-Item -ItemType Directory -Path $folder -Force|Out-Null
            if(-not (Test-Path $path)){Copy-Item -LiteralPath $stage.PayloadPath -Destination $path}
            [IO.File]::WriteAllText((Join-Path $folder '.verified'),$candidate.CodeGate.CompressedHash,[Text.UTF8Encoding]::new($false))
            Write-GuardJson (Join-Path $folder '.payload') @{sha256=$candidate.CodeGate.PayloadHash;size=(Get-Item $path).Length}
            Protect-CodeBinary $path
        }
        New-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Claude' -Name disableAutoUpdates -PropertyType DWord -Value 1 -Force|Out-Null
        Assert-MigrationBudget
        Install-GuardDesktopUserPolicy
        # 管理员真实缓存与交互式桌面缓存均须核验，避免一侧旧引擎遗漏执行拒绝。
        $cacheWorker=Join-Path $PSScriptRoot 'Repair-ClaudeCodeContext-Admin.ps1'
        $cacheResult=Get-GuardPath ('private\cache-repair-'+[guid]::NewGuid().ToString('N')+'.json')
        & $cacheWorker -Worker -ResultFile $cacheResult -ReviewedWorkerHash (Get-GuardHash $cacheWorker)
        if($LASTEXITCODE -and $LASTEXITCODE -ne 0){throw 'Administrator cache permissions repair failed.'}
        & (Join-Path $PSScriptRoot 'Repair-ClaudeCodeContext-Admin.ps1')
        if($LASTEXITCODE -and $LASTEXITCODE -ne 0){throw 'Desktop cache permissions repair failed.'}
        Assert-MigrationBudget
        Assert-GuardPolicy
        Test-CodeCacheGate
        Assert-GuardFirewall
        Install-SupervisorTask $candidate $d
        $supervisorTaskInstalled=$true
        $result.SupervisorInstalled=$true;$result.UpdatePolicyInstalled=$true
        Remove-Item -LiteralPath (Get-GuardPath 'private\maintenance.json') -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Get-GuardPath 'private\safety-hold.json') -ErrorAction SilentlyContinue
        if($OperationId){$null=Set-GuardMaintenanceOperation $OperationId @{Phase='Restarting'}}
        Assert-MigrationBudget
        Resume-GuardSupervisorTask -State $candidate
        Start-GuardProxy -DeadlineUtc $budgetEnd
        if($OperationId){$null=Set-GuardMaintenanceOperation $OperationId @{Phase='Verifying'}}
        $result['Egress']=Test-GuardEgress
        $health=Wait-GuardSupervisorReady -TimeoutSeconds 90 -DeadlineUtc $budgetEnd
        Assert-MigrationBudget
        $result['DesktopSupervisorVerified']=$true
        $result.DesktopVersion=$candidate.Desktop.Version;$result.CodeVersion=$candidate.CodeGate.Version;$result.Success=$true
        $result.CompletedAt=[datetime]::UtcNow.ToString('o')
        Write-GuardJson (Get-GuardPath 'evidence\version-migration.json') $result
    } catch {
        $result.Reason=$_.Exception.Message
        try {
            if($OperationId -and $operationClaimed){
                $op=Read-GuardMaintenanceOperation $OperationId
                if($op.BackupFile){Restore-GuardMaintenanceBackup $op}
            } elseif($priorTaskXml) {
                # 保留无入口 OperationId 的命令行维护兼容；精确停止后恢复旧任务。
                $null=Suspend-GuardSupervisorTask -State (Get-GuardState) -TimeoutSeconds 30
                if($baselineChanged){Write-GuardJson (Get-GuardPath 'private\deployment.json') $oldState;Stop-GuardProxyEmergency;Write-GuardJson (Get-GuardPath 'private\safety-hold.json') @{Time=(Get-Date -Format o);Reason='Reviewed maintenance failed; reviewed migration required.'}}
                if($configBackup){Copy-Item -LiteralPath $configBackup -Destination (Get-GuardPath 'private\proxy.json')}
                $null=Register-ScheduledTask -TaskName $d.Reliability.TaskName -Xml $priorTaskXml -Force
                if($priorTaskSnapshot.WasEnabled){$null=Enable-ScheduledTask -TaskName $d.Reliability.TaskName;if($priorTaskSnapshot.WasRunning){Start-ScheduledTask -TaskName $d.Reliability.TaskName}}
            }
            $result.RollbackRestored=$true
        }catch{$result.RollbackError=$_.Exception.Message;$result.Reason+='; rollback failed: '+$result.RollbackError}
        # 新增阻断规则及尚未核准的缓存留在受保护状态，保留失败证据和恢复路径。
    } finally {
        $result.CompletedAt=[datetime]::UtcNow.ToString('o')
        Write-GuardJson $ResultFile $result
        if($OperationId -and $operationClaimed){
            $phase=if($result.Success){'Completed'}else{'Failed'}
            $kind=if($result.Success){$null}elseif($result.Reason -match 'Exit Claude'){'UnprotectedInstance'}else{'MaintenanceFailed'}
            $message=if($kind -eq 'UnprotectedInstance'){'请完全退出 Claude 和本地 Code 后再点击“维护版本”。'}elseif($result.Reason){'版本维护失败：'+$result.Reason}else{$null}
            $null=Set-GuardMaintenanceOperation $OperationId @{Status=$phase;Phase=$phase;Reason=$message;FailureKind=$kind;RecoveryRequired=[bool]$result.RollbackError;RollbackRestored=$result.RollbackRestored}
        }
        $marker=Get-GuardPath 'private\maintenance.json'
        if(Test-Path -LiteralPath $marker){$m=Read-GuardJson $marker;if((Get-GuardLifecycleValue $m 'StageId') -eq $result.StageId -and -not $result.RollbackError){Remove-Item -LiteralPath $marker}}
        if($installerHeld){$installer.ReleaseMutex()};$installer.Dispose()
    }
    if(-not $result.Success){exit 1}
    exit 0
}
if($StageFile -or $StageHash -or $ResultFile){throw 'Install arguments require Install mode.'}
$prepareEnd=[datetime]::UtcNow.AddSeconds(660)
function Assert-PreparationBudget {if([datetime]::UtcNow -ge $prepareEnd){throw 'MaintenanceTimeout: 维护准备超过 660 秒，请查看进度。'}}
if($OperationId){$op=Read-GuardMaintenanceOperation $OperationId;if(-not $op -or $op.Phase -ne 'Preparing' -or $op.CoordinatorPid -ne $PID){throw 'Maintenance preparation owner changed.'}}
Assert-PreparationBudget
Assert-GuardPolicy
$current=Get-GuardDesktop
if($current.Family -ne $d.Desktop.Family){throw 'Installed package identity changed.'}
Assert-AnthropicSignature $current.Path
$archive=Join-Path (Split-Path $current.Path) 'resources\app.asar'
$manifest=& node (Join-Path $PSScriptRoot 'Read-DesktopCodeManifest.cjs') $archive
if($LASTEXITCODE -ne 0){throw 'New Code manifest could not be verified.'}
$m=$manifest|ConvertFrom-Json
if(-not $m.msixAutomaticCodeUpdatesDisabled -or -not $m.desktopUpdatePolicySupported){throw 'This Desktop update mechanism requires additional review.'}
if(-not (Test-Path (Get-GuardPath 'private\safety-hold.json'))){
    if($OperationId -and (Get-GuardLifecycleValue $op 'SupervisorSuspended' $false) -and (Get-GuardLifecycleValue $op 'DesktopTaskSnapshot')){Start-GuardProxy -SupervisorWorker}else{Start-GuardProxy}
    $null=Test-GuardEgress
}
$id=[guid]::NewGuid().ToString('N')
$compressed=Get-GuardPath ('private\code-'+$m.platform.checksum+'.zst')
$payload=Get-GuardPath ('private\code-'+$m.platform.checksum+'.exe')
if(-not (Test-Path $compressed)) {
    if(Test-Path (Get-GuardPath 'private\safety-hold.json')){throw 'SafetyHold: uncached official payload needs separate network review.'}
    & (Get-GuardPath 'runtime\network-probe.exe') --silent --show-error --fail --connect-timeout 10 --max-time 600 --proxy $d.ProxyUrl --noproxy '' --output $compressed ($m.baseUrl+'/'+$m.desktopCodeVersion+'/win32-x64/'+$m.platform.binary)
    if($LASTEXITCODE -ne 0){throw 'Official Code download failed.'}
}
if((Get-GuardHash $compressed).ToLowerInvariant() -ne $m.platform.checksum){throw 'Official compressed Code checksum mismatch.'}
if(-not (Test-Path $payload)) {
    $meta=& node (Join-Path $PSScriptRoot 'Expand-VerifiedCode.cjs') $compressed $payload $m.platform.checksum
    if($LASTEXITCODE -ne 0){throw 'Verified Code decompression failed.'}
}
Assert-AnthropicSignature $payload
Assert-PreparationBudget
$roots=@($d.CodeGate.Roots)
$candidate=$d|ConvertTo-Json -Depth 30|ConvertFrom-Json
$candidate.Desktop=$current
$candidate.CodePaths=@($roots|ForEach-Object {Join-Path $_ ($m.desktopCodeVersion+'\'+$m.platform.checksum.Substring(0,12)+'\claude.exe')})
$candidate.CodeGate=@{Schema=1;Roots=$roots;Version=$m.desktopCodeVersion;PayloadHash=(Get-GuardHash $payload).ToLowerInvariant();PayloadPath=$payload;ArchivePath=$archive;ArchiveHash=(Get-GuardHash $archive);CompressedHash=$m.platform.checksum}
$sameVersion=($current.Hash -eq $d.Desktop.Hash -and $candidate.CodeGate.PayloadHash -eq $d.CodeGate.PayloadHash)
if(-not $sameVersion){
    $candidate.CodeCoverage='prepared'
    if($candidate.PSObject.Properties['LocalCodeAcceptance']){$candidate|Add-Member -NotePropertyName HistoricalCodeAcceptance -NotePropertyValue $candidate.LocalCodeAcceptance -Force;$candidate.PSObject.Properties.Remove('LocalCodeAcceptance')}
}
$candidate|Add-Member -NotePropertyName Reliability -NotePropertyValue (New-GuardReliability $d.Reliability) -Force
$configStage=Get-GuardPath ('private\proxy-stage-'+$id+'.json')
Write-GuardJson $configStage (New-GuardIPv4Config (Read-GuardJson (Get-GuardPath 'private\proxy.json')))
$check=& (Get-GuardPath 'runtime\sing-box.exe') check -c $configStage 2>&1
if($LASTEXITCODE -ne 0){throw 'IPv4-only configuration check failed; details suppressed.'}
$candidate.ProxyConfigHash=Get-GuardHash $configStage
$files=@('ClaudeGuard.psm1','ClaudeGuard-Lifecycle.ps1','ClaudeGuard-Health.ps1','ClaudeSupervisorHost.cs','runtime\ClaudeSupervisorHost.exe','runtime\ClaudeProGuard.exe','private\launcher-paths.txt','ClaudeCodeGate.psm1','ClaudeGuard-Supervisor-v2.ps1','ClaudeGuard-Runtime.psm1','Read-ClaudeProcessEnvironment.py','ClaudeGuard-UiBridge.ps1','Update-ClaudeGuard.ps1','Repair-ClaudeCodeContext-Admin.ps1','Install-ClaudeGuard.ps1','Read-DesktopCodeManifest.cjs','Expand-VerifiedCode.cjs','ClaudeGuard-VersionInfo.psm1','Get-ClaudeVersionInfo.ps1','ClaudeGuard-DesktopUpdate.psm1','Invoke-ClaudeDesktopUpdate.ps1')
$stage=[ordered]@{Id=$id;Created=(Get-Date -Format o);PreviousStateHash=(Get-GuardHash (Get-GuardPath 'private\deployment.json'));Candidate=$candidate;PayloadPath=$payload;Manifest=$m;ConfigStage=$configStage;ScriptHashes=@($files|ForEach-Object { @{Name=$_;Hash=(Get-GuardHash (Get-GuardPath $_))} })}
$stagePath=Get-GuardPath ('private\upgrade-stage-'+$id+'.json')
Write-GuardJson $stagePath $stage
Assert-PreparationBudget
Write-GuardJson (Get-GuardPath 'private\latest-upgrade-stage.json') @{Path=$stagePath;Hash=(Get-GuardHash $stagePath);Id=$id}
[pscustomobject]@{StageFile=$stagePath;StageHash=(Get-GuardHash $stagePath);DesktopVersion=$current.Version;CodeVersion=$m.desktopCodeVersion;PayloadSignature='Valid';CodeHash=$candidate.CodeGate.PayloadHash}|ConvertTo-Json
