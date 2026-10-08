[CmdletBinding()]
param([switch]$SupervisorOnly,[string]$ResultFile)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$d=Get-GuardState
if(-not (Test-GuardAdmin) -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $d.UserSid){throw 'Same-account administrator context required.'}
if($ResultFile){
    $ResultFile=[IO.Path]::GetFullPath($ResultFile)
    if([IO.Path]::GetDirectoryName($ResultFile) -ne (Get-GuardPath 'private') -or [IO.Path]::GetFileName($ResultFile) -notmatch '^supervisor-only-result-[0-9a-f]{32}\.json$'){throw 'Invalid supervisor maintenance result path.'}
}
$result=[ordered]@{Time=(Get-Date -Format o);Success=$false;Reason=$null;Mode=if($SupervisorOnly){'SupervisorOnly'}else{'DesktopPolicyRepair'};DesktopPolicyRepaired=$false;SupervisorHealthy=$false;RolledBack=$false;RollbackError=$null}
if($SupervisorOnly){
    $suspended=$false;$taskInstalled=$false;$maintenanceToken=$null;$previousMaintenance=$null
    $maintenancePath=Get-GuardPath 'private\maintenance.json'
    function Clear-SupervisorRepairMaintenance {
        if($maintenanceToken -and (Test-Path -LiteralPath $maintenancePath)){
            $currentMaintenance=Read-GuardJson $maintenancePath
            if($currentMaintenance.Token -ne $maintenanceToken){throw 'Supervisor maintenance ownership changed.'}
            if($previousMaintenance){Write-GuardJson $maintenancePath $previousMaintenance}else{Remove-Item -LiteralPath $maintenancePath}
        }
        $script:maintenanceToken=$null
    }
    try {
    $task=Get-ScheduledTask -TaskName $d.Reliability.TaskName -TaskPath '\' -ErrorAction Stop
    Assert-GuardSupervisorTask $task $d
    $transaction=Get-GuardPath ('private\supervisor-only-transaction-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $transaction -ErrorAction Stop|Out-Null
    $statePath=Get-GuardPath 'private\deployment.json'
    Copy-Item -LiteralPath $statePath -Destination (Join-Path $transaction 'deployment.json')
    $oldXml=Export-ScheduledTask -TaskName $d.Reliability.TaskName -TaskPath '\'
    $snapshot=[pscustomobject]@{WasEnabled=[bool]$task.Settings.Enabled;WasRunning=($task.State.ToString() -eq 'Running');Processes=@()}
    [IO.File]::WriteAllText((Join-Path $transaction 'task.xml'),$oldXml,[Text.UTF8Encoding]::new($false))
    $result['BackupPath']=$transaction
    $marker=Get-GuardPath 'private\active-supervisor-fix-backup.txt'
    $matchesApproved=$true
    foreach($entry in @(@{Name='ClaudeGuard.psm1';Hash=$d.Reliability.GuardHash},@{Name=[IO.Path]::GetFileName((Get-GuardSupervisorScript $d.Reliability));Hash=$d.Reliability.SupervisorHash},@{Name='ClaudeGuard-Runtime.psm1';Hash=$d.Reliability.RuntimeHash},@{Name='Read-ClaudeProcessEnvironment.py';Hash=$d.Reliability.EnvironmentReaderHash})){
        if((Get-GuardHash (Get-GuardPath $entry.Name)) -ne $entry.Hash){$matchesApproved=$false}
    }
    # 正常维护直接快照当前核准版本；只有源码已由候选替换时才使用登记的旧版本备份。
    $sourceBackup=if($matchesApproved){$transaction}elseif(Test-Path -LiteralPath $marker){[IO.Path]::GetFullPath((Get-Content -LiteralPath $marker -Raw).Trim())}else{throw 'Staged supervisor source requires an approved rollback backup.'}
    if([IO.Path]::GetDirectoryName($sourceBackup) -ne (Get-GuardPath 'private') -or [IO.Path]::GetFileName($sourceBackup) -notmatch '^(supervisor-fix-backup-|supervisor-only-transaction-)' -or -not (Test-Path -LiteralPath $sourceBackup -PathType Container) -or ((Get-Item -LiteralPath $sourceBackup).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Invalid approved supervisor source backup.'}
    $rollbackFiles=@()
    $changedFiles=@('ClaudeGuard.psm1','ClaudeGuard-Supervisor-v2.ps1','ClaudeGuard-Runtime.psm1','Read-ClaudeProcessEnvironment.py','Test-ClaudeSupervisorDecisions.ps1','Get-ClaudeHealth.ps1','ClaudeGuard-UiBridge.ps1','ClaudeGuardLauncher.cs','ClaudeSupervisorHost.cs','ClaudeGuard-Lifecycle.ps1','ClaudeGuard-Health.ps1','Build-ClaudeShortcut.ps1','Repair-ClaudeSupervisorContext-Admin.ps1','Update-ClaudeGuard.ps1','Remove-ClaudeGuard.ps1','runtime\ClaudeProGuard.exe','runtime\ClaudeSupervisorHost.exe')
    $candidateBackup=Join-Path $transaction 'candidate';New-Item -ItemType Directory -Path $candidateBackup|Out-Null
    foreach($name in $changedFiles){
        $target=Get-GuardPath $name;$leaf=[IO.Path]::GetFileName($target)
        if(Test-Path -LiteralPath $target){Copy-Item -LiteralPath $target -Destination (Join-Path $candidateBackup $leaf)}
        $original=if($matchesApproved){$target}else{Join-Path $sourceBackup $leaf}
        if(Test-Path -LiteralPath $original){
            $copy=Join-Path $transaction ('before-'+$leaf)
            Copy-Item -LiteralPath $original -Destination $copy
            $rollbackFiles+=[pscustomobject]@{Target=$target;Backup=$copy;Hash=(Get-GuardHash $copy)}
        }
    }
    foreach($entry in @(@{Name='ClaudeGuard.psm1';Hash=$d.Reliability.GuardHash},@{Name=[IO.Path]::GetFileName((Get-GuardSupervisorScript $d.Reliability));Hash=$d.Reliability.SupervisorHash},@{Name='ClaudeGuard-Runtime.psm1';Hash=$d.Reliability.RuntimeHash},@{Name='Read-ClaudeProcessEnvironment.py';Hash=$d.Reliability.EnvironmentReaderHash})){
        $saved=@($rollbackFiles|Where-Object Target -eq (Get-GuardPath $entry.Name))
        if($saved.Count -ne 1 -or $saved[0].Hash -ne $entry.Hash){throw 'Supervisor rollback source does not match the approved deployment; deployment refused.'}
    }
    Write-GuardJson (Join-Path $transaction 'rollback-files.json') $rollbackFiles
    $protectedPaths=@((Get-GuardPath 'private\proxy.json'),(Get-GuardPath 'runtime\sing-box.exe'),(Get-GuardPath 'private\firewall.json'),(Join-Path $d.ConfigDir 'settings.json'),$d.OriginalCli.Path)+@($d.CodePaths)
    $protected=@($protectedPaths|ForEach-Object {[pscustomobject]@{Path=$_;Hash=(Get-GuardHash $_)}})
    $holdPath=Get-GuardPath 'private\safety-hold.json'
    $holdHash=if(Test-Path -LiteralPath $holdPath){Get-GuardHash $holdPath}else{$null}
    $proxyBefore=if(Test-Path -LiteralPath (Get-GuardPath 'private\proxy-process.json')){Read-GuardJson (Get-GuardPath 'private\proxy-process.json')}else{$null}
    $candidate=$d|ConvertTo-Json -Depth 40|ConvertFrom-Json
        $candidate.Reliability=New-GuardReliability $d.Reliability
        Assert-GuardReliabilityFiles $candidate
        if(Test-Path -LiteralPath $maintenancePath){$previousMaintenance=Read-GuardJson $maintenancePath;if(([datetime]$previousMaintenance.Until).ToUniversalTime() -gt [datetime]::UtcNow){throw 'Another supervisor maintenance operation is active.'}}
        $maintenanceToken=[guid]::NewGuid().ToString('N')
        Write-GuardJson $maintenancePath @{Token=$maintenanceToken;Mode='SupervisorOnly';Until=[datetime]::UtcNow.AddMinutes(8).ToString('o')}
        $suspended=$true
        $snapshot=Suspend-GuardSupervisorTask -State $d -TimeoutSeconds 30
        $result['PreviousProcesses']=@($snapshot.Processes)
        # 此模式只验证静态策略和已运行专用代理身份，不停止代理或修改 Code/策略。
        Assert-GuardPolicy -RuntimeOnly
        Assert-GuardFirewall
        Assert-GuardCore
        foreach($entry in $protected){if((Get-GuardHash $entry.Path) -ne $entry.Hash){throw 'Protected source changed during supervisor maintenance.'}}
        Assert-GuardReliabilityFiles $candidate
        Write-GuardJson $statePath $candidate
        Register-GuardSupervisorTask -State $candidate -PreviousState $d
        $taskInstalled=$true
        Clear-SupervisorRepairMaintenance
        Resume-GuardSupervisorTask -State $candidate
        $health=Wait-GuardSupervisorReady -TimeoutSeconds 90
        foreach($entry in $protected){if((Get-GuardHash $entry.Path) -ne $entry.Hash){throw 'Protected source changed after supervisor restart.'}}
        if($proxyBefore){$proxyAfter=Read-GuardJson (Get-GuardPath 'private\proxy-process.json');if($proxyAfter.Pid -ne $proxyBefore.Pid -or $proxyAfter.Started -ne $proxyBefore.Started){throw 'Dedicated proxy process changed during supervisor-only maintenance.'}}
        $holdNow=if(Test-Path -LiteralPath $holdPath){Get-GuardHash $holdPath}else{$null}
        if($holdNow -ne $holdHash){throw 'SafetyHold changed during supervisor-only maintenance.'}
        $result.SupervisorHealthy=$true;$result['Health']=$health;$result.Success=$true
    } catch {
        $result.Reason=$_.Exception.Message
        if($suspended){
            try {
                $rollbackTask=Get-ScheduledTask -TaskName $d.Reliability.TaskName -TaskPath '\'
                try {Assert-GuardSupervisorTask $rollbackTask $candidate;$shutdownState=$candidate}catch{Assert-GuardSupervisorTask $rollbackTask $d;$shutdownState=$d}
                $null=Suspend-GuardSupervisorTask -State $shutdownState -TimeoutSeconds 30
                foreach($entry in $rollbackFiles){if((Get-GuardHash $entry.Backup) -ne $entry.Hash){throw 'Supervisor rollback backup changed.'};Copy-Item -LiteralPath $entry.Backup -Destination $entry.Target}
                Copy-Item -LiteralPath (Join-Path $transaction 'deployment.json') -Destination $statePath
                $null=Register-ScheduledTask -TaskName $d.Reliability.TaskName -TaskPath '\' -Xml $oldXml -Force
                Assert-GuardSupervisorTask (Get-ScheduledTask -TaskName $d.Reliability.TaskName -TaskPath '\') $d
                if($snapshot.WasEnabled){$null=Enable-ScheduledTask -TaskName $d.Reliability.TaskName -TaskPath '\'}else{$null=Disable-ScheduledTask -TaskName $d.Reliability.TaskName -TaskPath '\'}
                Clear-SupervisorRepairMaintenance
                if($snapshot.WasRunning){Start-ScheduledTask -TaskName $d.Reliability.TaskName -TaskPath '\'}
                $result.RolledBack=$true
            }catch{$result.RollbackError=$_.Exception.Message}
        }
    }finally{
        try{Clear-SupervisorRepairMaintenance}catch{$result['MaintenanceCleanupError']=$_.Exception.Message}
        Write-GuardJson (Get-GuardPath 'evidence\supervisor-only-repair.json') $result
        if($ResultFile){Write-GuardJson $ResultFile $result}
    }
    if(-not $result.Success){Write-Error ('Supervisor-only maintenance failed: '+$result.Reason+'; rollback: '+$result.RolledBack+'; '+$result.RollbackError);exit 1}
    $result|ConvertTo-Json -Depth 10
    exit 0
}
if(@(Get-GuardDesktopProcesses).Count){throw 'Exit Claude before desktop policy repair.'}
$task=Get-ScheduledTask -TaskName $d.Reliability.TaskName
Assert-GuardSupervisorTask $task $d
try {
    $snapshot=Suspend-GuardSupervisorTask -State $d -TimeoutSeconds 30
    Install-GuardDesktopUserPolicy
    & (Join-Path $PSScriptRoot 'Repair-ClaudeCodeContext-Admin.ps1')
    if($LASTEXITCODE -and $LASTEXITCODE -ne 0){throw 'Desktop cache permissions repair failed.'}
    $result.DesktopPolicyRepaired=$true
    $hold=Get-GuardPath 'private\safety-hold.json'
    if(Test-Path $hold){Copy-Item -LiteralPath $hold -Destination (Get-GuardPath ('private\safety-hold-reviewed-'+[guid]::NewGuid().ToString('N')+'.json'));Remove-Item -LiteralPath $hold}
    Resume-GuardSupervisorTask -State $d
    $health=Wait-GuardSupervisorReady -TimeoutSeconds 90
    $result.SupervisorHealthy=$true
    $result['Egress']=Test-GuardEgress
    $result.Success=$true
} catch {
    $result.Reason=$_.Exception.Message
    $result['SupervisorKeptDisabled']=$false
    try {$null=Suspend-GuardSupervisorTask -State $d -TimeoutSeconds 30;$result['SupervisorKeptDisabled']=$true;$result.Reason+='; supervisor task remains disabled after repair failure; review the failure before resuming.'}
    catch {$result.Reason+='; supervisor failure shutdown could not be confirmed: '+$_.Exception.Message}
} finally {Write-GuardJson (Get-GuardPath 'evidence\supervisor-context-repair.json') $result;if($ResultFile){Write-GuardJson $ResultFile $result}}
if(-not $result.Success){exit 1}
