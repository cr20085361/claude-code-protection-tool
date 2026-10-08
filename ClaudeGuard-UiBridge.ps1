[CmdletBinding()]
param([ValidateSet('Start','Check','Login','Update','Diagnose')][string]$Action='Start',[string]$ResultFile,[string]$ActionId)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
if($ResultFile){
    $ResultFile=[IO.Path]::GetFullPath($ResultFile)
    if([IO.Path]::GetDirectoryName($ResultFile) -ne (Get-GuardPath 'private') -or [IO.Path]::GetFileName($ResultFile) -notmatch '^ui-result-[0-9a-f]{32}\.json$'){throw 'Invalid private UI result path.'}
}
if(-not $ActionId){$ActionId=[guid]::NewGuid().ToString('N')}
if($Action -ne 'Diagnose'){Register-GuardUiAction $ActionId $Action}
$deadline=[datetime]::UtcNow.AddSeconds(150)
$result=[ordered]@{Success=$false;Pending=$false;OperationId=$null;Phase=$null;Message='';Started=$false;SessionVerified=$false;DesktopPid=$null;FailureKind=$null;ApprovedVersion=$null;InstalledVersion=$null;SupervisorStatus=$null;SupervisorVerified=$false;SupervisorTime=$null;SupervisorRunId=$null;ApiTransport=$null;ActionId=$ActionId}
function Wait-VersionMaintenance([string]$Id,$Installer=$null) {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    do {
        $op=Read-GuardMaintenanceOperation $Id
        if($op.Status -in @('Completed','Failed','Interrupted')){return (Get-GuardMaintenanceUiResult $op)}
        $snapshot=Get-GuardMaintenanceAssessment $op
        if($snapshot.Interrupted -or ($Installer -and $Installer.HasExited)){
            $null=Set-GuardMaintenanceOperation $Id @{Status='Interrupted';Phase='Interrupted';RecoveryRequired=$true;FailureKind='MaintenanceInterrupted';Reason='维护进程已退出，尚未取得最终结果，需要同账号管理员恢复。'}
            return (Sync-GuardMaintenanceUiResult $Id)
        }
        # 此预算只限制入口观察，不终止仍在修改防护的管理员进程。
        if($watch.Elapsed.TotalSeconds -ge 600){return (Get-GuardMaintenanceUiResult $op)}
        Start-Sleep -Milliseconds 750
    }while($true)
}
$createdOperation=$null
if($Action -eq 'Diagnose'){
    try{$result.ApiTransport=Test-GuardApiTransport;$result.Success=$true}catch{$result.Message='官方 API 无账号诊断暂未完成。'}
    if($ResultFile){Write-GuardJson $ResultFile $result}else{$result|ConvertTo-Json -Compress}
    exit 0
}
try {
    $d=Get-GuardState
    $result.ApprovedVersion=$d.Desktop.Version
    $result.InstalledVersion=(Get-GuardDesktop).Version
    $result.SessionVerified=Test-GuardLocalCodeAcceptance
    $existing=@(Get-GuardDesktopProcesses)
    if($Action -eq 'Update') {
        $snapshot=Get-GuardMaintenanceSnapshot
        if($snapshot.Active){
            Set-GuardUiMaintenanceBinding $ActionId $snapshot.Operation.ActionId
            $result=Wait-VersionMaintenance $snapshot.Operation.ActionId
        }elseif($snapshot.Interrupted -or ($snapshot.Operation -and $snapshot.Operation.RecoveryRequired)){
            $id=$snapshot.Operation.ActionId
            Set-GuardUiMaintenanceBinding $ActionId $id
            $shell=Get-GuardApprovedShellPath
            $args='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+(Join-Path $PSScriptRoot 'Update-ClaudeGuard.ps1')+'" -RecoverOperationId '+$id
            try{$p=Start-GuardMaintenanceAdministrator $shell $args}catch{
                if(Test-GuardMaintenanceAuthorizationCancelled $_.Exception){throw 'AdministratorCancelled: Windows 管理员授权已取消。'}
                throw
            }
            try{
                # 恢复 worker 尚未认领前等待其启动，避免读取旧的 Interrupted 记录。
                $startup=[Diagnostics.Stopwatch]::StartNew()
                do{$op=Read-GuardMaintenanceOperation $id;if($op.WorkerPid -eq $p.Id -or $p.HasExited){break};Start-Sleep -Milliseconds 200}while($startup.Elapsed.TotalSeconds -lt 15)
                $result=Wait-VersionMaintenance $id $p
            }finally{$p.Dispose()}
        }else{
            $createdOperation=$ActionId
            $null=New-GuardMaintenanceOperation $ActionId
            Set-GuardUiMaintenanceBinding $ActionId $ActionId
            $null=Sync-GuardMaintenanceUiResult $ActionId
            if($existing.Count){throw 'Exit Claude and local Code before migration.'}
            $stageText=& (Join-Path $PSScriptRoot 'Update-ClaudeGuard.ps1') -OperationId $ActionId
            if(-not $stageText){throw 'Version migration stage was not created.'}
            $stage=$stageText|ConvertFrom-Json
            $stageId=(Read-GuardJson $stage.StageFile).Id
            $resultPath=Get-GuardPath ('private\upgrade-result-'+[guid]::NewGuid().ToString('N')+'.json')
            $null=Set-GuardMaintenanceOperation $ActionId @{Phase='AwaitingAuthorization';StageId=$stageId;StageFile=$stage.StageFile;StageHash=$stage.StageHash;ResultFile=$resultPath}
            $shell=Get-GuardApprovedShellPath
            $args='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+(Join-Path $PSScriptRoot 'Update-ClaudeGuard.ps1')+'" -Install -StageFile "'+$stage.StageFile+'" -StageHash '+$stage.StageHash+' -ResultFile "'+$resultPath+'" -OperationId '+$ActionId
            try{$p=Start-GuardMaintenanceAdministrator $shell $args}catch{
                if(Test-GuardMaintenanceAuthorizationCancelled $_.Exception){throw 'AdministratorCancelled: Windows 管理员授权已取消。'}
                throw
            }
            try{$result=Wait-VersionMaintenance $ActionId $p}finally{$p.Dispose()}
        }
        # 对外返回本次入口 ActionId；操作身份独立保存，接续时不冒用原入口调用。
        $result.ActionId=$ActionId
    } elseif($Action -eq 'Start') {
        $m=Get-GuardMaintenanceSnapshot;if($m.Active -or $m.Interrupted -or ($m.Operation -and $m.Operation.RecoveryRequired)){throw 'MaintenanceInterrupted: 维护尚未结束，请先接续维护。'}
        if($existing.Count) {
            Assert-GuardPolicy
            Assert-GuardFirewall
            Start-GuardProxy -DeadlineUtc $deadline
            $null=Get-GuardVerifiedEgress
            $last=Read-GuardJson (Get-GuardPath 'evidence\last-launch.json')
            $matching=@($existing|Where-Object{$_.ProcessId -eq $last.Pid})
            if($matching.Count -ne 1 -or ([datetime]$last.ProcessStart).ToUniversalTime().Ticks -ne (Get-Process -Id $last.Pid).StartTime.ToUniversalTime().Ticks){throw 'Claude is already running outside the protected launcher.'}
            Assert-GuardDesktopNetwork $last.Pid -DeadlineUtc $deadline
            $result.DesktopPid=$last.Pid
            $result.Message='Claude 已通过安全入口启动。请切换到 Claude 窗口继续。'
        } else {
            $result.DesktopPid=Start-GuardDesktop -DeadlineUtc $deadline
            $result.Started=$true
            $result.Message=if($result.SessionVerified){'Claude 已打开。当前版本的本机本地 Code 基础使用验收已完成。'}else{'Claude 已打开。网络防护准备完成；Code 正常会话尚待验证。'}
        }
    } elseif($Action -eq 'Login') {
        $m=Get-GuardMaintenanceSnapshot;if($m.Active -or $m.Interrupted -or ($m.Operation -and $m.Operation.RecoveryRequired)){throw 'MaintenanceInterrupted: 维护尚未结束，请先接续维护。'}
        Assert-GuardPolicy
        Assert-GuardFirewall
        Start-GuardProxy -DeadlineUtc $deadline
        $null=Get-GuardVerifiedEgress
        $linkFile=Get-GuardPath 'private\login-link.json'
        try{
            $link=Read-GuardJson $linkFile
            & (Join-Path $PSScriptRoot 'Start-ClaudeLoginBrowser.ps1') -Url $link.Url
            $result.Message='专用登录浏览器已打开。请自行完成官方登录。'
        }finally{if(Test-Path -LiteralPath $linkFile){Remove-Item -LiteralPath $linkFile}}
    } else {
        $m=Get-GuardMaintenanceSnapshot;if($m.Active -or $m.Interrupted -or ($m.Operation -and $m.Operation.RecoveryRequired)){throw 'MaintenanceInterrupted: 维护尚未结束，请先接续维护。'}
        Assert-GuardPolicy
        Assert-GuardFirewall
        Start-GuardProxy -DeadlineUtc $deadline
        $null=Get-GuardVerifiedEgress
        if($existing.Count){
            $last=Read-GuardJson (Get-GuardPath 'evidence\last-launch.json')
            if(@($existing|Where-Object ProcessId -eq $last.Pid).Count -ne 1 -or (Get-Process -Id $last.Pid).StartTime.ToUniversalTime().Ticks -ne ([datetime]$last.ProcessStart).ToUniversalTime().Ticks){throw 'Claude is already running outside the protected launcher.'}
            Assert-GuardDesktopNetwork $last.Pid -DeadlineUtc $deadline
        }
        $result.Message=if($result.SessionVerified){'固定出口及防护检查通过；当前版本的本机本地 Code 基础使用已验收。'}else{'固定出口、代理、防火墙和新版本执行门槛检查通过。真实 Code 会话验收状态请查看报告。'}
    }
    if($Action -ne 'Update'){
        $snapshot=Get-GuardSupervisorSnapshot
        if(-not $snapshot.Ready){throw ('SupervisorUnavailable: '+$snapshot.Reason)}
        if([datetime]::UtcNow -ge $deadline){throw 'SupervisorUnavailable: 本次入口操作超时'}
        $result.SupervisorVerified=$true;$result.SupervisorStatus=$snapshot.Health.Status
        $result.SupervisorTime=$snapshot.Health.Time;$result.SupervisorRunId=$snapshot.Health.RunId
        $result.Success=$true
        $oldError=Get-GuardPath 'private\last-ui-error.json'
        $currentClaim=Read-GuardJson (Get-GuardPath 'private\active-ui-action.json')
        if($currentClaim.ActionId -eq $ActionId -and (Test-Path -LiteralPath $oldError)){Remove-Item -LiteralPath $oldError}
    }
} catch {
    $result.Success=$false
    $detail=$_.Exception.Message
    if($detail -match '^Desktop updated'){
        $result.FailureKind='UpgradeRequired'
        $result.Message='Claude 已自动更新：'+$result.ApprovedVersion+' → '+$result.InstalledVersion+'。新版本防护待迁移，请完全退出 Claude 后点击“维护版本”。'
    }
    elseif($detail -match 'SafetyHold|safety hold|Fixed egress mismatch'){$result.FailureKind='SafetyHold';$result.Message='出口或运行防护异常，专用网络已暂停。请退出 Claude 后点击“维护版本”，核验完成再使用。'}
    elseif($detail -match 'SupervisorUnavailable'){$result.FailureKind='SupervisorUnavailable';$result.Message='后台守护尚未恢复，不能确认防护准备完成。已打开的会话保留；请等待自动恢复或点击“重新检查”。'}
    elseif($detail -match 'already running|Exit Claude'){ $result.FailureKind='UnprotectedInstance';$result.Message='Claude 已从其他入口运行或尚未退出。请完全退出 Claude 后重试。' }
    elseif($detail -match 'execution gate|Code cache'){ $result.FailureKind='CodeCachePermissions';$result.Message='本地 Code 缓存的执行防护需要维护，已停止启动。请完全退出 Claude 后点击“维护版本”。' }
    elseif($detail -eq 'Pinned desktop proxy policy is missing.'){ $result.Message='当前桌面会话的固定代理策略缺失，已停止启动。请先修复策略，再重新检查。' }
    elseif($detail -match "Cannot find path.*claude-code"){ $result.Message='当前桌面会话的已核准 Code 缓存缺失，已停止启动。请补齐本地引擎后重新检查。' }
    elseif($detail -match 'updated|changed|metadata|binary'){ $result.Message='软件或防护配置发生变化，已停止启动。请重新核验并补齐规则后使用。' }
    elseif($detail -match 'runtime coverage|not prepared'){ $result.Message='首次配置尚未完成，已停止启动。请先完成引擎和防火墙配置。' }
    elseif($detail -match 'Desktop.*proxy|Desktop.*network'){ $result.FailureKind='DesktopProxyUnverified';$result.Message='未能确认 Claude 使用专用连接，已停止本次启动。请重新检查后重试。' }
    elseif($detail -match 'Neutral egress|egress mismatch'){ $result.FailureKind='UpstreamUnavailable';$result.Message='固定节点出口探测失败。守护正在有限重试；恢复后点击“重新检查”。' }
    elseif($detail -match 'proxy|Proxy|interface|VPS'){ $result.FailureKind='DedicatedProxyUnavailable';$result.Message='专用代理或绑定网卡不可用，已停止启动。请查看说明中的故障记录。' }
    elseif($detail -match '^AdministratorCancelled:'){ $result.FailureKind='AdministratorCancelled';$result.Message='Windows 管理员授权已取消，版本维护未执行。请点击“维护版本”重试。' }
    elseif($detail -match 'MaintenanceInterrupted'){ $result.FailureKind='MaintenanceInterrupted';$result.Message='维护中断，需要同账号管理员恢复。请点击“维护版本”。' }
    elseif($detail -match 'MaintenanceBusy'){ $result.Pending=$true;$result.Message='版本维护正在进行，请等待或重新打开入口接续观察。' }
    else { $result.Message='安全检查未通过，已停止启动。请查看本地验收报告。' }
    if($createdOperation){
        $op=Read-GuardMaintenanceOperation $createdOperation
        if($op -and $op.Status -eq 'Running' -and -not $op.WorkerPid){
            $null=Set-GuardMaintenanceOperation $createdOperation @{Status='Failed';Phase='Failed';FailureKind=$result.FailureKind;Reason=$result.Message}
        }
    }
    $claim=Read-GuardJson (Get-GuardPath 'private\active-ui-action.json')
    if($claim.ActionId -eq $ActionId){Write-GuardJson (Get-GuardPath 'private\last-ui-error.json') @{Time=(Get-Date -Format o);Detail=$detail;FailureKind=$result.FailureKind;ApprovedVersion=$result.ApprovedVersion;InstalledVersion=$result.InstalledVersion}}
}
$active=Read-GuardMaintenanceOperation
$claim=Read-GuardJson (Get-GuardPath 'private\active-ui-action.json')
if($claim.ActionId -eq $ActionId -and (-not $active -or -not $result.OperationId -or $active.ActionId -eq $result.OperationId)){
    if($Action -eq 'Update' -and $result.OperationId){$null=Sync-GuardMaintenanceUiResult $result.OperationId}else{Write-GuardJson (Get-GuardPath 'evidence\last-ui-result.json') $result}
}
if($ResultFile){
    Write-GuardJson ($ResultFile+'.tmp') $result
    [IO.File]::Move(($ResultFile+'.tmp'),$ResultFile,$true)
}else{$result|ConvertTo-Json -Compress}
if(-not $result.Success -and -not $result.Pending){exit 1}
