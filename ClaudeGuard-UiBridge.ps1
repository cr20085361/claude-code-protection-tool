[CmdletBinding()]
param(
    [ValidateSet('Start','Check','Login','Update','Diagnose','NetworkEnvCheck','NetworkEnvScore','NetworkEnvRuntimeWatch','NetworkEnvSetGate','NetworkEnvAutoFix','NetworkEnvEnablePolicy','NetworkEnvRestorePolicy','NetworkEnvLaunchSafeBrowser','NetworkEnvCliEnable','NetworkEnvCliClear','NetworkEnvCliTerminal')][string]$Action='Start',
    [string]$ResultFile,
    [string]$ActionId,
    [string]$TargetUrl='https://ipkk.com/claude-ip-check',
    [ValidateSet('Auto','Dedicated','Shared')][string]$ProxyMode='Auto',
    [switch]$CheckConnectivity,
    [int]$Threshold=-1,
    [ValidateSet('Unchanged','True','False')][string]$GateEnabled='Unchanged',
    [ValidateSet('','AutoHealAndWarn','StrictTerminate','WarnOnly','Disabled')][string]$RuntimeEnforcementMode='',
    [switch]$BypassRiskGate
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
if($ResultFile){
    $ResultFile=[IO.Path]::GetFullPath($ResultFile)
    if([IO.Path]::GetDirectoryName($ResultFile) -ne (Get-GuardPath 'private') -or [IO.Path]::GetFileName($ResultFile) -notmatch '^ui-result-[0-9a-f]{32}\.json$'){throw 'Invalid private UI result path.'}
}
if(-not $ActionId){$ActionId=[guid]::NewGuid().ToString('N')}
$isNetworkEnvAction=$Action -like 'NetworkEnv*'
if($Action -ne 'Diagnose' -and -not $isNetworkEnvAction){Register-GuardUiAction $ActionId $Action}
$deadline=[datetime]::UtcNow.AddSeconds(150)
$result=[ordered]@{Success=$false;Pending=$false;OperationId=$null;Phase=$null;Message='';Started=$false;SessionVerified=$false;DesktopPid=$null;RuntimeVerified=$false;FailureKind=$null;ApprovedVersion=$null;InstalledVersion=$null;SupervisorStatus=$null;SupervisorVerified=$false;SupervisorTime=$null;SupervisorRunId=$null;ApiTransport=$null;ActionId=$ActionId;NetworkEnv=$null;RiskScore=$null}
function Assert-GuardUiRetryWindow($Snapshot,[datetimeoffset]$Now=[datetimeoffset]::UtcNow) {
    # 仅使用已核验身份和时效的快照；不能把旧记录或未知进程当成节点故障。
    if($Snapshot.Ready -or $Snapshot.Kind -notin @('UpstreamUnavailable','Checking')){return}
    $h=$Snapshot.Health
    if(-not $h -or [int]$h.ConsecutiveFailures -lt 1){return}
    $next=[datetimeoffset]::MinValue
    if([datetimeoffset]::TryParse([string]$h.NextProbe,[ref]$next) -and $next -gt $Now.AddSeconds(3)){
        throw ('UpstreamUnavailable: 固定节点连接检查失败；后台将在 '+$next.ToLocalTime().ToString('HH:mm:ss')+' 自动重试。请检查专用节点服务和网络。')
    }
}
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
if($isNetworkEnvAction){
    Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-NetworkEnv.psm1') -Force
    try{
        switch($Action){
            'NetworkEnvCheck'{
                $risk=Get-NetworkEnvRiskScore -CheckConnectivity:$CheckConnectivity -ProxyMode $ProxyMode
                $result.RiskScore=$risk
                $result.NetworkEnv=$risk.Baseline
                $result.Message=$risk.Summary+"`r`n`r`n"+$risk.Baseline.SummaryText
                $result.Success=$true
            }
            'NetworkEnvScore'{
                $risk=Get-NetworkEnvRiskScore -CheckConnectivity:$CheckConnectivity -ProxyMode $ProxyMode
                $result.RiskScore=$risk
                $result.Message=$risk.Summary
                $result.Success=$true
            }
            'NetworkEnvRuntimeWatch'{
                $risk=Invoke-NetworkEnvRuntimeWatch -CheckConnectivity:$CheckConnectivity -ProxyMode $ProxyMode
                $result.RiskScore=$risk
                $result.NetworkEnv=$risk.Baseline
                $result.Message=if($risk.RuntimeAlertMessage){$risk.RuntimeAlertMessage}else{$risk.Summary}
                $result.Success=$true
            }
            'NetworkEnvSetGate'{
                $gateVal=switch($GateEnabled){'True'{$true}'False'{$false}default{$null}}
                $threshVal=if($Threshold -ge 0){$Threshold}else{$null}
                $null=Set-NetworkEnvRiskConfig -GateEnabled $gateVal -MaxRiskScore $threshVal -ProxyMode $ProxyMode -RuntimeEnforcementMode $RuntimeEnforcementMode
                $risk=Get-NetworkEnvRiskScore -CheckConnectivity:$CheckConnectivity -ProxyMode $ProxyMode
                $result.RiskScore=$risk
                $result.Message="已更新网络风险门禁与动态巡检策略。`r`n`r`n"+$risk.Summary
                $result.Success=$true
            }
            'NetworkEnvAutoFix'{
                try{
                    $sel=Get-NetworkEnvProxySelection -ProxyMode $ProxyMode
                    $cli=Get-NetworkEnvCliProxyStatus
                    if(-not $cli.UserEnv.HTTPS_PROXY){$null=Set-NetworkEnvCliProxy -Port $sel.Port -Scope User}
                }catch{}
                if(Test-NetworkEnvPolicyRegistryWritable -Browsers @('Chrome','Edge')){
                    $null=Enable-NetworkEnvBrowserPolicy -Browsers @('Chrome','Edge')
                }else{
                    $null=Invoke-NetworkEnvElevatedBrowserPolicy -Mode Enable -Browser All -ShellPath (Get-GuardApprovedShellPath)
                }
                $risk=Get-NetworkEnvRiskScore -CheckConnectivity:$CheckConnectivity -ProxyMode $ProxyMode
                try{$null=Save-NetworkEnvRuntimeBaseline -RiskReport $risk}catch{}
                $result.RiskScore=$risk
                $result.NetworkEnv=$risk.Baseline
                $result.Message="已完成一键防泄露与代理修复（已自动备份原配置）。请重启已打开的浏览器生效。`r`n`r`n"+$risk.Summary+"`r`n`r`n"+$risk.Baseline.SummaryText
                $result.Success=$true
            }
            'NetworkEnvEnablePolicy'{
                if(Test-NetworkEnvPolicyRegistryWritable -Browsers @('Chrome','Edge')){
                    $null=Enable-NetworkEnvBrowserPolicy -Browsers @('Chrome','Edge')
                }else{
                    $null=Invoke-NetworkEnvElevatedBrowserPolicy -Mode Enable -Browser All -ShellPath (Get-GuardApprovedShellPath)
                }
                $risk=Get-NetworkEnvRiskScore -CheckConnectivity:$CheckConnectivity -ProxyMode $ProxyMode
                $result.RiskScore=$risk
                $result.NetworkEnv=$risk.Baseline
                $result.Message="已写入当前用户级 Chrome/Edge 防 WebRTC 与 DoH 泄露策略（已自动备份）。请重启浏览器使其生效。`r`n`r`n"+$risk.Summary+"`r`n`r`n"+$risk.Baseline.SummaryText
                $result.Success=$true
            }
            'NetworkEnvRestorePolicy'{
                if(Test-NetworkEnvPolicyRegistryWritable -Browsers @('Chrome','Edge')){
                    $null=Restore-NetworkEnvBrowserPolicy -Browsers @('Chrome','Edge')
                }else{
                    $null=Invoke-NetworkEnvElevatedBrowserPolicy -Mode Restore -Browser All -ShellPath (Get-GuardApprovedShellPath)
                }
                $risk=Get-NetworkEnvRiskScore -CheckConnectivity:$CheckConnectivity -ProxyMode $ProxyMode
                $result.RiskScore=$risk
                $result.NetworkEnv=$risk.Baseline
                $result.Message="已还原/清除 Chrome/Edge 防泄露策略。请重启浏览器生效。`r`n`r`n"+$risk.Summary+"`r`n`r`n"+$risk.Baseline.SummaryText
                $result.Success=$true
            }
            'NetworkEnvLaunchSafeBrowser'{
                $launch=Start-NetworkEnvSafeBrowser -Url $TargetUrl -ProxyMode $ProxyMode
                $result.NetworkEnv=$launch
                $result.Message=("已启动安全隔离浏览器 {0} (PID={1})，通道 {2}（UDP转发={3}，防泄露策略={4}）。" -f $launch.Browser,$launch.Pid,$launch.ProxyUrl,$launch.UdpAssociateSupported,$launch.PolicyProtected)
                $result.Success=$true
            }
            'NetworkEnvCliEnable'{
                $sel=Get-NetworkEnvProxySelection -ProxyMode $ProxyMode
                $null=Set-NetworkEnvCliProxy -Port $sel.Port -Scope User
                $risk=Get-NetworkEnvRiskScore -ProxyMode $ProxyMode
                $result.RiskScore=$risk
                $result.NetworkEnv=$risk.Baseline
                $result.Message=("已写入用户级 CLI 代理环境变量 (127.0.0.1:{0})，已备份原值。新开终端即可直接运行 claude / codex。`r`n`r`n" -f $sel.Port)+$risk.Summary+"`r`n`r`n"+$risk.Baseline.SummaryText
                $result.Success=$true
            }
            'NetworkEnvCliClear'{
                $null=Set-NetworkEnvCliProxy -Scope ClearUser
                $risk=Get-NetworkEnvRiskScore -ProxyMode $ProxyMode
                $result.RiskScore=$risk
                $result.NetworkEnv=$risk.Baseline
                $result.Message="已清除/还原用户级 CLI 代理环境变量。新开终端生效。`r`n`r`n"+$risk.Summary+"`r`n`r`n"+$risk.Baseline.SummaryText
                $result.Success=$true
            }
            'NetworkEnvCliTerminal'{
                $sel=Get-NetworkEnvProxySelection -ProxyMode $ProxyMode
                $shellExe=Get-GuardApprovedShellPath
                $map=New-NetworkEnvCliEnvMap -Port $sel.Port
                $psi=[Diagnostics.ProcessStartInfo]::new($shellExe)
                $psi.UseShellExecute=$false
                $psi.WorkingDirectory=$PSScriptRoot
                foreach($kv in $map.GetEnumerator()){$psi.Environment[$kv.Key]=$kv.Value}
                $psi.ArgumentList.Add('-NoExit')
                $psi.ArgumentList.Add('-NoProfile')
                $psi.ArgumentList.Add('-Command')
                $psi.ArgumentList.Add("Write-Host '已注入非 TUN 代理环境 127.0.0.1:$($sel.Port) (适合直接运行 claude / codex)。' -ForegroundColor Green")
                $term=[Diagnostics.Process]::Start($psi)
                $result.NetworkEnv=[pscustomobject]@{Pid=$term.Id;Port=$sel.Port}
                $result.Message=("已打开代理终端窗口 (PID={0}, 127.0.0.1:{1})，可直接输入 claude 或 codex 使用。" -f $term.Id,$sel.Port)
                $result.Success=$true
            }
        }
    }catch{
        $result.Success=$false
        $errMsg=$_.Exception.Message
        if($errMsg -match '^AdministratorCancelled:\s*(.+)$'){
            $result.FailureKind='AdministratorCancelled'
            $result.Message=$Matches[1]
        }else{
            $result.Message='网络优化操作失败：'+$errMsg
        }
    }
    if($ResultFile){Write-GuardJson $ResultFile $result}else{$result|ConvertTo-Json -Depth 12 -Compress}
    if(-not $result.Success){exit 1}
    exit 0
}
if($Action -eq 'Diagnose'){
    try{$result.ApiTransport=Test-GuardApiTransport;$result.Success=$true}catch{$result.Message='官方 API 无账号诊断暂未完成。'}
    if($ResultFile){Write-GuardJson $ResultFile $result}else{$result|ConvertTo-Json -Depth 12 -Compress}
    exit 0
}
try {
    $d=Get-GuardState
    $result.ApprovedVersion=$d.Desktop.Version
    $result.InstalledVersion=(Get-GuardDesktop).Version
    $result.SessionVerified=Test-GuardLocalCodeAcceptance
    $existing=@(Get-GuardDesktopProcesses)
    if($Action -in @('Start','Check','Login')){
        $maintenanceState=Get-GuardMaintenanceSnapshot
        if(-not ($maintenanceState.Active -or $maintenanceState.Interrupted -or ($maintenanceState.Operation -and $maintenanceState.Operation.RecoveryRequired))){
            $currentHealth=Get-GuardSupervisorSnapshot
            if($currentHealth.Kind -eq 'SafetyHold' -or (Test-Path -LiteralPath (Get-GuardPath 'private\safety-hold.json'))){throw ('SafetyHold: '+$currentHealth.Reason)}
            Assert-GuardUiRetryWindow $currentHealth
        }
    }
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
            if($existing.Count -or @(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -in @($d.CodePaths)}).Count){throw 'Exit Claude and local Code before migration.'}
            $createdOperation=$ActionId
            $null=New-GuardMaintenanceOperation $ActionId
            Set-GuardUiMaintenanceBinding $ActionId $ActionId
            $null=Sync-GuardMaintenanceUiResult $ActionId
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
        Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-NetworkEnv.psm1') -Force; $riskGate=Get-NetworkEnvRiskScore -ProxyMode $ProxyMode; $result.RiskScore=$riskGate; if(-not $BypassRiskGate -and -not $riskGate.PassedGate){$null=Assert-NetworkEnvRiskGate -Baseline $riskGate.Baseline -ProxyMode $ProxyMode}; if($existing.Count) {
            Assert-GuardPolicy
            Assert-GuardFirewall
            Start-GuardProxy -DeadlineUtc $deadline
            $null=Get-GuardVerifiedEgress
            $last=Read-GuardJson (Get-GuardPath 'evidence\last-launch.json')
            $matching=@($existing|Where-Object{$_.ProcessId -eq $last.Pid})
            if($matching.Count -ne 1 -or ([datetime]$last.ProcessStart).ToUniversalTime().Ticks -ne (Get-Process -Id $last.Pid).StartTime.ToUniversalTime().Ticks){throw 'Claude is already running outside the protected launcher.'}
            Assert-GuardDesktopNetwork $last.Pid -DeadlineUtc $deadline
            Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-Runtime.psm1')
            Assert-GuardLaunchedRuntime $last.Pid $last.ProcessStart $deadline
            $result.DesktopPid=$last.Pid
            $result.Message='Claude 已通过安全入口启动。请切换到 Claude 窗口继续。'
        } else {
            $result.DesktopPid=Start-GuardDesktop -DeadlineUtc $deadline
            $result.Started=$true
            $result.Message=if($result.SessionVerified){'Claude 已打开。当前版本的本机本地 Code 基础使用验收已完成。'}else{'Claude 已打开。网络防护准备完成；Code 正常会话尚待验证。'}
        }
        $result.RuntimeVerified=$true
        try{$null=Save-NetworkEnvRuntimeBaseline -RiskReport $riskGate}catch{}
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
        Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-Runtime.psm1')
        $null=Resolve-GuardReaderPython
        Assert-GuardPolicy
        Assert-GuardFirewall
        Start-GuardProxy -DeadlineUtc $deadline
        $null=Get-GuardVerifiedEgress
        if($existing.Count){
            $last=Read-GuardJson (Get-GuardPath 'evidence\last-launch.json')
            if(@($existing|Where-Object ProcessId -eq $last.Pid).Count -ne 1 -or (Get-Process -Id $last.Pid).StartTime.ToUniversalTime().Ticks -ne ([datetime]$last.ProcessStart).ToUniversalTime().Ticks){throw 'Claude is already running outside the protected launcher.'}
            Assert-GuardDesktopNetwork $last.Pid -DeadlineUtc $deadline
            Assert-GuardLaunchedRuntime $last.Pid $last.ProcessStart $deadline
            $result.RuntimeVerified=$true;$result.DesktopPid=$last.Pid
        }
        Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-NetworkEnv.psm1') -Force; try{$result.RiskScore=Get-NetworkEnvRiskScore -ProxyMode $ProxyMode}catch{}; $result.Message=if($result.SessionVerified){'固定出口及防护检查通过；当前版本的本机本地 Code 基础使用已验收。'}else{'固定出口、代理、防火墙和新版本执行门槛检查通过。真实 Code 会话验收状态请查看报告。'}
    }
    if($Action -ne 'Update'){
        $snapshot=Get-GuardSupervisorSnapshot
        if($snapshot.Kind -eq 'SafetyHold'){throw ('SafetyHold: '+$snapshot.Reason)}
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
    elseif($detail -match '^RuntimeReaderUnavailable:'){$result.FailureKind='RuntimeReaderUnavailable';$result.Message=$detail.Substring('RuntimeReaderUnavailable: '.Length)}
    elseif($detail -match '^RuntimeVerificationFailed:'){$result.FailureKind='RuntimeVerificationFailed';$result.Message=if($detail -match 'RuntimeReaderUnavailable|RuntimeEnvironmentUnreadable'){'未能核实客户端的运行环境。请检查 64 位 Python 3 是否可用，并用同一 Windows 账号重新打开安全入口。'}else{'客户端的运行防护检查未通过。请退出 Claude，点击“重新检查”查看当前状态。'}}
    elseif($detail -match '^RuntimeLaunchIdentityChanged:|^RuntimeVerificationTimeout:'){$result.FailureKind='RuntimeUnconfirmed';$result.Message='未能确认本次客户端启动。请查看当前防护状态，再点击“打开 Claude”重试。'}
    elseif($detail -match 'SafetyHold|safety hold|Fixed egress mismatch'){$result.FailureKind='SafetyHold';$result.Message='后台守护已暂停专用网络。请按入口显示的暂停原因处理，再点击“维护版本”恢复防护。'}
    elseif($detail -match '^UpstreamUnavailable: '){$result.FailureKind='UpstreamUnavailable';$result.Message=$detail.Substring('UpstreamUnavailable: '.Length)}
    elseif($detail -match 'SupervisorUnavailable'){$result.FailureKind='SupervisorUnavailable';$result.Message='后台守护尚未恢复，不能确认防护准备完成。已打开的会话保留；请等待自动恢复或点击“重新检查”。'}
    elseif($detail -match 'already running|Exit Claude'){ $result.FailureKind='UnprotectedInstance';$result.Message='Claude 已从其他入口运行或尚未退出。请完全退出 Claude 后重试。' }
    elseif($detail -match 'execution gate|Code cache'){ $result.FailureKind='CodeCachePermissions';$result.Message='本地 Code 缓存的执行防护需要维护，已停止启动。请完全退出 Claude 后点击“维护版本”。' }
    elseif($detail -eq 'Pinned desktop proxy policy is missing.'){ $result.Message='当前桌面会话的固定代理策略缺失，已停止启动。请先修复策略，再重新检查。' }
    elseif($detail -match "Cannot find path.*claude-code"){ $result.Message='当前桌面会话的已核准 Code 缓存缺失，已停止启动。请补齐本地引擎后重新检查。' }
    elseif($detail -match 'updated|changed|metadata|binary'){ $result.Message='软件或防护配置发生变化，已停止启动。请重新核验并补齐规则后使用。' }
    elseif($detail -match 'runtime coverage|not prepared'){ $result.Message='首次配置尚未完成，已停止启动。请先完成引擎和防火墙配置。' }
    elseif($detail -match 'Desktop.*proxy|Desktop.*network'){ $result.FailureKind='DesktopProxyUnverified';$result.Message='未能确认 Claude 使用专用连接，已停止本次启动。请重新检查后重试。' }
    elseif($detail -match '^NetworkRiskGateBlocked: '){ $result.FailureKind='NetworkRiskBlocked';$result.Message=$detail.Substring('NetworkRiskGateBlocked: '.Length) }
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
}else{$result|ConvertTo-Json -Depth 12 -Compress}
if(-not $result.Success -and -not $result.Pending){exit 1}
