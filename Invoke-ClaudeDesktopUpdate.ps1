[CmdletBinding()]
param([ValidateSet('Download','Install','InstallWorker','Observe')][string]$Action='Observe',[string]$OperationId,[string]$RequestHash,[string]$CommandId)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-VersionInfo.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-DesktopUpdate.psm1') -Force
if($Action -eq 'Observe'){Get-ClaudeDesktopUpdateSnapshot $PSScriptRoot|ConvertTo-Json -Depth 10 -Compress;exit 0}
if($OperationId -notmatch '^[a-f0-9]{32}$'){throw '更新操作身份无效。'}
if($CommandId -and $CommandId -notmatch '^[a-f0-9]{32}$'){throw '更新命令身份无效。'}
function Write-CommandFailure([string]$Message){if($CommandId){Write-GuardJson (Join-Path $PSScriptRoot ('private\desktop-command-'+$CommandId+'.json')) @{CommandId=$CommandId;OperationId=$OperationId;Message=$Message;Time=(Get-Date -Format o)}}}
if($Action -eq 'Download'){try{Start-ClaudeDesktopUpdateDownload $PSScriptRoot $OperationId;exit 0}catch{Write-CommandFailure $_.Exception.Message;exit 1}}
if($Action -eq 'InstallWorker'){
    if($RequestHash -notmatch '^[A-Fa-f0-9]{64}$'){throw '更新请求哈希无效。'}
    Invoke-ClaudeDesktopUpdateInstallation $PSScriptRoot $OperationId $RequestHash
    exit 0
}
$request=$null
try{
    $request=New-ClaudeDesktopUpdateRequest $PSScriptRoot $OperationId
    $id=$request.Request.Id
    $args='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+(Join-Path $PSScriptRoot 'Invoke-ClaudeDesktopUpdate.ps1')+'" -Action InstallWorker -OperationId '+$id+' -RequestHash '+$request.Hash
    $p=Start-GuardMaintenanceAdministrator (Get-GuardApprovedShellPath) $args
    try{
        # 独立协调器等待最终结果；关闭 GUI 不终止 Windows 安装及维护。
        $p.WaitForExit()
        $op=Read-GuardMaintenanceOperation $id
        if($op.Status -eq 'Running'){
            $null=Set-GuardMaintenanceOperation $id @{Status='Interrupted';Phase='Interrupted';RecoveryRequired=$true;FailureKind='MaintenanceInterrupted';Reason='安装进程已退出，缺少最终结果，需要同账号管理员恢复。'}
        }
        $null=Get-ClaudeDesktopUpdateSnapshot $PSScriptRoot
    }finally{$p.Dispose()}
}catch{
    Write-CommandFailure $_.Exception.Message
    if($request){
        $id=$request.Request.Id;$op=Read-GuardMaintenanceOperation $id
        if($op.Status -eq 'Running' -and -not $op.WorkerPid){
            $cancel=Test-GuardMaintenanceAuthorizationCancelled $_.Exception
            $message=if($cancel){'Windows 管理员授权已取消，安装未执行。'}else{'更新安装未能启动，请重新核对。'}
            $null=Set-GuardMaintenanceOperation $id @{Status='Failed';Phase='Failed';FailureKind=$(if($cancel){'AdministratorCancelled'}else{'InstallerStartFailed'});Reason=$message}
            $null=Set-ClaudeDesktopUpdate $PSScriptRoot $OperationId @{Status='Ready';Phase='Ready';MaintenanceId=$null;FailureKind=$(if($cancel){'AdministratorCancelled'}else{'InstallerStartFailed'});Message=$message}
        }
    }else{
        $op=Read-ClaudeDesktopUpdate $PSScriptRoot $OperationId
        if($op -and $op.Status -eq 'Ready'){$null=Set-ClaudeDesktopUpdate $PSScriptRoot $OperationId @{Message=$_.Exception.Message;FailureKind='InstallPrecondition'}}
    }
    exit 1
}
