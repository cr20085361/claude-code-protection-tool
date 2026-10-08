[CmdletBinding()]
param([string]$ProjectRoot=$PSScriptRoot)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $ProjectRoot 'ClaudeGuard.psm1') -Force
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes,System.Drawing
Add-Type @'
using System;using System.Runtime.InteropServices;
public static class MaintenanceNativeWindow {
 [StructLayout(LayoutKind.Sequential)]public struct Rect{public int Left,Top,Right,Bottom;}
 [DllImport("user32.dll",SetLastError=true)]public static extern IntPtr SendMessageTimeout(IntPtr h,uint msg,IntPtr w,IntPtr l,uint flags,uint timeout,out IntPtr result);
 [DllImport("user32.dll")]public static extern bool GetWindowRect(IntPtr h,out Rect r);
 [DllImport("user32.dll")]public static extern bool PrintWindow(IntPtr h,IntPtr dc,uint flags);
 [DllImport("user32.dll")]public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
}
'@
$exe=Join-Path $ProjectRoot 'runtime\ClaudeProGuard.exe'
$result=[ordered]@{StartedAt=(Get-Date -Format o);Passed=$false;ActualInstalledExecutable=$true;MaintenanceCompleted=$false;CloseReopenDuringMaintenance=$false;NoAutoStartDuringMaintenance=$false;CheckPassed=$false;FinalCloseReopenStartPassed=$false;AmberProgressObserved=$false;Phases=@();Labels=@();Error=$null}
$phaseLabels=[Collections.Generic.List[object]]::new()
function Get-Window($Process){
    $end=[datetime]::UtcNow.AddSeconds(20)
    do{$Process.Refresh();if($Process.MainWindowHandle -ne [IntPtr]::Zero){return [Windows.Automation.AutomationElement]::FromHandle($Process.MainWindowHandle)};if([datetime]::UtcNow -ge $end){throw 'Actual launcher window not found.'};Start-Sleep -Milliseconds 200}while($true)
}
function Read-Labels($Window){@($Window.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)|Where-Object {$_.Current.ClassName -like 'WindowsForms10.STATIC*'}|ForEach-Object {$_.Current.Name})}
function Click-Button($Window,[string]$Name){
    $buttons=@($Window.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)|Where-Object {$_.Current.Name -eq $Name -and $_.Current.ClassName -like 'WindowsForms10.BUTTON*'})
    if($buttons.Count -ne 1 -or -not $buttons[0].Current.IsEnabled){throw ('Actual native button unavailable: '+$Name)}
    $answer=[IntPtr]::Zero
    if([MaintenanceNativeWindow]::SendMessageTimeout([IntPtr]$buttons[0].Current.NativeWindowHandle,245,[IntPtr]::Zero,[IntPtr]::Zero,2,2000,[ref]$answer) -eq [IntPtr]::Zero){throw 'Actual native click failed.'}
}
function Wait-UiResult([datetime]$After){
    $end=[datetime]::UtcNow.AddSeconds(190)
    do{
        $file=Join-Path $ProjectRoot 'evidence\last-ui-result.json'
        if((Get-Item -LiteralPath $file).LastWriteTime -gt $After){
            $r=Read-GuardJson $file
            if(-not $r.Success -or -not $r.SupervisorVerified){throw ('Actual UI action failed: '+$r.Message)}
            return $r
        }
        if([datetime]::UtcNow -ge $end){throw 'Actual UI action timed out.'};Start-Sleep -Milliseconds 500
    }while($true)
}
try{
    if(@(Get-Process -Name ClaudeProGuard -ErrorAction SilentlyContinue).Count){throw 'Existing launcher must be closed before native maintenance test.'}
    if(@(Get-GuardDesktopProcesses).Count){throw 'Exit Claude and local Code before native maintenance test.'}
    $previous=Read-GuardMaintenanceOperation
    $p=Start-Process -FilePath $exe -ArgumentList '--maintenance' -WorkingDirectory $ProjectRoot -WindowStyle Normal -PassThru
    $window=Get-Window $p
    Click-Button $window '维护版本'
    $end=[datetime]::UtcNow.AddSeconds(1300);$operation=$null;$reopened=$false
    do{
        Start-Sleep -Seconds 1
        $op=Read-GuardMaintenanceOperation
        if(-not $op -or ($previous -and $op.ActionId -eq $previous.ActionId)){continue}
        $operation=$op
        if($op.Phase -notin @($phaseLabels.Phase)){
            $labels=Read-Labels $window
            $phaseLabels.Add([pscustomobject]@{Time=(Get-Date -Format o);Phase=$op.Phase;Labels=$labels})
        }
        if($op.Phase -in @('Migrating','Restarting','Verifying') -and -not $reopened){
            # 等待一轮实际 UI 轮询，核对暂停属于维护进度。
            Start-Sleep -Seconds 3
            $labels=Read-Labels $window
            if(@($labels|Where-Object {$_ -match '版本维护中|正在恢复并核验'}).Count){$result.AmberProgressObserved=$true}
            $null=$p.CloseMainWindow();if(-not $p.WaitForExit(10000)){throw 'Actual launcher did not close during maintenance.'}
            $p=Start-Process -FilePath $exe -WorkingDirectory $ProjectRoot -WindowStyle Normal -PassThru
            $window=Get-Window $p;$reopened=$true;$result.CloseReopenDuringMaintenance=$true
            Start-Sleep -Seconds 3
            if(@(Get-GuardDesktopProcesses).Count){throw 'Reopened launcher auto-started Claude during maintenance.'}
            $result.NoAutoStartDuringMaintenance=$true
        }
        if($op.Status -eq 'Completed'){break}
        if($op.Status -in @('Failed','Interrupted')){throw ('Actual maintenance failed: '+$op.Reason)}
        if([datetime]::UtcNow -ge $end){throw 'Actual maintenance observation timed out; installer is left running.'}
    }while($true)
    $migration=Read-GuardJson $operation.ResultFile;$ui=Read-GuardJson (Join-Path $ProjectRoot 'evidence\last-ui-result.json')
    if(-not $migration.Success -or -not $ui.Success -or -not $ui.SupervisorVerified -or $ui.OperationId -ne $operation.ActionId){throw 'Final maintenance result and UI evidence are inconsistent.'}
    $result.MaintenanceCompleted=$true;$result['OperationId']=$operation.ActionId;$result['MaintenanceSeconds']=([datetimeoffset]$operation.CompletedAt-[datetimeoffset]$operation.StartedAt).TotalSeconds
    Start-Sleep -Seconds 3
    $result.Labels=Read-Labels $window
    if(-not @($result.Labels|Where-Object {$_ -match '版本维护完成'}).Count){throw 'Actual maintenance completion label missing.'}
    $started=Get-Date;Click-Button $window '重新检查';$null=Wait-UiResult $started;$result.CheckPassed=$true
    $null=$p.CloseMainWindow();if(-not $p.WaitForExit(10000)){throw 'Actual completed launcher did not close.'}
    $started=Get-Date;$p=Start-Process -FilePath $exe -WorkingDirectory $ProjectRoot -WindowStyle Normal -PassThru
    $window=Get-Window $p;$null=Wait-UiResult $started;$result.FinalCloseReopenStartPassed=$true
    Start-Sleep -Seconds 3
    $result['FinalLabels']=Read-Labels $window
    $dpi=[MaintenanceNativeWindow]::SetThreadDpiAwarenessContext([IntPtr](-1));$rect=New-Object MaintenanceNativeWindow+Rect
    if(-not [MaintenanceNativeWindow]::GetWindowRect($p.MainWindowHandle,[ref]$rect)){throw 'Native window bounds unavailable.'}
    $bitmap=[Drawing.Bitmap]::new(($rect.Right-$rect.Left),($rect.Bottom-$rect.Top));$graphics=[Drawing.Graphics]::FromImage($bitmap)
    try{$dc=$graphics.GetHdc();try{if(-not [MaintenanceNativeWindow]::PrintWindow($p.MainWindowHandle,$dc,2)){throw 'Actual window capture failed.'}}finally{$graphics.ReleaseHdc($dc)};$image=Join-Path $ProjectRoot 'evidence\maintenance-native-final.png';$bitmap.Save($image,[Drawing.Imaging.ImageFormat]::Png);$result['Screenshot']=$image}finally{$graphics.Dispose();$bitmap.Dispose();$null=[MaintenanceNativeWindow]::SetThreadDpiAwarenessContext($dpi)}
    $result.Passed=$true
}catch{$result.Error=$_.Exception.Message}finally{
    $result.Phases=@($phaseLabels);$result['CompletedAt']=Get-Date -Format o
    Write-GuardJson (Join-Path $ProjectRoot 'evidence\maintenance-native-acceptance.json') $result
}
$result|ConvertTo-Json -Depth 5
if(-not $result.Passed){exit 1}
