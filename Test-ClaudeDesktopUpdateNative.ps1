$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-VersionInfo.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-DesktopUpdate.psm1') -Force
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes,System.Drawing
Add-Type @'
using System;using System.Runtime.InteropServices;
public class DesktopUpdateNativeCapture {
 [StructLayout(LayoutKind.Sequential)]public struct Rect{public int Left,Top,Right,Bottom;}
 [DllImport("user32.dll")]public static extern bool GetWindowRect(IntPtr h,out Rect r);
 [DllImport("user32.dll")]public static extern bool PrintWindow(IntPtr h,IntPtr dc,uint f);
 [DllImport("user32.dll")]public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr c);
 [DllImport("user32.dll")]public static extern IntPtr SendMessageTimeout(IntPtr h,uint m,IntPtr w,IntPtr l,uint f,uint t,out IntPtr r);
}
'@
function Get-InstalledWindow {
    $p=@(Get-Process -Name ClaudeProGuard -ErrorAction Stop)
    if($p.Count -ne 1 -or $p[0].Path -ne (Join-Path $PSScriptRoot 'runtime\ClaudeProGuard.exe')){throw 'Unexpected installed launcher.'}
    $p=$p[0];$p.Refresh();[pscustomobject]@{Process=$p;Window=[Windows.Automation.AutomationElement]::FromHandle($p.MainWindowHandle)}
}
function Get-Controls($Window){@($Window.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition))}
function Get-Button($Window,[string]$Name){@(Get-Controls $Window|Where-Object {$_.Current.Name -eq $Name -and $_.Current.ClassName -like 'WindowsForms10.BUTTON*'})}
function Get-Labels($Window){@(Get-Controls $Window|Where-Object {$_.Current.ClassName -like 'WindowsForms10.STATIC*'}|ForEach-Object {$_.Current.Name})}
function Save-Window($Process,[string]$Name){
    $old=[DesktopUpdateNativeCapture]::SetThreadDpiAwarenessContext([IntPtr](-1));$r=New-Object DesktopUpdateNativeCapture+Rect
    try{
        if(-not [DesktopUpdateNativeCapture]::GetWindowRect($Process.MainWindowHandle,[ref]$r)){throw 'Native bounds unavailable.'}
        $b=[Drawing.Bitmap]::new(($r.Right-$r.Left),($r.Bottom-$r.Top));$g=[Drawing.Graphics]::FromImage($b)
        try{$dc=$g.GetHdc();try{if(-not [DesktopUpdateNativeCapture]::PrintWindow($Process.MainWindowHandle,$dc,2)){throw 'Native screenshot failed.'}}finally{$g.ReleaseHdc($dc)};$path=Join-Path $PSScriptRoot ('evidence\'+$Name);$b.Save($path,[Drawing.Imaging.ImageFormat]::Png);return $path}finally{$g.Dispose();$b.Dispose()}
    }finally{$null=[DesktopUpdateNativeCapture]::SetThreadDpiAwarenessContext($old)}
}
$result=[ordered]@{Time=(Get-Date -Format o);Passed=$false;ActualNativeWindow=$true;ButtonsUncovered=$false;ActualOfficialDownload=$false;DownloadCloseReopen=$false;SignatureAndCodeCache=$false;SameVersionInstallDisabled=$false;ProtectedDesktopRetained=$false;NewVersionInstallation='NOT_RUN';Error=$null}
try{
    $desktopBefore=@(Get-GuardDesktopProcesses|ForEach-Object {$p=Get-Process -Id $_.ProcessId;[pscustomobject]@{Id=$p.Id;Path=$p.Path;Started=$p.StartTime.ToUniversalTime().ToString('o')}})
    $ui=Get-InstalledWindow;$deadline=[datetime]::UtcNow.AddSeconds(60)
    do{$download=Get-Button $ui.Window '下载官方包';if($download.Count -eq 1 -and $download[0].Current.IsEnabled){break};Start-Sleep -Milliseconds 250}while([datetime]::UtcNow -lt $deadline)
    if($download.Count -ne 1 -or -not $download[0].Current.IsEnabled){throw 'Official download button unavailable.'}
    $status=@(Get-Controls $ui.Window|Where-Object {$_.Current.ClassName -like 'WindowsForms10.STATIC*' -and $_.Current.BoundingRectangle.Height -ge 140 -and $_.Current.BoundingRectangle.Width -gt 1000})
    if($status.Count -ne 1){throw 'Expected actual top status label.'}
    $buttons=@(Get-Controls $ui.Window|Where-Object {$_.Current.ClassName -like 'WindowsForms10.BUTTON*' -and $_.Current.Name -in @('Claude 已打开','打开 Claude','重新检查','登录链接','查看说明','维护版本')})
    if($buttons.Count -ne 5 -or @($buttons|Where-Object {$status[0].Current.BoundingRectangle.Bottom -ge $_.Current.BoundingRectangle.Top}).Count){throw 'Top button border still covered.'}
    $result.ButtonsUncovered=$true;$result['ActualStatusBottom']=$status[0].Current.BoundingRectangle.Bottom;$result['ActualButtonTop']=$buttons[0].Current.BoundingRectangle.Top
    $clicked=[datetimeoffset]::UtcNow;$answer=[IntPtr]::Zero
    if([DesktopUpdateNativeCapture]::SendMessageTimeout([IntPtr]$download[0].Current.NativeWindowHandle,245,[IntPtr]::Zero,[IntPtr]::Zero,2,2000,[ref]$answer) -eq [IntPtr]::Zero){throw 'Native download click failed.'}
    $deadline=[datetime]::UtcNow.AddSeconds(90);$op=$null
    do{
        $op=Get-ClaudeDesktopUpdateSnapshot $PSScriptRoot
        if($op -and [datetimeoffset]$op.StartedAt -ge $clicked -and $op.Status -eq 'Downloading' -and $op.DownloadedBytes -gt 1048576){break}
        if($op -and [datetimeoffset]$op.StartedAt -ge $clicked -and $op.Status -eq 'Failed'){throw $op.Message}
        Start-Sleep -Milliseconds 500
    }while([datetime]::UtcNow -lt $deadline)
    if(-not $op -or [datetimeoffset]$op.StartedAt -lt $clicked -or $op.Status -ne 'Downloading' -or $op.DownloadedBytes -le 1048576){throw 'Actual download progress not observed.'}
    $id=$op.Id;$result['OperationId']=$id;$result['ProgressScreenshot']=Save-Window $ui.Process 'desktop-update-download-progress.png'
    $null=$ui.Process.CloseMainWindow();if(-not $ui.Process.WaitForExit(10000)){throw 'Launcher did not close.'}
    if(-not (Test-GuardMaintenanceProcess $op.WorkerPid $op.WorkerStarted $op.WorkerPath)){throw 'Download worker did not survive GUI close.'}
    $p=Start-Process -FilePath (Join-Path $PSScriptRoot 'runtime\ClaudeProGuard.exe') -WorkingDirectory $PSScriptRoot -WindowStyle Normal -PassThru
    $deadline=[datetime]::UtcNow.AddSeconds(20)
    do{$p.Refresh();if($p.MainWindowHandle -ne [IntPtr]::Zero){break};Start-Sleep -Milliseconds 200}while([datetime]::UtcNow -lt $deadline)
    if($p.MainWindowHandle -eq [IntPtr]::Zero){throw 'Reopened launcher unavailable.'}
    $ui=Get-InstalledWindow
    if((Read-ClaudeDesktopUpdate $PSScriptRoot).Id -ne $id){throw 'Reopened launcher lost download correlation.'}
    $result.DownloadCloseReopen=$true
    $deadline=[datetime]::UtcNow.AddSeconds(1000)
    do{$op=Get-ClaudeDesktopUpdateSnapshot $PSScriptRoot;if($op.Id -ne $id){throw 'Active download replaced.'};if($op.Status -eq 'Ready'){break};if($op.Status -in @('Failed','Interrupted')){throw $op.Message};Start-Sleep -Seconds 1}while([datetime]::UtcNow -lt $deadline)
    if($op.Status -ne 'Ready'){throw 'Actual official package not ready before observation budget.'}
    $result.ActualOfficialDownload=$true
    $package=Assert-ClaudeDesktopUpdatePackage $PSScriptRoot $op.PackageFile $op.TargetVersion $op.PackageHash
    Assert-ClaudeDesktopUpdateCodeCache $PSScriptRoot $package $op.CodePayloadHash
    $result.SignatureAndCodeCache=$true;$result['DownloadedBytes']=$op.PackageBytes;$result['PackageHash']=$op.PackageHash;$result['DesktopVersion']=$op.TargetVersion;$result['CodeVersion']=$op.CodeVersion
    $deadline=[datetime]::UtcNow.AddSeconds(45)
    do{$labels=Get-Labels $ui.Window;$install=Get-Button $ui.Window '安装并维护';if(@($labels|Where-Object {$_ -like '*当前版本无需升级*'}).Count -and @($labels|Where-Object {$_ -match '后台守护健康|另一站已确认固定出口'}).Count){break};Start-Sleep -Milliseconds 250}while([datetime]::UtcNow -lt $deadline)
    if($install.Count -ne 1 -or $install[0].Current.IsEnabled -or -not @($labels|Where-Object {$_ -like '*当前版本无需升级*'}).Count){throw 'Current-version package incorrectly offers installation.'}
    $result.SameVersionInstallDisabled=$true
    foreach($d in $desktopBefore){if(-not (Test-GuardMaintenanceProcess $d.Id $d.Started $d.Path)){throw 'Existing Desktop changed during download.'}}
    $result.ProtectedDesktopRetained=$true;$result['Labels']=$labels;$result['Screenshot']=Save-Window $ui.Process 'desktop-update-native-final.png';$result.Passed=$true
}catch{$result.Error=$_.Exception.Message}finally{$result|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'evidence\desktop-update-native-acceptance.json') -Encoding utf8}
$result|ConvertTo-Json -Depth 6
if(-not $result.Passed){exit 1}
