$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes,System.Drawing
Add-Type @'
using System;using System.Runtime.InteropServices;
public static class VersionNativeCapture {
 [StructLayout(LayoutKind.Sequential)]public struct Rect{public int Left,Top,Right,Bottom;}
 [DllImport("user32.dll")]public static extern bool GetWindowRect(IntPtr h,out Rect r);
 [DllImport("user32.dll")]public static extern bool PrintWindow(IntPtr h,IntPtr dc,uint flags);
 [DllImport("user32.dll")]public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr ctx);
 [DllImport("user32.dll")]public static extern IntPtr SendMessageTimeout(IntPtr h,uint m,IntPtr w,IntPtr l,uint f,uint t,out IntPtr result);
}
'@
$result=[ordered]@{Time=(Get-Date -Format o);Passed=$false;ActualNativeWindow=$true;InstalledVersionsVisible=$false;RuntimeStateVisible=$false;ManualOfficialQuery=$false;HealthUnaffected=$false;Labels=@();Error=$null}
function Read-Labels($Window){@($Window.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)|Where-Object {$_.Current.ClassName -like 'WindowsForms10.STATIC*'}|ForEach-Object {$_.Current.Name})}
try{
    $p=@(Get-Process -Name ClaudeProGuard -ErrorAction Stop)
    if($p.Count -ne 1 -or $p[0].Path -ne (Join-Path $PSScriptRoot 'runtime\ClaudeProGuard.exe')){throw 'Expected installed launcher.'}
    $p=$p[0];$p.Refresh();$w=[Windows.Automation.AutomationElement]::FromHandle($p.MainWindowHandle)
    $deadline=[datetime]::UtcNow.AddSeconds(45)
    do{$labels=Read-Labels $w;if(@($labels|Where-Object {$_ -match '^Desktop .*配套 Code.*已核准 Code'}).Count){break};Start-Sleep -Milliseconds 250}while([datetime]::UtcNow -lt $deadline)
    if(-not @($labels|Where-Object {$_ -match '^Desktop .*配套 Code.*已核准 Code'}).Count){throw 'Installed version labels missing.'}
    $result.InstalledVersionsVisible=$true
    if(-not @($labels|Where-Object {$_ -match '^本地 Code：未运行|^本地 Code 运行中：'}).Count){throw 'Runtime state label missing.'}
    $result.RuntimeStateVisible=$true
    $deadline=[datetime]::UtcNow.AddSeconds(45);$button=$null
    do{$button=@($w.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)|Where-Object {$_.Current.Name -eq '检查新版' -and $_.Current.ClassName -like 'WindowsForms10.BUTTON*'});if($button.Count -eq 1 -and $button[0].Current.IsEnabled){break};Start-Sleep -Milliseconds 250}while([datetime]::UtcNow -lt $deadline)
    if($button.Count -ne 1 -or -not $button[0].Current.IsEnabled){throw 'Manual version button unavailable.'}
    $clicked=[datetimeoffset]::UtcNow;$answer=[IntPtr]::Zero
    if([VersionNativeCapture]::SendMessageTimeout([IntPtr]$button[0].Current.NativeWindowHandle,245,[IntPtr]::Zero,[IntPtr]::Zero,2,2000,[ref]$answer) -eq [IntPtr]::Zero){throw 'Native check click failed.'}
    $deadline=[datetime]::UtcNow.AddSeconds(45)
    do{
        $cache=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'private\version-update-status.json') -Raw|ConvertFrom-Json
        if([datetimeoffset]$cache.CheckedAt -ge $clicked){break}
        Start-Sleep -Milliseconds 250
    }while([datetime]::UtcNow -lt $deadline)
    if([datetimeoffset]$cache.CheckedAt -lt $clicked -or $cache.Status -ne 'Checked'){throw 'Actual official query did not succeed.'}
    $result.ManualOfficialQuery=$true;$result['LatestDesktopVersion']=$cache.LastSuccess.LatestDesktopVersion
    Start-Sleep -Seconds 2
    $labels=Read-Labels $w
    if(-not @($labels|Where-Object {$_ -match '^官方检查 |^上次检查 '}).Count){throw 'Actual query feedback missing.'}
    if(-not @($labels|Where-Object {$_ -match '后台守护健康|另一站已确认固定出口'}).Count){throw 'Current health footer unavailable.'}
    $result.HealthUnaffected=$true;$result.Labels=$labels
    $previous=[VersionNativeCapture]::SetThreadDpiAwarenessContext([IntPtr](-1));$rect=New-Object VersionNativeCapture+Rect
    if(-not [VersionNativeCapture]::GetWindowRect($p.MainWindowHandle,[ref]$rect)){throw 'Window bounds unavailable.'}
    $bitmap=[Drawing.Bitmap]::new(($rect.Right-$rect.Left),($rect.Bottom-$rect.Top));$g=[Drawing.Graphics]::FromImage($bitmap)
    try{$dc=$g.GetHdc();try{if(-not [VersionNativeCapture]::PrintWindow($p.MainWindowHandle,$dc,2)){throw 'Native screenshot failed.'}}finally{$g.ReleaseHdc($dc)};$image=Join-Path $PSScriptRoot 'evidence\version-info-native-final.png';$bitmap.Save($image,[Drawing.Imaging.ImageFormat]::Png);$result['Screenshot']=$image}finally{$g.Dispose();$bitmap.Dispose();$null=[VersionNativeCapture]::SetThreadDpiAwarenessContext($previous)}
    $result.Passed=$true
}catch{$result.Error=$_.Exception.Message}finally{
    $result|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'evidence\version-info-native-acceptance.json') -Encoding utf8
}
$result|ConvertTo-Json -Depth 6
if(-not $result.Passed){exit 1}
