# 使用真实安全入口的原生 UI Automation 控件，不能以预览图替代本测试。
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes,System.Drawing
Add-Type @'
using System;using System.Runtime.InteropServices;
public static class GuardWindowCapture {
 [StructLayout(LayoutKind.Sequential)] public struct Rect {public int Left,Top,Right,Bottom;}
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out Rect r);
 [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h,IntPtr dc,uint flags);
 [DllImport("user32.dll")] public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
 [DllImport("user32.dll",SetLastError=true)] public static extern IntPtr SendMessageTimeout(IntPtr h,uint message,IntPtr w,IntPtr l,uint flags,uint timeout,out IntPtr result);
}
'@
$root=$PSScriptRoot;$exe=Join-Path $root 'runtime\ClaudeProGuard.exe'
$result=@{Time=(Get-Date -Format o);ActualNativeUI=$true;StartPassed=$false;CheckPassed=$false;CloseReopenPassed=$false;Screenshot=$null;Labels=@();Error=$null}
function Read-SharedUiResult([string]$path){
    $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    $reader=New-Object IO.StreamReader($stream,[Text.Encoding]::UTF8)
    try{$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose()}
}
function Wait-Result([datetime]$after){
    $watch=[Diagnostics.Stopwatch]::StartNew()
    do{
        Start-Sleep -Milliseconds 500
        $file=Join-Path $root 'evidence\last-ui-result.json'
        try{
            if((Get-Item -LiteralPath $file -ErrorAction Stop).LastWriteTime -ge $after){
                $r=Read-SharedUiResult $file
                if(-not $r.Success -or -not $r.SupervisorVerified){throw ('Actual UI action failed: '+$r.Message)}
                return $r
            }
        }catch{
            # ReplaceFile 的短暂缺失与共享冲突不能冒充真实入口失败；仍由总体时限约束。
            $exception=$_.Exception;while($exception.InnerException){$exception=$exception.InnerException}
            $native=$exception.HResult -band 65535
            if($_.FullyQualifiedErrorId -notlike '*PathNotFound*' -and $native -notin @(2,3,32,33)){throw}
        }
        if($watch.Elapsed.TotalSeconds -gt 190){throw 'Actual UI action timed out.'}
    }while($true)
}
function Get-Window($process){
    $watch=[Diagnostics.Stopwatch]::StartNew()
    do{$process.Refresh();if($process.MainWindowHandle -ne [IntPtr]::Zero){return [Windows.Automation.AutomationElement]::FromHandle($process.MainWindowHandle)};Start-Sleep -Milliseconds 200;if($watch.Elapsed.TotalSeconds -gt 20){throw 'Actual launcher window not found.'}}while($true)
}
try {
    if(@(Get-Process -Name ClaudeProGuard -ErrorAction SilentlyContinue).Count){throw 'Close the existing safety launcher before native test.'}
    $started=Get-Date;$p=Start-Process -FilePath $exe -WorkingDirectory $root -WindowStyle Normal -PassThru
    $window=Get-Window $p;$r=Wait-Result $started;$result.StartPassed=$true
    $buttons=$window.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)
    $button=@($buttons|Where-Object {$_.Current.Name -eq '重新检查' -and $_.Current.ClassName -like 'WindowsForms10.BUTTON*'})
    if($button.Count -ne 1){throw 'Actual Recheck button was not found.'}
    $started=Get-Date;$clickResult=[IntPtr]::Zero
    if([GuardWindowCapture]::SendMessageTimeout([IntPtr]$button[0].Current.NativeWindowHandle,245,[IntPtr]::Zero,[IntPtr]::Zero,2,2000,[ref]$clickResult) -eq [IntPtr]::Zero){throw 'Actual native Recheck click timed out.'}
    $result['RecheckClickMethod']='Verified native BUTTON BM_CLICK'
    $r=Wait-Result $started;$result.CheckPassed=$true
    $null=$p.CloseMainWindow();if(-not $p.WaitForExit(10000)){throw 'Launcher did not close.'}
    $started=Get-Date;$p=Start-Process -FilePath $exe -WorkingDirectory $root -WindowStyle Normal -PassThru
    $window=Get-Window $p;$r=Wait-Result $started;$result.CloseReopenPassed=$true
    Start-Sleep -Seconds 3
    $texts=$window.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)
    $result.Labels=@($texts|Where-Object {$_.Current.ClassName -like 'WindowsForms10.STATIC*'}|ForEach-Object {$_.Current.Name})
    if(-not (@($result.Labels|Where-Object {$_ -match '后台守护健康|另一站已确认固定出口'}).Count)){throw 'Actual healthy footer not shown.'}
    if(@($result.Labels|Where-Object {$_ -match '已过期|正在恢复|尚未确认'}).Count){throw 'Actual UI retained a stale guardian warning.'}
    $previousDpi=[GuardWindowCapture]::SetThreadDpiAwarenessContext([IntPtr](-1))
    $p.Refresh();$rect=New-Object GuardWindowCapture+Rect
    if(-not [GuardWindowCapture]::GetWindowRect($p.MainWindowHandle,[ref]$rect)){throw 'Window bounds unavailable.'}
    $bitmap=New-Object Drawing.Bitmap(($rect.Right-$rect.Left),($rect.Bottom-$rect.Top));$graphics=[Drawing.Graphics]::FromImage($bitmap)
    try{$dc=$graphics.GetHdc();try{if(-not [GuardWindowCapture]::PrintWindow($p.MainWindowHandle,$dc,2)){throw 'Actual window capture failed.'}}finally{$graphics.ReleaseHdc($dc)};$result.Screenshot=Join-Path $root 'evidence\supervisor-fixed-native-ui.png';$bitmap.Save($result.Screenshot,[Drawing.Imaging.ImageFormat]::Png)}finally{$graphics.Dispose();$bitmap.Dispose();$null=[GuardWindowCapture]::SetThreadDpiAwarenessContext($previousDpi)}
}catch{$result.Error=$_.Exception.Message}finally{$result|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'evidence\supervisor-native-ui.json') -Encoding utf8}
$result|ConvertTo-Json -Depth 5
if($result.Error){exit 1}
