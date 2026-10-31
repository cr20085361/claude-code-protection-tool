[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
$root=$PSScriptRoot
$result=[ordered]@{Time=(Get-Date -Format o);ActualNativeUI=$true;RecoveryLabelPassed=$false;AutoHealthyLabelPassed=$false;WorkerJobCleanupPassed=$false;ClaudePreserved=$false;ProxyPreserved=$false;Error=$null}
function Read-UtfJson([string]$Name){[IO.File]::ReadAllText((Join-Path $root $Name),[Text.Encoding]::UTF8)|ConvertFrom-Json}
function Get-Labels($Process){$Process.Refresh();$window=[Windows.Automation.AutomationElement]::FromHandle($Process.MainWindowHandle);$texts=$window.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition);@($texts|Where-Object {$_.Current.ClassName -like 'WindowsForms10.STATIC*'}|ForEach-Object {$_.Current.Name})}
try{
    $launcher=@(Get-Process -Name ClaudeProGuard -ErrorAction Stop|Where-Object {$_.Path -eq (Join-Path $root 'runtime\ClaudeProGuard.exe')})
    if($launcher.Count -ne 1){throw 'Actual safety launcher window is required.'};$launcher=$launcher[0]
    $health=Read-UtfJson 'private\supervisor-health.json';$deployment=Read-UtfJson 'private\deployment.json';$lastLaunch=Read-UtfJson 'evidence\last-launch.json'
    if($health.Status -notin @('Healthy','ProbeDegraded')){throw 'A fresh healthy guardian is required before UI fault injection.'}
    $desktop=Get-Process -Id $lastLaunch.Pid -ErrorAction Stop;$desktopStart=$desktop.StartTime.ToUniversalTime().Ticks
    $proxyRecord=Read-UtfJson 'private\proxy-process.json';$proxy=Get-Process -Id $proxyRecord.Pid -ErrorAction Stop;$proxyStart=$proxy.StartTime.ToUniversalTime().Ticks
    $worker=Get-Process -Id $health.SupervisorPid -ErrorAction Stop;$owner=Get-Process -Id $health.HostPid -ErrorAction Stop;$null=$owner.Handle
    if($owner.Path -ne $deployment.Reliability.HostPath -or $owner.StartTime.ToUniversalTime().Ticks -ne ([datetimeoffset]::Parse($health.HostStarted)).UtcDateTime.Ticks -or $worker.Path -ne $deployment.Reliability.ShellPath -or $worker.StartTime.ToUniversalTime().Ticks -ne ([datetimeoffset]::Parse($health.SupervisorStarted)).UtcDateTime.Ticks){throw 'Guardian startup identity changed.'}
    $started=Get-Date;$owner.Kill();if(-not $owner.WaitForExit(10000) -or -not $worker.WaitForExit(15000)){throw 'Host Job did not stop its worker.'};$result.WorkerJobCleanupPassed=$true
    $end=(Get-Date).AddSeconds(15)
    do{$labels=Get-Labels $launcher;if(@($labels|Where-Object {$_ -match '后台守护正在恢复|后台守护尚未恢复'}).Count){$result.RecoveryLabelPassed=$true;$result['RecoveryLabels']=$labels;break};if((Get-Date) -ge $end){throw 'Actual UI did not show guardian recovery.'};Start-Sleep -Milliseconds 400}while($true)
    $end=(Get-Date).AddSeconds(180)
    do{
        $labels=Get-Labels $launcher
        if(@($labels|Where-Object {$_ -match '后台守护健康|另一站已确认固定出口'}).Count -and -not @($labels|Where-Object {$_ -match '正在恢复|尚未恢复|已过期'}).Count){$result.AutoHealthyLabelPassed=$true;$result['HealthyLabels']=$labels;break}
        if((Get-Date) -ge $end){throw 'Actual UI did not automatically recover its healthy display.'};Start-Sleep -Seconds 1
    }while($true)
    $desktop.Refresh();$proxy.Refresh()
    if($desktop.HasExited -or $desktop.StartTime.ToUniversalTime().Ticks -ne $desktopStart -or $proxy.HasExited -or $proxy.StartTime.ToUniversalTime().Ticks -ne $proxyStart){throw 'Existing Claude or proxy was interrupted by guardian recovery.'}
    $result.ClaudePreserved=$true;$result.ProxyPreserved=$true;$result['ElapsedSeconds']=[math]::Round(((Get-Date)-$started).TotalSeconds,2)
}catch{$result.Error=$_.Exception.Message}
finally{$result|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $root 'evidence\supervisor-native-recovery-ui.json') -Encoding UTF8}
$result|ConvertTo-Json -Depth 8
if($result.Error){exit 1}
