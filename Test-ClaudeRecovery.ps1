[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$d=Get-GuardState
if(-not $d.PSObject.Properties['Reliability']){throw 'Supervisor is not deployed.'}
if(@(Get-GuardDesktopProcesses).Count -or @(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -in @($d.CodePaths)}).Count){throw 'Exit Claude and Code before dedicated proxy recovery testing.'}
if(Test-Path (Get-GuardPath 'private\maintenance.json')){throw 'A maintenance operation is pending.'}
Start-GuardProxy
$before=Read-GuardJson (Get-GuardPath 'private\proxy-process.json')
$watch=[Diagnostics.Stopwatch]::StartNew()
$result=[ordered]@{Time=(Get-Date -Format o);OldPid=$before.Pid;NewPid=$null;RecoveredWithoutLauncher=$false;RecoverySeconds=$null;ExitEventRecorded=$false;Egress=$null;Passed=$false}
try {
    # 核对过精确进程身份后，只结束本方案的专用进程。
    Stop-GuardProxy
    do {
        Start-Sleep -Milliseconds 500
        if(@(Get-GuardListener).Count) {
            Assert-GuardCore
            $after=Read-GuardJson (Get-GuardPath 'private\proxy-process.json')
            if($after.Pid -ne $before.Pid){$result.NewPid=$after.Pid;$result.RecoveredWithoutLauncher=$true;$result.RecoverySeconds=[Math]::Round($watch.Elapsed.TotalSeconds,2);break}
        }
    } while($watch.Elapsed.TotalSeconds -lt 45)
    if(-not $result.RecoveredWithoutLauncher){throw 'Dedicated proxy did not recover within 45 seconds.'}
    $result.Egress=Test-GuardEgress
    $events=@(Get-Content (Get-GuardPath 'private\supervisor-events.jsonl')|ForEach-Object {$_|ConvertFrom-Json})
    $result.ExitEventRecorded=(@($events|Where-Object {$_.Kind -eq 'ProxyExited' -and $_.Data.Pid -eq $before.Pid}).Count -gt 0)
    if(-not $result.ExitEventRecorded){throw 'Proxy exit was not recorded by its supervisor.'}
    $result.Passed=$true
} finally {
    if(-not @(Get-GuardListener).Count){Start-GuardProxy}
    Write-GuardJson (Get-GuardPath 'evidence\supervisor-recovery-test.json') $result
}
$result|ConvertTo-Json -Depth 5
