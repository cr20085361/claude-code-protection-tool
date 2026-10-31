[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$d=Get-GuardState
if (@(Get-GuardDesktopProcesses).Count -and $d.PolicyInstalled) { throw 'Exit desktop before fault injection against its configured proxy.' }
$result=[ordered]@{Time=(Get-Date -Format o);Normal=$null;StoppedProxyFails=$false;OccupiedPortRefused=$false;UnreachableVpsFails=$false;Restored=$false}
try {
    Start-GuardProxy
    $result.Normal=Test-GuardEgress
    if($d.PSObject.Properties['Reliability']) {
        Write-GuardJson (Get-GuardPath 'private\maintenance.json') @{Until=(Get-Date).AddMinutes(3).ToString('o');Reason='dedicated-proxy-failure-tests'}
        Start-Sleep -Seconds 7
    }
    Stop-GuardProxy
    Start-Sleep -Milliseconds 300
    $dead=Invoke-GuardProbe 'https://api.ipify.org?format=json'
    if ($dead.ExitCode -eq 0) { throw 'Stopped-proxy request unexpectedly succeeded.' }
    $result.StoppedProxyFails=$true
    $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,10818)
    try {
        $listener.Start()
        try { Start-GuardProxy; throw 'Occupied port was accepted.' } catch {
            if ($_.Exception.Message -eq 'Occupied port was accepted.') { throw }
            $result.OccupiedPortRefused=$true
        }
    } finally { $listener.Stop() }
    # Use a separate port and TEST-NET address; the genuine VPS config and credentials stay unchanged.
    $c=Read-GuardJson (Get-GuardPath 'private\proxy.json')
    $c.inbounds[0].listen_port=10819
    $c.outbounds[0].server='192.0.2.1'
    $c.log.output=Get-GuardPath 'private\fault-proxy.log'
    $path=Get-GuardPath 'private\fault-proxy.json'
    Write-GuardJson $path $c
    $p=Start-Process -FilePath (Get-GuardPath 'runtime\sing-box.exe') -ArgumentList @('run','-c',('"'+$path+'"')) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Get-GuardPath 'private\fault.stdout.log') -RedirectStandardError (Get-GuardPath 'private\fault.stderr.log')
    try {
        Start-Sleep -Milliseconds 500
        if ($p.HasExited) { throw 'Fault proxy failed to start; failure injection was not exercised.' }
        $bad=Invoke-GuardProbe 'https://api.ipify.org?format=json' 'http://127.0.0.1:10819'
        if ($bad.ExitCode -eq 0) { throw 'Unreachable VPS unexpectedly succeeded.' }
        $result.UnreachableVpsFails=$true
    } finally { if (-not $p.HasExited) { Stop-Process -Id $p.Id }; Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue }
} finally {
    if($d.PSObject.Properties['Reliability']){Remove-Item -LiteralPath (Get-GuardPath 'private\maintenance.json') -ErrorAction SilentlyContinue}
    Start-GuardProxy
    $null=Test-GuardEgress
    $result.Restored=$true
    Write-GuardJson (Get-GuardPath 'evidence\proxy-failure-tests.json') $result
}
$result | ConvertTo-Json -Depth 5
