[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
Assert-GuardFirewall -DesktopOnly
Assert-GuardRule (Get-GuardPath 'runtime\network-probe.exe')
$normal=Test-GuardEgress
$result=[ordered]@{Time=(Get-Date -Format o);ExactDesktopRule=$true;ProbeRule=$true;LoopbackProxyWorks=$true;Egress=$normal;DirectIPv4Blocked=$false;IPv6Coverage='rule-only-not-live-tested';DirectBaselineExitCode=$null;DirectBlockedExitCode=$null;Target=$null;PublicDirectBaselineExitCode=$null}
# Same neutral literal-IP HTTPS target, original Windows curl versus dedicated curl copy.
$url='https://1.1.1.1/cdn-cgi/trace'
$null=& "$env:SystemRoot\System32\curl.exe" --silent --show-error --fail --proxy '' --noproxy '*' --connect-timeout 5 --max-time 10 $url 2>$null
$result.DirectBaselineExitCode=$LASTEXITCODE
$result.PublicDirectBaselineExitCode=$LASTEXITCODE
if ($result.DirectBaselineExitCode -ne 0) {
    # A blocked public baseline cannot establish causality. Use the reachable LAN gateway,
    # still a non-loopback IPv4 destination covered by exactly the same rule.
    $routes=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric)
    if ($routes.Count) {
        $url='http://'+$routes[0].NextHop+'/'
        $null=& "$env:SystemRoot\System32\curl.exe" --silent --show-error --proxy '' --noproxy '*' --connect-timeout 3 --max-time 5 -o NUL $url 2>$null
        $result.DirectBaselineExitCode=$LASTEXITCODE
    }
}
$result.Target=$url
$blocked=Invoke-GuardProbe $url ''
$result.DirectBlockedExitCode=$blocked.ExitCode
if ($result.DirectBaselineExitCode -eq 0 -and $blocked.ExitCode -ne 0) { $result.DirectIPv4Blocked=$true }
Write-GuardJson (Get-GuardPath 'evidence\firewall-tests.json') $result
$result | ConvertTo-Json -Depth 5
if (-not $result.DirectIPv4Blocked) { throw 'Direct IPv4 firewall proof is inconclusive; do not mark accepted.' }
