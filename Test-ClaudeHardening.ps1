[CmdletBinding()]
param([switch]$Native)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$d=Get-GuardState
$cases=[Collections.Generic.List[object]]::new()
function Record([string]$Name,[bool]$Passed) {
    if(-not $Passed){throw ('Hardening regression failed: '+$Name)}
    $cases.Add(@{Case=$Name;Passed=$true})
}
$goodA=@{ExitCode=0;Body="ip=$($d.ExpectedIp)`nloc=US"}
$goodB=@{ExitCode=0;Body=(@{ip=$d.ExpectedIp}|ConvertTo-Json -Compress)}
$failed=@{ExitCode=28;Body=''}
$malformed=@{ExitCode=0;Body='not an IP response'}
$r=Resolve-GuardEgressProbes $goodA $goodB $d.ExpectedIp
Record 'both-neutral-probes-match' ($r.VerifiedProbeCount -eq 2 -and -not $r.ProbeDegraded)
foreach($pair in @(@($goodA,$failed),@($failed,$goodB),@($goodA,$malformed))){
    $r=Resolve-GuardEgressProbes $pair[0] $pair[1] $d.ExpectedIp
    Record ('single-neutral-proof-'+$cases.Count) ($r.VerifiedProbeCount -eq 1 -and $r.ProbeDegraded)
}
foreach($ip in @('192.0.2.99','2606:4700:4700::1111')) {
    $wrong=@{ExitCode=0;Body=(@{ip=$ip}|ConvertTo-Json -Compress)}
    $stopped=$false
    try{$null=Resolve-GuardEgressProbes $goodA $wrong $d.ExpectedIp}catch{$stopped=$_.Exception.Message -match '^Fixed egress mismatch'}
    Record ('wrong-egress-rejected-'+$ip) $stopped
}
$refused=$false
try{$null=Resolve-GuardEgressProbes $failed $malformed $d.ExpectedIp}catch{$refused=$_.Exception.Message -match '^Neutral egress probes failed'}
Record 'no-valid-egress-proof-refused' $refused
$before=Read-GuardJson (Get-GuardPath 'private\proxy.json')
$hardened=New-GuardIPv4Config $before
Record 'fixed-node-and-interface-preserved' (($before.outbounds|ConvertTo-Json -Depth 30 -Compress) -eq ($hardened.outbounds|ConvertTo-Json -Depth 30 -Compress))
Record 'ipv6-rejected-before-domain-resolution' ($hardened.dns.strategy -eq 'ipv4_only' -and $hardened.route.rules[0].ip_version -eq 6 -and $hardened.route.rules[0].action -eq 'reject' -and $hardened.route.rules[1].strategy -eq 'ipv4_only')
$names=@('ANTHROPIC_BASE_URL','HTTPS_PROXY','NODE_TLS_REJECT_UNAUTHORIZED','NODE_EXTRA_CA_CERTS','CLAUDE_ENV_FILE')
$prior=@{}
try {
    foreach($name in $names){$prior[$name]=[Environment]::GetEnvironmentVariable($name,'Process');[Environment]::SetEnvironmentVariable($name,'test-untrusted-value','Process')}
    $child=New-GuardDesktopEnvironment $d
    Record 'child-provider-and-certificate-overrides-cleared' ($null -eq $child.ANTHROPIC_BASE_URL -and $null -eq $child.NODE_EXTRA_CA_CERTS -and $null -eq $child.CLAUDE_ENV_FILE)
    Record 'child-proxy-and-tls-pinned' ($child.HTTPS_PROXY -eq $d.ProxyUrl -and $child.NODE_TLS_REJECT_UNAUTHORIZED -eq '1' -and $child.NO_PROXY -eq 'localhost,127.0.0.1,::1')
    Record 'parent-environment-not-mutated-by-builder' ([Environment]::GetEnvironmentVariable('HTTPS_PROXY','Process') -eq 'test-untrusted-value')
} finally {foreach($name in $names){[Environment]::SetEnvironmentVariable($name,$prior[$name],'Process')}}
$nativeResult=$null
if($Native) {
    if(@(Get-NetTCPConnection -LocalPort 10819 -State Listen -ErrorAction SilentlyContinue).Count){throw 'Native fixture port is already occupied.'}
    $id=[guid]::NewGuid().ToString('N')
    $path=Get-GuardPath ('private\hardening-fixture-'+$id+'.json')
    $log=Get-GuardPath ('private\hardening-fixture-'+$id+'.log')
    $hardened.inbounds[0].listen_port=10819
    $hardened.log.output=$log;$hardened.log.level='debug'
    Write-GuardJson $path $hardened
    $p=$null
    try {
        $null=& (Get-GuardPath 'runtime\sing-box.exe') check -c $path 2>&1
        if($LASTEXITCODE -ne 0){throw 'Native hardening configuration is invalid.'}
        $p=Start-Process -FilePath (Get-GuardPath 'runtime\sing-box.exe') -ArgumentList @('run','-c',('"'+$path+'"')) -WindowStyle Hidden -PassThru -RedirectStandardOutput ($log+'.stdout') -RedirectStandardError ($log+'.stderr')
        for($i=0;$i -lt 30;$i++){if(@(Get-NetTCPConnection -State Listen -LocalPort 10819 -ErrorAction SilentlyContinue).Count){break};Start-Sleep -Milliseconds 100}
        if($p.HasExited){throw 'Native hardening fixture did not start.'}
        $a=Invoke-GuardProbe 'https://www.cloudflare.com/cdn-cgi/trace' 'http://127.0.0.1:10819'
        $b=Invoke-GuardProbe 'https://api.ipify.org?format=json' 'http://127.0.0.1:10819'
        $egress=Resolve-GuardEgressProbes $a $b $d.ExpectedIp
        $ipv6=Invoke-GuardProbe 'https://[2606:4700:4700::1111]/cdn-cgi/trace' 'http://127.0.0.1:10819'
        $ruleMatched=(@(Get-Content $log|Where-Object {$_ -match 'ip_version=6.*reject'}).Count -gt 0)
        $nativeResult=@{ConfigurationAccepted=$true;FixedIPv4Egress=$egress;LiteralIPv6RequestExitCode=$ipv6.ExitCode;IPv6RejectRuleMatched=$ruleMatched;DedicatedProductionConfigUnchanged=((Get-GuardHash (Get-GuardPath 'private\proxy.json')) -eq $d.ProxyConfigHash);ProductionProxyPid=(Read-GuardJson (Get-GuardPath 'private\proxy-process.json')).Pid}
        Record 'native-literal-ipv6-reject-with-route-proof' ($ipv6.ExitCode -ne 0 -and $ruleMatched)
        Record 'native-fixed-ipv4-and-production-preserved' ($egress.VerifiedProbeCount -ge 1 -and $nativeResult.DedicatedProductionConfigUnchanged)
    } finally {
        if($p -and -not $p.HasExited){Stop-Process -Id $p.Id -ErrorAction SilentlyContinue}
        Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
        # 日志留在受限 private 目录，不输出节点或账户信息。
    }
}
$result=@{Time=(Get-Date -Format o);Cases=@($cases);Passed=$true;Native=$nativeResult;Scope='Pure decision cases and optional isolated native proxy; no authenticated account or production fault injection.'}
Write-GuardJson (Get-GuardPath 'evidence\hardening-regression.json') $result
$result|ConvertTo-Json -Depth 7
