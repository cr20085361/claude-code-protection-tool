[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
Assert-GuardCore
$null=Test-GuardEgress
$chrome='C:\Program Files\Google\Chrome\Application\chrome.exe'
if (-not (Test-Path -LiteralPath $chrome)) { throw 'Chrome not found.' }
$profile=Get-GuardPath 'private\browser-neutral-profile'
if (@(Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -eq $chrome -and $_.CommandLine -like ('*'+$profile+'*')}).Count) { throw 'Close dedicated browser before testing.' }
if (@(Get-NetTCPConnection -State Listen -LocalPort 10819 -ErrorAction SilentlyContinue).Count) { throw 'Failure-test proxy port is occupied.' }
$bypass='localhost;127.0.0.1;[::1]'
$result=[ordered]@{Time=(Get-Date -Format o);ChromeHash=(Get-GuardHash $chrome);NormalProxy=$false;StoppedProxyFails=$false;LoopbackCallbackWorks=$false;BypassList=$bypass;Passed=$false;Scope='headless-neutral-distinct-profile-fixed-proxy-flags; interactive-login-unverified';CredentialsUsed=$false}
Write-GuardJson (Get-GuardPath 'evidence\browser-failure-test.json') $result
function Read-BrowserProbeOutput([string]$Path) {
    for($attempt=0;$attempt -lt 30;$attempt++) {
        try{return [IO.File]::ReadAllText($Path)}catch [IO.IOException]{Start-Sleep -Milliseconds 100}
    }
    throw 'Neutral browser output was not released after exit.'
}
foreach ($mode in @('normal','dead')) {
    $port=if($mode -eq 'normal'){10818}else{10819}
    $stdout=Get-GuardPath ('private\browser-'+$mode+'.html')
    $stderr=Get-GuardPath ('private\browser-'+$mode+'.stderr.log')
    $args=@('--headless=new','--disable-gpu','--dump-dom','--timeout=12000',('--user-data-dir="'+$profile+'"'),("--proxy-server=http://127.0.0.1:$port"),('--proxy-bypass-list='+$bypass),'--disable-quic','--disable-background-networking','--no-first-run','--no-default-browser-check','https://api.ipify.org?format=json')
    $p=Start-Process -FilePath $chrome -ArgumentList $args -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if (-not $p.WaitForExit(30000)) { Stop-Process -Id $p.Id; throw 'Browser neutral test timed out.' }
    $body=$null
    for($attempt=0;$attempt -lt 30;$attempt++) {
        try { $body=[IO.File]::ReadAllText($stdout); break } catch [IO.IOException] { Start-Sleep -Milliseconds 100 }
    }
    if ($null -eq $body) { throw 'Browser output was not released after process exit.' }
    $errorText=Get-Content -LiteralPath $stderr -Raw
    if ($mode -eq 'normal') { $result.NormalProxy=($body -match '154\.44\.22\.208') } else { $result.StoppedProxyFails=(($body -match 'ERR_PROXY_CONNECTION_FAILED' -or $errorText -match 'Page load failed: net::ERR_PROXY_CONNECTION_FAILED') -and $body -notmatch '154\.44\.22\.208') }
}
$listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
$listener.Start()
$localPort=$listener.LocalEndpoint.Port
$accept=$listener.AcceptTcpClientAsync()
$callbackOut=Get-GuardPath 'private\browser-loopback.html'
$callbackErr=Get-GuardPath 'private\browser-loopback.stderr.log'
$browser=$null
try {
    $args=@('--headless=new','--disable-gpu','--dump-dom','--timeout=12000',('--user-data-dir="'+$profile+'"'),'--proxy-server=http://127.0.0.1:10819',('--proxy-bypass-list='+$bypass),'--disable-quic','--disable-background-networking','--no-first-run','--no-default-browser-check',("http://127.0.0.1:$localPort/callback-probe"))
    $browser=Start-Process -FilePath $chrome -ArgumentList $args -WindowStyle Hidden -PassThru -RedirectStandardOutput $callbackOut -RedirectStandardError $callbackErr
    if(-not $accept.Wait(10000)){throw 'Neutral local callback request was not received.'}
    $client=$accept.Result
    try {
        $stream=$client.GetStream();$stream.ReadTimeout=3000
        $buffer=[byte[]]::new(4096);$request=''
        do{$count=$stream.Read($buffer,0,$buffer.Length);if($count -eq 0){break};$request+=[Text.Encoding]::ASCII.GetString($buffer,0,$count)}while(-not $request.Contains("`r`n`r`n") -and $request.Length -lt 8192)
        $body='<html><body>LOCAL_AUTH_CALLBACK_PROBE_OK</body></html>'
        $response="HTTP/1.1 200 OK`r`nContent-Type: text/html`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body"
        $bytes=[Text.Encoding]::ASCII.GetBytes($response);$stream.Write($bytes,0,$bytes.Length);$stream.Flush()
    }finally{$client.Dispose()}
    if(-not $browser.WaitForExit(20000)){throw 'Neutral local callback browser did not finish.'}
    $result.LoopbackCallbackWorks=((Read-BrowserProbeOutput $callbackOut) -match 'LOCAL_AUTH_CALLBACK_PROBE_OK')
} finally {
    $listener.Stop()
    if($browser -and -not $browser.HasExited){Stop-Process -Id $browser.Id}
}
$result.Passed=($result.NormalProxy -and $result.StoppedProxyFails -and $result.LoopbackCallbackWorks)
Write-GuardJson (Get-GuardPath 'evidence\browser-failure-test.json') $result
$result | ConvertTo-Json
if (-not $result.Passed) { throw 'Dedicated browser proxy test failed.' }
