[CmdletBinding()]
param([Parameter(Mandatory)][string]$Url)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$uri=[uri]$Url
if ($uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Host -notin @('claude.ai','claude.com','platform.claude.com','console.anthropic.com','accounts.anthropic.com')) { throw 'Only an official HTTPS login URL is accepted.' }
Assert-GuardPolicy
Assert-GuardFirewall
Assert-GuardCore
$null=Test-GuardEgress
$proof=Read-GuardJson (Get-GuardPath 'evidence\browser-failure-test.json')
if (-not $proof.Passed -or $proof.BypassList -ne 'localhost;127.0.0.1;[::1]' -or -not $proof.LoopbackCallbackWorks) { throw 'Dedicated browser has not passed its current proxy and local callback tests.' }
$chrome='C:\Program Files\Google\Chrome\Application\chrome.exe'
if ((Get-GuardHash $chrome) -ne $proof.ChromeHash) { throw 'Browser changed; repeat failure test before login.' }
$arguments=@(('--user-data-dir="'+(Get-GuardPath 'browser-profile')+'"'),'--proxy-server=http://127.0.0.1:10818','--proxy-bypass-list=localhost;127.0.0.1;[::1]','--disable-quic','--no-first-run','--no-default-browser-check',('"'+$uri.AbsoluteUri+'"'))
$null=Start-Process -FilePath $chrome -ArgumentList $arguments -WindowStyle Normal -PassThru -RedirectStandardOutput (Get-GuardPath 'private\login-browser.stdout.log') -RedirectStandardError (Get-GuardPath 'private\login-browser.stderr.log')
