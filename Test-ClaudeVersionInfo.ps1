$ErrorActionPreference='Stop'
$module=Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-VersionInfo.psm1') -Force -PassThru
$checks=[Collections.Generic.List[string]]::new()
function Require([bool]$Ok,[string]$Name){if(-not $Ok){throw $Name};$checks.Add($Name)}
function Reject([scriptblock]$Call,[string]$Name){$rejected=$false;try{& $Call|Out-Null}catch{$rejected=$true};Require $rejected $Name}
$url='https://downloads.claude.ai/releases/win32/x64/2.26454.2/Claude-'+('a'*40)+'.msix'
$headers="HTTP/1.1 200 Connection established"+[Environment]::NewLine+"HTTP/1.1 307 Temporary Redirect"+[Environment]::NewLine+"location: "+$url+[Environment]::NewLine
Require ((ConvertFrom-ClaudeVersionHeaders $headers).LatestDesktopVersion -eq '2.26454.2') 'official-get-redirect-parsed'
Require ((Get-ClaudeVersionDecision '2.26454.2' '2.26454.2.0') -eq 'Current') 'three-and-four-part-versions-normalized'
Require ((Get-ClaudeVersionDecision '2.100.0' '2.99.0') -eq 'Available') 'numeric-version-order'
Require ((Get-ClaudeVersionDecision '2.26454.2' '2.26455.1.0') -eq 'Ahead') 'ahead-is-not-downgrade'
Reject {ConvertTo-ClaudeVersion '2.1.3-beta'} 'unexpected-version-refused'
Reject {ConvertFrom-ClaudeVersionHeaders ($headers.Replace('downloads.claude.ai','downloads.claude.ai.attacker.test'))} 'foreign-redirect-refused'
Reject {ConvertFrom-ClaudeVersionHeaders ($headers.Replace('https://','http://'))} 'http-redirect-refused'
Reject {ConvertFrom-ClaudeVersionHeaders ($headers.Replace('win32/x64','win32/arm64'))} 'wrong-architecture-refused'
Reject {ConvertFrom-ClaudeVersionHeaders ($headers.Replace('307 Temporary Redirect','403 Forbidden'))} 'challenge-is-not-no-update'
Reject {ConvertFrom-ClaudeVersionHeaders ($headers+"location: "+$url)} 'ambiguous-location-refused'
Reject {ConvertFrom-ClaudeVersionHeaders ($headers.Replace('.msix','.msix?token=unexpected'))} 'unexpected-query-refused'
Reject {ConvertFrom-ClaudeVersionHeaders ('x'*65537)} 'response-budget-enforced'
$root=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeVersionInfo-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $root 'private')|Out-Null
try {
    & $module {
        $script:QueryCalls=0;$script:FailQuery=$false
        function script:Read-GuardJson($Path){Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json}
        function script:Write-GuardJson($Path,$Value){$temp=$Path+'.tmp';[IO.File]::WriteAllText($temp,($Value|ConvertTo-Json -Depth 10));[IO.File]::Move($temp,$Path,$true)}
        function script:Invoke-ClaudeVersionCatalogRequest($Probe,$Proxy){
            $script:QueryCalls++;if($script:FailQuery){throw 'fixture unavailable'}
            [pscustomobject]@{LatestDesktopVersion='2.26454.2';DownloadUrl='https://downloads.claude.ai/fixture.msix';SourceUrl='https://claude.ai/fixture'}
        }
    }
    $state=[pscustomobject]@{ProxyUrl='http://127.0.0.1:10818';Desktop=@{Path='C:\Claude\Claude.exe'};CodeGate=@{Roots=@('C:\ClaudeCache');Version='2.1.293';PayloadHash='good'};CodePaths=@('C:\ClaudeCache\2.1.293\abc\claude.exe')}
    $now=[datetimeoffset]::UtcNow
    $notChecked=Get-ClaudeVersionCatalog $root $state
    Require ($notChecked.Status -eq 'NotChecked' -and (& $module {$script:QueryCalls}) -eq 0) 'local-observation-does-not-query'
    [IO.File]::WriteAllText((Join-Path $root 'private\version-update-status.json'),'{"SchemaVersion":1}')
    Require ((Get-ClaudeVersionCatalog $root $state).Status -eq 'NotChecked') 'incomplete-cache-does-not-break-local-observation'
    $good=Get-ClaudeVersionCatalog $root $state -CheckUpdates -Now $now
    Require ($good.Status -eq 'Checked' -and (& $module {$script:QueryCalls}) -eq 1) 'catalog-query-saved'
    $cache=Get-ClaudeVersionCatalog $root $state -CheckUpdates -Now $now.AddHours(1)
    Require ((& $module {$script:QueryCalls}) -eq 1) 'six-hour-success-cache-reused'
    $fresh=Get-ClaudeVersionCatalog $root $state -CheckUpdates -Force -Now $now.AddHours(1)
    Require ((& $module {$script:QueryCalls}) -eq 2) 'manual-check-bypasses-cache'
    & $module {$script:FailQuery=$true}
    $failed=Get-ClaudeVersionCatalog $root $state -CheckUpdates -Force -Now $now.AddHours(2)
    Require ($failed.Status -eq 'QueryFailed' -and $failed.LastSuccess.LatestDesktopVersion -eq '2.26454.2') 'failure-retains-last-success'
    $null=Get-ClaudeVersionCatalog $root $state -CheckUpdates -Now $now.AddHours(2).AddMinutes(5)
    Require ((& $module {$script:QueryCalls}) -eq 3) 'failed-query-backoff'
    [IO.File]::WriteAllText((Join-Path $root 'private\safety-hold.json'),'{}')
    $hold=Get-ClaudeVersionCatalog $root $state -CheckUpdates -Force
    Require ($hold.Status -eq 'Deferred' -and (& $module {$script:QueryCalls}) -eq 3) 'hold-does-not-start-network'
    Remove-Item -LiteralPath (Join-Path $root 'private\safety-hold.json')
    [IO.File]::WriteAllText((Join-Path $root 'private\active-version-maintenance.json'),'{"Status":"Running","RecoveryRequired":false}')
    $maintenance=Get-ClaudeVersionCatalog $root $state -CheckUpdates -Force
    Require ($maintenance.Status -eq 'Deferred' -and (& $module {$script:QueryCalls}) -eq 3) 'maintenance-does-not-start-network'
    $main=[pscustomobject]@{ProcessId=10;ParentProcessId=0;ExecutablePath=$state.Desktop.Path}
    $code=[pscustomobject]@{ProcessId=11;ParentProcessId=10;ExecutablePath=$state.CodePaths[0]}
    $reader={param($p)[pscustomobject]@{Version='2.1.293';Hash='good';StartedAt='2026-10-08T00:00:00Z'}}
    Require (@(Get-ClaudeVersionRuntime $state @($main) $reader).Count -eq 0) 'desktop-alone-is-not-running-code'
    $running=@(Get-ClaudeVersionRuntime $state @($main,$code) $reader)
    Require ($running.Count -eq 1 -and $running[0].Identity -eq 'Approved') 'runtime-bound-to-approved-payload-and-desktop'
    Require ((@(Get-ClaudeVersionRuntime $state @($main,$code) $reader -DesktopMatchesApproved $false))[0].Identity -eq 'UnknownOrigin') 'changed-desktop-does-not-claim-approved-runtime'
    $code.ParentProcessId=90
    Require ((@(Get-ClaudeVersionRuntime $state @($main,$code) $reader))[0].Identity -eq 'UnknownOrigin') 'same-payload-without-desktop-parent-not-claimed'
    $code.ParentProcessId=10
    Require ((@(Get-ClaudeVersionRuntime $state @($main,$code) {param($p)[pscustomobject]@{Version='2.1.293';Hash='tampered';StartedAt='x'}}))[0].Identity -eq 'Unreviewed') 'matching-version-with-different-hash-not-approved'
    Require (@(Get-ClaudeVersionRuntime $state @($main,$code) {param($p)$null}).Count -eq 0) 'exited-or-reused-pid-is-ignored'
    $cli=[pscustomobject]@{ProcessId=12;ParentProcessId=10;ExecutablePath='C:\Other\claude.exe'}
    Require (@(Get-ClaudeVersionRuntime $state @($main,$cli) $reader).Count -eq 0) 'ordinary-cli-outside-managed-roots-excluded'
    $old=[pscustomobject]@{ProcessId=13;ParentProcessId=10;ExecutablePath='C:\ClaudeCache\2.1.286\old\claude.exe'}
    Require ((@(Get-ClaudeVersionRuntime $state @($main,$old) {param($p)[pscustomobject]@{Version='2.1.286';Hash='old';StartedAt='x'}}))[0].Identity -eq 'Unreviewed') 'old-running-engine-not-replaced-by-cache-latest'
    # 临时原生父/子进程验证 CIM 精度、文件版本和真实 PID；不运行 Claude 或访问网络。
    & $module {function script:Get-GuardHash($Path){(Get-FileHash -LiteralPath $Path).Hash}}
    $nativeSource=Join-Path $root 'Native.cs';$parentExe=Join-Path $root 'Parent.exe'
    [IO.File]::WriteAllText($nativeSource,'using System;using System.Diagnostics;using System.Threading;using System.Reflection;[assembly:AssemblyFileVersion("2.1.293.0")] public class N{public static void Main(string[] a){if(a.Length==0){Thread.Sleep(30000);return;}using(var p=Process.Start(new ProcessStartInfo(a[0]){UseShellExecute=false,CreateNoWindow=true})){p.WaitForExit();}}}')
    $csc=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $csc /nologo /target:winexe ('/out:'+$parentExe) $nativeSource
    if($LASTEXITCODE){throw 'Native process fixture compile failed.'}
    $cacheRoot=Join-Path $root 'cache';$childPath=Join-Path $cacheRoot '2.1.293\abc\claude.exe'
    New-Item -ItemType Directory -Path (Split-Path $childPath)|Out-Null;Copy-Item -LiteralPath $parentExe -Destination $childPath
    $state.Desktop.Path=$parentExe;$state.CodeGate.Roots=@($cacheRoot);$state.CodePaths=@($childPath);$state.CodeGate.PayloadHash=(Get-FileHash -LiteralPath $childPath).Hash
    $parentProcess=Start-Process -FilePath $parentExe -ArgumentList $childPath -WindowStyle Hidden -PassThru;$child=$null
    try{
        $deadline=[datetime]::UtcNow.AddSeconds(10)
        do{$list=@(Get-CimInstance Win32_Process);$child=@($list|Where-Object {$_.ParentProcessId -eq $parentProcess.Id -and $_.ExecutablePath -eq $childPath});if($child.Count){break};Start-Sleep -Milliseconds 100}while([datetime]::UtcNow -lt $deadline)
        Require ($child.Count -eq 1) 'native-child-process-observed'
        $native=@(Get-ClaudeVersionRuntime $state $list)
        Require ($native.Count -eq 1 -and $native[0].Version -eq '2.1.293' -and $native[0].Identity -eq 'Approved') 'native-cim-precision-and-file-version-identity'
        & $module {function script:Get-GuardHash($Path){throw 'Fixture file temporarily unreadable.'}}
        $unreadable=@(Get-ClaudeVersionRuntime $state $list)
        Require ($unreadable.Count -eq 1 -and $unreadable[0].Identity -eq 'Unreadable' -and -not $unreadable[0].Version) 'native-read-failure-retains-live-unconfirmed-process'
        & $module {function script:Get-GuardHash($Path){(Get-FileHash -LiteralPath $Path).Hash}}
        $stale=$child[0]|Select-Object *
        $stale.CreationDate=([datetime]$stale.CreationDate).AddSeconds(-1)
        Require (-not (Get-ClaudeVersionFileIdentity $stale)) 'native-start-time-mismatch-refused'
    }finally{
        foreach($owned in @($child)){if($owned -and $owned.ExecutablePath -eq $childPath){$live=Get-CimInstance Win32_Process -Filter ('ProcessId='+$owned.ProcessId) -ErrorAction SilentlyContinue;if($live -and $live.ExecutablePath -eq $childPath -and $live.CreationDate -eq $owned.CreationDate){Stop-Process -Id $owned.ProcessId -ErrorAction SilentlyContinue}}}
        if(-not $parentProcess.WaitForExit(3000)){$parentProcess.Kill()};$parentProcess.Dispose()
    }
    $result=@{Passed=$true;FixtureOnly=$true;ProductionTouched=$false;Time=(Get-Date -Format o);Count=$checks.Count;Checks=@($checks)}
    $result|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'evidence\version-info-regression.json') -Encoding utf8
    $result|ConvertTo-Json -Depth 5
}finally {
    $full=[IO.Path]::GetFullPath($root);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if(-not $full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '^ClaudeVersionInfo-[a-f0-9]{32}$'){throw 'Unsafe fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
