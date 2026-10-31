[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$runtimePath=Join-Path $PSScriptRoot 'ClaudeGuard-Runtime.psm1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($runtimePath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join '; ')}
$functions=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ne 'Stop-GuardUnsafeRuntime'},$false)|ForEach-Object {$_.Extent.Text}) -join [Environment]::NewLine
$cases=@()
$module=New-Module -ScriptBlock ([scriptblock]::Create($functions))
try{
    $cases=@(& $module {
        $script:started=[datetime]'2026-10-31T01:00:00Z'
        function Get-GuardState{[pscustomobject]@{Desktop=[pscustomobject]@{Path='desktop'};CodePaths=@('code')}}
        function Get-CimInstance{$script:processes}
        function Get-NetTCPConnection{if($script:enumerationFails){throw 'Fixture TCP enumeration failure'};$script:tcp}
        function Get-GuardTcpListeners{if($script:listenerFails){throw 'Fixture listener inventory failure'};$script:inventory}
        function Join-Path{param($Path,$ChildPath) $ChildPath}
        function Get-Process{param($Id) [pscustomobject]@{StartTime=if($script:reusePid -and $Id -eq 200){$script:started.AddSeconds($script:reads)}else{$script:started}}}
        function Invoke-GuardEnvironmentReader{
            param($PythonPath,$ReaderPath,$ProcessId,$TimeoutMilliseconds,$LocalServicePath,$LocalServiceStarted)
            $script:reads++
            if($script:timeout -and $LocalServicePath){return [pscustomobject]@{ExitCode=124;TimedOut=$true;Output=''}}
            $e=@{Pid=$ProcessId;ApprovedPath=($ProcessId -eq 100);LocalServiceIdentityVerified=$script:identity;
                ConfigDirMatches=($script:environment -and -not ($script:badWorker -and $ProcessId -eq 201));HttpProxyMatches=$true;HttpsProxyMatches=$true;AllProxyMatches=$true;NoProxyOnlyLoopback=$true;
                TlsVerificationEnabled=$true;UnexpectedTlsOverrideNames=@();UnexpectedProviderOverrideNames=@()}
            [pscustomobject]@{ExitCode=0;TimedOut=$false;Output=($e|ConvertTo-Json -Compress)}
        }
        foreach($name in @('detached-roadmap','unknown-environment','wrong-account-or-image','pid-reused','reader-timeout','wildcard-listener','ipv6-wildcard-listener','unknown-listener','wrong-address-same-port','shared-proxy-10808','shared-proxy-10813','preview-direct-ipv4','preview-direct-ipv6','preview-shared-proxy','preview-child-direct','preview-fixed-proxy','accepted-inbound','listener-state-unknown','owned-service','external-desktop','tcp-enumeration-failure','listener-enumeration-failure','non-listening-bind','gateway-worker','worker-unknown-environment','worker-wildcard-listener','unknown-persistent-recheck','vanished-loopback-recheck')){
            $script:processes=@([pscustomobject]@{ProcessId=100;ParentProcessId=1;ExecutablePath='desktop';CommandLine='--proxy-server=http://127.0.0.1:10818'},
                [pscustomobject]@{ProcessId=200;ParentProcessId=999;ExecutablePath='python';CommandLine='roadmap serve --port 8765'},
                [pscustomobject]@{ProcessId=201;ParentProcessId=200;ExecutablePath='child';CommandLine=''})
            $connection=[pscustomobject]@{OwningProcess=100;LocalAddress='127.0.0.1';LocalPort=50000;RemoteAddress='127.0.0.1';RemotePort=8765;State='Established'}
            $listener=[pscustomobject]@{OwningProcess=200;LocalAddress='127.0.0.1';LocalPort=8765;RemoteAddress='0.0.0.0';RemotePort=0;State='Listen'}
            $script:tcp=@($connection,$listener);$script:environment=$true;$script:identity=$true;$script:reusePid=$false;$script:timeout=$false;$script:reads=0;$script:enumerationFails=$false;$script:listenerFails=$false;$script:badWorker=$false
            $safe=$name -in @('detached-roadmap','preview-fixed-proxy','accepted-inbound','listener-state-unknown','owned-service','non-listening-bind','gateway-worker','vanished-loopback-recheck')
            switch($name){
                'unknown-environment' {$script:environment=$false}
                'wrong-account-or-image' {$script:identity=$false}
                'pid-reused' {$script:reusePid=$true}
                'reader-timeout' {$script:timeout=$true}
                'wildcard-listener' {$listener.LocalAddress='0.0.0.0'}
                'ipv6-wildcard-listener' {$script:tcp+=@([pscustomobject]@{OwningProcess=200;LocalAddress='::';LocalPort=8765;RemoteAddress='::';RemotePort=0;State='Listen'})}
                'unknown-listener' {$script:tcp=@($connection)}
                'wrong-address-same-port' {$connection.RemoteAddress='127.0.0.2'}
                'shared-proxy-10808' {$connection.RemotePort=10808;$listener.LocalPort=10808}
                'shared-proxy-10813' {$connection.RemotePort=10813;$listener.LocalPort=10813}
                'listener-state-unknown' {$listener.State='Closed'}
                'owned-service' {$script:processes[1].ParentProcessId=100}
                'external-desktop' {$connection.RemoteAddress='203.0.113.1';$connection.RemotePort=443}
                'tcp-enumeration-failure' {$script:enumerationFails=$true}
                'listener-enumeration-failure' {$script:listenerFails=$true}
                'unknown-persistent-recheck' {$script:tcp=@($connection)}
                'vanished-loopback-recheck' {$script:tcp=@($connection)}
                'worker-unknown-environment' {$script:badWorker=$true}

            }
            if($name -in @('preview-direct-ipv4','preview-direct-ipv6','preview-shared-proxy','preview-child-direct','preview-fixed-proxy','accepted-inbound')){
                $extra=[pscustomobject]@{OwningProcess=200;LocalAddress='127.0.0.1';LocalPort=50001;RemoteAddress='203.0.113.1';RemotePort=443;State='Established'}
                switch($name){
                    'preview-direct-ipv6' {$extra.RemoteAddress='2001:db8::1'}
                    'preview-shared-proxy' {$extra.RemoteAddress='127.0.0.1';$extra.RemotePort=10808}
                    'preview-child-direct' {$extra.OwningProcess=201}
                    'preview-fixed-proxy' {$extra.RemoteAddress='127.0.0.1';$extra.RemotePort=10818}
                    'accepted-inbound' {$extra.LocalPort=8765;$extra.RemoteAddress='127.0.0.1';$extra.RemotePort=50000}
                }
                $script:tcp+=@($extra)
            }
            $script:inventory=@($script:tcp|Where-Object {$_.RemotePort -eq 0})
            if($name -eq 'non-listening-bind'){$script:tcp+=@([pscustomobject]@{OwningProcess=200;LocalAddress='0.0.0.0';LocalPort=55078;RemoteAddress='0.0.0.0';RemotePort=0;State='Bound'})}
            if($name -in @('gateway-worker','worker-unknown-environment','worker-wildcard-listener')){
                $worker=[pscustomobject]@{OwningProcess=201;LocalAddress=$(if($name -eq 'worker-wildcard-listener'){'0.0.0.0'}else{'127.0.0.1'});LocalPort=51383;RemoteAddress='0.0.0.0';RemotePort=0;State='Listen'}
                $script:inventory+=@($worker)
                $script:tcp+=@($worker,[pscustomobject]@{OwningProcess=200;LocalAddress='127.0.0.1';LocalPort=55078;RemoteAddress='127.0.0.1';RemotePort=51383;State='Established'},
                    [pscustomobject]@{OwningProcess=201;LocalAddress='127.0.0.1';LocalPort=51383;RemoteAddress='127.0.0.1';RemotePort=55078;State='Established'})
            }
            if($name -eq 'vanished-loopback-recheck'){
                function Get-NetTCPConnection{if($script:reads -gt 0){@()}else{$script:tcp}}
            }else{function Get-NetTCPConnection{if($script:enumerationFails){throw 'Fixture TCP enumeration failure'};$script:tcp}}
            $thrown=$false
            try{$observed=Get-GuardRuntimeSafety -EvidenceBudgetMilliseconds 3000}catch{if($name -notin @('tcp-enumeration-failure','listener-enumeration-failure')){throw};$thrown=$true}
            if($name -in @('tcp-enumeration-failure','listener-enumeration-failure')){if(-not $thrown){throw 'Enumeration failure was silently approved.'}}
            elseif($observed.Safe -ne $safe){throw ('Local preview regression failed: '+$name+' '+($observed|ConvertTo-Json -Depth 10 -Compress))}
            if($name -eq 'unknown-persistent-recheck' -and -not $observed.PSObject.Properties['LoopbackRecheck']){throw 'Persistent unknown loopback was not rechecked.'}
            if($name -eq 'detached-roadmap' -and (@($observed.PreviewServices).Count -ne 1 -or 201 -notin $observed.PreviewMonitoredPids)){throw 'Detached service monitoring omitted its child.'}
            [pscustomobject]@{Name=$name;Passed=$true;ExpectedSafe=$safe}
        }
    })
}finally{Remove-Module $module -Force}
# 原生进程令牌、启动时间和映像比较在独立本机服务上验证，不启动生产 Claude。
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$fixture=Join-Path $PSScriptRoot ('private\preview-fixture-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $fixture 'private')|Out-Null
$server=$null
try{
    $reader=Join-Path $fixture 'Read-ClaudeProcessEnvironment.py'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py') -Destination $reader
    $state=Get-GuardState
    $state|ConvertTo-Json -Depth 40|Set-Content -LiteralPath (Join-Path $fixture 'private\deployment.json') -Encoding utf8
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=(Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\python.exe');$info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.ArgumentList.Add('-c');$info.ArgumentList.Add('import socket,time; s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(); time.sleep(30)')
    $environment=New-GuardDesktopEnvironment $state
    foreach($key in $environment.Keys){if($null -eq $environment[$key]){$null=$info.Environment.Remove($key)}else{$info.Environment[$key]=[string]$environment[$key]}}
    $server=[Diagnostics.Process]::Start($info)
    $started=$server.StartTime.ToUniversalTime().ToFileTimeUtc()
    $output=& $info.FileName $reader $server.Id --local-service-path $info.FileName --local-service-started $started 2>$null
    if($LASTEXITCODE -ne 0){throw 'Native local service proof failed.'}
    $e=$output|ConvertFrom-Json
    if(-not $e.LocalServiceIdentityVerified -or $e.ApprovedPath -or -not $e.ConfigDirMatches -or -not $e.HttpProxyMatches){throw 'Native local service proof was not bound to its environment.'}
    $cases+=@([pscustomobject]@{Name='native-same-account-image-start-environment';Passed=$true})
    foreach($case in @('default-path-denied','wrong-start','wrong-image','wrong-account')){
        $arguments=@($reader,[string]$server.Id)
        if($case -ne 'default-path-denied'){$arguments+=@('--local-service-path',$(if($case -eq 'wrong-image'){'C:\Windows\not-the-server.exe'}else{$info.FileName}),'--local-service-started',[string]$(if($case -eq 'wrong-start'){$started+1}else{$started}))}
        if($case -eq 'wrong-account'){$state.UserSid='S-1-5-18';$state|ConvertTo-Json -Depth 40|Set-Content -LiteralPath (Join-Path $fixture 'private\deployment.json') -Encoding utf8}
        $output=& $info.FileName @arguments 2>$null
        if($LASTEXITCODE -eq 0 -or $output){throw ('Native local service negative proof failed: '+$case)}
        $cases+=@([pscustomobject]@{Name=('native-'+$case);Passed=$true})
    }
}finally{
    if($server){if(-not $server.HasExited){$server.Kill();$null=$server.WaitForExit(2000)};$server.Dispose()}
    $full=[IO.Path]::GetFullPath($fixture);$private=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'private'))
    if(-not $full.StartsWith($private+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '^preview-fixture-[a-f0-9]{32}$'){throw 'Unsafe fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
$result=[pscustomobject]@{Time=(Get-Date).ToString('o');Passed=$true;FixtureOnly=$true;NativeLocalServiceEvidence=$true;ProductionProcessesTouched=$false;Cases=$cases}
$result|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'evidence\local-preview-regression.json') -Encoding utf8
$result
