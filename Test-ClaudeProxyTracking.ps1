[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'ClaudeGuard.psm1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join ';')}
$names=@('Read-GuardJson','Write-GuardJson','Test-GuardLoopbackAccept','Get-GuardListener','Get-GuardProxyProcessIdentity','Sync-GuardProxyProcess','Assert-GuardCore','Start-GuardProxy')
$functions=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $names},$true))
if($functions.Count -ne $names.Count){throw 'Required production functions were not found.'}
$fixture=Join-Path $PSScriptRoot ('private\proxy-tracking-fixture-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $fixture 'private') -Force|Out-Null
$fixtureFunctions=($functions.Extent.Text -join "`n").Replace("'Local\ClaudeProGuardProxy-v1'",("'Local\ClaudeGuardProxyFixture-"+[guid]::NewGuid().ToString('N')+"'"))
$module=New-Module -ScriptBlock ([scriptblock]::Create($fixtureFunctions+"`nExport-ModuleMember -Function *"))
try {
    $cases=& $module {
        param($Fixture)
        Set-StrictMode -Version Latest
        $script:Root=$Fixture;$script:Cases=[Collections.Generic.List[string]]::new()
        function Check($Name,[scriptblock]$Body){& $Body;$script:Cases.Add($Name)}
        function Require($Value,$Message){if(-not $Value){throw $Message}}
        function Refuse([scriptblock]$Body){$rejected=$false;try{& $Body}catch{$rejected=$true};Require $rejected 'Unsafe state was accepted.'}
        # Exercise the actual socket check on an ephemeral loopback port, never the production proxy.
        $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
        $listener.Start();$port=$listener.LocalEndpoint.Port
        try{Check 'real-loopback-listener-accepts' {Require (Test-GuardLoopbackAccept $port) 'Socket was not detected.'}}finally{$listener.Stop()}
        Check 'closed-loopback-port-rejected' {Require (-not (Test-GuardLoopbackAccept $port)) 'Closed socket was accepted.'}
        function Get-GuardPath([string]$Name){Join-Path $script:Root $Name}
        $script:Core=Join-Path $Fixture 'xray.exe';$script:Config=Get-GuardPath 'private\proxy.json'
        $script:State=[pscustomobject]@{CoreHash='fixture';ProxyConfigHash='fixture';ExpectedIp='203.0.113.1';InterfaceName='Fixture';InterfaceGuid='fixture'}
        function Get-GuardState{$script:State}
        function Get-GuardCorePath{$script:Core}
        function Get-GuardHash{'fixture'}
        function Get-GuardLifecycleValue($Object,$Name,$Default){$Default}
        function Get-NetAdapter{[pscustomobject]@{Status='Up';InterfaceGuid='fixture'}}
        function Test-GuardLoopbackAccept{$script:Accepts}
        function Get-NetTCPConnection{param($LocalPort) if($script:QueryFailure){throw 'TCP enumeration failed.'};$script:Rows}
        function New-FakeProcess([int]$ProcessId,[bool]$Exited=$false){
            $p=[pscustomobject]@{Id=$ProcessId;Handle=1;StartTime=[datetime]::Parse('2026-10-31T00:00:00Z').ToUniversalTime();HasExited=$Exited}
            $p|Add-Member ScriptMethod Dispose {}
            $p|Add-Member ScriptMethod Kill {$script:Killed+=@($this.Id);$this.HasExited=$true}
            $p
        }
        function Get-Process{param($Id) $script:Live}
        function Get-CimInstance{param($ClassName,$Filter) if($Filter){$script:Cim}else{$script:Configured}}
        function Start-Process{
            $script:Starts++
            if($script:LaunchMode -eq 'success'){
                $script:Live=$script:NewProcess;$script:Cim=[pscustomobject]@{ExecutablePath=$script:Core;CommandLine=('"'+$script:Core+'" run -c "'+$script:Config+'"')}
                $script:Rows=@(New-Row 'Listen' 44)
            }
            $script:NewProcess
        }
        function Start-Sleep{}
        function New-Row($State,[int]$Owner=33,[string]$Address='127.0.0.1',[int]$RemotePort=0){[pscustomobject]@{State=$State;LocalAddress=$Address;LocalPort=10818;RemoteAddress='0.0.0.0';RemotePort=$RemotePort;OwningProcess=$Owner}}
        function Reset {
            $script:Accepts=$true;$script:QueryFailure=$false;$script:Starts=0;$script:Killed=@();$script:Configured=@();$script:LaunchMode='failure'
            $script:Live=New-FakeProcess 33;$script:NewProcess=New-FakeProcess 44 $true
            $script:Rows=@(New-Row 'Listen')
            $script:Cim=[pscustomobject]@{ExecutablePath=$script:Core;CommandLine=('"'+$script:Core+'" run -c "'+$script:Config+'"')}
            Write-GuardJson (Get-GuardPath 'private\proxy.json') @{outbounds=@(@{type='vless';server='203.0.113.1'});route=@{final='fixed-vps'}}
            Write-GuardJson (Get-GuardPath 'private\proxy-process.json') @{Pid=99;Started=[datetime]::UtcNow.ToString('o');SupervisorOwned=$true}
        }
        Reset
        Check 'ordinary-listener-detected' {Require (@(Get-GuardListener).Count -eq 1) 'Listener missing.'}
        Check 'unknown-state-live-endpoint-detected' {$script:Rows=@(New-Row 0);Require (@(Get-GuardListener).Count -eq 1) 'Incident listener was missed.'}
        Check 'closed-reported-live-endpoint-detected' {$script:Rows=@(New-Row 'Closed');Require (@(Get-GuardListener).Count -eq 1) 'Live endpoint reported closed was missed.'}
        Check 'finwait-reported-live-endpoint-detected' {$script:Rows=@(New-Row 'FinWait1');Require (@(Get-GuardListener).Count -eq 1) 'Live endpoint reported closing was missed.'}
        Check 'closed-reported-dead-endpoint-rejected' {$script:Accepts=$false;Require (@(Get-GuardListener).Count -eq 0) 'Closed endpoint was accepted.'}
        Check 'unknown-state-closed-endpoint-rejected' {$script:Accepts=$false;Require (@(Get-GuardListener).Count -eq 0) 'Unreachable endpoint was accepted.'}
        Check 'unknown-state-connection-not-listener' {$script:Accepts=$true;$script:Rows=@(New-Row 0 33 '127.0.0.1' 443);Require (@(Get-GuardListener).Count -eq 0) 'Connection was accepted as listener.'}
        Check 'misreported-listen-connection-not-listener' {$script:Rows=@(New-Row 'Listen' 33 '127.0.0.1' 443);Require (@(Get-GuardListener).Count -eq 0) 'Connection reported Listen was accepted.'}
        Check 'bound-nonaccepting-endpoint-not-listener' {$script:Accepts=$false;$script:Rows=@(New-Row 'Bound');Require (@(Get-GuardListener).Count -eq 0) 'Bound endpoint was accepted.'}
        Check 'enumeration-failure-does-not-start-proxy' {$script:QueryFailure=$true;Refuse {Start-GuardProxy -SupervisorWorker};Require ($script:Starts -eq 0) 'Started after query error.'}
        Reset
        Check 'stale-record-recovered-without-restart' {
            $script:Rows=@(New-Row 0)
            Require (Sync-GuardProxyProcess -SupervisorWorker) 'Record was not recovered.'
            Assert-GuardCore
            $tracked=Read-GuardJson (Get-GuardPath 'private\proxy-process.json')
            Require ($tracked.Pid -eq 33 -and $script:Starts -eq 0 -and $script:Killed.Count -eq 0) 'Recovery touched a running process.'
        }
        Check 'correct-record-is-idempotent' {Require (-not (Sync-GuardProxyProcess -SupervisorWorker)) 'Correct identity was rewritten.'}
        Check 'live-listener-skips-new-process' {Start-GuardProxy -SupervisorWorker;Require ($script:Starts -eq 0) 'Duplicate proxy was started.'}
        foreach($mode in @('foreign-path','foreign-config','extra-config-argument','exited-process','wildcard-address','duplicate-listener')){
            Reset
            switch($mode){
                'foreign-path' {$script:Cim.ExecutablePath='C:\foreign.exe'}
                'foreign-config' {$script:Cim.CommandLine=$script:Cim.CommandLine.Replace('proxy.json','other.json')}
                'extra-config-argument' {$script:Cim.CommandLine+=' -c "C:\other.json"'}
                'exited-process' {$script:Live.HasExited=$true}
                'wildcard-address' {$script:Rows=@(New-Row 'Listen' 33 '0.0.0.0')}
                'duplicate-listener' {$script:Rows=@((New-Row 'Listen'),(New-Row 'Listen' 66))}
            }
            Check ($mode+'-cannot-replace-tracking') {
                Refuse {Sync-GuardProxyProcess -SupervisorWorker}
                Require ((Read-GuardJson (Get-GuardPath 'private\proxy-process.json')).Pid -eq 99) 'Untrusted process replaced tracking.'
            }
        }
        Reset
        Check 'pid-reuse-start-time-mismatch-rejected' {
            Write-GuardJson (Get-GuardPath 'private\proxy-process.json') @{Pid=33;Started=[datetime]::UtcNow.ToString('o')}
            Refuse {Assert-GuardCore}
        }
        Reset
        Check 'unverified-running-proxy-is-not-duplicated' {
            $script:Rows=@();$script:Configured=@($script:Cim)
            Refuse {Start-GuardProxy -SupervisorWorker}
            Require ($script:Starts -eq 0) 'Duplicate was started for an unverified running process.'
        }
        Reset
        Check 'failed-start-preserves-previous-record' {
            $script:Rows=@();$before=Get-Content (Get-GuardPath 'private\proxy-process.json') -Raw
            Refuse {Start-GuardProxy -SupervisorWorker}
            Require ($script:Starts -eq 1 -and (Get-Content (Get-GuardPath 'private\proxy-process.json') -Raw) -ceq $before) 'Failed startup overwrote tracking.'
        }
        Reset
        Check 'unready-new-child-only-is-cleaned-up' {
            $script:Rows=@();$script:NewProcess.HasExited=$false
            Refuse {Start-GuardProxy -SupervisorWorker}
            Require ($script:Killed.Count -eq 1 -and $script:Killed[0] -eq 44 -and (Read-GuardJson (Get-GuardPath 'private\proxy-process.json')).Pid -eq 99) 'Cleanup touched another process or tracking.'
        }
        Reset
        Check 'successful-start-commits-verified-child' {
            $script:Rows=@();$script:NewProcess.HasExited=$false;$script:LaunchMode='success'
            Start-GuardProxy -SupervisorWorker
            Require ((Read-GuardJson (Get-GuardPath 'private\proxy-process.json')).Pid -eq 44 -and $script:Killed.Count -eq 0) 'Verified child was not committed.'
        }
        @($script:Cases)
    } $fixture
    $result=@{Passed=$true;FixtureOnly=$true;ProductionProcessesTouched=$false;Cases=@($cases);CaseCount=@($cases).Count;Time=[datetime]::UtcNow.ToString('o')}
    $result|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'evidence\proxy-tracking-regression.json') -Encoding utf8
    $result|ConvertTo-Json -Depth 5
}finally{
    Remove-Module $module -ErrorAction SilentlyContinue
    # Only this invocation's validated fixture directory is eligible for cleanup.
    $resolved=[IO.Path]::GetFullPath($fixture)
    $allowed=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'private'))+[IO.Path]::DirectorySeparatorChar
    if($resolved.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($resolved) -match '^proxy-tracking-fixture-[0-9a-f]{32}$'){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
