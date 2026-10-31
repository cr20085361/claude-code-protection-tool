Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion -lt [version]'7.4') { throw 'Use PowerShell 7.4 or newer (pwsh) for isolated process environment support.' }
$script:Root = $PSScriptRoot
$script:Policy = 'HKCU:\SOFTWARE\Policies\Claude'
$script:Group = 'ClaudeProGuard-v1'
$script:RemoteRanges = @('0.0.0.0-126.255.255.255','128.0.0.0-255.255.255.255','::-::','::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')

function Get-GuardPath([string]$Name) { Join-Path $script:Root $Name }
function Read-GuardJson([string]$Path) {
    $retry=[Diagnostics.Stopwatch]::StartNew()
    do {
        try {
            $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            try{$reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8,$true);try{return ($reader.ReadToEnd()|ConvertFrom-Json)}finally{$reader.Dispose()}}finally{$stream.Dispose()}
        }catch{
            $failure=$_.Exception;while($failure.InnerException){$failure=$failure.InnerException}
            if(($failure.HResult -band 65535) -notin @(2,3,32,33) -or $retry.ElapsedMilliseconds -ge 500){throw}
            [Threading.Thread]::Sleep(10)
        }
    }while($true)
}
function Write-GuardJson([string]$Path, $Value) {
    $temp=$Path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try {
        [IO.File]::WriteAllText($temp, ($Value | ConvertTo-Json -Depth 40), [Text.UTF8Encoding]::new($false))
        $retry=[Diagnostics.Stopwatch]::StartNew()
        do {
            try{
                if([IO.File]::Exists($Path)){[IO.File]::Replace($temp,$Path,[NullString]::Value)}else{[IO.File]::Move($temp,$Path)}
                break
            }
            catch {
                $failure=$_.Exception;while($failure.InnerException){$failure=$failure.InnerException}
                $nativeCode=$failure.HResult -band 65535
                # ReplaceFile 1175 保留源/目标原名，可与短暂占用一起有限重试；1176/1177 不保证目标仍在。
                if($nativeCode -notin @(5,32,33,1175) -or $retry.ElapsedMilliseconds -ge 2000){throw}
                [Threading.Thread]::Sleep(50)
            }
        }while($true)
    } finally { if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp} }
}
function Get-GuardState { Read-GuardJson (Get-GuardPath 'private\deployment.json') }
function Get-GuardSupervisorScript($Reliability) {
    $name=if($Reliability.PSObject.Properties['SupervisorScript']){[string]$Reliability.SupervisorScript}else{'ClaudeGuard-Supervisor.ps1'}
    if($name -notin @('ClaudeGuard-Supervisor.ps1','ClaudeGuard-Supervisor-v2.ps1')){throw 'Supervisor script policy changed.'}
    Get-GuardPath $name
}
. (Get-GuardPath 'ClaudeGuard-Lifecycle.ps1')
. (Get-GuardPath 'ClaudeGuard-Health.ps1')
function New-GuardIPv4Config($Config) {
    $copy=$Config|ConvertTo-Json -Depth 40|ConvertFrom-Json
    if($copy.PSObject.Properties['routing']){return $copy} # Xray node pools already reject literal IPv6 and use IPv4 node sockets.
    $copy.dns.strategy='ipv4_only'
    $copy.route|Add-Member -NotePropertyName rules -NotePropertyValue @([ordered]@{ip_version=6;action='reject'},[ordered]@{action='resolve';strategy='ipv4_only'}) -Force
    $copy
}
function Get-GuardHash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
function Get-GuardCorePath($State=(Get-GuardState)) {
    $engine=Get-GuardLifecycleValue $State 'ProxyEngine' 'sing-box'
    switch($engine){'sing-box'{Get-GuardPath 'runtime\sing-box.exe'} 'xray'{Get-GuardPath 'runtime\xray.exe'} default{throw 'Unsupported dedicated proxy engine.'}}
}
function Test-GuardProxyConfiguration([string]$Path,$State=(Get-GuardState)) {
    $core=Get-GuardCorePath $State
    if((Get-GuardLifecycleValue $State 'ProxyEngine' 'sing-box') -eq 'xray'){$output=& $core run -test -c $Path 2>&1}else{$output=& $core check -c $Path 2>&1}
    if($LASTEXITCODE -ne 0){throw 'Dedicated proxy configuration validation failed.'}
}
function New-GuardXrayNodePool($Nodes,[string]$InterfaceName,[int]$Port=10818) {
    $approved=@($Nodes|ConvertTo-Json -Depth 40|ConvertFrom-Json)
    if(-not $approved.Count){throw 'At least one approved node is required.'}
    $tags=@()
    for($i=0;$i -lt $approved.Count;$i++){
        $n=$approved[$i];$ip=$null
        if($n.protocol -ne 'vless' -or -not [Net.IPAddress]::TryParse([string]$n.settings.address,[ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $n.settings.port -lt 1 -or $n.settings.port -gt 65535 -or $n.streamSettings.security -ne 'reality' -or $n.streamSettings.network -notin @('raw','tcp')){throw 'Node pool requires explicit IPv4 VLESS Reality nodes.'}
        # Rebuild from approved fields: never import direct routes, DNS, mux or proxy chaining from the shared client.
        $tag='node-'+$i;$tags+=$tag
        $approved[$i]=[pscustomobject]@{tag=$tag;protocol='vless';settings=$n.settings;streamSettings=@{network='raw';security='reality';realitySettings=$n.streamSettings.realitySettings;sockopt=@{interface=$InterfaceName;domainStrategy='UseIPv4'}}}
    }
    [pscustomobject]@{
        log=@{loglevel='warning'}
        inbounds=@(@{tag='local';listen='127.0.0.1';port=$Port;protocol='mixed';settings=@{auth='noauth';udp=$false}})
        outbounds=@($approved)+@(@{tag='block';protocol='blackhole'})
        observatory=@{subjectSelector=@('node-');probeUrl='https://www.gstatic.com/generate_204';probeInterval='30s';enableConcurrency=$true}
        routing=@{domainStrategy='AsIs';rules=@(@{type='field';ip=@('::/0');outboundTag='block'},@{type='field';network='tcp,udp';balancerTag='approved-nodes'});balancers=@(@{tag='approved-nodes';selector=@('node-');fallbackTag='block';strategy=@{type='leastPing'}})}
    }
}
function Assert-GuardXrayNodePool($Config,$State) {
    $nodes=@($Config.outbounds|Where-Object protocol -eq 'vless')
    $expected=@(Get-GuardExpectedIps $State)
    if(-not $nodes.Count -or @($Config.outbounds).Count -ne $nodes.Count+1){throw 'Approved node pool invariant failed.'}
    foreach($node in $nodes){if([string]$node.settings.address -notin $expected){throw 'Approved node pool endpoint changed.'}}
    $canonical=New-GuardXrayNodePool $nodes $State.InterfaceName
    # Compare structural invariants independent of JSON property ordering; config hash covers every byte.
    if($Config.inbounds.Count -ne 1 -or $Config.inbounds[0].listen -ne '127.0.0.1' -or $Config.inbounds[0].port -ne 10818 -or $Config.inbounds[0].protocol -ne 'mixed' -or $Config.outbounds[-1].protocol -ne 'blackhole' -or $Config.outbounds[-1].tag -ne 'block'){throw 'Approved node pool listener or fallback changed.'}
    if($Config.routing.domainStrategy -ne 'AsIs' -or $Config.routing.rules.Count -ne 2 -or $Config.routing.rules[0].ip[0] -ne '::/0' -or $Config.routing.rules[0].outboundTag -ne 'block' -or $Config.routing.rules[1].balancerTag -ne 'approved-nodes' -or $Config.routing.balancers.Count -ne 1 -or $Config.routing.balancers[0].fallbackTag -ne 'block' -or $Config.routing.balancers[0].strategy.type -ne 'leastPing'){throw 'Approved node pool routing changed.'}
    foreach($node in $nodes){if($node.streamSettings.sockopt.interface -ne $State.InterfaceName -or $node.streamSettings.sockopt.domainStrategy -ne 'UseIPv4'){throw 'Approved node pool interface changed.'}}
}
function Test-GuardLocalCodeAcceptance {
    $d=Get-GuardState
    if($d.CodeCoverage -ne 'verified' -or -not $d.PSObject.Properties['LocalCodeAcceptance']){return $false}
    try {
        $current=Get-GuardDesktop
        if($current.Path -ne $d.Desktop.Path -or $current.Hash -ne $d.Desktop.Hash -or $current.Version -ne $d.Desktop.Version){return $false}
        if($d.LocalCodeAcceptance.EvidenceFile -ne 'evidence\local-code-acceptance.json'){return $false}
        $path=Get-GuardPath $d.LocalCodeAcceptance.EvidenceFile
        if((Get-GuardHash $path) -ne $d.LocalCodeAcceptance.EvidenceHash){return $false}
        $a=Read-GuardJson $path
        if(-not $a.BasicAccepted -or -not $a.AuthenticatedCodeResponseVerified -or -not $a.LocalFileReadVerified -or $a.DesktopHash -ne $d.Desktop.Hash -or $a.CodeHash -ne $d.CodeGate.PayloadHash){return $false}
        if($a.RuntimeEvidenceFile -ne 'evidence\local-code-runtime-accepted.json' -or $a.TestSessionEvidenceFile -ne 'evidence\test-session-summary.json'){return $false}
        ((Get-GuardHash (Get-GuardPath $a.RuntimeEvidenceFile)) -eq $a.RuntimeEvidenceHash -and (Get-GuardHash (Get-GuardPath $a.TestSessionEvidenceFile)) -eq $a.TestSessionEvidenceHash)
    }catch{return $false}
}
function Test-GuardAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Protect-GuardDirectory([string]$Path) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($s in @($sid,'S-1-5-18','S-1-5-32-544')) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Get-GuardDesktop {
    $p = @(Get-AppxPackage -Name Claude)
    if ($p.Count -ne 1) { throw 'Expected exactly one installed Claude package.' }
    $exe = Join-Path $p[0].InstallLocation 'app\Claude.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw 'Claude executable not found.' }
    [pscustomobject]@{ Version=$p[0].Version.ToString(); Path=$exe; Family=$p[0].PackageFamilyName; Hash=(Get-GuardHash $exe) }
}
function Assert-GuardNoMachinePolicy {
    foreach ($path in @('HKLM:\SOFTWARE\Policies\Claude','HKLM:\SOFTWARE\WOW6432Node\Policies\Claude')) {
        if (Test-Path $path) {
            if ((Get-Item $path).GetValueNames().Count -gt 0) { throw 'HKLM Claude policy overrides HKCU; deployment stopped.' }
        }
    }
}
function Get-GuardPolicyValue([string]$Name) {
    if (-not (Test-Path $script:Policy)) { return $null }
    (Get-Item $script:Policy).GetValue($Name,$null)
}
function Assert-GuardPolicy([switch]$RuntimeOnly) {
    Assert-GuardNoMachinePolicy
    $proxyPolicy=Get-GuardPolicyValue 'egressProxyUrl'
    if ($null -eq $proxyPolicy) { throw 'Pinned desktop proxy policy is missing.' }
    if ($proxyPolicy -ne 'http://127.0.0.1:10818') { throw 'Pinned desktop proxy policy changed.' }
    $d = Get-GuardState
    if($d.PSObject.Properties['Reliability'] -and (Get-GuardPolicyValue 'disableAutoUpdates') -ne 1){throw 'Managed desktop update policy is missing or changed.'}
    if (Get-GuardPolicyValue 'egressProxyPacUrl') { throw 'PAC policy takes precedence; startup stopped.' }
    $d = Get-GuardState
    $settings = Read-GuardJson (Join-Path $d.ConfigDir 'settings.json')
    if ($settings.PSObject.Properties.Name -contains 'env') {
        foreach ($key in $settings.env.PSObject.Properties.Name) {
            if ($key -match 'ANTHROPIC|BEDROCK|VERTEX|FOUNDRY|CLAUDE_CODE_OAUTH') { throw 'Provider or credential override detected in Pro settings.' }
        }
    }
    if ($d.CodeCoverage -in @('prepared','verified')) {
        if($settings.env.HTTP_PROXY -ne $d.ProxyUrl -or $settings.env.HTTPS_PROXY -ne $d.ProxyUrl){throw 'Dedicated Code proxy settings changed.'}
        if($settings.env.ALL_PROXY -ne $d.ProxyUrl -or $settings.env.NO_PROXY -ne 'localhost,127.0.0.1,::1'){throw 'Dedicated Code proxy bypass settings changed.'}
        if($settings.env.PSObject.Properties['NODE_TLS_REJECT_UNAUTHORIZED'] -and $settings.env.NODE_TLS_REJECT_UNAUTHORIZED -eq '0'){throw 'TLS certificate verification is disabled in Code settings.'}
    }
    if (-not $RuntimeOnly -and (Get-GuardHash $d.OriginalCli.Path) -ne $d.OriginalCli.Hash) { throw 'Original CLI settings changed; review before continuing.' }
}
function Initialize-Guard {
    $statePath = Get-GuardPath 'private\deployment.json'
    if (Test-Path $statePath) { throw 'Already initialized; use diagnostics or removal, not a new snapshot.' }
    Assert-GuardNoMachinePolicy
    if (Get-GuardPolicyValue 'egressProxyPacUrl') { throw 'Existing PAC policy conflicts.' }
    $desktop = Get-GuardDesktop
    $configDir = Join-Path $env:USERPROFILE '.claude-pro-desktop'
    if (Test-Path $configDir) { throw 'Pro config directory already exists; refusing to overwrite.' }
    $local = Read-GuardJson (Get-GuardPath 'private\bootstrap-local.json')
    $source = [string]$local.SourceConfig
    $coreSource = [string]$local.CorePath
    $node = @((Read-GuardJson $source).outbounds | Where-Object { $_.tag -eq 'proxy' -and $_.type -eq 'vless' })
    if ($node.Count -ne 1 -or $node[0].server -ne $local.ExpectedIp) { throw 'Source fixed VPS did not match approved node.' }
    $nic = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' })
    if ($nic.Count -ne 1) { throw 'Physical interface is ambiguous; explicit review required.' }
    foreach ($dir in @('private','runtime','evidence','browser-profile')) { New-Item -ItemType Directory -Path (Get-GuardPath $dir) -Force | Out-Null; Protect-GuardDirectory (Get-GuardPath $dir) }
    New-Item -ItemType Directory -Path $configDir | Out-Null
    Protect-GuardDirectory $configDir
    Write-GuardJson (Join-Path $configDir 'settings.json') @{autoUpdatesChannel='stable';env=@{HTTP_PROXY='http://127.0.0.1:10818';HTTPS_PROXY='http://127.0.0.1:10818';ALL_PROXY='http://127.0.0.1:10818';NO_PROXY='localhost,127.0.0.1,::1';DISABLE_AUTOUPDATER='1'}}
    Copy-Item -LiteralPath $coreSource -Destination (Get-GuardPath 'runtime\sing-box.exe')
    Copy-Item -LiteralPath "$env:SystemRoot\System32\curl.exe" -Destination (Get-GuardPath 'runtime\network-probe.exe')
    $out = $node[0]
    $out.tag = 'fixed-vps'
    $out | Add-Member -NotePropertyName bind_interface -NotePropertyValue $nic[0].Name -Force
    foreach ($key in @('detour','domain_resolver','domain_strategy','routing_mark')) { $out.PSObject.Properties.Remove($key) }
    $proxyConfig = @{
        log=@{level='warn';timestamp=$true;output=(Get-GuardPath 'private\proxy.log')}
        dns=@{servers=@(@{type='https';tag='vps-doh';server='1.1.1.1';server_port=443;path='/dns-query';tls=@{enabled=$true;server_name='cloudflare-dns.com'};detour='fixed-vps'});final='vps-doh';strategy='prefer_ipv4'}
        inbounds=@(@{type='mixed';tag='local';listen='127.0.0.1';listen_port=10818})
        outbounds=@($out)
        route=@{final='fixed-vps';default_domain_resolver='vps-doh'}
    }
    $cfgPath = Get-GuardPath 'private\proxy.json'
    Write-GuardJson $cfgPath $proxyConfig
    $check = & (Get-GuardPath 'runtime\sing-box.exe') check -c $cfgPath 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Dedicated sing-box config check failed (details suppressed to protect credentials).' }
    $state = @{
        Schema=1;Created=(Get-Date -Format o);UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        ProxyUrl='http://127.0.0.1:10818';ExpectedIp=[string]$local.ExpectedIp;InterfaceName=$nic[0].Name;InterfaceGuid=$nic[0].InterfaceGuid.ToString()
        ConfigDir=$configDir;Desktop=$desktop;CoreHash=(Get-GuardHash (Get-GuardPath 'runtime\sing-box.exe'));ProxyConfigHash=(Get-GuardHash $cfgPath)
        OriginalCli=@{Path=(Join-Path $env:USERPROFILE '.claude\settings.json');Hash=(Get-GuardHash (Join-Path $env:USERPROFILE '.claude\settings.json'))}
        SourceSnapshots=@(@{Path=$source;Hash=(Get-GuardHash $source)},@{Path=[string]$local.GuiConfig;Hash=(Get-GuardHash ([string]$local.GuiConfig))})
        PolicyBackup=@{KeyExisted=(Test-Path $script:Policy);Value=(Get-GuardPolicyValue 'egressProxyUrl');Kind=$null}
        CodeCoverage='unverified';CodePaths=@();FirewallInstalled=$false;PolicyInstalled=$false
    }
    if ($null -ne $state.PolicyBackup.Value) { $state.PolicyBackup.Kind=(Get-Item $script:Policy).GetValueKind('egressProxyUrl').ToString() }
    Write-GuardJson $statePath $state
    Write-Output 'Initialized dedicated proxy, restricted credential storage, and Pro config. No desktop policy changed yet.'
}
function Install-GuardUserPolicy {
    $d=Get-GuardState
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $d.UserSid) { throw 'Cannot install policy for a different Windows account.' }
    Assert-GuardNoMachinePolicy
    if (Get-GuardPolicyValue 'egressProxyPacUrl') { throw 'PAC conflict.' }
    $now = Get-GuardPolicyValue 'egressProxyUrl'
    if ($now -ne $d.PolicyBackup.Value -and $now -ne $d.ProxyUrl) { throw 'Existing policy changed since backup.' }
    New-Item -Path $script:Policy -Force | Out-Null
    New-ItemProperty -Path $script:Policy -Name egressProxyUrl -Value $d.ProxyUrl -PropertyType String -Force | Out-Null
    if($d.PSObject.Properties['Reliability']) {
        $update=Get-GuardPolicyValue 'disableAutoUpdates'
        if($null -ne $update -and $update -ne 1){throw 'Existing update policy changed externally.'}
        New-ItemProperty -Path $script:Policy -Name disableAutoUpdates -Value 1 -PropertyType DWord -Force|Out-Null
    }
    $d.PolicyInstalled=$true
    Write-GuardJson (Get-GuardPath 'private\deployment.json') $d
    Assert-GuardPolicy
}
function Get-GuardCodeCacheRoots($Desktop) {
    # Desktop 3.x moved its user data outside MSIX LocalCache. Keep legacy caches gated.
    if (-not $Desktop -or $Desktop.Family -notmatch '^[A-Za-z0-9]+_[A-Za-z0-9]+$') { throw 'Invalid Claude package family for Code cache paths.' }
    @(
        (Join-Path $env:APPDATA 'Claude\claude-code'),
        (Join-Path $env:LOCALAPPDATA ('Packages\'+$Desktop.Family+'\LocalCache\Roaming\Claude\claude-code')),
        (Join-Path $env:LOCALAPPDATA ('Claude-Data\'+$Desktop.Family.ToLowerInvariant()+'\claude-code'))
    )
}
function Repair-GuardDesktopCodeCache {
    # 仅补齐桌面上下文缺失的已核准载荷；已有目录/文件必须通过原门禁。
    if (-not (Test-GuardAdmin)) { throw 'Same-account administrator rights are required for Code cache deployment.' }
    $d=Get-GuardState
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $d.UserSid) { throw 'Cannot repair Code cache for a different Windows account.' }
    if ($d.CodeCoverage -notin @('prepared','verified')) { throw 'Code cache repair requires an approved deployment.' }
    $expectedRoots=@(Get-GuardCodeCacheRoots $d.Desktop)
    if (@(Compare-Object @($expectedRoots|Sort-Object) @($d.CodeGate.Roots|Sort-Object)).Count) { throw 'Code cache roots differ from the approved desktop paths.' }
    $relativeCode=if($d.PSObject.Properties['Reliability']){$d.CodeGate.Version+'\'+$d.CodeGate.CompressedHash.Substring(0,12)+'\claude.exe'}else{$d.CodeGate.Version+'\claude.exe'}
    $expectedPaths=@($expectedRoots|ForEach-Object {Join-Path $_ $relativeCode})
    if (@(Compare-Object @($expectedPaths|Sort-Object) @($d.CodePaths|Sort-Object)).Count) { throw 'Code binary paths differ from the approved deployment.' }
    $payload=if($d.CodeGate.PSObject.Properties['PayloadPath']){$d.CodeGate.PayloadPath}else{Get-GuardPath 'private\official-code.exe'}
    if ((Get-GuardHash $payload) -ne $d.CodeGate.PayloadHash) { throw 'Pinned Code source payload changed.' }
    if ((Get-GuardHash $d.CodeGate.ArchivePath) -ne $d.CodeGate.ArchiveHash) { throw 'Desktop engine metadata changed; cache repair refused.' }
    Assert-GuardFirewall -DesktopOnly
    Import-Module (Join-Path $script:Root 'ClaudeCodeGate.psm1')
    # 先完整预检，避免修复第一处后才发现第二处已有配置冲突。
    foreach($root in $expectedRoots) { if (Test-Path -LiteralPath $root) { Assert-CodeCacheGate $root } }
    foreach($path in $expectedPaths) {
        Assert-GuardRule $path
        Assert-GuardSharedProxyBlock $path
        if ((Test-Path -LiteralPath $path) -and (Get-GuardHash $path) -ne $d.CodeGate.PayloadHash) { throw 'Existing Code binary differs from the approved payload; repair refused.' }
    }
    $created=@()
    foreach($root in $expectedRoots) {
        if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force|Out-Null; Set-CodeCacheGate $root; $created+=$root }
        $path=Join-Path $root $relativeCode
        $versionDir=Split-Path $path -Parent
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -ItemType Directory -Path $versionDir -Force|Out-Null
            Copy-Item -LiteralPath $payload -Destination $path
            [IO.File]::WriteAllText((Join-Path $versionDir '.verified'),$d.CodeGate.CompressedHash,[Text.UTF8Encoding]::new($false))
            Write-GuardJson (Join-Path $versionDir '.payload') @{sha256=$d.CodeGate.PayloadHash;size=(Get-Item -LiteralPath $path).Length}
        }
        # An existing verified payload may still inherit the cache's execution deny.
        Protect-CodeBinary $path
    }
    Test-CodeCacheGate
    Assert-CodePrepared
    Write-GuardJson (Get-GuardPath 'evidence\code-cache-desktop-repair.json') @{Time=(Get-Date -Format o);Success=$true;CreatedRoots=$created;CodeVersion=$d.CodeGate.Version;PayloadHash=$d.CodeGate.PayloadHash;UnknownExecutableBlocked=$true;CodeCoverage=$d.CodeCoverage}
}
function Install-GuardDesktopUserPolicy([switch]$RepairCodeCache) {
    # 由交互式桌面用户令牌执行安装，并以该进程的回读作为验收依据。
    $d=Get-GuardState
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($sid -ne $d.UserSid) { throw 'Cannot install policy for a different Windows account.' }
    if (-not (Test-GuardAdmin)) { throw 'Same-account administrator rights are required to install desktop policy.' }
    $id=[guid]::NewGuid().ToString('N')
    $taskName='ClaudeProGuard-PolicyRepair-'+$id
    $resultPath=Get-GuardPath ('private\policy-install-'+$id+'.json')
    $launcherPaths=Get-GuardPath 'private\launcher-paths.txt'
    $shell=if (Test-Path -LiteralPath $launcherPaths) { (Get-Content -LiteralPath $launcherPaths -Raw).Trim() } else { (Get-Command pwsh -ErrorAction Stop).Source }
    if (-not (Test-Path -LiteralPath $shell -PathType Leaf)) { throw 'Launcher PowerShell runtime is missing.' }
    $service=New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder=$service.GetFolder('\')
    $definition=$service.NewTask(0)
    $definition.RegistrationInfo.Description='Claude 安全入口：同账号桌面会话的一次性代理策略修复。'
    $definition.Principal.UserId=$sid
    $definition.Principal.LogonType=3 # InteractiveToken，无密码，沿用已授权的管理员权限。
    $definition.Principal.RunLevel=1
    $definition.Settings.Hidden=$true
    $definition.Settings.AllowDemandStart=$true
    $definition.Settings.DisallowStartIfOnBatteries=$false
    $definition.Settings.StopIfGoingOnBatteries=$false
    $definition.Settings.ExecutionTimeLimit='PT1M'
    $action=$definition.Actions.Create(0)
    $action.Path=$shell
    $action.WorkingDirectory=$script:Root
    $action.Arguments='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+(Get-GuardPath 'Install-ClaudeGuard.ps1')+'" -PolicyWorker -ResultFile "'+$resultPath+'"'
    if ($RepairCodeCache) { $action.Arguments+=' -RepairCodeCache' }
    $registered=$null
    try {
        $registered=$folder.RegisterTaskDefinition($taskName,$definition,6,$sid,$null,3,$null)
        $null=$registered.Run($null)
        $watch=[Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath $resultPath)) {
            if ($watch.Elapsed.TotalSeconds -ge 60) { throw 'Desktop policy installation timed out; startup remains stopped.' }
            Start-Sleep -Milliseconds 200
        }
        $result=Read-GuardJson $resultPath
        Write-GuardJson (Get-GuardPath 'evidence\policy-install-desktop-context.json') $result
        if (-not $result.Success) { throw ('Desktop policy installation failed: '+$result.Reason) }
        if ($result.UserSid -ne $d.UserSid -or $result.ProxyPolicy -ne $d.ProxyUrl -or -not $result.PolicyVerified) { throw 'Desktop policy installation readback is inconsistent.' }
    } finally {
        if ($registered) {
            # 只清理本次创建的唯一任务，不影响既有计划任务。
            $registered.Stop(0)
            $folder.DeleteTask($taskName,0)
        }
        if (Test-Path -LiteralPath $resultPath) { Remove-Item -LiteralPath $resultPath }
    }
}
function Test-GuardLoopbackAccept([int]$Port=10818) {
    $client=[Net.Sockets.TcpClient]::new()
    try {
        $connect=$client.ConnectAsync([Net.IPAddress]::Loopback,$Port)
        $connect.Wait(500) -and $client.Connected
    }catch{$false}finally{$client.Dispose()}
}
function Get-GuardListener {
    # 本机曾把同一监听端点报告为 0、Closed、FinWait1；State 不能作为存在性的依据。
    # 只保留无远端的端点，并实际验证接受连接；调用方仍核验地址和进程身份。
    try{$rows=@(Get-NetTCPConnection -LocalPort 10818 -ErrorAction Stop)}
    catch{if($_.CategoryInfo.Category -eq 'ObjectNotFound'){return};throw}
    $endpoints=@($rows|Where-Object {$_.RemotePort -eq 0 -and $_.RemoteAddress -in @('0.0.0.0','::')})
    if($endpoints.Count -and (Test-GuardLoopbackAccept)){$endpoints}
}
function Get-GuardProxyProcessIdentity($Listener) {
    $d=Get-GuardState;$core=Get-GuardCorePath $d;$cfg=Get-GuardPath 'private\proxy.json'
    if(-not $Listener -or $Listener.LocalAddress -ne '127.0.0.1'){throw 'Proxy absent or unexpected listeners.'}
    $live=Get-Process -Id $Listener.OwningProcess -ErrorAction Stop
    try {
        $null=$live.Handle
        $proc=Get-CimInstance Win32_Process -Filter "ProcessId=$($Listener.OwningProcess)" -ErrorAction Stop
        $command='^\s*"?'+[regex]::Escape($core)+'"?\s+run\s+-c\s+"'+[regex]::Escape($cfg)+'"\s*$'
        if(-not $proc -or $proc.ExecutablePath -ne $core -or $proc.CommandLine -notmatch $command -or $live.HasExited){throw 'Port belongs to another program or configuration.'}
        [pscustomobject]@{Pid=[int]$live.Id;Started=$live.StartTime.ToUniversalTime().ToString('o')}
    }finally{$live.Dispose()}
}
function Sync-GuardProxyProcess([switch]$SupervisorWorker) {
    Assert-GuardCore -ConfigurationOnly
    $listeners=@(Get-GuardListener)
    if($listeners.Count -ne 1){throw 'Proxy absent or unexpected listeners.'}
    $identity=Get-GuardProxyProcessIdentity $listeners[0]
    $path=Get-GuardPath 'private\proxy-process.json'
    $tracked=if(Test-Path -LiteralPath $path){Read-GuardJson $path}else{$null}
    if($tracked -and $tracked.Pid -eq $identity.Pid -and ([datetime]$tracked.Started).ToUniversalTime().Ticks -eq ([datetime]$identity.Started).ToUniversalTime().Ticks){return $false}
    # 只接管已核验的同一路径、同一配置和真实端点；不根据陈旧 PID 结束任何进程。
    Write-GuardJson $path @{Pid=$identity.Pid;Started=$identity.Started;SupervisorOwned=[bool]$SupervisorWorker}
    return $true
}
function Assert-GuardCore([switch]$ConfigurationOnly,$ProcessIdentity=$null) {
    $d=Get-GuardState
    $core=Get-GuardCorePath $d
    $cfg=Get-GuardPath 'private\proxy.json'
    if ((Get-GuardHash $core) -ne $d.CoreHash -or (Get-GuardHash $cfg) -ne $d.ProxyConfigHash) { throw 'Proxy runtime or fixed config changed.' }
    $c=Read-GuardJson $cfg
    if((Get-GuardLifecycleValue $d 'ProxyEngine' 'sing-box') -eq 'xray'){Assert-GuardXrayNodePool $c $d}
    elseif (@($c.outbounds).Count -ne 1 -or $c.outbounds[0].type -ne 'vless' -or $c.outbounds[0].server -ne $d.ExpectedIp -or $c.route.final -ne 'fixed-vps') { throw 'Fixed outbound invariant failed.' }
    if((Get-GuardLifecycleValue $d 'ProxyEngine' 'sing-box') -eq 'sing-box' -and $d.PSObject.Properties['Reliability'] -and $d.Reliability.PSObject.Properties['Ipv4Only'] -and $d.Reliability.Ipv4Only) {
        if($c.dns.strategy -ne 'ipv4_only' -or @($c.route.rules).Count -ne 2 -or $c.route.rules[0].ip_version -ne 6 -or $c.route.rules[0].action -ne 'reject' -or $c.route.rules[1].action -ne 'resolve' -or $c.route.rules[1].strategy -ne 'ipv4_only'){throw 'IPv4-only proxy invariant failed.'}
    }
    $nic = Get-NetAdapter -Name $d.InterfaceName -ErrorAction Stop
    if ($nic.Status -ne 'Up' -or $nic.InterfaceGuid.ToString() -ne $d.InterfaceGuid) { throw 'Bound physical interface unavailable or replaced.' }
    if($ConfigurationOnly){return}
    $listeners=@(Get-GuardListener)
    if ($listeners.Count -ne 1 -or $listeners[0].LocalAddress -ne '127.0.0.1') { throw 'Proxy absent or unexpected listeners.' }
    $identity=Get-GuardProxyProcessIdentity $listeners[0]
    $runtime=if($ProcessIdentity){$ProcessIdentity}else{Read-GuardJson (Get-GuardPath 'private\proxy-process.json')}
    if ($runtime.Pid -ne $identity.Pid -or ([datetime]$runtime.Started).ToUniversalTime().Ticks -ne ([datetime]$identity.Started).ToUniversalTime().Ticks) { throw 'Proxy process identity does not match tracked instance.' }
}
function Start-GuardProxy([switch]$SupervisorWorker,[datetime]$DeadlineUtc=[datetime]::MaxValue) {
    $d=Get-GuardState
    if(-not $SupervisorWorker -and $d.PSObject.Properties['Reliability']) {
        if(Test-Path (Get-GuardPath 'private\safety-hold.json')){throw 'SafetyHold: reviewed maintenance is required before restarting protected traffic.'}
        $task=Get-ScheduledTask -TaskName $d.Reliability.TaskName -ErrorAction Stop
        Assert-GuardSupervisorTask $task $d
        if($task.State.ToString() -ne 'Running'){Start-ScheduledTask -TaskName $d.Reliability.TaskName}
        $null=Wait-GuardSupervisorReady -TimeoutSeconds 90 -DeadlineUtc $DeadlineUtc
        Assert-GuardCore
        return
    }
    $mutex=[Threading.Mutex]::new($false,'Local\ClaudeProGuardProxy-v1')
    $held=$false
    try {
    try{$held=$mutex.WaitOne(10000)}catch [Threading.AbandonedMutexException]{$held=$true}
    if(-not $held){throw 'Dedicated proxy startup is busy.'}
    Assert-GuardCore -ConfigurationOnly
    if (@(Get-GuardListener).Count) { $null=Sync-GuardProxyProcess -SupervisorWorker:$SupervisorWorker; Assert-GuardCore; return }
    $core=Get-GuardCorePath $d
    if ((Get-GuardHash $core) -ne $d.CoreHash -or (Get-GuardHash (Get-GuardPath 'private\proxy.json')) -ne $d.ProxyConfigHash) { throw 'Proxy hash changed.' }
    $configured=@(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {$_.ExecutablePath -eq $core -and $_.CommandLine -match ('^\s*"?'+[regex]::Escape($core)+'"?\s+run\s+-c\s+"'+[regex]::Escape((Get-GuardPath 'private\proxy.json'))+'"\s*$')})
    if($configured.Count){throw 'Dedicated proxy is already running; listener could not be verified.'}
    $p=Start-Process -FilePath $core -ArgumentList @('run','-c',('"'+(Get-GuardPath 'private\proxy.json')+'"')) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Get-GuardPath 'private\proxy.stdout.log') -RedirectStandardError (Get-GuardPath 'private\proxy.stderr.log')
    $committed=$false
    try {
        $null=$p.Handle
        $identity=[pscustomobject]@{Pid=$p.Id;Started=$p.StartTime.ToUniversalTime().ToString('o');SupervisorOwned=[bool]$SupervisorWorker}
        for ($i=0;$i -lt 30;$i++) { if($p.HasExited){throw 'Dedicated proxy failed to start.'}; if (@(Get-GuardListener).Count) { break }; Start-Sleep -Milliseconds 100 }
        Assert-GuardCore -ProcessIdentity $identity
        if($p.HasExited){throw 'Dedicated proxy failed to start.'}
        # 只有本次创建的进程已实际监听且全部核验通过后，才提交进程身份。
        Write-GuardJson (Get-GuardPath 'private\proxy-process.json') $identity
        $committed=$true
    }finally{if(-not $committed -and -not $p.HasExited){$p.Kill()};$p.Dispose()}
    } finally {if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
}
function Stop-GuardProxy {
    if (@(Get-GuardListener).Count) { Assert-GuardCore; $p=Read-GuardJson (Get-GuardPath 'private\proxy-process.json'); Stop-Process -Id $p.Pid }
}
function Stop-GuardProxyEmergency {
    $path=Get-GuardPath 'private\proxy-process.json'
    if(-not (Test-Path $path)){return}
    $tracked=Read-GuardJson $path
    $process=Get-CimInstance Win32_Process -Filter "ProcessId=$($tracked.Pid)" -ErrorAction SilentlyContinue
    $running=Get-Process -Id $tracked.Pid -ErrorAction SilentlyContinue
    if($process -and $running -and $process.ExecutablePath -eq (Get-GuardCorePath) -and $running.StartTime.ToUniversalTime().Ticks -eq ([datetime]$tracked.Started).ToUniversalTime().Ticks){Stop-Process -Id $tracked.Pid -ErrorAction SilentlyContinue}
}
function Invoke-GuardProbe([string]$Url,[string]$Proxy='http://127.0.0.1:10818',[int]$MaxTime=12) {
    $out=& (Get-GuardPath 'runtime\network-probe.exe') --silent --show-error --fail --connect-timeout 6 --max-time $MaxTime --proxy $Proxy --noproxy '' $Url 2>$null
    $code=$LASTEXITCODE
    [pscustomobject]@{ExitCode=$code;Body=($out -join "`n")}
}
function Resolve-GuardEgressProbes($Cloudflare,$Ipify,[string[]]$ExpectedIp) {
    $ip1='';$ip2=''
    if($Cloudflare.ExitCode -eq 0){$ip1=([regex]::Match($Cloudflare.Body,'(?m)^ip=(.+)$')).Groups[1].Value.Trim()}
    if($Ipify.ExitCode -eq 0){try{$ip2=[string](($Ipify.Body|ConvertFrom-Json).ip)}catch{}}
    $valid=@()
    foreach($value in @($ip1,$ip2)) {
        if($value) {
            $parsed=$null
            if([Net.IPAddress]::TryParse($value,[ref]$parsed)) {
                if($value -notin $ExpectedIp){throw 'Fixed egress mismatch; protected traffic must stop.'}
                $valid+=$value
            }
        }
    }
    if(-not $valid.Count){throw 'Neutral egress probes failed; desktop startup refused.'}
    [pscustomobject]@{Time=(Get-Date -Format o);CloudflareIp=$ip1;IpifyIp=$ip2;CloudflareCountry=([regex]::Match($Cloudflare.Body,'(?m)^loc=(.+)$')).Groups[1].Value.Trim();VerifiedProbeCount=$valid.Count;ProbeDegraded=($valid.Count -lt 2);CloudflareExitCode=$Cloudflare.ExitCode;IpifyExitCode=$Ipify.ExitCode}
}
function Test-GuardEgress {
    Assert-GuardCore
    $d=Get-GuardState
    $a=Invoke-GuardProbe 'https://www.cloudflare.com/cdn-cgi/trace'
    $b=Invoke-GuardProbe 'https://api.ipify.org?format=json'
    try {Resolve-GuardEgressProbes $a $b @(Get-GuardExpectedIps $d)}
    catch {
        if($_.Exception.Message -match '^Neutral egress probes failed'){throw ('Neutral egress probes failed; desktop startup refused. Cloudflare exit='+$a.ExitCode+'; Ipify exit='+$b.ExitCode+'.')}
        throw
    }
}
function Test-GuardApiTransport {
    $code=& (Get-GuardPath 'runtime\network-probe.exe') --silent --show-error --connect-timeout 6 --max-time 12 --proxy 'http://127.0.0.1:10818' --noproxy '' --output NUL --write-out '%{http_code}' 'https://api.anthropic.com/v1/models' 2>$null
    $exit=$LASTEXITCODE
    $http=[string]($code -join '')
    [pscustomobject]@{Time=(Get-Date -Format o);CurlExitCode=$exit;HttpStatus=$http;TlsTransportReached=($exit -eq 0 -and $http -match '^[1-5][0-9]{2}$');AccountAcceptanceTested=$false}
}
function New-GuardDesktopEnvironment($State) {
    $environment=@{}
    foreach ($k in @([Environment]::GetEnvironmentVariables('Process').Keys)) {
        if ([string]$k -match '^(ANTHROPIC_|CLAUDE_CODE_|CLAUDE_CONFIG_DIR$|CLAUDE_ENV_FILE$|HTTP_PROXY$|HTTPS_PROXY$|ALL_PROXY$|NO_PROXY$|BEDROCK_|AWS_|GOOGLE_|VERTEX_|AZURE_|NODE_OPTIONS$|ELECTRON_RUN_AS_NODE$|NODE_TLS_REJECT_UNAUTHORIZED$|NODE_EXTRA_CA_CERTS$|SSL_CERT_|CURL_CA_BUNDLE$|REQUESTS_CA_BUNDLE$|GLOBAL_AGENT_HTTP_PROXY$|npm_config_(proxy|https_proxy|noproxy)$)') { $environment[[string]$k]=$null }
    }
    $environment['CLAUDE_CONFIG_DIR']=$State.ConfigDir
    $environment['DISABLE_AUTOUPDATER']='1'
    foreach($key in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')){$environment[$key]=$State.ProxyUrl}
    $environment['NO_PROXY']='localhost,127.0.0.1,::1'
    $environment['NODE_TLS_REJECT_UNAUTHORIZED']='1'
    $environment
}
function Get-GuardRuleName([string]$Path) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $hex=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Path.ToLowerInvariant()))).Replace('-',''); 'ClaudeProGuard-'+$hex.Substring(0,20) } finally { $sha.Dispose() }
}
function Assert-GuardRule([string]$Path) {
    $r=Get-NetFirewallRule -PolicyStore ActiveStore -Name (Get-GuardRuleName $Path) -ErrorAction Stop
    $app=$r | Get-NetFirewallApplicationFilter
    $addr=$r | Get-NetFirewallAddressFilter
    $port=$r | Get-NetFirewallPortFilter
    if ($r.Enabled.ToString() -ne 'True' -or $r.Direction.ToString() -ne 'Outbound' -or $r.Action.ToString() -ne 'Block' -or $r.Profile.ToString() -ne 'Any' -or $app.Program -ne $Path -or $port.Protocol.ToString() -ne 'Any') { throw 'Firewall rule is incomplete or changed.' }
    $actual=@($addr.RemoteAddress | Sort-Object)
    # Windows may normalize ranges; compare to the persistent, system-normalized snapshot.
    $snap=Read-GuardJson (Get-GuardPath 'private\firewall.json')
    $s=@($snap.Rules | Where-Object { $_.Path -eq $Path -and $_.Name -eq (Get-GuardRuleName $Path) })
    if ($s.Count -ne 1 -or @(Compare-Object $actual @($s[0].RemoteAddress | Sort-Object)).Count) { throw 'Firewall address coverage changed.' }
}
function Install-GuardFirewall {
    if (-not (Test-GuardAdmin)) { throw 'Administrator rights required to install firewall rules.' }
    $d=Get-GuardState
    $current=Get-GuardDesktop
    if ($current.Path -ne $d.Desktop.Path -or $current.Hash -ne $d.Desktop.Hash) { throw 'Desktop changed since preparation; review and reinitialize coverage.' }
    $paths=@($d.Desktop.Path,(Get-GuardPath 'runtime\network-probe.exe')) + @($d.CodePaths)
    $records=@()
    foreach ($path in $paths) {
        $name=Get-GuardRuleName $path
        $existing=Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
        if ($existing -and $existing.Group -ne $script:Group) { throw 'Firewall rule name collision.' }
        if (-not $existing) {
            New-NetFirewallRule -Name $name -DisplayName ('Claude Pro guard: '+[IO.Path]::GetFileName($path)) -Group $script:Group -Direction Outbound -Action Block -Enabled True -Profile Any -Program $path -Protocol Any -RemoteAddress $script:RemoteRanges | Out-Null
        } else {
            Set-NetFirewallRule -Name $name -Direction Outbound -Action Block -Enabled True -Profile Any -Program $path -Protocol Any -RemoteAddress $script:RemoteRanges | Out-Null
        }
        $r=Get-NetFirewallRule -Name $name
        $records+=@{Name=$name;Path=$path;RemoteAddress=@(($r | Get-NetFirewallAddressFilter).RemoteAddress)}
        foreach($protocol in @('TCP','UDP')) {
            $proxyName='ClaudeProGuardProxy-'+$protocol+'-'+$name.Substring('ClaudeProGuard-'.Length)
            $proxyRule=Get-NetFirewallRule -Name $proxyName -ErrorAction SilentlyContinue
            if($proxyRule -and $proxyRule.Group -ne $script:Group){throw 'Alternative proxy rule name collision.'}
            if($proxyRule){
                Set-NetFirewallRule -Name $proxyName -Direction Outbound -Action Block -Enabled True -Profile Any -Program $path -Protocol $protocol -RemoteAddress @('127.0.0.0/8') -RemotePort @('10808','10813') | Out-Null
            }else{
                New-NetFirewallRule -Name $proxyName -DisplayName 'Claude Pro: block shared proxy' -Group $script:Group -Direction Outbound -Action Block -Enabled True -Profile Any -Program $path -Protocol $protocol -RemoteAddress @('127.0.0.0/8') -RemotePort @('10808','10813') | Out-Null
            }
            $records+=@{Name=$proxyName;Path=$path;Purpose='shared-proxy-block';RemoteAddress=@('127.0.0.0/8')}
        }
    }
    Write-GuardJson (Get-GuardPath 'private\firewall.json') @{Created=(Get-Date -Format o);Rules=$records;RequestedRanges=$script:RemoteRanges}
    foreach ($path in $paths) { Assert-GuardRule $path }
    $d.FirewallInstalled=$true
    Write-GuardJson (Get-GuardPath 'private\deployment.json') $d
}
function Assert-GuardFirewall([switch]$DesktopOnly) {
    $d=Get-GuardState
    foreach ($p in Get-NetFirewallProfile -PolicyStore ActiveStore) { if ($p.Enabled.ToString() -ne 'True') { throw 'A firewall profile is disabled.' } }
    $current=Get-GuardDesktop
    if ($current.Path -ne $d.Desktop.Path -or $current.Version -ne $d.Desktop.Version -or $current.Hash -ne $d.Desktop.Hash) { throw 'Desktop updated; this version is not approved. Do not launch until coverage is refreshed.' }
    Assert-GuardRule $current.Path
    Assert-GuardSharedProxyBlock $current.Path
    if (-not $DesktopOnly) {
        if ($d.CodeCoverage -notin @('prepared','verified') -or @($d.CodePaths).Count -eq 0) { throw 'Actual local Code runtime coverage is not verified. Pro launcher is locked.' }
        foreach ($p in $d.CodePaths) { Assert-GuardRule $p; Assert-GuardSharedProxyBlock $p }
        Import-Module (Join-Path $script:Root 'ClaudeCodeGate.psm1')
        Assert-CodePrepared
    }
}
function Assert-GuardSharedProxyBlock([string]$Path) {
    foreach($protocol in @('TCP','UDP')) {
        $name=Get-GuardRuleName $Path
        $r=Get-NetFirewallRule -PolicyStore ActiveStore -Name ('ClaudeProGuardProxy-'+$protocol+'-'+$name.Substring('ClaudeProGuard-'.Length)) -ErrorAction Stop
        $app=$r|Get-NetFirewallApplicationFilter;$port=$r|Get-NetFirewallPortFilter;$addr=$r|Get-NetFirewallAddressFilter
        $loopbackOnly=(@($addr.RemoteAddress).Count -eq 1 -and @($addr.RemoteAddress)[0] -in @('127.0.0.0/8','127.0.0.0/255.0.0.0'))
        if($r.Enabled.ToString() -ne 'True' -or $r.Action.ToString() -ne 'Block' -or $r.Direction.ToString() -ne 'Outbound' -or $r.Profile.ToString() -ne 'Any' -or $app.Program -ne $Path -or $port.Protocol.ToString() -ne $protocol -or @(Compare-Object @($port.RemotePort|Sort-Object) @('10808','10813')).Count -or -not $loopbackOnly){throw 'Shared proxy exclusion rule is missing or changed.'}
    }
}
function Get-GuardDesktopProcesses {
    $d=Get-GuardState
    @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $d.Desktop.Path })
}
function Get-GuardDesktopNetwork([int]$ProcessId) {
    $d=Get-GuardState
    $processes=@(Get-GuardDesktopProcesses)
    $main=@($processes|Where-Object ProcessId -eq $ProcessId)
    # CIM process metadata can briefly be absent just after CreateProcess.
    if($main.Count -ne 1 -or [string]::IsNullOrWhiteSpace($main[0].CommandLine)){
        return [pscustomobject]@{Time=(Get-Date -Format o);Pid=$ProcessId;Initializing=$true;ExpectedProxyObserved=$false;UnexpectedConnections=@();Connections=@()}
    }
    if($main[0].CommandLine -notmatch '--proxy-server=http://127.0.0.1:10818'){throw 'Protected Desktop fixed proxy argument is missing.'}
    $connections=@(Get-NetTCPConnection -ErrorAction SilentlyContinue|Where-Object {$_.OwningProcess -in @($processes.ProcessId) -and $_.State -in 'Established','SynSent'}|Select-Object OwningProcess,@{n='State';e={$_.State.ToString()}},RemoteAddress,RemotePort)
    $unexpected=@($connections|Where-Object {($_.RemoteAddress -ne '::1' -and $_.RemoteAddress -notlike '127.*') -or (($_.RemoteAddress -eq '::1' -or $_.RemoteAddress -like '127.*') -and $_.RemotePort -in @(10808,10813))})
    $network=@($processes|Where-Object {$_.CommandLine -match 'network.mojom.NetworkService'})
    $fixed=@($connections|Where-Object {$_.OwningProcess -in @($network.ProcessId) -and $_.RemoteAddress -eq '127.0.0.1' -and $_.RemotePort -eq 10818 -and $_.State -eq 'Established'})
    [pscustomobject]@{Time=(Get-Date -Format o);Pid=$ProcessId;Initializing=$false;ExpectedProxyObserved=($fixed.Count -gt 0);UnexpectedConnections=$unexpected;Connections=$connections}
}
function Assert-GuardDesktopNetwork([int]$ProcessId,[datetime]$DeadlineUtc=[datetime]::MaxValue) {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    do {
        $snapshot=Get-GuardDesktopNetwork $ProcessId
        if($snapshot.UnexpectedConnections.Count){throw 'Unexpected Desktop network path observed; do not continue login.'}
        if($snapshot.ExpectedProxyObserved){
            Write-GuardJson (Get-GuardPath 'evidence\startup-network.json') $snapshot
            return
        }
        Start-Sleep -Milliseconds 750
    } while($watch.Elapsed.TotalSeconds -lt 45 -and [datetime]::UtcNow -lt $DeadlineUtc)
    throw 'Actual Desktop proxy connection could not be verified; do not continue login.'
}
function Start-GuardDesktop([datetime]$DeadlineUtc=[datetime]::MaxValue) {
    Assert-GuardPolicy
    Assert-GuardFirewall
    Start-GuardProxy -DeadlineUtc $DeadlineUtc
    $egress=Get-GuardVerifiedEgress
    if (@(Get-GuardDesktopProcesses).Count) { throw 'Claude is already running. Fully exit it before using this launcher.' }
    $d=Get-GuardState
    # Process-only environment: do not modify global/user environment or the ordinary CLI.
    $environment=New-GuardDesktopEnvironment $d
    # Separate log files prevent a long-lived Desktop from keeping the launcher's JSON pipes open.
    $arguments=@(('--proxy-server='+$d.ProxyUrl),'--proxy-bypass-list=localhost;127.0.0.1;[::1]','--disable-quic')
    $proc=Start-Process -FilePath $d.Desktop.Path -WorkingDirectory $script:Root -ArgumentList $arguments -Environment $environment -WindowStyle Normal -PassThru -RedirectStandardOutput (Get-GuardPath 'private\desktop.stdout.log') -RedirectStandardError (Get-GuardPath 'private\desktop.stderr.log')
    Write-GuardJson (Get-GuardPath 'evidence\last-launch.json') @{Time=(Get-Date -Format o);Pid=$proc.Id;ProcessStart=$proc.StartTime.ToUniversalTime().ToString('o');Path=$d.Desktop.Path;ConfigDir=$d.ConfigDir;Proxy=$d.ProxyUrl;Egress=$egress;Mode='pro-local-code';RealCodeSessionVerified=(Test-GuardLocalCodeAcceptance)}
    try { Assert-GuardDesktopNetwork $proc.Id -DeadlineUtc $DeadlineUtc } catch {
        # This launch began with no existing Desktop. Stop only its exact executable tree.
        $owned=@(Get-GuardDesktopProcesses)
        $main=@($owned|Where-Object ProcessId -eq $proc.Id)
        if($main.Count -eq 1 -and (Get-Process -Id $proc.Id).StartTime.ToUniversalTime().Ticks -eq $proc.StartTime.ToUniversalTime().Ticks){
            $allowed=@($proc.Id)
            do{$added=@($owned|Where-Object {$_.ParentProcessId -in $allowed -and $_.ProcessId -notin $allowed}|ForEach-Object {$_.ProcessId});$allowed+=$added}while($added.Count)
            foreach($ownedPid in $allowed){Stop-Process -Id $ownedPid -ErrorAction SilentlyContinue}
        }
        throw
    }
    $proc.Id
}
Export-ModuleMember -Function *-Guard*
