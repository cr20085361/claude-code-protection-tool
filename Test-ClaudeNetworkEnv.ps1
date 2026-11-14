[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'ClaudeGuard-NetworkEnv.psm1'
Import-Module $modulePath -Force

$checks = [Collections.Generic.List[string]]::new()
function Pass([string]$Name, [scriptblock]$Body) {
    & $Body
    $checks.Add($Name)
}
function Refuse([scriptblock]$Body) {
    $failed = $false
    try { & $Body | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw 'Expected exception was not thrown.' }
}

# 1. Static AST parse check for all network-env & modified scripts
Pass 'ast-parse-all-network-env-scripts' {
    $files = @(
        'ClaudeGuard-NetworkEnv.psm1',
        'Get-ClaudeNetworkEnv.ps1',
        'Set-ClaudeWebRtcPolicy.ps1',
        'Start-ClaudeSafeBrowser.ps1',
        'Set-ClaudeCliProxy.ps1',
        'Start-ClaudeLoginBrowser.ps1',
        'Start-ClaudePro.ps1',
        'ClaudeGuard-UiBridge.ps1',
        'Test-ClaudeNetworkEnv.ps1'
    )
    foreach ($f in $files) {
        $tokens = $null; $errors = $null
        $null = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $f), [ref]$tokens, [ref]$errors)
        if ($errors -and $errors.Count -gt 0) {
            throw ("Syntax errors in {0}: {1}" -f $f, ($errors[0].Message))
        }
    }
}

# 2. Loopback SOCKS5 + UDP Associate probe (both REP=0x00 and REP=0x01)
Pass 'socks5-udp-associate-probe-supported-and-declined' {
    foreach ($repByte in @([byte]0x00, [byte]0x01)) {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $ps = $null
        try {
            $port = $listener.LocalEndpoint.Port
            $ps = [powershell]::Create()
            $null = $ps.AddScript({
                param($ListenerObj, [byte]$Reply)
                $client = $ListenerObj.AcceptTcpClient()
                try {
                    $s = $client.GetStream()
                    $g = [byte[]]::new(3)
                    $null = $s.Read($g, 0, 3)
                    if ($g[0] -ne 0x05) { throw 'Bad greeting' }
                    $s.Write([byte[]](0x05, 0x00), 0, 2)
                    $req = [byte[]]::new(10)
                    $null = $s.Read($req, 0, 10)
                    if ($req[1] -ne 0x03) { throw 'Expected UDP ASSOCIATE' }
                    # VER=5, REP=$Reply, RSV=0, ATYP=1, IP=127.0.0.1, PORT=54321 (0xD4, 0x31)
                    $resp = [byte[]](0x05, $Reply, 0x00, 0x01, 127, 0, 0, 1, 0xD4, 0x31)
                    $s.Write($resp, 0, $resp.Length)
                    $s.Flush()
                } finally {
                    $client.Dispose()
                }
            }).AddArgument($listener).AddArgument($repByte)
            $async = $ps.BeginInvoke()
            $probe = Test-NetworkEnvSocks5Probe -HostName '127.0.0.1' -Port $port -TimeoutMs 2500
            $ps.EndInvoke($async)
            if (-not $probe.TcpReachable -or -not $probe.Socks5Supported) { throw 'SOCKS5 handshake failed.' }
            if ($repByte -eq 0x00 -and (-not $probe.UdpAssociateSupported -or $probe.UdpRelayPort -ne 54321)) {
                throw 'Expected UDP Associate support with relay port 54321.'
            }
            if ($repByte -eq 0x01 -and ($probe.UdpAssociateSupported -or $probe.UdpReplyCode -ne 1)) {
                throw 'Expected UDP Associate declined with REP=1.'
            }
        } finally {
            if ($ps) { $ps.Dispose() }
            $listener.Stop()
        }
    }
}

# 3. Sandboxed browser policy enable, idempotency, and exact restore
$testRegRoot = 'HKCU:\Software\ClaudeGuardNetEnvTest-' + [guid]::NewGuid().ToString('N')
$testBackup = Join-Path $PSScriptRoot ('private\test-netenv-policy-backup-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    Pass 'policy-writability-check-distinguishes-sandbox-and-protected-hkcu' {
        $writableSandbox = Test-NetworkEnvPolicyRegistryWritable -RegistryRoot $testRegRoot -Browsers @('Chrome', 'Edge')
        if (-not $writableSandbox) { throw 'Expected sandbox HKCU test root to be writable.' }
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            $writableProtected = Test-NetworkEnvPolicyRegistryWritable -RegistryRoot 'HKCU:\Software\Policies' -Browsers @('Chrome', 'Edge')
            if ($writableProtected) { throw 'Standard user should detect HKCU\Software\Policies as requiring elevation.' }
        }
    }

    Pass 'sandbox-policy-enable-and-clean-restore' {
        $before = @(Get-NetworkEnvBrowserPolicyStatus -Browsers @('Chrome', 'Edge') -RegistryRoot $testRegRoot -MachineRegistryRoot '')
        if ($before[0].FullyProtected -or $before[1].FullyProtected) { throw 'Clean sandbox unexpectedly protected.' }

        $enabled = @(Enable-NetworkEnvBrowserPolicy -Browsers @('Chrome', 'Edge') -RegistryRoot $testRegRoot -BackupFile $testBackup)
        if (-not $enabled[0].FullyProtected -or -not $enabled[1].FullyProtected) { throw 'Policies were not enabled.' }
        # Idempotent re-enable must not overwrite backup
        $null = Enable-NetworkEnvBrowserPolicy -Browsers @('Chrome', 'Edge') -RegistryRoot $testRegRoot -BackupFile $testBackup

        $restored = @(Restore-NetworkEnvBrowserPolicy -Browsers @('Chrome', 'Edge') -RegistryRoot $testRegRoot -BackupFile $testBackup)
        if ($restored[0].FullyProtected -or $restored[1].FullyProtected) { throw 'Policies were not restored.' }
        if (Test-Path -LiteralPath (Join-Path $testRegRoot 'Google\Chrome')) { throw 'Newly created Chrome policy key was not cleaned up.' }
        if (Test-Path -LiteralPath $testBackup) { throw 'Backup file should be removed after full restore.' }
    }

    Pass 'sandbox-policy-preserves-preexisting-values-on-restore' {
        $chromePath = Join-Path $testRegRoot 'Google\Chrome'
        New-Item -Path $chromePath -Force | Out-Null
        Set-ItemProperty -LiteralPath $chromePath -Name 'WebRtcIPHandling' -Value 'default_public_interface_only' -Type String
        Set-ItemProperty -LiteralPath $chromePath -Name 'CustomUnrelatedPolicy' -Value 'keep-me' -Type String

        $null = Enable-NetworkEnvBrowserPolicy -Browsers @('Chrome') -RegistryRoot $testRegRoot -BackupFile $testBackup
        $afterEnable = @(Get-NetworkEnvBrowserPolicyStatus -Browsers @('Chrome') -RegistryRoot $testRegRoot -MachineRegistryRoot '')[0]
        if (-not $afterEnable.FullyProtected) { throw 'Chrome sandbox enable failed.' }

        $afterRestore = @(Restore-NetworkEnvBrowserPolicy -Browsers @('Chrome') -RegistryRoot $testRegRoot -BackupFile $testBackup)[0]
        if ($afterRestore.WebRtcIPHandling -ne 'default_public_interface_only') { throw 'Prior WebRtcIPHandling value was not restored.' }
        if ($null -ne $afterRestore.DnsOverHttpsMode) { throw 'Added DnsOverHttpsMode was not removed.' }
        $unrelated = (Get-ItemProperty -LiteralPath $chromePath -Name 'CustomUnrelatedPolicy').CustomUnrelatedPolicy
        if ($unrelated -ne 'keep-me') { throw 'Unrelated policy value was altered.' }
    }
} finally {
    if (Test-Path -LiteralPath $testRegRoot) { Remove-Item -LiteralPath $testRegRoot -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $testBackup) { Remove-Item -LiteralPath $testBackup -Force -ErrorAction SilentlyContinue }
}

# 4. Safe browser argument builder & proxy selection invariants
Pass 'safe-browser-args-and-scheme-validation' {
    $argList = New-NetworkEnvBrowserArgs -ProxyPort 10808 -ProxyScheme 'socks5' -Lang 'en-US' -Url 'https://ipkk.com/claude-ip-check'
    if ($argList -notcontains '--proxy-server=socks5://127.0.0.1:10808') { throw 'Missing socks5 proxy argument.' }
    if ($argList -notcontains '--disable-quic') { throw 'Missing --disable-quic.' }
    if ($argList -notcontains '--lang=en-US') { throw 'Missing --lang=en-US.' }
    Refuse { New-NetworkEnvBrowserArgs -ProxyPort 10808 -Url 'file:///C:/Windows/System32/calc.exe' }
}

Pass 'proxy-selection-auto-dedicated-shared' {
    $fixtures = @(
        [pscustomobject]@{ Port = 10818; Role = 'DedicatedGuard'; ProcessName = 'xray'; TcpAccepting = $true; Socks5Supported = $true; UdpAssociateSupported = $false },
        [pscustomobject]@{ Port = 10808; Role = 'SystemProxy'; ProcessName = 'xray'; TcpAccepting = $true; Socks5Supported = $true; UdpAssociateSupported = $true }
    )
    $auto = Get-NetworkEnvProxySelection -ProxyMode Auto -Listeners $fixtures
    if ($auto.Port -ne 10808 -or -not $auto.UdpAssociateSupported) { throw 'Auto mode should prefer UDP-capable SOCKS5 listener.' }
    $ded = Get-NetworkEnvProxySelection -ProxyMode Dedicated -Listeners $fixtures
    if ($ded.Port -ne 10818) { throw 'Dedicated mode should pick 10818.' }
    $shared = Get-NetworkEnvProxySelection -ProxyMode Shared -Listeners $fixtures
    if ($shared.Port -ne 10808) { throw 'Shared mode should pick SystemProxy 10808.' }
    $noDedicated = @($fixtures | Where-Object { $_.Port -ne 10818 })
    Refuse { Get-NetworkEnvProxySelection -ProxyMode Dedicated -Listeners $noDedicated }
}

# 5. CLI proxy map & session isolation
Pass 'cli-proxy-env-map-and-session-restore' {
    $saved = @{}
    foreach ($k in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'NODE_USE_ENV_PROXY')) {
        $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
    }
    try {
        $applied = Set-NetworkEnvCliProxy -Port 10808 -Scope Session
        if ($env:HTTPS_PROXY -ne 'http://127.0.0.1:10808' -or $env:NODE_USE_ENV_PROXY -ne '1') { throw 'Session env not set.' }
        if ($applied.Applied.Keys -match 'ANTHROPIC|OPENAI') { throw 'CLI proxy map must never inject provider credentials.' }
    } finally {
        foreach ($k in $saved.Keys) {
            [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process')
        }
    }
}

# 6. Read-only live baseline execution
Pass 'read-only-live-baseline-diagnostic' {
    $b = Get-NetworkEnvBaseline
    if (-not $b -or -not $b.SummaryText -or $b.RiskLevel -notin @('Low', 'Moderate', 'Elevated')) {
        throw 'Invalid baseline report structure.'
    }
}

# 7. Isolated risk config persistence & score gate transitions
$testRiskCfg = Join-Path $PSScriptRoot ('private\test-netenv-riskcfg-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    Pass 'risk-config-persistence-and-range-validation' {
        $def = Get-NetworkEnvRiskConfig -ConfigPath $testRiskCfg
        if (-not $def.GateEnabled -or $def.MaxRiskScore -ne 20) { throw 'Expected default GateEnabled=true, MaxRiskScore=20.' }
        $updated = Set-NetworkEnvRiskConfig -MaxRiskScore 15 -GateEnabled $false -ProxyMode Dedicated -ConfigPath $testRiskCfg
        if ($updated.MaxRiskScore -ne 15 -or $updated.GateEnabled -or $updated.ProxyMode -ne 'Dedicated') { throw 'Config update mismatch.' }
        $reloaded = Get-NetworkEnvRiskConfig -ConfigPath $testRiskCfg
        if ($reloaded.MaxRiskScore -ne 15 -or $reloaded.GateEnabled -or $reloaded.ProxyMode -ne 'Dedicated') { throw 'Config reload mismatch.' }
        Refuse { Set-NetworkEnvRiskConfig -MaxRiskScore 101 -ConfigPath $testRiskCfg }
        Refuse { Set-NetworkEnvRiskConfig -MaxRiskScore -1 -ConfigPath $testRiskCfg }
    }

    Pass 'risk-score-weights-and-gate-blocking' {
        $null = Set-NetworkEnvRiskConfig -GateEnabled $true -MaxRiskScore 20 -ProxyMode Auto -ConfigPath $testRiskCfg
        $unprotectedBaseline = [pscustomobject]@{
            SystemProxy     = [pscustomobject]@{ ProxyEnable = $true; ParsedPort = 10808; AutoConfigURL = '' }
            Listeners       = @([pscustomobject]@{ Port = 10808; Role = 'SystemProxy'; ProcessName = 'xray'; TcpAccepting = $true; Socks5Supported = $true; UdpAssociateSupported = $false })
            BrowserPolicies = @([pscustomobject]@{ Browser = 'Chrome'; Installed = $true; FullyProtected = $false })
            CliStatus       = [pscustomobject]@{ UserEnv = [pscustomobject]@{ HTTPS_PROXY = $null }; ProcessEnv = [pscustomobject]@{ HTTPS_PROXY = $null } }
            IPv6Interfaces  = @()
            TimezoneId      = 'China Standard Time'
            Connectivity    = $null
        }
        $high = Get-NetworkEnvRiskScore -Baseline $unprotectedBaseline -ConfigPath $testRiskCfg
        # Base(+2) + Proxy(0) + Browser(+18) + UDP(+4) + SysProxy(0) + TZ(+6) + IPv6(0) + CLI(+2) = 32
        if ($high.Score -ne 32 -or $high.Grade -ne 'B' -or $high.PassedGate) {
            throw ("Expected score=32 Grade=B PassedGate=false, got Score={0} Grade={1} PassedGate={2}" -f $high.Score, $high.Grade, $high.PassedGate)
        }
        Refuse { Assert-NetworkEnvRiskGate -Baseline $unprotectedBaseline -ConfigPath $testRiskCfg }

        # Explicit override still allows inspection/override when caller requests it
        $overridden = Assert-NetworkEnvRiskGate -Baseline $unprotectedBaseline -ConfigPath $testRiskCfg -AllowOverride
        if ($overridden.Score -ne 32) { throw 'AllowOverride altered score unexpectedly.' }

        # Protecting Chrome drops score by 18 => 14 (Grade A) <= threshold 20
        $protectedBaseline = [pscustomobject]@{
            SystemProxy     = $unprotectedBaseline.SystemProxy
            Listeners       = $unprotectedBaseline.Listeners
            BrowserPolicies = @([pscustomobject]@{ Browser = 'Chrome'; Installed = $true; FullyProtected = $true })
            CliStatus       = $unprotectedBaseline.CliStatus
            IPv6Interfaces  = @()
            TimezoneId      = 'China Standard Time'
            Connectivity    = $null
        }
        $low = Assert-NetworkEnvRiskGate -Baseline $protectedBaseline -ConfigPath $testRiskCfg
        if ($low.Score -ne 14 -or $low.Grade -ne 'A' -or -not $low.PassedGate) {
            throw ("Expected score=14 Grade=A PassedGate=true, got Score={0} Grade={1} PassedGate={2}" -f $low.Score, $low.Grade, $low.PassedGate)
        }

        # Disabling local proxy adds +50 => blocked (>= 64, Grade C/D)
        $noProxyBaseline = [pscustomobject]@{
            SystemProxy     = [pscustomobject]@{ ProxyEnable = $false; ParsedPort = $null; AutoConfigURL = '' }
            Listeners       = @()
            BrowserPolicies = $protectedBaseline.BrowserPolicies
            CliStatus       = $unprotectedBaseline.CliStatus
            IPv6Interfaces  = @()
            TimezoneId      = 'China Standard Time'
            Connectivity    = $null
        }
        $critical = Get-NetworkEnvRiskScore -Baseline $noProxyBaseline -ConfigPath $testRiskCfg
        if ($critical.Score -lt 55 -or $critical.PassedGate) { throw 'Missing local proxy must push score above threshold and block.' }
    }
} finally {
    if (Test-Path -LiteralPath $testRiskCfg) { Remove-Item -LiteralPath $testRiskCfg -Force -ErrorAction SilentlyContinue }
}

$evidenceDir = Join-Path $PSScriptRoot 'evidence'
if (-not (Test-Path -LiteralPath $evidenceDir)) { New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null }
$evidencePath = Join-Path $evidenceDir 'network-env-regression.json'
Write-NetworkEnvJson $evidencePath ([ordered]@{
    Passed      = $true
    FixtureOnly = $true
    CaseCount   = $checks.Count
    Cases       = @($checks)
    Time        = (Get-Date -Format o)
})

[pscustomobject]@{
    Passed    = $true
    CaseCount = $checks.Count
    Cases     = @($checks)
} | ConvertTo-Json -Depth 5
