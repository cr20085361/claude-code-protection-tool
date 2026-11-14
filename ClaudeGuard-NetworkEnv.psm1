Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion -lt [version]'7.4') {
    throw 'Use PowerShell 7.4 or newer (pwsh) for ClaudeGuard-NetworkEnv.'
}

$script:NetEnvRoot = $PSScriptRoot
$script:DefaultCandidatePorts = @(10818, 10808, 10809, 7890, 7897, 2080, 2081)
$script:ManagedBrowserPolicyNames = @('WebRtcIPHandling', 'DnsOverHttpsMode', 'BuiltInDnsClientEnabled')
$script:ManagedCliEnvNames = @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'NODE_USE_ENV_PROXY')

function Get-NetworkEnvPath([string]$RelativePath) {
    Join-Path $script:NetEnvRoot $RelativePath
}

function Initialize-NetworkEnvDirectory([string]$Path) {
    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

function Read-NetworkEnvJson([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8) | ConvertFrom-Json
}

function Write-NetworkEnvJson([string]$Path, $Value) {
    Initialize-NetworkEnvDirectory $Path
    $temp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temp, ($Value | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
        if ([IO.File]::Exists($Path)) {
            [IO.File]::Replace($temp, $Path, [NullString]::Value)
        } else {
            [IO.File]::Move($temp, $Path)
        }
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -ErrorAction SilentlyContinue }
    }
}

function Get-NetworkEnvSystemProxy {
    $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $props = if (Test-Path -LiteralPath $regPath) { Get-ItemProperty -LiteralPath $regPath -ErrorAction SilentlyContinue } else { $null }
    $enabled = if ($props -and $null -ne $props.ProxyEnable) { [int]$props.ProxyEnable -eq 1 } else { $false }
    $server = if ($props -and $props.PSObject.Properties['ProxyServer']) { [string]$props.ProxyServer } else { '' }
    $override = if ($props -and $props.PSObject.Properties['ProxyOverride']) { [string]$props.ProxyOverride } else { '' }
    $pac = if ($props -and $props.PSObject.Properties['AutoConfigURL']) { [string]$props.AutoConfigURL } else { '' }

    $parsedHost = $null
    $parsedPort = $null
    if ($server -match '^(?:https?=)?([^;:=\s]+):(\d+)(?:;|$)') {
        $parsedHost = $Matches[1]
        $parsedPort = [int]$Matches[2]
    } elseif ($server -match 'socks=([^;:\s]+):(\d+)') {
        $parsedHost = $Matches[1]
        $parsedPort = [int]$Matches[2]
    }

    [pscustomobject]@{
        ProxyEnable   = $enabled
        ProxyServer   = $server
        ProxyOverride = $override
        AutoConfigURL = $pac
        ParsedHost    = $parsedHost
        ParsedPort    = $parsedPort
    }
}

function Test-NetworkEnvTcpAccept([string]$HostName = '127.0.0.1', [int]$Port, [int]$TimeoutMs = 400) {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync($HostName, $Port)
        if (-not $task.Wait($TimeoutMs)) { return $false }
        return $client.Connected
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Read-NetworkEnvExactBytes([IO.Stream]$Stream, [int]$Count) {
    $buf = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buf, $offset, $Count - $offset)
        if ($read -le 0) { throw 'Unexpected EOF from SOCKS5 endpoint.' }
        $offset += $read
    }
    $buf
}

function Test-NetworkEnvSocks5Probe {
    [CmdletBinding()]
    param(
        [string]$HostName = '127.0.0.1',
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
        [int]$TimeoutMs = 1500
    )

    $result = [ordered]@{
        Host                  = $HostName
        Port                  = $Port
        TcpReachable          = $false
        Socks5Supported       = $false
        UdpAssociateSupported = $false
        UdpReplyCode          = $null
        UdpRelayPort          = $null
        Error                 = $null
    }

    $client = [Net.Sockets.TcpClient]::new()
    try {
        $connectTask = $client.ConnectAsync($HostName, $Port)
        if (-not $connectTask.Wait($TimeoutMs) -or -not $client.Connected) {
            $result.Error = 'TCP connect timed out or refused.'
            return [pscustomobject]$result
        }
        $result.TcpReachable = $true
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $stream.WriteTimeout = $TimeoutMs

        # SOCKS5 No-Auth Greeting: VER=5, NMETHODS=1, METHOD=0
        $greeting = [byte[]](0x05, 0x01, 0x00)
        $stream.Write($greeting, 0, $greeting.Length)
        $stream.Flush()
        $greetResp = Read-NetworkEnvExactBytes -Stream $stream -Count 2
        if ($greetResp[0] -ne 0x05 -or $greetResp[1] -ne 0x00) {
            $result.Error = ('SOCKS5 greeting rejected (method=0x{0:X2}).' -f $greetResp[1])
            return [pscustomobject]$result
        }
        $result.Socks5Supported = $true

        # SOCKS5 UDP ASSOCIATE: VER=5, CMD=3 (UDP ASSOCIATE), RSV=0, ATYP=1 (IPv4), DST=0.0.0.0:0
        $udpReq = [byte[]](0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        $stream.Write($udpReq, 0, $udpReq.Length)
        $stream.Flush()
        $head = Read-NetworkEnvExactBytes -Stream $stream -Count 4
        if ($head[0] -ne 0x05) {
            $result.Error = 'Invalid SOCKS5 UDP ASSOCIATE response version.'
            return [pscustomobject]$result
        }
        $rep = [int]$head[1]
        $result.UdpReplyCode = $rep
        $atyp = [int]$head[3]
        $addrLen = switch ($atyp) {
            1 { 4 }
            4 { 16 }
            3 {
                $lenByte = Read-NetworkEnvExactBytes -Stream $stream -Count 1
                [int]$lenByte[0]
            }
            default { 0 }
        }
        if ($addrLen -gt 0) {
            $null = Read-NetworkEnvExactBytes -Stream $stream -Count $addrLen
        }
        $portBytes = Read-NetworkEnvExactBytes -Stream $stream -Count 2
        $relayPort = ([int]$portBytes[0] -shl 8) -bor [int]$portBytes[1]
        if ($rep -eq 0) {
            $result.UdpAssociateSupported = $true
            $result.UdpRelayPort = $relayPort
        } else {
            $result.Error = ('SOCKS5 UDP ASSOCIATE declined (REP=0x{0:X2}).' -f $rep)
        }
    } catch {
        $result.Error = $_.Exception.Message
    } finally {
        $client.Dispose()
    }
    [pscustomobject]$result
}

function Get-NetworkEnvListeningProxies {
    [CmdletBinding()]
    param(
        [int[]]$CandidatePorts = $script:DefaultCandidatePorts,
        [switch]$ProbeSocks5
    )

    $sysProxy = Get-NetworkEnvSystemProxy
    $ports = [Collections.Generic.List[int]]::new()
    foreach ($p in $CandidatePorts) {
        if ($p -gt 0 -and -not $ports.Contains($p)) { $ports.Add($p) }
    }
    if ($sysProxy.ParsedPort -and -not $ports.Contains($sysProxy.ParsedPort)) {
        $ports.Add($sysProxy.ParsedPort)
    }

    $tcpRows = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
        $_.LocalPort -in $ports -and $_.RemotePort -eq 0 -and $_.RemoteAddress -in @('0.0.0.0', '::')
    })

    $found = [Collections.Generic.List[object]]::new()
    foreach ($port in $ports) {
        $rowsForPort = @($tcpRows | Where-Object { $_.LocalPort -eq $port })
        $accepted = Test-NetworkEnvTcpAccept -HostName '127.0.0.1' -Port $port -TimeoutMs 350
        if (-not $accepted -and $rowsForPort.Count -eq 0) { continue }

        $ownerPid = if ($rowsForPort.Count -gt 0) { [int]$rowsForPort[0].OwningProcess } else { $null }
        $procName = $null
        if ($ownerPid) {
            $proc = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
            if ($proc) { $procName = $proc.ProcessName }
        }
        $role = if ($port -eq 10818) { 'DedicatedGuard' } elseif ($sysProxy.ProxyEnable -and $sysProxy.ParsedPort -eq $port) { 'SystemProxy' } else { 'LocalProxy' }
        $probe = if ($ProbeSocks5 -and $accepted) { Test-NetworkEnvSocks5Probe -HostName '127.0.0.1' -Port $port -TimeoutMs 1200 } else { $null }

        $found.Add([pscustomobject]@{
            Port                  = $port
            ListenAddress         = if ($rowsForPort.Count -gt 0) { [string]$rowsForPort[0].LocalAddress } else { '127.0.0.1' }
            TcpAccepting          = $accepted
            OwningPid             = $ownerPid
            ProcessName           = $procName
            Role                  = $role
            Socks5Supported       = if ($probe) { $probe.Socks5Supported } else { $null }
            UdpAssociateSupported = if ($probe) { $probe.UdpAssociateSupported } else { $null }
            UdpReplyCode          = if ($probe) { $probe.UdpReplyCode } else { $null }
            ProbeError            = if ($probe) { $probe.Error } else { $null }
        })
    }
    @($found)
}

function Get-NetworkEnvBrowserRegistrySubPath([string]$Browser) {
    switch ($Browser) {
        'Chrome' { 'Google\Chrome' }
        'Edge'   { 'Microsoft\Edge' }
        default  { throw "Unsupported browser '$Browser'. Expected Chrome or Edge." }
    }
}

function Get-NetworkEnvBrowserExecutable {
    [CmdletBinding()]
    param([ValidateSet('Chrome', 'Edge')][string]$Browser = 'Chrome')

    $candidates = if ($Browser -eq 'Chrome') {
        @(
            (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'),
            (Join-Path $env:LocalAppData 'Google\Chrome\Application\chrome.exe')
        )
    } else {
        @(
            (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),
            (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe'),
            (Join-Path $env:LocalAppData 'Microsoft\Edge\Application\msedge.exe')
        )
    }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return $candidate
        }
    }
    return $null
}

function Read-RegistryValueInfo([string]$KeyPath, [string]$Name) {
    if (-not (Test-Path -LiteralPath $KeyPath)) {
        return [pscustomobject]@{ Exists = $false; Value = $null; Kind = $null }
    }
    $key = Get-Item -LiteralPath $KeyPath -ErrorAction SilentlyContinue
    if (-not $key) { return [pscustomobject]@{ Exists = $false; Value = $null; Kind = $null } }
    $names = @($key.GetValueNames())
    if ($Name -notin $names) {
        return [pscustomobject]@{ Exists = $false; Value = $null; Kind = $null }
    }
    [pscustomobject]@{
        Exists = $true
        Value  = $key.GetValue($Name, $null)
        Kind   = $key.GetValueKind($Name).ToString()
    }
}

function Get-NetworkEnvBrowserPolicyStatus {
    [CmdletBinding()]
    param(
        [ValidateSet('Chrome', 'Edge')][string[]]$Browsers = @('Chrome', 'Edge'),
        [string]$RegistryRoot = 'HKCU:\Software\Policies',
        [string]$MachineRegistryRoot = 'HKLM:\SOFTWARE\Policies'
    )

    $results = [Collections.Generic.List[object]]::new()
    foreach ($browser in $Browsers) {
        $sub = Get-NetworkEnvBrowserRegistrySubPath $browser
        $userPath = Join-Path $RegistryRoot $sub
        $machinePath = if ($MachineRegistryRoot) { Join-Path $MachineRegistryRoot $sub } else { $null }

        $webrtc = Read-RegistryValueInfo $userPath 'WebRtcIPHandling'
        $doh = Read-RegistryValueInfo $userPath 'DnsOverHttpsMode'
        $builtinDns = Read-RegistryValueInfo $userPath 'BuiltInDnsClientEnabled'

        $hklmConflict = $false
        if ($machinePath -and (Test-Path -LiteralPath $machinePath)) {
            $mWebrtc = Read-RegistryValueInfo $machinePath 'WebRtcIPHandling'
            $mDoh = Read-RegistryValueInfo $machinePath 'DnsOverHttpsMode'
            if ($mWebrtc.Exists -or $mDoh.Exists) { $hklmConflict = $true }
        }

        $exe = Get-NetworkEnvBrowserExecutable -Browser $browser
        $results.Add([pscustomobject]@{
            Browser                 = $browser
            Installed               = [bool]$exe
            ExecutablePath          = $exe
            PolicyPath              = $userPath
            WebRtcIPHandling        = $webrtc.Value
            DnsOverHttpsMode        = $doh.Value
            BuiltInDnsClientEnabled = $builtinDns.Value
            WebRtcProtected         = ($webrtc.Exists -and [string]$webrtc.Value -eq 'disable_non_proxied_udp')
            DohDisabled             = ($doh.Exists -and [string]$doh.Value -eq 'off')
            BuiltInDnsDisabled      = ($builtinDns.Exists -and [int]$builtinDns.Value -eq 0)
            FullyProtected          = (
                $webrtc.Exists -and [string]$webrtc.Value -eq 'disable_non_proxied_udp' -and
                $doh.Exists -and [string]$doh.Value -eq 'off' -and
                $builtinDns.Exists -and [int]$builtinDns.Value -eq 0
            )
            MachinePolicyConflict   = $hklmConflict
        })
    }
    @($results)
}

function Enable-NetworkEnvBrowserPolicy {
    [CmdletBinding()]
    param(
        [ValidateSet('Chrome', 'Edge')][string[]]$Browsers = @('Chrome', 'Edge'),
        [string]$RegistryRoot = 'HKCU:\Software\Policies',
        [string]$BackupFile = (Get-NetworkEnvPath 'private\network-env-policy-backup.json')
    )

    $existingBackup = Read-NetworkEnvJson $BackupFile
    $backupMap = @{}
    if ($existingBackup -and $existingBackup.PSObject.Properties['Browsers']) {
        foreach ($prop in $existingBackup.Browsers.PSObject.Properties) {
            $backupMap[$prop.Name] = $prop.Value
        }
    }

    foreach ($browser in $Browsers) {
        $sub = Get-NetworkEnvBrowserRegistrySubPath $browser
        $path = Join-Path $RegistryRoot $sub
        if (-not $backupMap.ContainsKey($browser)) {
            $keyExisted = Test-Path -LiteralPath $path
            $values = [ordered]@{}
            foreach ($name in $script:ManagedBrowserPolicyNames) {
                $info = Read-RegistryValueInfo $path $name
                $values[$name] = [ordered]@{
                    Exists = $info.Exists
                    Value  = $info.Value
                    Kind   = $info.Kind
                }
            }
            $backupMap[$browser] = [ordered]@{
                PolicyPath = $path
                KeyExisted = $keyExisted
                Values     = $values
            }
        }
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        Set-ItemProperty -LiteralPath $path -Name 'WebRtcIPHandling' -Value 'disable_non_proxied_udp' -Type String
        Set-ItemProperty -LiteralPath $path -Name 'DnsOverHttpsMode' -Value 'off' -Type String
        Set-ItemProperty -LiteralPath $path -Name 'BuiltInDnsClientEnabled' -Value 0 -Type DWord
    }

    Write-NetworkEnvJson $BackupFile ([ordered]@{
        SchemaVersion = 1
        SavedAt       = (Get-Date -Format o)
        RegistryRoot  = $RegistryRoot
        Browsers      = $backupMap
    })

    Get-NetworkEnvBrowserPolicyStatus -Browsers $Browsers -RegistryRoot $RegistryRoot
}

function Restore-NetworkEnvBrowserPolicy {
    [CmdletBinding()]
    param(
        [ValidateSet('Chrome', 'Edge')][string[]]$Browsers = @('Chrome', 'Edge'),
        [string]$RegistryRoot = 'HKCU:\Software\Policies',
        [string]$BackupFile = (Get-NetworkEnvPath 'private\network-env-policy-backup.json')
    )

    $backup = Read-NetworkEnvJson $BackupFile
    foreach ($browser in $Browsers) {
        $sub = Get-NetworkEnvBrowserRegistrySubPath $browser
        $path = Join-Path $RegistryRoot $sub
        $entry = if ($backup -and $backup.PSObject.Properties['Browsers'] -and $backup.Browsers.PSObject.Properties[$browser]) {
            $backup.Browsers.$browser
        } else {
            $null
        }

        if ($entry) {
            foreach ($name in $script:ManagedBrowserPolicyNames) {
                $v = $entry.Values.$name
                if ($v -and $v.Exists) {
                    if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
                    $propType = if ($v.Kind -eq 'DWord') { 'DWord' } else { 'String' }
                    Set-ItemProperty -LiteralPath $path -Name $name -Value $v.Value -Type $propType
                } elseif (Test-Path -LiteralPath $path) {
                    Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue
                }
            }
            if (-not $entry.KeyExisted -and (Test-Path -LiteralPath $path)) {
                $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
                if ($item -and $item.ValueCount -eq 0 -and $item.SubKeyCount -eq 0) {
                    Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
                }
            }
        } elseif (Test-Path -LiteralPath $path) {
            foreach ($name in $script:ManagedBrowserPolicyNames) {
                Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue
            }
        }
    }

    if ($backup -and $backup.PSObject.Properties['Browsers']) {
        $remaining = [ordered]@{}
        foreach ($prop in $backup.Browsers.PSObject.Properties) {
            if ($prop.Name -notin $Browsers) {
                $remaining[$prop.Name] = $prop.Value
            }
        }
        if ($remaining.Count -eq 0) {
            if (Test-Path -LiteralPath $BackupFile) { Remove-Item -LiteralPath $BackupFile -ErrorAction SilentlyContinue }
        } else {
            Write-NetworkEnvJson $BackupFile ([ordered]@{
                SchemaVersion = 1
                SavedAt       = $backup.SavedAt
                RegistryRoot  = $RegistryRoot
                Browsers      = $remaining
            })
        }
    }

    Get-NetworkEnvBrowserPolicyStatus -Browsers $Browsers -RegistryRoot $RegistryRoot
}

function Get-NetworkEnvCliProxyStatus {
    [CmdletBinding()]
    param([string]$UserProfileRoot = $env:USERPROFILE)

    $procEnv = [ordered]@{}
    $userEnv = [ordered]@{}
    foreach ($name in $script:ManagedCliEnvNames) {
        $procEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        $userEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'User')
    }

    $claudeCmd = Get-Command claude -ErrorAction SilentlyContinue
    $codexCmd = Get-Command codex -ErrorAction SilentlyContinue
    $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
    $curlCmd = Get-Command curl.exe -ErrorAction SilentlyContinue

    [pscustomobject]@{
        ProcessEnv    = [pscustomobject]$procEnv
        UserEnv       = [pscustomobject]$userEnv
        HasClaudeDir  = (Test-Path -LiteralPath (Join-Path $UserProfileRoot '.claude'))
        HasCodexDir   = (Test-Path -LiteralPath (Join-Path $UserProfileRoot '.codex'))
        ClaudeCliPath = if ($claudeCmd) { $claudeCmd.Source } else { $null }
        CodexCliPath  = if ($codexCmd) { $codexCmd.Source } else { $null }
        NodePath      = if ($nodeCmd) { $nodeCmd.Source } else { $null }
        CurlPath      = if ($curlCmd) { $curlCmd.Source } else { $null }
    }
}

function New-NetworkEnvCliEnvMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
        [switch]$UseSocks5hAllProxy
    )

    $httpUrl = "http://127.0.0.1:$Port"
    $allUrl = if ($UseSocks5hAllProxy) { "socks5h://127.0.0.1:$Port" } else { $httpUrl }
    [ordered]@{
        HTTP_PROXY         = $httpUrl
        HTTPS_PROXY        = $httpUrl
        ALL_PROXY          = $allUrl
        NO_PROXY           = 'localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'
        NODE_USE_ENV_PROXY = '1'
    }
}

function Set-NetworkEnvCliProxy {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 65535)][int]$Port = 10808,
        [ValidateSet('Session', 'User', 'ClearUser')][string]$Scope = 'Session',
        [switch]$UseSocks5hAllProxy,
        [string]$BackupFile = (Get-NetworkEnvPath 'private\network-env-cli-backup.json')
    )

    if ($Scope -eq 'Session') {
        $map = New-NetworkEnvCliEnvMap -Port $Port -UseSocks5hAllProxy:$UseSocks5hAllProxy
        foreach ($kv in $map.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($kv.Key, $kv.Value, 'Process')
        }
        return [pscustomobject]@{ Scope = 'Session'; Applied = $map; Restored = $false }
    }

    if ($Scope -eq 'User') {
        if (-not (Test-Path -LiteralPath $BackupFile)) {
            $snap = [ordered]@{}
            foreach ($name in $script:ManagedCliEnvNames) {
                $snap[$name] = [Environment]::GetEnvironmentVariable($name, 'User')
            }
            Write-NetworkEnvJson $BackupFile ([ordered]@{
                SchemaVersion = 1
                SavedAt       = (Get-Date -Format o)
                UserEnv       = $snap
            })
        }
        $map = New-NetworkEnvCliEnvMap -Port $Port -UseSocks5hAllProxy:$UseSocks5hAllProxy
        foreach ($kv in $map.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($kv.Key, $kv.Value, 'User')
            [Environment]::SetEnvironmentVariable($kv.Key, $kv.Value, 'Process')
        }
        return [pscustomobject]@{ Scope = 'User'; Applied = $map; BackupFile = $BackupFile }
    }

    # ClearUser
    $backup = Read-NetworkEnvJson $BackupFile
    foreach ($name in $script:ManagedCliEnvNames) {
        $prior = if ($backup -and $backup.PSObject.Properties['UserEnv'] -and $backup.UserEnv.PSObject.Properties[$name]) {
            $backup.UserEnv.$name
        } else {
            $null
        }
        [Environment]::SetEnvironmentVariable($name, $prior, 'User')
        [Environment]::SetEnvironmentVariable($name, $prior, 'Process')
    }
    if (Test-Path -LiteralPath $BackupFile) { Remove-Item -LiteralPath $BackupFile -ErrorAction SilentlyContinue }
    [pscustomobject]@{ Scope = 'ClearUser'; RestoredFromBackup = [bool]$backup }
}

function Get-NetworkEnvProxySelection {
    [CmdletBinding()]
    param(
        [ValidateSet('Auto', 'Dedicated', 'Shared')][string]$ProxyMode = 'Auto',
        [int]$ProxyPort = 0,
        $Listeners = $null
    )

    if (-not $Listeners) {
        $Listeners = Get-NetworkEnvListeningProxies -ProbeSocks5
    }
    $list = @($Listeners | Where-Object { $_.TcpAccepting })

    if ($ProxyPort -gt 0) {
        $match = @($list | Where-Object { $_.Port -eq $ProxyPort })
        if ($match.Count -gt 0) {
            return [pscustomobject]@{
                Port                  = $match[0].Port
                Role                  = $match[0].Role
                ProcessName           = $match[0].ProcessName
                Socks5Supported       = [bool]$match[0].Socks5Supported
                UdpAssociateSupported = [bool]$match[0].UdpAssociateSupported
            }
        }
        if (Test-NetworkEnvTcpAccept -Port $ProxyPort) {
            $probe = Test-NetworkEnvSocks5Probe -Port $ProxyPort
            return [pscustomobject]@{
                Port                  = $ProxyPort
                Role                  = 'Custom'
                ProcessName           = $null
                Socks5Supported       = [bool]$probe.Socks5Supported
                UdpAssociateSupported = [bool]$probe.UdpAssociateSupported
            }
        }
        throw "指定的本地代理端口 127.0.0.1:$ProxyPort 未处于监听状态。"
    }

    if ($ProxyMode -eq 'Dedicated') {
        $match = @($list | Where-Object { $_.Port -eq 10818 })
        if ($match.Count -eq 0) {
            throw '本项目专用代理 127.0.0.1:10818 当前未运行（可能处于安全暂停或未启动）。'
        }
        return [pscustomobject]@{
            Port                  = 10818
            Role                  = $match[0].Role
            ProcessName           = $match[0].ProcessName
            Socks5Supported       = [bool]$match[0].Socks5Supported
            UdpAssociateSupported = [bool]$match[0].UdpAssociateSupported
        }
    }

    if ($ProxyMode -eq 'Shared') {
        $sys = @($list | Where-Object { $_.Role -eq 'SystemProxy' })
        if ($sys.Count -gt 0) { $picked = $sys[0] }
        else {
            $nonDedicated = @($list | Where-Object { $_.Port -ne 10818 })
            if ($nonDedicated.Count -eq 0) { throw '未检测到已启动的本地共享代理端口（如 10808 / 7890）。' }
            $picked = $nonDedicated[0]
        }
        return [pscustomobject]@{
            Port                  = $picked.Port
            Role                  = $picked.Role
            ProcessName           = $picked.ProcessName
            Socks5Supported       = [bool]$picked.Socks5Supported
            UdpAssociateSupported = [bool]$picked.UdpAssociateSupported
        }
    }

    # Auto mode: prefer UDP-capable SOCKS5 listener, then Dedicated 10818, then SystemProxy, then any active proxy
    $udpCapable = @($list | Where-Object { $_.Socks5Supported -and $_.UdpAssociateSupported })
    if ($udpCapable.Count -gt 0) {
        $dedUdp = @($udpCapable | Where-Object { $_.Port -eq 10818 })
        $picked = if ($dedUdp.Count -gt 0) { $dedUdp[0] } else { $udpCapable[0] }
    } else {
        $ded = @($list | Where-Object { $_.Port -eq 10818 })
        $sys = @($list | Where-Object { $_.Role -eq 'SystemProxy' })
        $picked = if ($ded.Count -gt 0) { $ded[0] } elseif ($sys.Count -gt 0) { $sys[0] } elseif ($list.Count -gt 0) { $list[0] } else { $null }
    }
    if (-not $picked) {
        throw '未检测到任何正在监听的本地代理端口（10818 / 10808 / 7890 等）。请先启动代理客户端。'
    }
    [pscustomobject]@{
        Port                  = $picked.Port
        Role                  = $picked.Role
        ProcessName           = $picked.ProcessName
        Socks5Supported       = [bool]$picked.Socks5Supported
        UdpAssociateSupported = [bool]$picked.UdpAssociateSupported
    }
}

function New-NetworkEnvBrowserArgs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$ProxyPort,
        [ValidateSet('socks5', 'http')][string]$ProxyScheme = 'socks5',
        [string]$ProfileDir = (Get-NetworkEnvPath 'browser-safe-profile'),
        [string]$Lang = 'en-US',
        [string]$Url = 'https://ipkk.com/claude-ip-check'
    )

    $uri = [uri]$Url
    if ($uri.Scheme -notin @('http', 'https')) {
        throw 'Safe browser only accepts http/https URLs.'
    }

    $argList = [Collections.Generic.List[string]]::new()
    $argList.Add(('--user-data-dir=' + $ProfileDir))
    $argList.Add(('--proxy-server=' + $ProxyScheme + '://127.0.0.1:' + $ProxyPort))
    $argList.Add('--proxy-bypass-list=localhost;127.0.0.1;[::1]')
    $argList.Add('--disable-quic')
    $argList.Add(('--lang=' + $Lang))
    if ($Lang -like 'en*') {
        $argList.Add('--accept-lang=en-US,en;q=0.9')
    }
    $argList.Add('--no-first-run')
    $argList.Add('--no-default-browser-check')
    $argList.Add($uri.AbsoluteUri)
    @($argList)
}

function Start-NetworkEnvSafeBrowser {
    [CmdletBinding()]
    param(
        [string]$Url = 'https://ipkk.com/claude-ip-check',
        [ValidateSet('Auto', 'Dedicated', 'Shared')][string]$ProxyMode = 'Auto',
        [int]$ProxyPort = 0,
        [ValidateSet('Chrome', 'Edge')][string]$Browser = 'Chrome',
        [string]$Lang = 'en-US',
        [switch]$AutoApplyPolicy
    )

    $exe = Get-NetworkEnvBrowserExecutable -Browser $Browser
    if (-not $exe) {
        $fallback = if ($Browser -eq 'Chrome') { 'Edge' } else { 'Chrome' }
        $exe = Get-NetworkEnvBrowserExecutable -Browser $fallback
        if (-not $exe) { throw '未找到 Google Chrome 或 Microsoft Edge 可执行文件。' }
        $Browser = $fallback
    }

    $policyStatus = @(Get-NetworkEnvBrowserPolicyStatus -Browsers @($Browser))[0]
    if (-not $policyStatus.FullyProtected -and $AutoApplyPolicy) {
        $policyStatus = @(Enable-NetworkEnvBrowserPolicy -Browsers @($Browser))[0]
    }

    $selection = Get-NetworkEnvProxySelection -ProxyMode $ProxyMode -ProxyPort $ProxyPort
    $scheme = if ($selection.Socks5Supported) { 'socks5' } else { 'http' }
    $profileDir = Get-NetworkEnvPath 'browser-safe-profile'
    if (-not (Test-Path -LiteralPath $profileDir)) {
        New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    }

    $browserArgs = New-NetworkEnvBrowserArgs -ProxyPort $selection.Port -ProxyScheme $scheme -ProfileDir $profileDir -Lang $Lang -Url $Url
    $psi = [Diagnostics.ProcessStartInfo]::new($exe)
    $psi.UseShellExecute = $false
    foreach ($item in $browserArgs) { $psi.ArgumentList.Add($item) }
    $proc = [Diagnostics.Process]::Start($psi)
    if (-not $proc) { throw '安全隔离浏览器进程启动失败。' }

    [pscustomobject]@{
        Started               = $true
        Pid                   = $proc.Id
        Browser               = $Browser
        ExecutablePath        = $exe
        ProxyUrl              = ($scheme + '://127.0.0.1:' + $selection.Port)
        ProxyRole             = $selection.Role
        UdpAssociateSupported = $selection.UdpAssociateSupported
        PolicyProtected       = $policyStatus.FullyProtected
        ProfileDir            = $profileDir
        Url                   = $Url
    }
}

function Invoke-NetworkEnvCurlProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$ProxyUrl,
        [switch]$StatusOnly
    )

    $probeExe = Get-NetworkEnvPath 'runtime\network-probe.exe'
    if (-not (Test-Path -LiteralPath $probeExe -PathType Leaf)) {
        $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
        if (-not $curl) { throw 'curl.exe / network-probe.exe not found.' }
        $probeExe = $curl.Source
    }

    if ($StatusOnly) {
        $out = & $probeExe --silent --show-error --connect-timeout 6 --max-time 12 --proxy $ProxyUrl --noproxy '' --output NUL --write-out '%{http_code}' $Url 2>$null
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; HttpStatus = ([string]($out -join '')).Trim(); Body = '' }
    }

    $out = & $probeExe --silent --show-error --fail --connect-timeout 6 --max-time 12 --proxy $ProxyUrl --noproxy '' $Url 2>$null
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; HttpStatus = $null; Body = ($out -join "`n") }
}

function Test-NetworkEnvEndpointConnectivity {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port)

    $proxyUrl = "http://127.0.0.1:$Port"
    $ipify = Invoke-NetworkEnvCurlProbe -Url 'https://api.ipify.org?format=json' -ProxyUrl $proxyUrl
    $trace = Invoke-NetworkEnvCurlProbe -Url 'https://www.cloudflare.com/cdn-cgi/trace' -ProxyUrl $proxyUrl
    $anthropic = Invoke-NetworkEnvCurlProbe -Url 'https://api.anthropic.com/v1/models' -ProxyUrl $proxyUrl -StatusOnly
    $openai = Invoke-NetworkEnvCurlProbe -Url 'https://api.openai.com/v1/models' -ProxyUrl $proxyUrl -StatusOnly

    $egressIp = $null
    if ($ipify.ExitCode -eq 0 -and $ipify.Body) {
        try { $egressIp = [string](($ipify.Body | ConvertFrom-Json).ip) } catch {}
    }
    $cfIp = ([regex]::Match($trace.Body, '(?m)^ip=(.+)$')).Groups[1].Value.Trim()
    $cfLoc = ([regex]::Match($trace.Body, '(?m)^loc=(.+)$')).Groups[1].Value.Trim()
    $cfColo = ([regex]::Match($trace.Body, '(?m)^colo=(.+)$')).Groups[1].Value.Trim()
    if (-not $egressIp -and $cfIp) { $egressIp = $cfIp }

    [pscustomobject]@{
        Time               = (Get-Date -Format o)
        ProxyUrl           = $proxyUrl
        EgressIp           = $egressIp
        Country            = $cfLoc
        CloudflareColo     = $cfColo
        AnthropicReachable = ($anthropic.ExitCode -eq 0 -and $anthropic.HttpStatus -match '^[1-5][0-9]{2}$')
        AnthropicStatus    = $anthropic.HttpStatus
        OpenAiReachable    = ($openai.ExitCode -eq 0 -and $openai.HttpStatus -match '^[1-5][0-9]{2}$')
        OpenAiStatus       = $openai.HttpStatus
    }
}

function Get-NetworkEnvInterfaceIPv6Status {
    $adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
    $list = [Collections.Generic.List[object]]::new()
    foreach ($nic in $adapters) {
        $binding = Get-NetAdapterBinding -Name $nic.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue
        $v6Addrs = @(Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike 'fe80*' -and $_.IPAddress -ne '::1' })
        $list.Add([pscustomobject]@{
            Name              = $nic.Name
            IPv6BindingEnabled = if ($binding) { [bool]$binding.Enabled } else { $null }
            GlobalIPv6Count   = $v6Addrs.Count
        })
    }
    @($list)
}

function Get-NetworkEnvBaseline {
    [CmdletBinding()]
    param([switch]$CheckConnectivity)

    $sysProxy = Get-NetworkEnvSystemProxy
    $listeners = @(Get-NetworkEnvListeningProxies -ProbeSocks5)
    $browserPolicies = @(Get-NetworkEnvBrowserPolicyStatus)
    $cliStatus = Get-NetworkEnvCliProxyStatus
    $ipv6 = @(Get-NetworkEnvInterfaceIPv6Status)
    $tz = [TimeZoneInfo]::Local
    $safetyHold = Test-Path -LiteralPath (Get-NetworkEnvPath 'private\safety-hold.json')

    $findings = [Collections.Generic.List[object]]::new()
    $recommendations = [Collections.Generic.List[string]]::new()

    if ($listeners.Count -eq 0) {
        $findings.Add([pscustomobject]@{ Code = 'NoLocalProxy'; Severity = 'Critical'; Message = '未检测到常见本地代理端口监听（10818 / 10808 / 7890 等）。' })
        $recommendations.Add('先启动本地代理客户端（v2rayN / Clash / 本项目专用代理）。')
    }

    $installedBrowsers = @($browserPolicies | Where-Object { $_.Installed })
    $unprotectedBrowsers = @($installedBrowsers | Where-Object { -not $_.FullyProtected })
    if ($unprotectedBrowsers.Count -gt 0) {
        $names = ($unprotectedBrowsers | ForEach-Object { $_.Browser }) -join ' / '
        $findings.Add([pscustomobject]@{ Code = 'WebRtcDohPolicyMissing'; Severity = 'High'; Message = "$names 尚未启用防 WebRTC UDP / DoH 泄露策略，不开 TUN 时易触发高风险扣分（如 31 分）。" })
        $recommendations.Add('运行 Set-ClaudeWebRtcPolicy.ps1 -Enable 或在 UI「网络优化」中一键开启防泄露策略，并重启浏览器验证。')
    }

    $udpReady = @($listeners | Where-Object { $_.Socks5Supported -and $_.UdpAssociateSupported })
    $dedicated = @($listeners | Where-Object { $_.Port -eq 10818 })
    if ($dedicated.Count -gt 0 -and -not $dedicated[0].UdpAssociateSupported) {
        $findings.Add([pscustomobject]@{ Code = 'DedicatedProxyUdpDisabled'; Severity = 'Info'; Message = '专用代理 10818 当前配置为 udp=false；配合 WebRTC 防泄露策略可阻断本地直连泄露。' })
    }
    if ($listeners.Count -gt 0 -and $udpReady.Count -eq 0) {
        $findings.Add([pscustomobject]@{ Code = 'NoSocks5UdpListener'; Severity = 'Medium'; Message = '当前监听的本地代理均未开启 SOCKS5 UDP Associate；启用浏览器防泄露策略可阻断 STUN 直连泄露，若需 STUN 返回 VPS IP 需在代理客户端开启 UDP 转发。' })
        $recommendations.Add('在代理客户端（如 v2rayN / Mihomo）确认本地入站与出站节点均已开启 UDP 转发。')
    }

    if (-not $cliStatus.UserEnv.HTTPS_PROXY -and -not $cliStatus.ProcessEnv.HTTPS_PROXY) {
        $findings.Add([pscustomobject]@{ Code = 'CliProxyUnset'; Severity = 'Medium'; Message = '终端环境未设置 HTTP_PROXY / HTTPS_PROXY，独立运行的 claude / codex CLI 默认不继承 Windows 系统代理。' })
        $recommendations.Add('使用 Set-ClaudeCliProxy.ps1 -Scope Launch -Command claude（或 codex）以会话级代理启动，或按需注入环境变量。')
    }

    if ($tz.Id -match 'China|Taipei' -or [Math]::Abs($tz.BaseUtcOffset.TotalHours - 8) -lt 0.01) {
        $findings.Add([pscustomobject]@{ Code = 'TimezoneMismatchHint'; Severity = 'Low'; Message = "本机系统时区为 $($tz.Id) (UTC+8)，浏览网页版或 ipkk 检测时仍会产生「时区不一致」弱线索。" })
        $recommendations.Add('进阶降分可使用 Start-ClaudeSafeBrowser.ps1（--lang=en-US 隔离配置）或参考 configs/browser_isolation_guide.md。')
    }

    if (@($ipv6 | Where-Object { $_.GlobalIPv6Count -gt 0 }).Count -gt 0) {
        $findings.Add([pscustomobject]@{ Code = 'HostGlobalIPv6Present'; Severity = 'Low'; Message = '本机物理网卡存在全局 IPv6 地址，非代理流量或双栈直连探测可能暴露国内 IPv6。' })
        $recommendations.Add('确保代理客户端及分流规则屏蔽或经代理转发 IPv6 流量。')
    }

    if ($safetyHold) {
        $findings.Add([pscustomobject]@{ Code = 'GuardSafetyHoldActive'; Severity = 'Info'; Message = '注意：本项目专用守护当前存在 private/safety-hold.json 暂停状态，10818 专用代理可能未启动。' })
    }

    $connectivity = $null
    if ($CheckConnectivity -and $listeners.Count -gt 0) {
        try {
            $sel = Get-NetworkEnvProxySelection -ProxyMode Auto -Listeners $listeners
            $connectivity = Test-NetworkEnvEndpointConnectivity -Port $sel.Port
        } catch {
            $connectivity = [pscustomobject]@{ Error = $_.Exception.Message }
        }
    }

    $highOrCritical = @($findings | Where-Object { $_.Severity -in @('Critical', 'High') }).Count
    $medium = @($findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $riskLevel = if ($highOrCritical -gt 0) { 'Elevated' } elseif ($medium -gt 0) { 'Moderate' } else { 'Low' }

    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add("=== 非 TUN 网络环境基线诊断 (Risk: $riskLevel) ===")
    $lines.Add(("系统代理: {0} | Server={1} | PAC={2}" -f $(if ($sysProxy.ProxyEnable) { '已开启' } else { '未开启' }), $(if ($sysProxy.ProxyServer) { $sysProxy.ProxyServer } else { '<无>' }), $(if ($sysProxy.AutoConfigURL) { $sysProxy.AutoConfigURL } else { '<无>' })))
    if ($listeners.Count -eq 0) {
        $lines.Add('本地监听端口: 未检测到活跃代理端口')
    } else {
        foreach ($l in $listeners) {
            $lines.Add(("本地端口 127.0.0.1:{0} [{1}, {2}] -> SOCKS5={3}, UDP转发={4}" -f $l.Port, $l.Role, ($l.ProcessName ?? 'unknown'), $l.Socks5Supported, $l.UdpAssociateSupported))
        }
    }
    foreach ($bp in $browserPolicies) {
        if (-not $bp.Installed) { continue }
        $lines.Add(("浏览器策略 {0}: 防泄露={1} (WebRtcIPHandling={2}, DnsOverHttpsMode={3}, BuiltInDns={4})" -f $bp.Browser, $bp.FullyProtected, ($bp.WebRtcIPHandling ?? '<未设置>'), ($bp.DnsOverHttpsMode ?? '<未设置>'), $(if ($null -ne $bp.BuiltInDnsClientEnabled) { $bp.BuiltInDnsClientEnabled } else { '<未设置>' })))
    }
    $lines.Add(("CLI 代理变量: Session HTTPS_PROXY={0} | User HTTPS_PROXY={1} | Claude={2} | Codex目录={3}" -f ($cliStatus.ProcessEnv.HTTPS_PROXY ?? '<未设置>'), ($cliStatus.UserEnv.HTTPS_PROXY ?? '<未设置>'), ($cliStatus.ClaudeCliPath ?? '<未检测到>'), $cliStatus.HasCodexDir))
    $lines.Add(("本机时区: {0} ({1})" -f $tz.Id, $tz.StandardName))
    if ($connectivity) {
        if ($connectivity.PSObject.Properties['Error']) {
            $lines.Add("连通性探测失败: $($connectivity.Error)")
        } else {
            $lines.Add(("出口连通性 ({0}): EgressIP={1} ({2}/{3}) | Anthropic={4}({5}) | OpenAI={6}({7})" -f $connectivity.ProxyUrl, ($connectivity.EgressIp ?? '?'), ($connectivity.Country ?? '?'), ($connectivity.CloudflareColo ?? '?'), $connectivity.AnthropicReachable, $connectivity.AnthropicStatus, $connectivity.OpenAiReachable, $connectivity.OpenAiStatus))
        }
    }
    if ($findings.Count -gt 0) {
        $lines.Add('--- 风险与提示 ---')
        foreach ($f in $findings) {
            $lines.Add("[$($f.Severity)] $($f.Message)")
        }
    }

    [pscustomobject]@{
        Time              = (Get-Date -Format o)
        RiskLevel         = $riskLevel
        SystemProxy       = $sysProxy
        Listeners         = $listeners
        BrowserPolicies   = $browserPolicies
        CliStatus         = $cliStatus
        IPv6Interfaces    = $ipv6
        TimezoneId        = $tz.Id
        GuardSafetyHold   = $safetyHold
        Connectivity      = $connectivity
        Findings          = @($findings)
        Recommendations   = @($recommendations)
        SummaryText       = ($lines -join [Environment]::NewLine)
    }
}

function Get-NetworkEnvDefaultRiskConfigPath {
    Get-NetworkEnvPath 'private\network-env-config.json'
}

function Get-NetworkEnvRiskConfig {
    [CmdletBinding()]
    param([string]$ConfigPath = (Get-NetworkEnvDefaultRiskConfigPath))

    $defaults = [ordered]@{
        SchemaVersion             = 1
        GateEnabled               = $true
        MaxRiskScore              = 20
        CheckConnectivityOnLaunch = $true
        ProxyMode                 = 'Auto'
        UpdatedAt                 = $null
    }
    $saved = Read-NetworkEnvJson $ConfigPath
    if ($saved) {
        if ($null -ne $saved.PSObject.Properties['GateEnabled']) { $defaults.GateEnabled = [bool]$saved.GateEnabled }
        if ($null -ne $saved.PSObject.Properties['MaxRiskScore']) {
            $v = [int]$saved.MaxRiskScore
            $defaults.MaxRiskScore = [Math]::Max(0, [Math]::Min(100, $v))
        }
        if ($null -ne $saved.PSObject.Properties['CheckConnectivityOnLaunch']) { $defaults.CheckConnectivityOnLaunch = [bool]$saved.CheckConnectivityOnLaunch }
        if ($saved.PSObject.Properties['ProxyMode'] -and [string]$saved.ProxyMode -in @('Auto', 'Dedicated', 'Shared')) {
            $defaults.ProxyMode = [string]$saved.ProxyMode
        }
        if ($saved.PSObject.Properties['UpdatedAt']) { $defaults.UpdatedAt = $saved.UpdatedAt }
    }
    [pscustomobject]@{
        SchemaVersion             = $defaults.SchemaVersion
        GateEnabled               = $defaults.GateEnabled
        MaxRiskScore              = $defaults.MaxRiskScore
        CheckConnectivityOnLaunch = $defaults.CheckConnectivityOnLaunch
        ProxyMode                 = $defaults.ProxyMode
        UpdatedAt                 = $defaults.UpdatedAt
        ConfigPath                = $ConfigPath
    }
}

function Set-NetworkEnvRiskConfig {
    [CmdletBinding()]
    param(
        [Nullable[bool]]$GateEnabled,
        [Nullable[int]]$MaxRiskScore,
        [Nullable[bool]]$CheckConnectivityOnLaunch,
        [ValidateSet('', 'Auto', 'Dedicated', 'Shared')][string]$ProxyMode = '',
        [string]$ConfigPath = (Get-NetworkEnvDefaultRiskConfigPath)
    )

    $current = Get-NetworkEnvRiskConfig -ConfigPath $ConfigPath
    $nextGate = if ($null -ne $GateEnabled) { [bool]$GateEnabled } else { [bool]$current.GateEnabled }
    $nextMax = if ($null -ne $MaxRiskScore) {
        if ([int]$MaxRiskScore -lt 0 -or [int]$MaxRiskScore -gt 100) { throw 'MaxRiskScore must be between 0 and 100.' }
        [int]$MaxRiskScore
    } else { [int]$current.MaxRiskScore }
    $nextConn = if ($null -ne $CheckConnectivityOnLaunch) { [bool]$CheckConnectivityOnLaunch } else { [bool]$current.CheckConnectivityOnLaunch }
    $nextMode = if ($ProxyMode) { $ProxyMode } else { [string]$current.ProxyMode }

    $payload = [ordered]@{
        SchemaVersion             = 1
        GateEnabled               = $nextGate
        MaxRiskScore              = $nextMax
        CheckConnectivityOnLaunch = $nextConn
        ProxyMode                 = $nextMode
        UpdatedAt                 = (Get-Date -Format o)
    }
    Write-NetworkEnvJson $ConfigPath $payload
    Get-NetworkEnvRiskConfig -ConfigPath $ConfigPath
}

function New-NetworkEnvRiskItem {
    param(
        [string]$Id,
        [string]$Label,
        [int]$Points,
        [int]$MaxPoints,
        [string]$Status,
        [string]$Detail,
        [string]$FixHint = ''
    )
    [pscustomobject]@{
        Id        = $Id
        Label     = $Label
        Points    = $Points
        MaxPoints = $MaxPoints
        Status    = $Status
        Detail    = $Detail
        FixHint   = $FixHint
    }
}

function Get-NetworkEnvRiskScore {
    [CmdletBinding()]
    param(
        [switch]$CheckConnectivity,
        [ValidateSet('', 'Auto', 'Dedicated', 'Shared')][string]$ProxyMode = '',
        [string]$ConfigPath = (Get-NetworkEnvDefaultRiskConfigPath),
        $Baseline
    )

    $cfg = Get-NetworkEnvRiskConfig -ConfigPath $ConfigPath
    $effectiveMode = if ($ProxyMode) { $ProxyMode } else { $cfg.ProxyMode }
    $b = if ($null -ne $Baseline) { $Baseline } else { Get-NetworkEnvBaseline -CheckConnectivity:$CheckConnectivity }

    $items = [Collections.Generic.List[object]]::new()

    # 1. Base node baseline (+2)
    $items.Add((New-NetworkEnvRiskItem -Id 'BaseNode' -Label '代理节点基准' -Points 2 -MaxPoints 2 -Status 'Info' -Detail '干净非家宽代理节点基准风险 (+2)' -FixHint ''))

    # 2. Local proxy listener (+50 if missing/unreachable)
    $listeners = @($b.Listeners)
    $selectedProxy = $null
    if ($listeners.Count -gt 0) {
        try { $selectedProxy = Get-NetworkEnvProxySelection -ProxyMode $effectiveMode -Listeners $listeners } catch { $selectedProxy = $null }
    }
    if (-not $selectedProxy) {
        $items.Add((New-NetworkEnvRiskItem -Id 'LocalProxy' -Label '本地代理监听' -Points 50 -MaxPoints 50 -Status 'Risk' -Detail '未检测到可用本地代理端口 (10818/10808/7890 等)' -FixHint '先启动本地代理客户端或恢复守护'))
    } else {
        $items.Add((New-NetworkEnvRiskItem -Id 'LocalProxy' -Label '本地代理监听' -Points 0 -MaxPoints 50 -Status 'Pass' -Detail ("已就绪 127.0.0.1:{0} ({1})" -f $selectedProxy.Port, $selectedProxy.Role) -FixHint ''))
    }

    # 3. Browser WebRTC & DoH policy (+18 if any installed browser unprotected)
    $installedBrowsers = @($b.BrowserPolicies | Where-Object { $_.Installed })
    $unprotected = @($installedBrowsers | Where-Object { -not $_.FullyProtected })
    if ($unprotected.Count -gt 0) {
        $bNames = ($unprotected | ForEach-Object { $_.Browser }) -join '/'
        $items.Add((New-NetworkEnvRiskItem -Id 'BrowserLeakPolicy' -Label 'WebRTC/DoH 防泄露' -Points 18 -MaxPoints 18 -Status 'Risk' -Detail "$bNames 未启用防 WebRTC 与 DoH 泄露策略" -FixHint '点击“开启防泄露策略”或运行一键修复'))
    } else {
        $bDesc = if ($installedBrowsers.Count -gt 0) { (($installedBrowsers | ForEach-Object { $_.Browser }) -join '/') + ' 已启用防泄露策略' } else { '未检测到 Chrome/Edge，无浏览器策略暴露' }
        $items.Add((New-NetworkEnvRiskItem -Id 'BrowserLeakPolicy' -Label 'WebRTC/DoH 防泄露' -Points 0 -MaxPoints 18 -Status 'Pass' -Detail $bDesc -FixHint ''))
    }

    # 4. SOCKS5 / UDP Associate (+4 if selected proxy or all listeners lack UDP)
    $udpReady = @($listeners | Where-Object { $_.Socks5Supported -and $_.UdpAssociateSupported })
    if ($selectedProxy -and $selectedProxy.Socks5Supported -and $selectedProxy.UdpAssociateSupported) {
        $items.Add((New-NetworkEnvRiskItem -Id 'Socks5UdpForward' -Label 'SOCKS5 / UDP 转发' -Points 0 -MaxPoints 4 -Status 'Pass' -Detail ("127.0.0.1:{0} 支持 UDP Associate" -f $selectedProxy.Port) -FixHint ''))
    } elseif ($listeners.Count -gt 0 -and $udpReady.Count -eq 0) {
        $items.Add((New-NetworkEnvRiskItem -Id 'Socks5UdpForward' -Label 'SOCKS5 / UDP 转发' -Points 4 -MaxPoints 4 -Status 'Warn' -Detail '当前活跃代理未开启 SOCKS5 UDP Associate' -FixHint '在代理客户端启用 UDP 转发（配合浏览器防泄露可阻断 STUN）'))
    } else {
        $items.Add((New-NetworkEnvRiskItem -Id 'Socks5UdpForward' -Label 'SOCKS5 / UDP 转发' -Points 4 -MaxPoints 4 -Status 'Warn' -Detail '未确认选中通道的 SOCKS5 UDP 转发能力' -FixHint '切换到支持 UDP 的节点入站或确认代理设置'))
    }

    # 5. System proxy & PAC (+5)
    $sys = $b.SystemProxy
    $portMatched = $false
    if ($sys -and $sys.ProxyEnable -and $sys.ParsedPort) {
        $portMatched = @($listeners | Where-Object { $_.Port -eq [int]$sys.ParsedPort }).Count -gt 0
    }
    $hasPac = $sys -and -not [string]::IsNullOrWhiteSpace([string]$sys.AutoConfigURL)
    if (-not $sys -or -not $sys.ProxyEnable -or $hasPac -or ($listeners.Count -gt 0 -and -not $portMatched)) {
        $sysDetail = if ($hasPac) { '存在系统 PAC 脚本，可能绕过固定端口' } elseif (-not $sys -or -not $sys.ProxyEnable) { 'Windows 系统代理未开启' } else { "系统代理端口 ($($sys.ParsedPort)) 与活跃监听不一致" }
        $items.Add((New-NetworkEnvRiskItem -Id 'SystemProxyAndPac' -Label '系统代理与 PAC' -Points 5 -MaxPoints 5 -Status 'Warn' -Detail $sysDetail -FixHint '启用系统代理并确保指向本地活跃端口，清除异常 PAC'))
    } else {
        $items.Add((New-NetworkEnvRiskItem -Id 'SystemProxyAndPac' -Label '系统代理与 PAC' -Points 0 -MaxPoints 5 -Status 'Pass' -Detail ("系统代理已指向 127.0.0.1:{0}，无 PAC 冲突" -f $sys.ParsedPort) -FixHint ''))
    }

    # 6. Connectivity & API TLS check (+20 when checked & failed)
    $conn = $b.Connectivity
    if ($null -eq $conn) {
        $items.Add((New-NetworkEnvRiskItem -Id 'ConnectivityTls' -Label '出口与 API 连通性' -Points 0 -MaxPoints 20 -Status 'Skipped' -Detail '本次未执行在线连通探测（仅本地环境评分）' -FixHint '勾选“测连通性”可核验真实出口与 TLS 握手'))
    } elseif ($conn.PSObject.Properties['Error'] -and $conn.Error) {
        $items.Add((New-NetworkEnvRiskItem -Id 'ConnectivityTls' -Label '出口与 API 连通性' -Points 20 -MaxPoints 20 -Status 'Risk' -Detail ("代理出口探测失败：$($conn.Error)") -FixHint '检查代理节点连通性及上游 VPS 状态'))
    } elseif (-not $conn.AnthropicReachable -or -not $conn.OpenAiReachable) {
        $items.Add((New-NetworkEnvRiskItem -Id 'ConnectivityTls' -Label '出口与 API 连通性' -Points 20 -MaxPoints 20 -Status 'Risk' -Detail ("目标接口不可达 (Anthropic=$($conn.AnthropicStatus), OpenAI=$($conn.OpenAiStatus))") -FixHint '切换可用节点并重测出口连通性'))
    } else {
        $ipLabel = if ($conn.EgressIp) { "$($conn.EgressIp) ($($conn.Country)/$($conn.CloudflareColo))" } else { '已连通' }
        $items.Add((New-NetworkEnvRiskItem -Id 'ConnectivityTls' -Label '出口与 API 连通性' -Points 0 -MaxPoints 20 -Status 'Pass' -Detail "出口 $ipLabel · Anthropic/OpenAI 可达" -FixHint ''))
    }

    # 7. Timezone weak hint (+6)
    $tzId = [string]$b.TimezoneId
    $tzHint = ($tzId -match 'China|Taipei')
    if (-not $tzHint) {
        try {
            $tzObj = [TimeZoneInfo]::FindSystemTimeZoneById($tzId)
            if ([Math]::Abs($tzObj.BaseUtcOffset.TotalHours - 8) -lt 0.01) { $tzHint = $true }
        } catch {}
    }
    if ($tzHint) {
        $items.Add((New-NetworkEnvRiskItem -Id 'TimezoneHint' -Label '系统时区指纹' -Points 6 -MaxPoints 6 -Status 'Warn' -Detail "本机时区为 $tzId (UTC+8)，存在跨区弱线索" -FixHint '浏览风控检测站可使用隔离浏览器或调整时区'))
    } else {
        $items.Add((New-NetworkEnvRiskItem -Id 'TimezoneHint' -Label '系统时区指纹' -Points 0 -MaxPoints 6 -Status 'Pass' -Detail "系统时区 ($tzId) 无明显东八区跨区提示" -FixHint ''))
    }

    # 8. Host global IPv6 (+3)
    $v6Risk = @($b.IPv6Interfaces | Where-Object { $_.GlobalIPv6Count -gt 0 }).Count -gt 0
    if ($v6Risk) {
        $items.Add((New-NetworkEnvRiskItem -Id 'HostIPv6' -Label '本机全局 IPv6' -Points 3 -MaxPoints 3 -Status 'Warn' -Detail '物理网卡存在全局 IPv6 地址，双栈直连存在暴露风险' -FixHint '在代理规则中拦截或接管 IPv6 流量'))
    } else {
        $items.Add((New-NetworkEnvRiskItem -Id 'HostIPv6' -Label '本机全局 IPv6' -Points 0 -MaxPoints 3 -Status 'Pass' -Detail '无本机公网 IPv6 暴露' -FixHint ''))
    }

    # 9. CLI proxy env (+2)
    $cliOk = $b.CliStatus -and ($b.CliStatus.UserEnv.HTTPS_PROXY -or $b.CliStatus.ProcessEnv.HTTPS_PROXY)
    if (-not $cliOk) {
        $items.Add((New-NetworkEnvRiskItem -Id 'CliProxyEnv' -Label 'CLI 代理环境变量' -Points 2 -MaxPoints 2 -Status 'Warn' -Detail '未设置用户级或会话级 HTTP/HTTPS_PROXY（仅影响终端 CLI）' -FixHint '使用“打开 CLI 代理终端”或“写入用户级 CLI 代理”'))
    } else {
        $items.Add((New-NetworkEnvRiskItem -Id 'CliProxyEnv' -Label 'CLI 代理环境变量' -Points 0 -MaxPoints 2 -Status 'Pass' -Detail '已配置 CLI 代理环境变量' -FixHint ''))
    }

    $rawScore = [int](($items | Measure-Object -Property Points -Sum).Sum)
    $score = [Math]::Max(0, [Math]::Min(100, $rawScore))
    $grade = if ($score -le 8) { 'A+' } elseif ($score -le 25) { 'A' } elseif ($score -le 45) { 'B' } elseif ($score -le 70) { 'C' } else { 'D' }
    $passedGate = (-not $cfg.GateEnabled) -or ($score -le $cfg.MaxRiskScore)

    $topRisks = @($items | Where-Object { $_.Points -gt 0 -and $_.Id -ne 'BaseNode' } | Sort-Object -Property Points -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Label)(+$($_.Points))" })
    $gateText = if (-not $cfg.GateEnabled) { '门禁已关闭（仅提示）' } elseif ($passedGate) { "通过门限 ($score ≤ $($cfg.MaxRiskScore))" } else { "超出门限 ($score > $($cfg.MaxRiskScore))，已拦截" }
    $summary = "网络风险评分: $score / 100 ($grade 级) | $gateText"
    if ($topRisks.Count -gt 0) { $summary += " | 主要扣分: " + ($topRisks -join '、') }

    [pscustomobject]@{
        Time         = (Get-Date -Format o)
        Score        = $score
        Grade        = $grade
        Threshold    = $cfg.MaxRiskScore
        GateEnabled  = $cfg.GateEnabled
        PassedGate   = $passedGate
        ProxyMode    = $effectiveMode
        SelectedPort = if ($selectedProxy) { $selectedProxy.Port } else { $null }
        ConfigPath   = $cfg.ConfigPath
        TopRisks     = $topRisks
        Summary      = $summary
        Breakdown    = @($items)
        Baseline     = $b
    }
}

function Assert-NetworkEnvRiskGate {
    [CmdletBinding()]
    param(
        [switch]$CheckConnectivity,
        [ValidateSet('', 'Auto', 'Dedicated', 'Shared')][string]$ProxyMode = '',
        [string]$ConfigPath = (Get-NetworkEnvDefaultRiskConfigPath),
        $Baseline,
        [switch]$AllowOverride
    )

    $report = Get-NetworkEnvRiskScore -CheckConnectivity:$CheckConnectivity -ProxyMode:$ProxyMode -ConfigPath $ConfigPath -Baseline $Baseline
    if ($report.PassedGate -or $AllowOverride) {
        return $report
    }
    $reasons = if ($report.TopRisks.Count -gt 0) { $report.TopRisks -join '、' } else { '总风险分过高' }
    throw ("NetworkRiskGateBlocked: 已拦截启动，当前网络风险评分 {0}/100 ({1} 级) 高于设定门限 {2}。主要风险：{3}。" -f $report.Score, $report.Grade, $report.Threshold, $reasons)
}

function Test-NetworkEnvPolicyRegistryWritable {
    [CmdletBinding()]
    param(
        [string]$RegistryRoot = 'HKCU:\Software\Policies',
        [ValidateSet('Chrome', 'Edge')][string[]]$Browsers = @('Chrome', 'Edge')
    )

    $disposeHive = $false
    $baseHive = $null
    $relRoot = $null
    try {
        if ($RegistryRoot -match '^HKCU:\\(.+)$') {
            $relRoot = $Matches[1]
            $baseHive = [Microsoft.Win32.Registry]::CurrentUser
        } elseif ($RegistryRoot -match '^Registry::HKEY_USERS\\([^\\]+)\\(.+)$') {
            $sid = $Matches[1]
            $relRoot = $Matches[2]
            $baseHive = [Microsoft.Win32.Registry]::Users.OpenSubKey($sid, $false)
            $disposeHive = $true
            if (-not $baseHive) { return $false }
        } else {
            return $true
        }

        foreach ($browser in $Browsers) {
            $sub = Get-NetworkEnvBrowserRegistrySubPath $browser
            $fullRel = "$relRoot\$sub"
            $parts = $fullRel.Split('\')
            $writable = $false
            for ($i = $parts.Length; $i -ge 1; $i--) {
                $candidate = ($parts[0..($i - 1)]) -join '\'
                try {
                    $k = $baseHive.OpenSubKey($candidate, $true)
                    if ($k) {
                        $k.Close()
                        $writable = $true
                        break
                    }
                } catch {
                    $writable = $false
                    break
                }
            }
            if (-not $writable) { return $false }
        }
        return $true
    } finally {
        if ($disposeHive -and $baseHive) { $baseHive.Dispose() }
    }
}

function Invoke-NetworkEnvElevatedBrowserPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Enable', 'Restore')][string]$Mode,
        [ValidateSet('All', 'Chrome', 'Edge')][string]$Browser = 'All',
        [string]$ShellPath
    )

    if (-not $ShellPath) {
        $launcherPaths = Get-NetworkEnvPath 'private\launcher-paths.txt'
        if (Test-Path -LiteralPath $launcherPaths) {
            $ShellPath = (Get-Content -LiteralPath $launcherPaths -Raw).Trim()
        } else {
            $ShellPath = (Get-Command pwsh -ErrorAction Stop).Source
        }
    }
    $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $scriptPath = Get-NetworkEnvPath 'Set-ClaudeWebRtcPolicy.ps1'
    $resultFile = Get-NetworkEnvPath ('private\netenv-policy-result-' + [guid]::NewGuid().ToString('N') + '.json')
    $modeSwitch = if ($Mode -eq 'Enable') { '-Enable' } else { '-Restore' }
    $argString = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" {1} -Browser {2} -TargetUserSid "{3}" -ResultFile "{4}"' -f $scriptPath, $modeSwitch, $Browser, $userSid, $resultFile

    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $ShellPath
    $psi.Arguments = $argString
    $psi.WorkingDirectory = $script:NetEnvRoot
    $psi.UseShellExecute = $true
    $psi.Verb = 'runas'
    $psi.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden

    $proc = $null
    try {
        try {
            $proc = [Diagnostics.Process]::Start($psi)
        } catch {
            $ex = $_.Exception
            if (($ex -is [ComponentModel.Win32Exception] -and $ex.NativeErrorCode -eq 1223) -or
                ($ex.InnerException -is [ComponentModel.Win32Exception] -and $ex.InnerException.NativeErrorCode -eq 1223)) {
                throw 'AdministratorCancelled: Windows 管理员授权已取消，浏览器防泄露策略未写入（HKCU\Software\Policies 受系统保护，需要管理员权限）。'
            }
            throw
        }
        if (-not $proc.WaitForExit(90000)) {
            throw '等待管理员写入浏览器防泄露策略超时。'
        }
        if (-not (Test-Path -LiteralPath $resultFile)) {
            throw ("提权写入浏览器防泄露策略失败（退出码 {0}，未生成结果文件）。" -f $proc.ExitCode)
        }
        $res = Read-NetworkEnvJson $resultFile
        if (-not $res -or -not $res.Success) {
            $err = if ($res -and $res.Error) { [string]$res.Error } else { '未知错误' }
            throw ("提权写入浏览器防泄露策略失败：{0}" -f $err)
        }
        @($res.Browsers)
    } finally {
        if ($proc) { $proc.Dispose() }
        if (Test-Path -LiteralPath $resultFile) { Remove-Item -LiteralPath $resultFile -Force -ErrorAction SilentlyContinue }
    }
}

Export-ModuleMember -Function *-NetworkEnv*
