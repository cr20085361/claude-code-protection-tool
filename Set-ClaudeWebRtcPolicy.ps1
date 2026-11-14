[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Enable', Mandatory)][switch]$Enable,
    [Parameter(ParameterSetName = 'Restore', Mandatory)][switch]$Restore,
    [Parameter(ParameterSetName = 'Status')][switch]$Status,
    [ValidateSet('All', 'Chrome', 'Edge')][string]$Browser = 'All',
    [string]$TargetUserSid,
    [string]$ResultFile,
    [switch]$NoElevate,
    [switch]$Json
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-NetworkEnv.psm1') -Force

$targets = if ($Browser -eq 'All') { @('Chrome', 'Edge') } else { @($Browser) }
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$regRoot = if ($TargetUserSid -and $TargetUserSid -ne $currentSid) {
    "Registry::HKEY_USERS\$TargetUserSid\Software\Policies"
} else {
    'HKCU:\Software\Policies'
}

if ($ResultFile) {
    $payload = [ordered]@{ Success = $false; Action = $PSCmdlet.ParameterSetName; Browsers = @(); Error = $null }
    try {
        $res = if ($Enable) {
            Enable-NetworkEnvBrowserPolicy -Browsers $targets -RegistryRoot $regRoot
        } elseif ($Restore) {
            Restore-NetworkEnvBrowserPolicy -Browsers $targets -RegistryRoot $regRoot
        } else {
            Get-NetworkEnvBrowserPolicyStatus -Browsers $targets -RegistryRoot $regRoot
        }
        $payload.Success = $true
        $payload.Browsers = @($res)
    } catch {
        $payload.Error = $_.Exception.Message
    }
    $dir = Split-Path -Path $ResultFile -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $tmp = $ResultFile + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    [IO.File]::WriteAllText($tmp, ($payload | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($tmp, $ResultFile, $true)
    if (-not $payload.Success) { exit 1 }
    exit 0
}

$result = if ($Enable) {
    if (-not $NoElevate -and -not (Test-NetworkEnvPolicyRegistryWritable -RegistryRoot $regRoot -Browsers $targets)) {
        Invoke-NetworkEnvElevatedBrowserPolicy -Mode Enable -Browser $Browser
    } else {
        Enable-NetworkEnvBrowserPolicy -Browsers $targets -RegistryRoot $regRoot
    }
} elseif ($Restore) {
    if (-not $NoElevate -and -not (Test-NetworkEnvPolicyRegistryWritable -RegistryRoot $regRoot -Browsers $targets)) {
        Invoke-NetworkEnvElevatedBrowserPolicy -Mode Restore -Browser $Browser
    } else {
        Restore-NetworkEnvBrowserPolicy -Browsers $targets -RegistryRoot $regRoot
    }
} else {
    Get-NetworkEnvBrowserPolicyStatus -Browsers $targets -RegistryRoot $regRoot
}

if ($Json) {
    [pscustomobject]@{
        Action   = $PSCmdlet.ParameterSetName
        Browsers = @($result)
    } | ConvertTo-Json -Depth 8
} else {
    foreach ($item in $result) {
        Write-Output ("[{0}] Installed={1} | FullyProtected={2} | WebRtcIPHandling={3} | DnsOverHttpsMode={4} | BuiltInDnsClientEnabled={5}" -f `
            $item.Browser, $item.Installed, $item.FullyProtected, ($item.WebRtcIPHandling ?? '<未设置>'), ($item.DnsOverHttpsMode ?? '<未设置>'), $(if ($null -ne $item.BuiltInDnsClientEnabled) { $item.BuiltInDnsClientEnabled } else { '<未设置>' }))
    }
    if ($Enable) {
        Write-Output '已写入当前用户级 Chrome/Edge 防泄露策略（已自动备份至 private\network-env-policy-backup.json）。请重启浏览器或在 chrome://policy 点击“重新加载政策”使其生效。'
    } elseif ($Restore) {
        Write-Output '已恢复/清理 Chrome/Edge 防泄露策略。请重启浏览器生效。'
    }
}
