[CmdletBinding()]
param(
    [int]$Port = 0,
    [ValidateSet('Session', 'User', 'ClearUser', 'Launch')][string]$Scope = 'Session',
    [string]$Command,
    [string[]]$CommandArgs = @(),
    [switch]$UseSocks5hAllProxy,
    [switch]$Verify,
    [switch]$PrintSnippet,
    [switch]$Json
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-NetworkEnv.psm1') -Force

if ($Scope -ne 'ClearUser' -and $Port -le 0) {
    $sel = Get-NetworkEnvProxySelection -ProxyMode Auto
    $Port = $sel.Port
}

if ($PrintSnippet) {
    $map = New-NetworkEnvCliEnvMap -Port $Port -UseSocks5hAllProxy:$UseSocks5hAllProxy
    $snippet = @(
        '# PowerShell (当前终端会话生效，适合运行 claude / codex)'
        ('$env:HTTP_PROXY = "' + $map.HTTP_PROXY + '"')
        ('$env:HTTPS_PROXY = "' + $map.HTTPS_PROXY + '"')
        ('$env:ALL_PROXY = "' + $map.ALL_PROXY + '"')
        ('$env:NO_PROXY = "' + $map.NO_PROXY + '"')
        ('$env:NODE_USE_ENV_PROXY = "' + $map.NODE_USE_ENV_PROXY + '"')
    ) -join [Environment]::NewLine
    if ($Json) {
        [pscustomobject]@{ Port = $Port; Env = $map; Snippet = $snippet } | ConvertTo-Json -Depth 6
    } else {
        Write-Output $snippet
    }
    exit 0
}

if ($Scope -eq 'Launch') {
    if ([string]::IsNullOrWhiteSpace($Command)) {
        throw 'Scope=Launch requires -Command (for example: claude, codex, or pwsh).'
    }
    $resolved = Get-Command $Command -ErrorAction SilentlyContinue
    if (-not $resolved) { throw "Command '$Command' not found in PATH." }
    $map = New-NetworkEnvCliEnvMap -Port $Port -UseSocks5hAllProxy:$UseSocks5hAllProxy
    $psi = [Diagnostics.ProcessStartInfo]::new($resolved.Source)
    $psi.UseShellExecute = $false
    foreach ($kv in $map.GetEnumerator()) {
        $psi.Environment[$kv.Key] = $kv.Value
    }
    foreach ($a in $CommandArgs) { $psi.ArgumentList.Add($a) }
    $proc = [Diagnostics.Process]::Start($psi)
    if (-not $proc) { throw "Failed to start '$Command'." }
    $connectivity = if ($Verify) { Test-NetworkEnvEndpointConnectivity -Port $Port } else { $null }
    $output = [pscustomobject]@{ Scope = 'Launch'; Command = $resolved.Source; Pid = $proc.Id; Port = $Port; Connectivity = $connectivity }
    if ($Json) { $output | ConvertTo-Json -Depth 8 } else { Write-Output ("已使用代理 127.0.0.1:{0} 启动 {1} (PID={2})" -f $Port, $resolved.Name, $proc.Id) }
    exit 0
}

$applied = Set-NetworkEnvCliProxy -Port $Port -Scope $Scope -UseSocks5hAllProxy:$UseSocks5hAllProxy
$connectivity = if ($Verify -and $Scope -ne 'ClearUser') { Test-NetworkEnvEndpointConnectivity -Port $Port } else { $null }
$res = [pscustomobject]@{
    Scope        = $Scope
    Port         = $Port
    Result       = $applied
    Connectivity = $connectivity
}
if ($Json) {
    $res | ConvertTo-Json -Depth 8
} else {
    if ($Scope -eq 'ClearUser') {
        Write-Output '已清除/还原用户级 CLI 代理环境变量。新开终端后生效。'
    } elseif ($Scope -eq 'User') {
        Write-Output ("已写入用户级代理环境变量 (127.0.0.1:{0})，原始配置已备份至 private\network-env-cli-backup.json。新开终端即可直接运行 claude / codex。" -f $Port)
    } else {
        Write-Output ("已设置当前进程代理环境变量 (127.0.0.1:{0})。" -f $Port)
    }
    if ($connectivity) {
        Write-Output ("出口验证: IP={0} ({1}/{2}) | Anthropic={3}({4}) | OpenAI={5}({6})" -f ($connectivity.EgressIp ?? '?'), ($connectivity.Country ?? '?'), ($connectivity.CloudflareColo ?? '?'), $connectivity.AnthropicReachable, $connectivity.AnthropicStatus, $connectivity.OpenAiReachable, $connectivity.OpenAiStatus)
    }
}
