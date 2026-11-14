[CmdletBinding()]
param(
    [string]$Url = 'https://ipkk.com/claude-ip-check',
    [ValidateSet('Auto', 'Dedicated', 'Shared')][string]$ProxyMode = 'Auto',
    [int]$ProxyPort = 0,
    [ValidateSet('Chrome', 'Edge')][string]$Browser = 'Chrome',
    [string]$Lang = 'en-US',
    [switch]$AutoApplyPolicy,
    [switch]$Json
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-NetworkEnv.psm1') -Force

$launch = Start-NetworkEnvSafeBrowser -Url $Url -ProxyMode $ProxyMode -ProxyPort $ProxyPort -Browser $Browser -Lang $Lang -AutoApplyPolicy:$AutoApplyPolicy
if ($Json) {
    $launch | ConvertTo-Json -Depth 6
} else {
    Write-Output ("已启动安全隔离浏览器: {0} (PID={1})" -f $launch.Browser, $launch.Pid)
    Write-Output ("代理通道: {0} [{1}] | UDP转发={2} | 防泄露策略={3}" -f $launch.ProxyUrl, $launch.ProxyRole, $launch.UdpAssociateSupported, $launch.PolicyProtected)
    if (-not $launch.PolicyProtected) {
        Write-Warning '当前浏览器防泄露策略尚未启用；建议先执行 Set-ClaudeWebRtcPolicy.ps1 -Enable 以阻断非代理 UDP 与 DoH 泄露。'
    }
}
