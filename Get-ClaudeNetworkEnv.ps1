[CmdletBinding()]
param(
    [switch]$CheckConnectivity,
    [switch]$RuntimeWatch,
    [ValidateRange(0, 100)][int]$SetThreshold = -1,
    [ValidateSet('Unchanged', 'Enable', 'Disable')][string]$Gate = 'Unchanged',
    [ValidateSet('', 'AutoHealAndWarn', 'StrictTerminate', 'WarnOnly', 'Disabled')][string]$RuntimeMode = '',
    [switch]$Json
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-NetworkEnv.psm1') -Force

if ($SetThreshold -ge 0 -or $Gate -ne 'Unchanged' -or $RuntimeMode) {
    $gateBool = switch ($Gate) { 'Enable' { $true } 'Disable' { $false } default { $null } }
    $threshArg = if ($SetThreshold -ge 0) { $SetThreshold } else { $null }
    $null = Set-NetworkEnvRiskConfig -GateEnabled $gateBool -MaxRiskScore $threshArg -RuntimeEnforcementMode $RuntimeMode
}

$risk = if ($RuntimeWatch) {
    Invoke-NetworkEnvRuntimeWatch -CheckConnectivity:$CheckConnectivity
} else {
    Get-NetworkEnvRiskScore -CheckConnectivity:$CheckConnectivity
}
$baseline = $risk.Baseline
if ($Json) {
    [pscustomobject]@{
        Risk     = $risk
        Baseline = $baseline
    } | ConvertTo-Json -Depth 12
} else {
    Write-Output $risk.Summary
    if ($risk.RuntimeAlertMessage) {
        Write-Output ("动态巡检: [{0}] {1}" -f $risk.RuntimeStatus, $risk.RuntimeAlertMessage)
    }
    Write-Output ''
    Write-Output $baseline.SummaryText
    Write-Output ''
    Write-Output '--- 风险评分明细 ---'
    foreach ($item in $risk.Breakdown) {
        $pts = if ($item.Points -gt 0) { "+$($item.Points)" } else { '0' }
        Write-Output ("[{0}] {1,-18} {2,3} 分 | {3}" -f $item.Status, $item.Label, $pts, $item.Detail)
    }
    if ($baseline.Recommendations.Count -gt 0) {
        Write-Output ''
        Write-Output '--- 建议操作 ---'
        $i = 1
        foreach ($rec in $baseline.Recommendations) {
            Write-Output ("$i. $rec")
            $i++
        }
    }
}
