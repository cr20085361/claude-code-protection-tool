[CmdletBinding()]
param([switch]$FirewallOnly,[switch]$PolicyWorker,[switch]$RepairCodeCache,[string]$ResultFile)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
if ($PolicyWorker) {
    if ($FirewallOnly -or -not $ResultFile) { throw 'Invalid desktop policy worker arguments.' }
    $ResultFile=[IO.Path]::GetFullPath($ResultFile)
    if ([IO.Path]::GetDirectoryName($ResultFile) -ne (Get-GuardPath 'private') -or [IO.Path]::GetFileName($ResultFile) -notmatch '^policy-install-[0-9a-f]{32}\.json$') { throw 'Invalid private policy result path.' }
    $worker=[ordered]@{Time=(Get-Date -Format o);Success=$false;UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;PolicyWasMissing=($null -eq (Get-GuardPolicyValue 'egressProxyUrl'));ProxyPolicy=$null;PolicyVerified=$false;Reason=$null}
    try {
        Install-GuardUserPolicy
        $worker.ProxyPolicy=Get-GuardPolicyValue 'egressProxyUrl'
        $worker.PolicyVerified=$true
        if ($RepairCodeCache) { Repair-GuardDesktopCodeCache }
        $worker.Success=$true
    } catch { $worker.Reason=$_.Exception.Message }
    Write-GuardJson ($ResultFile+'.tmp') $worker
    [IO.File]::Move(($ResultFile+'.tmp'),$ResultFile,$true)
    if (-not $worker.Success) { exit 1 }
    exit 0
}
if ($ResultFile) { throw 'A result path requires the desktop policy worker.' }
if ($FirewallOnly -and $RepairCodeCache) { throw 'Code cache repair requires desktop policy installation.' }
try {
    if ($FirewallOnly) { Install-GuardFirewall } else { Install-GuardDesktopUserPolicy -RepairCodeCache:$RepairCodeCache }
    Write-GuardJson (Get-GuardPath ('evidence\install-'+$(if($FirewallOnly){'firewall'}else{'policy'})+'.json')) @{Time=(Get-Date -Format o);Success=$true}
    Write-Output 'Installation stage completed.'
} catch {
    Write-GuardJson (Get-GuardPath ('evidence\install-'+$(if($FirewallOnly){'firewall'}else{'policy'})+'.json')) @{Time=(Get-Date -Format o);Success=$false;Reason=$_.Exception.Message}
    throw
}
