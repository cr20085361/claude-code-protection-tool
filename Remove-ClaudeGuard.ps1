[CmdletBinding()]
param([switch]$FirewallOnly,[switch]$All)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$d=Get-GuardState
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $d.UserSid) { throw 'Use the same Windows account as installation.' }
if ($All -and $FirewallOnly) { throw 'Use either All or FirewallOnly.' }
if(-not $All -and -not $FirewallOnly){$All=$true}
if ($All -and @(Get-GuardDesktopProcesses).Count) { throw 'Fully exit Claude before restoring settings.' }
if($All) {
    $gui=Get-GuardPath 'runtime\ClaudeProGuard.exe'
    if(@(Get-CimInstance Win32_Process|Where-Object ExecutablePath -eq $gui).Count){throw 'Exit the safety launcher before rollback.'}
    Import-Module (Join-Path $PSScriptRoot 'ClaudeCodeGate.psm1')
    Assert-CodeRollbackReady
    $shortcutRecord=Read-GuardJson (Get-GuardPath 'evidence\desktop-shortcut.json')
    $expectedShortcut=Join-Path ([Environment]::GetFolderPath('Desktop')) 'Claude Pro（安全入口）.lnk'
    if($shortcutRecord.Path -ne $expectedShortcut -or $shortcutRecord.Target -ne $gui){throw 'Owned shortcut metadata changed.'}
    if(Test-Path -LiteralPath $expectedShortcut){
        $shell=New-Object -ComObject WScript.Shell
        if($shell.CreateShortcut($expectedShortcut).TargetPath -ne $gui){throw 'Desktop shortcut changed externally; refusing removal.'}
    }
}
if (-not $FirewallOnly) {
    if (-not (Test-GuardAdmin)) { throw 'Administrator rights required to restore the protected HKCU policy branch.' }
    if (@(Get-GuardDesktopProcesses).Count) { throw 'Fully exit Claude before restoring policy.' }
    $current=Get-GuardPolicyValue 'egressProxyUrl'
    if ($current -and $current -ne $d.ProxyUrl) { throw 'Policy changed externally; refusing to overwrite it.' }
    if($d.PSObject.Properties['Reliability']) {
        $task=Get-ScheduledTask -TaskName $d.Reliability.TaskName -ErrorAction SilentlyContinue
        if($task) {
            Assert-GuardSupervisorTask $task $d
        }
        if((Get-GuardPolicyValue 'disableAutoUpdates') -ne 1){throw 'Update policy changed externally; refusing restoration.'}
    }
}
if(-not $FirewallOnly -and $d.PSObject.Properties['Reliability']) {
    if($task){$null=Suspend-GuardSupervisorTask -State $d -TimeoutSeconds 30;Unregister-ScheduledTask -TaskName $d.Reliability.TaskName -TaskPath '\' -Confirm:$false}
    elseif(@(Get-GuardSupervisorProcessIdentities $d).Count){throw 'Supervisor task is absent while an owned host or worker remains; restoration refused.'}
    if($null -eq $d.UpdatePolicyBackup.Value){Remove-ItemProperty 'HKCU:\SOFTWARE\Policies\Claude' disableAutoUpdates}else{New-ItemProperty 'HKCU:\SOFTWARE\Policies\Claude' disableAutoUpdates -PropertyType $d.UpdatePolicyBackup.Kind -Value $d.UpdatePolicyBackup.Value -Force|Out-Null}
}
if ($FirewallOnly -or $All) {
    if (-not (Test-GuardAdmin)) { throw 'Administrator rights required.' }
    $snapshot=Read-GuardJson (Get-GuardPath 'private\firewall.json')
    $toRemove=@()
    foreach($owned in $snapshot.Rules) {
        $r=Get-NetFirewallRule -Name $owned.Name -ErrorAction SilentlyContinue
        if ($r) {
            if ($r.Group -ne 'ClaudeProGuard-v1' -or ($r|Get-NetFirewallApplicationFilter).Program -ne $owned.Path) { throw 'Owned firewall rule changed externally; refusing deletion.' }
            $toRemove+=$r
        }
    }
    if($All){Undo-CodeCacheGate}
    $toRemove | Remove-NetFirewallRule
    $d.FirewallInstalled=$false
}
if (-not $FirewallOnly) {
    if (@(Get-GuardDesktopProcesses).Count) { throw 'Fully exit Claude before restoring policy.' }
    if (Get-GuardPolicyValue 'egressProxyUrl') {
        if ((Get-GuardPolicyValue 'egressProxyUrl') -ne $d.ProxyUrl) { throw 'Policy changed externally; refusing to overwrite it.' }
        if ($null -eq $d.PolicyBackup.Value) { Remove-ItemProperty 'HKCU:\SOFTWARE\Policies\Claude' egressProxyUrl } else { New-ItemProperty 'HKCU:\SOFTWARE\Policies\Claude' egressProxyUrl -PropertyType $d.PolicyBackup.Kind -Value $d.PolicyBackup.Value -Force | Out-Null }
    }
    if (-not $d.PolicyBackup.KeyExisted -and (Test-Path 'HKCU:\SOFTWARE\Policies\Claude') -and (Get-Item 'HKCU:\SOFTWARE\Policies\Claude').GetValueNames().Count -eq 0) { Remove-Item 'HKCU:\SOFTWARE\Policies\Claude' }
    Stop-GuardProxy
    $d.PolicyInstalled=$false
}
if($All -and (Test-Path -LiteralPath $expectedShortcut)){Remove-Item -LiteralPath $expectedShortcut}
if($All){$d.CodeCoverage='removed'}
if(-not $FirewallOnly -and $d.PSObject.Properties['Reliability']){$d.PSObject.Properties.Remove('Reliability')}
Write-GuardJson (Get-GuardPath 'private\deployment.json') $d
Write-Output 'Owned settings and permissions restored; owned shortcut removed. Cache, credentials and evidence retained locally. Original CLI/v2rayN/browser profiles were not edited.'
