[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ClaudeCodeGate.psm1')
$root=Get-GuardPath ('private\rollback-probe-'+[guid]::NewGuid().ToString('N'))
$child=Join-Path $root 'version'
$unapproved=Join-Path $child 'unapproved.exe'
$approved=Join-Path $child 'approved.exe'
New-Item -ItemType Directory -Path $child -Force|Out-Null
function Invoke-LocalVersion([string]$Path) {
    $psi=[Diagnostics.ProcessStartInfo]::new($Path,'--version')
    $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true
    $p=[Diagnostics.Process]::Start($psi)
    $null=$p.StandardOutput.ReadToEnd()
    if(-not $p.WaitForExit(2000)){$p.Kill();throw 'Offline executable verification timed out.'}
    if($p.ExitCode -ne 0){throw 'Offline executable verification failed.'}
}
try {
    Set-CodeCacheGate $root
    foreach($path in @($unapproved,$approved)){Copy-Item (Get-GuardPath 'runtime\network-probe.exe') $path}
    $denied=$false
    try{Invoke-LocalVersion $unapproved}catch [ComponentModel.Win32Exception]{$denied=($_.Exception.NativeErrorCode -eq 5)}
    if(-not $denied){throw 'Fixture execution gate did not block the unapproved file.'}
    $fileAcl=[Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetAccessRuleProtection($true,$false)
    $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.WindowsIdentity]::GetCurrent().User,'ReadAndExecute','Allow'))
    foreach($sid in @('S-1-5-18','S-1-5-32-544')){$fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','Allow'))}
    Set-Acl -LiteralPath $approved -AclObject $fileAcl
    $rootOwner=(Get-Acl -LiteralPath $root).Owner
    $fileOwner=(Get-Acl -LiteralPath $approved).Owner
    Invoke-LocalVersion $approved
    Restore-CodeCachePermissions $root @($approved) ''
    if((Get-Acl $root).AreAccessRulesProtected -or (Get-Acl $approved).AreAccessRulesProtected){throw 'Fixture inheritance was not restored.'}
    if((Get-Acl -LiteralPath $root).Owner -ne $rootOwner -or (Get-Acl -LiteralPath $approved).Owner -ne $fileOwner){throw 'Fixture ownership changed during DACL-only rollback.'}
    Invoke-LocalVersion $approved
    Invoke-LocalVersion $unapproved
    Write-GuardJson (Get-GuardPath 'evidence\code-permission-rollback-test.json') @{Time=(Get-Date -Format o);Passed=$true;Scope='Disposable offline fixture only; production rollback was not executed.';OwnerPreserved=$true;OriginalCacheUntouched=$true;CredentialsUsed=$false;NetworkUsed=$false}
    'Offline permission rollback fixture passed.'
} catch {
    Write-GuardJson (Get-GuardPath 'evidence\code-permission-rollback-test.json') @{Time=(Get-Date -Format o);Passed=$false;Error=$_.Exception.Message;Scope='Disposable offline fixture only; production cache untouched.'}
    throw
} finally {
    # Fixed files and verified children only; no recursive deletion.
    foreach($path in @($unapproved,$approved)){
        if(Test-Path -LiteralPath $path){
            $cleanupAcl=[Security.AccessControl.FileSecurity]::new()
            $cleanupAcl.SetAccessRuleProtection($true,$false)
            $cleanupAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.WindowsIdentity]::GetCurrent().User,'FullControl','Allow'))
            Set-CodeAccessOnlyAcl $path $cleanupAcl
            Remove-Item -LiteralPath $path
        }
    }
    if(Test-Path -LiteralPath $child){Remove-Item -LiteralPath $child}
    if(Test-Path -LiteralPath $root){Remove-Item -LiteralPath $root}
}
