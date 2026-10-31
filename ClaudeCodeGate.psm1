Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1')

function Set-CodeAccessOnlyAcl([string]$Path,[Security.AccessControl.FileSystemSecurity]$Acl) {
    # Write only the DACL, preserving ownership and SACL; Set-Acl can request audit privileges.
    $full=[IO.Path]::GetFullPath($Path)
    $allowed=@((Get-GuardPath 'private'))
    $state=Get-GuardState
    if($state.PSObject.Properties.Name -contains 'CodeGate'){$allowed+=@($state.CodeGate.Roots)}
    $within=@($allowed|Where-Object {$full -eq [IO.Path]::GetFullPath($_) -or $full.StartsWith([IO.Path]::GetFullPath($_).TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)})
    if(-not $within.Count){throw 'DACL update escaped the owned Code/cache or private test paths.'}
    if(-not ('ClaudeGuardDacl' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class ClaudeGuardDacl {
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool GetSecurityDescriptorDacl(IntPtr sd, out bool present, out IntPtr dacl, out bool defaulted);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, EntryPoint="SetNamedSecurityInfoW")]
    static extern uint SetNamedSecurityInfo(string name, int type, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    public static void Apply(string path, byte[] descriptor, bool protect) {
        IntPtr sd=Marshal.AllocHGlobal(descriptor.Length);
        try {
            Marshal.Copy(descriptor,0,sd,descriptor.Length);
            bool present, defaulted; IntPtr dacl;
            if(!GetSecurityDescriptorDacl(sd,out present,out dacl,out defaulted)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if(!present || dacl==IntPtr.Zero) throw new InvalidOperationException("Refusing a null DACL.");
            uint result=SetNamedSecurityInfo(path,1,4u | (protect ? 0x80000000u : 0x20000000u),IntPtr.Zero,IntPtr.Zero,dacl,IntPtr.Zero);
            if(result!=0) throw new Win32Exception((int)result);
        } finally {Marshal.FreeHGlobal(sd);}
    }
}
'@
    }
    [ClaudeGuardDacl]::Apply($full,$Acl.GetSecurityDescriptorBinaryForm(),$Acl.AreAccessRulesProtected)
}

function Set-CodeCacheGate([string]$Path) {
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    foreach($s in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'Modify','ContainerInherit,ObjectInherit','None','Allow'))
    # ObjectInherit propagates through directories, applying ExecuteFile deny only to files.
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'ExecuteFile','ObjectInherit','InheritOnly','Deny'))
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Assert-CodeCacheGate([string]$Path) {
    $d=Get-GuardState
    $acl=Get-Acl -LiteralPath $Path
    $matches=@($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.IdentityReference.Value -eq $d.UserSid -and $_.AccessControlType.ToString() -eq 'Deny' -and
        ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ExecuteFile) -and
        $_.InheritanceFlags.ToString() -eq 'ObjectInherit' -and $_.PropagationFlags.ToString() -eq 'InheritOnly'
    })
    if (-not $acl.AreAccessRulesProtected -or $matches.Count -ne 1) { throw 'Code cache execution gate is missing or changed.' }
}
function Protect-CodeBinary([string]$Path) {
    $d=Get-GuardState
    Assert-GuardRule $Path
    $acl=[Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($d.UserSid),'ReadAndExecute','Allow'))
    foreach($s in @('S-1-5-18','S-1-5-32-544')) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s),'FullControl','Allow')) }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Test-CodeCacheGate {
    $d=Get-GuardState
    $results=@()
    foreach($root in $d.CodeGate.Roots) {
        Assert-CodeCacheGate $root
        $folder=Join-Path $root ('guard-probe-'+[guid]::NewGuid().ToString('N'))
        $nested=Join-Path $folder 'future-version'
        $file=Join-Path $nested 'probe.exe'
        New-Item -ItemType Directory -Path $nested -Force | Out-Null
        try {
            Copy-Item -LiteralPath (Get-GuardPath 'runtime\network-probe.exe') -Destination $file
            $denied=$false
            try {
                $psi=[Diagnostics.ProcessStartInfo]::new($file,'--version');$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
                $p=[Diagnostics.Process]::Start($psi)
                if (-not $p.WaitForExit(2000)) { $p.Kill() }
            } catch [ComponentModel.Win32Exception] { $denied=($_.Exception.NativeErrorCode -eq 5) }
            if (-not $denied) { throw 'An unapproved future executable was allowed to start.' }
            $results+=@{Root=$root;UnapprovedNestedExecutableDenied=$true;NativeErrorCode=5}
        } finally {
            # Only the exact disposable files/directories created above are removed, no recursion.
            if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file}
            Remove-Item -LiteralPath $nested
            Remove-Item -LiteralPath $folder
        }
    }
    Write-GuardJson (Get-GuardPath 'evidence\code-execution-gate-test.json') @{Time=(Get-Date -Format o);Passed=$true;Results=$results;CredentialsUsed=$false}
}
function Assert-CodePrepared {
    $d=Get-GuardState
    if ($d.CodeCoverage -notin @('prepared','verified') -or $d.CodeGate.Schema -ne 1) { throw 'Local Code protection is not prepared.' }
    if(@(Compare-Object @(Get-GuardCodeCacheRoots $d.Desktop|Sort-Object) @($d.CodeGate.Roots|Sort-Object)).Count){throw 'Code cache path coverage requires reviewed migration.'}
    if ((Get-GuardHash $d.CodeGate.ArchivePath) -ne $d.CodeGate.ArchiveHash) { throw 'Desktop engine metadata changed; protection review required.' }
    foreach($root in $d.CodeGate.Roots) {
        Assert-CodeCacheGate $root
        $exeFiles=@(Get-ChildItem -LiteralPath $root -Filter *.exe -Recurse -File)
        foreach($file in $exeFiles) {
            if ($file.FullName -notin @($d.CodePaths)) {
                $deny=@((Get-Acl -LiteralPath $file.FullName).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference.Value -eq $d.UserSid -and $_.AccessControlType.ToString() -eq 'Deny' -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ExecuteFile)})
                if (-not $deny.Count) { throw 'Unexpected executable lacks the Code cache execution gate.' }
            }
        }
    }
    foreach($path in $d.CodePaths) {
        Assert-GuardRule $path
        if((Get-GuardHash $path) -ne $d.CodeGate.PayloadHash){throw 'Approved Code binary changed.'}
        $acl=Get-Acl -LiteralPath $path
        if(-not $acl.AreAccessRulesProtected){throw 'Approved Code binary execution permission changed.'}
        $userRules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object {$_.IdentityReference.Value -eq $d.UserSid -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ExecuteFile)})
        if(@($userRules|Where-Object {$_.AccessControlType.ToString() -eq 'Deny'}).Count -or -not @($userRules|Where-Object {$_.AccessControlType.ToString() -eq 'Allow'}).Count){throw 'Approved Code binary is not executable by the desktop user.'}
    }
    $proof=Read-GuardJson (Get-GuardPath 'evidence\code-execution-gate-test.json')
    if (-not $proof.Passed) { throw 'Code execution gate has not passed credential-free tests.' }
    if(@(Compare-Object @($proof.Results.Root|Sort-Object) @($d.CodeGate.Roots|Sort-Object)).Count){throw 'Code execution gate proof does not cover the approved cache roots.'}
}
function Restore-CodeCachePermissions([string]$Root,[string[]]$ApprovedPaths,[string]$OriginalSddl) {
    # Restore only this component's known root/files; retain Code cache and user data.
    $parent=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
    foreach($path in $ApprovedPaths){if(-not [IO.Path]::GetFullPath($path).StartsWith($parent,[StringComparison]::OrdinalIgnoreCase)){throw 'Code rollback file escaped its approved root.'}}
    if($OriginalSddl) {
        $acl=[Security.AccessControl.DirectorySecurity]::new()
        $acl.SetSecurityDescriptorSddlForm($OriginalSddl)
    } else {
        $acl=[Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($false,$false)
    }
    Set-CodeAccessOnlyAcl $Root $acl
    foreach($path in $ApprovedPaths) {
        if(Test-Path -LiteralPath $path) {
            $fileAcl=[Security.AccessControl.FileSecurity]::new()
            $fileAcl.SetAccessRuleProtection($false,$false)
            Set-CodeAccessOnlyAcl $path $fileAcl
        }
    }
}
function Assert-CodeRollbackReady {
    $d=Get-GuardState
    if($d.CodeCoverage -notin @('prepared','verified')){throw 'Code rollback requires a reviewed prepared deployment.'}
    $backup=Read-GuardJson (Get-GuardPath 'private\code-gate-backup.json')
    if(@(Compare-Object @($backup.Roots.Path|Sort-Object) @($d.CodeGate.Roots|Sort-Object)).Count){throw 'Code rollback root snapshot changed.'}
    foreach($root in $d.CodeGate.Roots){Assert-CodeCacheGate $root}
    foreach($path in $d.CodePaths){if((Get-GuardHash $path) -ne $d.CodeGate.PayloadHash){throw 'Code binary changed; review before rollback.'}}
    $active=@(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -in @($d.CodePaths)})
    if($active.Count){throw 'Exit all protected local Code sessions before rollback.'}
}
function Undo-CodeCacheGate {
    if(-not (Test-GuardAdmin)){throw 'Code permission rollback requires administrator rights.'}
    Assert-CodeRollbackReady
    $d=Get-GuardState
    $backup=Read-GuardJson (Get-GuardPath 'private\code-gate-backup.json')
    foreach($item in $backup.Roots) {
        $paths=@($d.CodePaths|Where-Object {$_.StartsWith($item.Path.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)})
        Restore-CodeCachePermissions $item.Path $paths $item.Sddl
    }
    $d.CodeCoverage='removed'
    Write-GuardJson (Get-GuardPath 'private\deployment.json') $d
}
Export-ModuleMember -Function *-Code*
