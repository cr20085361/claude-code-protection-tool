[CmdletBinding()]
param([switch]$Worker,[string]$ResultFile,[string]$ReviewedWorkerHash)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ClaudeCodeGate.psm1') -Force
$d=Get-GuardState
if(-not (Test-GuardAdmin) -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $d.UserSid){throw 'Same-account administrator context required.'}
if(@(Get-GuardDesktopProcesses).Count -or @(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -in @($d.CodePaths)}).Count){throw 'Exit Claude and Code before cache permissions repair.'}
if($Worker) {
    $ResultFile=[IO.Path]::GetFullPath($ResultFile)
    if([IO.Path]::GetDirectoryName($ResultFile) -ne (Get-GuardPath 'private') -or [IO.Path]::GetFileName($ResultFile) -notmatch '^cache-repair-[0-9a-f]{32}\.json$' -or (Get-GuardHash $PSCommandPath) -ne $ReviewedWorkerHash){throw 'Reviewed cache worker arguments changed.'}
    $record=@{Time=(Get-Date -Format o);Success=$false;Reason=$null;ChangedPermissions=@();Candidates=@()}
    try {
        foreach($root in $d.CodeGate.Roots) {
            Assert-CodeCacheGate $root
            if((Get-Item $root).Attributes -band [IO.FileAttributes]::ReparsePoint -or @(Get-ChildItem $root -Recurse -Force|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'Code cache reparse point requires separate review.'}
            foreach($file in Get-ChildItem $root -Recurse -Force -File -Filter *.exe) {
                $acl=Get-Acl -LiteralPath $file.FullName
                $approved=$file.FullName -in @($d.CodePaths)
                $entry=@{Path=$file.FullName;Hash=(Get-GuardHash $file.FullName);Approved=$approved;BeforeSddl=$acl.Sddl}
                $record.Candidates+=@($entry)
                if($approved) {
                    if($entry.Hash -ne $d.CodeGate.PayloadHash){throw 'Approved engine hash changed; permissions repair refused.'}
                } else {
                    $deny=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object {$_.IdentityReference.Value -eq $d.UserSid -and $_.AccessControlType.ToString() -eq 'Deny' -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ExecuteFile)})
                    if(-not $deny.Count){
                        # 保留所有权、审计和既有权限，仅给未核准文件补充明确的执行拒绝。
                        Write-GuardJson ($ResultFile+'.acl-backup.json') $record
                        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($d.UserSid),'ExecuteFile','Deny'))
                        Set-CodeAccessOnlyAcl $file.FullName $acl
                        $record.ChangedPermissions+=@($file.FullName)
                    }
                }
            }
        }
        Repair-GuardDesktopCodeCache
        Assert-GuardFirewall
        $record.Success=$true
    } catch {$record.Reason=$_.Exception.Message} finally {Write-GuardJson $ResultFile $record}
    if(-not $record.Success){exit 1}
    exit 0
}
if($ResultFile -or $ReviewedWorkerHash){throw 'Worker arguments require Worker mode.'}
$id=[guid]::NewGuid().ToString('N');$name='ClaudeProGuard-CacheRepair-'+$id
$resultPath=Get-GuardPath ('private\cache-repair-'+$id+'.json')
$service=New-Object -ComObject Schedule.Service;$service.Connect();$folder=$service.GetFolder('\')
$definition=$service.NewTask(0)
$definition.Principal.UserId=$d.UserSid;$definition.Principal.LogonType=3;$definition.Principal.RunLevel=1
$definition.Settings.Hidden=$true;$definition.Settings.ExecutionTimeLimit='PT2M';$definition.Settings.DisallowStartIfOnBatteries=$false;$definition.Settings.StopIfGoingOnBatteries=$false
$action=$definition.Actions.Create(0);$action.Path=(Get-Content (Get-GuardPath 'private\launcher-paths.txt') -Raw).Trim();$action.WorkingDirectory=$PSScriptRoot
$action.Arguments='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+$PSCommandPath+'" -Worker -ReviewedWorkerHash '+(Get-GuardHash $PSCommandPath)+' -ResultFile "'+$resultPath+'"'
$registered=$null
try {
    $registered=$folder.RegisterTaskDefinition($name,$definition,6,$d.UserSid,$null,3,$null)
    $null=$registered.Run($null)
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while(-not (Test-Path $resultPath)){if($timer.Elapsed.TotalSeconds -ge 90){throw 'Desktop cache repair timed out.'};Start-Sleep -Milliseconds 200}
    $record=Read-GuardJson $resultPath
    Write-GuardJson (Get-GuardPath 'evidence\code-cache-context-repair.json') $record
    if(-not $record.Success){throw ('Desktop cache repair failed: '+$record.Reason)}
}finally{if($registered){$registered.Stop(0);$folder.DeleteTask($name,0)}}
