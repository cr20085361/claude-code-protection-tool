$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeCacheRepairTests-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $fixture,(Join-Path $fixture 'private'),(Join-Path $fixture 'cache')
$checks=[Collections.Generic.List[string]]::new()
try {
    & (Get-Module ClaudeGuard) {
        param($Fixture,$Project,$Checks)
        $source=Get-Content -LiteralPath (Join-Path $Project 'Repair-ClaudeCodeContext-Admin.ps1') -Raw
        $tokens=$null;$errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
        if($errors.Count){throw 'Cache repair parse failed.'}
        $branch=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.StartsWith('if($Worker)')},$true))
        if($branch.Count -ne 1){throw 'Cache worker branch not found.'}
        $workerBody=[scriptblock]::Create($branch[0].Extent.Text.Replace('exit 1','return').Replace('exit 0','return').Replace('(Get-GuardHash $PSCommandPath)',"'fixture'"))
        $root=Join-Path $Fixture 'cache';$missing=Join-Path $Fixture 'missing-cache'
        $unknown=Join-Path $root 'old-code.exe';$approved=Join-Path $root 'claude.exe'
        [IO.File]::WriteAllText($unknown,'old-fixture');[IO.File]::WriteAllText($approved,'approved-fixture')
        $d=[pscustomobject]@{UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;CodeGate=[pscustomobject]@{Roots=@($root,$missing);PayloadHash=(Get-GuardHash $approved)};CodePaths=@($approved)}
        $Worker=$true;$ResultFile=Join-Path $Fixture ('private\cache-repair-'+[guid]::NewGuid().ToString('N')+'.json');$ReviewedWorkerHash='fixture'
        $script:calls=[Collections.Generic.List[string]]::new()
        function Get-GuardPath($Name){Join-Path $Fixture $Name}
        function Assert-CodeCacheGate($Path){if(-not (Test-Path -LiteralPath $Path)){throw 'Missing root was checked before repair.'}}
        function Set-CodeAccessOnlyAcl($Path,$Acl){
            $denies=@($Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object {$_.AccessControlType.ToString() -eq 'Deny' -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ExecuteFile)})
            if($Path -ne $unknown -or -not $denies.Count){throw 'Worker did not restrict the unapproved executable.'}
            $script:calls.Add('deny-old-code')
        }
        function Repair-GuardDesktopCodeCache {
            if('deny-old-code' -notin $script:calls){throw 'Full cache verification ran before old permissions were repaired.'}
            $script:calls.Add('restore-approved-cache')
        }
        function Assert-GuardFirewall {$script:calls.Add('verify-all')}
        & $workerBody
        $result=Read-GuardJson $ResultFile
        if(-not $result.Success){throw $result.Reason}
        if(($script:calls -join ',') -ne 'deny-old-code,restore-approved-cache,verify-all'){throw 'Cache repair order changed.'}
        $Checks.Add('old-unapproved-executable-denied-before-full-cache-verification')
        if($result.ChangedPermissions.Count -ne 1 -or $result.ChangedPermissions[0] -ne $unknown){throw 'Approved executable permissions were changed.'}
        $Checks.Add('approved-executable-not-restricted')
        $Checks.Add('missing-root-deferred-to-approved-cache-repair')
        if(-not (Test-Path -LiteralPath ($ResultFile+'.acl-backup.json'))){throw 'ACL backup missing.'}
        $Checks.Add('prior-permissions-backed-up-before-repair')
        $script:calls.Clear();$d.CodeGate.PayloadHash='tampered'
        & $workerBody
        $result=Read-GuardJson $ResultFile
        if($result.Success -or 'restore-approved-cache' -in $script:calls -or 'verify-all' -in $script:calls){throw 'Changed approved binary was accepted.'}
        $Checks.Add('changed-approved-binary-stops-repair')
    } $fixture $PSScriptRoot $checks
    $result=@{Time=(Get-Date -Format o);Passed=$true;FixtureOnly=$true;Count=$checks.Count;Checks=@($checks)}
    Write-GuardJson (Join-Path $PSScriptRoot 'evidence\code-cache-repair-fixture-tests.json') $result
    $result|ConvertTo-Json -Depth 4
} finally {
    $full=[IO.Path]::GetFullPath($fixture);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if(-not $full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '^ClaudeCacheRepairTests-[0-9a-f]{32}$'){throw 'Unsafe cache fixture cleanup path.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
