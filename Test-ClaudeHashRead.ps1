[CmdletBinding()]
param([string]$Source=(Join-Path $PSScriptRoot 'ClaudeGuard.psm1'))
$ErrorActionPreference='Stop'
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$null,[ref]$null)
$fn=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-GuardHash'},$true)
. ([scriptblock]::Create($fn.Extent.Text))
$dir=Join-Path $PSScriptRoot ('private/hash-fixture-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $dir|Out-Null
try {
    $p=Join-Path $dir 'payload.bin';$checks=@()
    foreach($size in @(0,1,4095,4096,1048575,1048576,1048577,8388609)) {
        $bytes=[byte[]]::new($size);[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        [IO.File]::WriteAllBytes($p,$bytes)
        $expected=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
        if((Get-GuardHash $p) -cne $expected){throw 'Hash mismatch'}
        $checks+=$size
    }
    [IO.File]::WriteAllBytes($p,[byte[]]@(1));$a=Get-GuardHash $p
    [IO.File]::WriteAllBytes($p,[byte[]]@(2));if((Get-GuardHash $p) -eq $a){throw 'Stale hash reused'}
    $writer=[IO.FileStream]::new($p,'Open','Write','ReadWrite')
    try {$rejected=$false;try{Get-GuardHash $p|Out-Null}catch{$rejected=$true};if(-not $rejected){throw 'Concurrent writer accepted'}}finally{$writer.Dispose()}
    $missing=$false;try{Get-GuardHash (Join-Path $dir 'missing')|Out-Null}catch{$missing=$true};if(-not $missing){throw 'Missing file accepted'}
    @{Passed=$true;Sizes=$checks;MutationRehashed=$true;ConcurrentWriterRejected=$true;MissingRejected=$true}|ConvertTo-Json
} finally {
    $resolved=[IO.Path]::GetFullPath($dir);$allowed=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'private'))+'\'
    if(-not $resolved.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Cleanup outside private refused'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}