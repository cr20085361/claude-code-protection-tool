# Isolated checks of the production rule selector and validators. No Windows rules are changed.
[CmdletBinding()]param()
$ErrorActionPreference='Stop'
$module=Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -PassThru -Force
& $module {
    # Fixture filters are attached to the selected rule. Reordering the rules
    # deliberately gives the objects a different order from the expected paths.
    function Get-NetFirewallApplicationFilter { process { [pscustomobject]@{Program=$_.Program} } }
    function Get-NetFirewallAddressFilter { process { [pscustomobject]@{RemoteAddress=$_.Addresses} } }
    function Get-NetFirewallPortFilter { process { [pscustomobject]@{Protocol=$_.Protocol;RemotePort=$_.Ports} } }
    function Get-NetFirewallProfile { param($PolicyStore) [pscustomobject]@{Enabled=$true} }
    function Get-GuardDesktop { [pscustomobject]@{Path='C:\fixture\client.exe';Hash='abc';Version='1'} }
    function Get-GuardState { [pscustomobject]@{Desktop=(Get-GuardDesktop)} }
    $client=(Get-GuardDesktop).Path
    $name=Get-GuardRuleName $client
    $tcpName=$name.Replace('ClaudeProGuard-','ClaudeProGuardProxy-TCP-')
    $udpName=$name.Replace('ClaudeProGuard-','ClaudeProGuardProxy-UDP-')
    function Read-GuardJson { [pscustomobject]@{Rules=@([pscustomobject]@{Path=$client;Name=$name;RemoteAddress=@('203.0.113.0/24')})} }
    function Get-NetFirewallRule {
        param($Name,$PolicyStore)
        if($Name -ne 'ClaudeProGuard*' -or $PolicyStore -ne 'ActiveStore'){throw 'Unexpected store or lookup'}
        $readCount.Value++
        $ruleSet
    }
    foreach($case in 'healthy','missing','duplicate','wrong-program','wrong-ports','wrong-address','protocol','direct-coverage','disabled'){
        $readCount=[ref]0
        $ruleSet=@(foreach($n in $udpName,$name,$tcpName){
            $protocol=if($n -eq $name){'Any'}elseif($n -eq $tcpName){'TCP'}else{'UDP'}
            [pscustomobject]@{Name=$n;Program=$client;Protocol=$protocol;Enabled=$true;Action='Block';Direction='Outbound';Profile='Any';Ports=@('10808','10813');Addresses=if($n -eq $name){@('203.0.113.0/24')}else{@('127.0.0.0/8')}}
        })
        switch($case){
            'missing' {$ruleSet=@($ruleSet[0],$ruleSet[1])}
            'duplicate' {$ruleSet+=@($ruleSet[2])}
            'wrong-program' {$ruleSet[0].Program='C:\fixture\other.exe'}
            'wrong-ports' {$ruleSet[2].Ports=@('10808')}
            'wrong-address' {$ruleSet[2].Addresses=@('0.0.0.0/0')}
            'protocol' {$ruleSet[2].Protocol='UDP'}
            'direct-coverage' {$ruleSet[1].Addresses=@('127.0.0.0/8')}
            'disabled' {$ruleSet[1].Enabled=$false}
        }
        $failure=$null
        try{Assert-GuardFirewall -DesktopOnly}catch{$failure=$_.Exception.Message}
        if($readCount.Value -ne 1 -or (($null -eq $failure) -ne ($case -eq 'healthy'))){throw "Unexpected outcome for $case ($failure)"}
    }
    [pscustomobject]@{Passed=$true;Cases=9}
}
