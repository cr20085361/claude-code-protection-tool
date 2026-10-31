[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-Runtime.psm1') -Force
$sockets=[Collections.Generic.List[Net.Sockets.Socket]]::new()
$cases=@()
try{
    foreach($address in @('0.0.0.0','127.0.0.1','::','::1')){
        $ip=[Net.IPAddress]::Parse($address)
        foreach($listen in @($false,$true)){
            $socket=[Net.Sockets.Socket]::new($ip.AddressFamily,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
            $sockets.Add($socket)
            if($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){$socket.DualMode=$false}
            $socket.Bind([Net.IPEndPoint]::new($ip,0))
            if($listen){$socket.Listen(4)}
            $cases+=@([pscustomobject]@{Address=$address;Port=$socket.LocalEndPoint.Port;Listening=$listen;SocketAccepts=[bool]$socket.GetSocketOption([Net.Sockets.SocketOptionLevel]::Socket,[Net.Sockets.SocketOptionName]::AcceptConnection)})
        }
    }
    for($sample=0;$sample -lt 5;$sample++){
        $rows=@(Get-GuardTcpListeners|Where-Object OwningProcess -eq $PID)
        foreach($case in $cases){
            $found=@($rows|Where-Object {$_.LocalAddress -eq $case.Address -and $_.LocalPort -eq $case.Port}).Count -eq 1
            if($found -ne $case.Listening -or $case.SocketAccepts -ne $case.Listening){throw ('Native bind/listen classification failed: '+($case|ConvertTo-Json -Compress))}
        }
    }
    $result=[pscustomobject]@{Time=(Get-Date).ToString('o');Passed=$true;Samples=5;Cases=$cases;ProductionProcessesTouched=$false}
    $result|ConvertTo-Json -Depth 5|Set-Content (Join-Path $PSScriptRoot 'evidence\tcp-listener-inventory.json') -Encoding utf8
    $result
}finally{foreach($socket in $sockets){$socket.Dispose()}}
