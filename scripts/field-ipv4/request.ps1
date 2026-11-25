param(
    [Parameter(Mandatory)][string]$InterfaceAlias,
    [Parameter(Mandatory)][string]$ServerName,
    [Parameter(Mandatory)][ipaddress]$ServerIp,
    [Parameter(Mandatory)][ValidateRange(1024,65535)][int]$LocalPort
)
$ErrorActionPreference = 'Stop'
$address = @(Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 |
    Where-Object AddressState -eq Preferred)
if ($address.Count -ne 1) { throw "Expected one IPv4 source on $InterfaceAlias" }
$clock = [Diagnostics.Stopwatch]::StartNew()
$result = [ordered]@{
    utc = [DateTime]::UtcNow.ToString('o'); adapter = $InterfaceAlias
    source = $address[0].IPAddress; port = $LocalPort; name = $ServerName
    destination = $ServerIp.ToString(); tcp_ms = $null; tls_ms = $null
    http = $null; eof = $false; response_bytes = 0; error = $null
}
$tcp = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
$tls = $null
try {
    $tcp.Client.Bind([Net.IPEndPoint]::new([ipaddress]$result.source, $LocalPort))
    $index = [Net.IPAddress]::HostToNetworkOrder([int]$address[0].InterfaceIndex)
    $tcp.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, 31, $index)
    if (-not $tcp.ConnectAsync($ServerIp,443).Wait(4500)) { throw 'TCP timeout' }
    $result.tcp_ms = $clock.ElapsedMilliseconds
    $tls = [Net.Security.SslStream]::new($tcp.GetStream())
    if (-not $tls.AuthenticateAsClientAsync($ServerName).Wait(6500)) { throw 'TLS timeout' }
    $result.tls_ms = $clock.ElapsedMilliseconds
    $tls.ReadTimeout = 5000
    $req = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: $ServerName`r`nConnection: close`r`n`r`n")
    $tls.Write($req,0,$req.Length)
    $buffer = [byte[]]::new(16384)
    $first = ''
    while ($clock.Elapsed.TotalSeconds -lt 25) {
        $n = $tls.Read($buffer,0,$buffer.Length)
        if ($n -eq 0) { $result.eof = $true; break }
        $result.response_bytes += $n
        if (-not $result.http -and $first.Length -lt 1024) {
            $first += [Text.Encoding]::ASCII.GetString($buffer,0,[Math]::Min($n,1024-$first.Length))
            if ($first -match '^(HTTP/1\.[01] [0-9]{3})[^\r\n]*\r\n') { $result.http = $Matches[1] }
        }
    }
} catch { $result.error = $_.Exception.GetBaseException().Message }
finally {
    if ($null -ne $tls) { $tls.Dispose() }
    $tcp.Dispose()
}
[pscustomobject]$result | ConvertTo-Json -Compress
