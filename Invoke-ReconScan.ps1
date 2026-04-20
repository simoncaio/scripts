[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Target,

    [ValidateSet('All', 'IcmpSweep', 'TcpScan', 'SequentialScan')]
    [string]$Mode = 'All',

    [int[]]$Ports = @(
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389,
        5432, 5900, 5985, 5986, 6379, 7001, 8000, 8080, 8443, 9200
    ),

    [int]$SequentialStart = 1,
    [int]$SequentialEnd   = 1024,

    [int]$IcmpRangeStart = 1,
    [int]$IcmpRangeEnd   = 50,

    [int]$TimeoutMs   = 400,
    [int]$Concurrency = 50,

    [string]$LogPath
)

#--------------------------------------------------------------------------
# Setup
#--------------------------------------------------------------------------

$ErrorActionPreference = 'Stop'

if (-not $LogPath) {
    $stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $LogPath = Join-Path -Path $PSScriptRoot -ChildPath "recon-scan-$stamp.log"
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'EVENT', 'RESULT', 'WARN')]
        [string]$Level = 'INFO'
    )
    $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
}

function Write-Banner {
    param([string]$Text)
    $bar = '=' * 70
    Write-Host ''
    Write-Host $bar -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host $bar -ForegroundColor Cyan
    Add-Content -Path $LogPath -Value "`n$bar`n$Text`n$bar" -Encoding UTF8
}

function Get-PublicEgressIp {
    try {
        $ip = (Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 5).Trim()
        return $ip
    } catch {
        return 'unavailable'
    }
}

function Resolve-TargetIp {
    param([string]$Hostname)
    try {
        $resolved = [System.Net.Dns]::GetHostAddresses($Hostname) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            Select-Object -First 1
        if ($resolved) { return $resolved.IPAddressToString }
    } catch { }
    return $Hostname
}

#--------------------------------------------------------------------------
# Header
#--------------------------------------------------------------------------

Write-Banner "Cisco Secure Access - POC IPS - Recon Simulation"

$publicIp  = Get-PublicEgressIp
$targetIp  = Resolve-TargetIp -Hostname $Target
$startTime = Get-Date

Write-Log "Host de origem        : $env:COMPUTERNAME"
Write-Log "Usuario               : $env:USERNAME"
Write-Log "IP publico de saida   : $publicIp"
Write-Log "Alvo (hostname)       : $Target"
Write-Log "Alvo (IP resolvido)   : $targetIp"
Write-Log "Modo                  : $Mode"
Write-Log "Concorrencia          : $Concurrency"
Write-Log "Timeout TCP (ms)      : $TimeoutMs"
Write-Log "Arquivo de log        : $LogPath"
Write-Log "Inicio                : $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))"

Write-Log ""
Write-Log "ATENCAO: este script deve ser executado apenas em laboratorio." 'WARN'
Write-Log "Use apenas alvos autorizados (ex.: scanme.nmap.org ou VM propria)." 'WARN'
Write-Log ""

#--------------------------------------------------------------------------
# 1. ICMP Sweep
#--------------------------------------------------------------------------

function Invoke-IcmpSweep {
    param(
        [string]$BaseTarget,
        [int]$Start,
        [int]$End
    )

    Write-Banner "[1/3] ICMP Sweep - varredura de hosts vivos"

    # Base /24 derivada do IP alvo
    $targetAddr = Resolve-TargetIp -Hostname $BaseTarget
    $octets     = $targetAddr.Split('.')
    if ($octets.Count -ne 4) {
        Write-Log "Nao foi possivel derivar /24 a partir de $BaseTarget. Pulando ICMP sweep." 'WARN'
        return
    }
    $base = "$($octets[0]).$($octets[1]).$($octets[2])"

    Write-Log "Faixa ICMP: $base.$Start - $base.$End"
    Write-Log "Tipo de evento esperado no IPS: ICMP Sweep / PROTOCOL-ICMP" 'EVENT'

    $alive = 0
    $tested = 0

    $startSweep = Get-Date
    for ($i = $Start; $i -le $End; $i++) {
        $ip = "$base.$i"
        $tested++
        $reply = Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1 `
                                  -ErrorAction SilentlyContinue
        if ($reply) {
            $alive++
            Write-Log "ICMP reply de $ip" 'RESULT'
        }
    }
    $elapsed = ((Get-Date) - $startSweep).TotalSeconds

    Write-Log "ICMP sweep concluido: $tested hosts testados, $alive responderam, ${elapsed}s." 'RESULT'
}

#--------------------------------------------------------------------------
# 2. TCP Port Scan (paralelo, portas comuns)
#--------------------------------------------------------------------------

function Invoke-TcpPortScan {
    param(
        [string]$TargetHost,
        [int[]]$PortList,
        [int]$Timeout,
        [int]$ThreadCount
    )

    Write-Banner "[2/3] TCP Port Scan - varredura paralela em portas comuns"

    Write-Log "Alvo                  : $TargetHost"
    Write-Log "Portas a varrer       : $($PortList.Count) portas"
    Write-Log "Threads paralelas     : $ThreadCount"
    Write-Log "Tipo de evento esperado no IPS: INDICATOR-SCAN TCP portscan" 'EVENT'

    $scanBlock = {
        param($TargetHost, $Port, $Timeout)
        $client = New-Object System.Net.Sockets.TcpClient
        $result = [PSCustomObject]@{
            Port   = $Port
            Open   = $false
            Banner = ''
        }
        try {
            $async = $client.BeginConnect($TargetHost, $Port, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne($Timeout, $false)) {
                $client.EndConnect($async)
                $result.Open = $true
            }
        } catch {
            # Conexao recusada / filtrada
        } finally {
            $client.Close()
        }
        return $result
    }

    $pool     = [runspacefactory]::CreateRunspacePool(1, $ThreadCount)
    $pool.Open()
    $jobs     = @()

    $startScan = Get-Date

    foreach ($port in $PortList) {
        $ps = [powershell]::Create().AddScript($scanBlock).
                                    AddArgument($TargetHost).
                                    AddArgument($port).
                                    AddArgument($Timeout)
        $ps.RunspacePool = $pool
        $jobs += [PSCustomObject]@{
            Pipe   = $ps
            Handle = $ps.BeginInvoke()
            Port   = $port
        }
    }

    $openPorts = @()
    foreach ($job in $jobs) {
        $r = $job.Pipe.EndInvoke($job.Handle)[0]
        if ($r.Open) {
            $openPorts += $r.Port
            Write-Log "Porta TCP aberta: $($r.Port)/tcp" 'RESULT'
        }
        $job.Pipe.Dispose()
    }

    $pool.Close()
    $pool.Dispose()

    $elapsed = ((Get-Date) - $startScan).TotalSeconds
    Write-Log "TCP scan concluido em ${elapsed}s. Abertas: $($openPorts -join ', ')" 'RESULT'
}

#--------------------------------------------------------------------------
# 3. Sequential Port Scan (padrao classico nmap -p 1-1024)
#--------------------------------------------------------------------------

function Invoke-SequentialPortScan {
    param(
        [string]$TargetHost,
        [int]$From,
        [int]$To,
        [int]$Timeout,
        [int]$ThreadCount
    )

    Write-Banner "[3/3] Sequential Port Scan - padrao classico de reconnaissance"

    $total = $To - $From + 1
    Write-Log "Alvo                  : $TargetHost"
    Write-Log "Faixa sequencial      : $From - $To ($total portas)"
    Write-Log "Threads paralelas     : $ThreadCount"
    Write-Log "Tipo de evento esperado no IPS: INDICATOR-SCAN sequential portscan" 'EVENT'

    $portList = $From..$To
    Invoke-TcpPortScan -TargetHost $TargetHost -PortList $portList `
                       -Timeout $Timeout -ThreadCount $ThreadCount
}

#--------------------------------------------------------------------------
# Execucao
#--------------------------------------------------------------------------

switch ($Mode) {
    'IcmpSweep' {
        Invoke-IcmpSweep -BaseTarget $Target -Start $IcmpRangeStart -End $IcmpRangeEnd
    }
    'TcpScan' {
        Invoke-TcpPortScan -TargetHost $Target -PortList $Ports `
                           -Timeout $TimeoutMs -ThreadCount $Concurrency
    }
    'SequentialScan' {
        Invoke-SequentialPortScan -TargetHost $Target -From $SequentialStart `
                                  -To $SequentialEnd -Timeout $TimeoutMs `
                                  -ThreadCount $Concurrency
    }
    'All' {
        Invoke-IcmpSweep -BaseTarget $Target -Start $IcmpRangeStart -End $IcmpRangeEnd
        Invoke-TcpPortScan -TargetHost $Target -PortList $Ports `
                           -Timeout $TimeoutMs -ThreadCount $Concurrency
        Invoke-SequentialPortScan -TargetHost $Target -From $SequentialStart `
                                  -To $SequentialEnd -Timeout $TimeoutMs `
                                  -ThreadCount $Concurrency
    }
}

#--------------------------------------------------------------------------
# Footer - dados para correlacao com Secure Access
#--------------------------------------------------------------------------

$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds

Write-Banner "Resumo da execucao - dados para o Activity Search"

Write-Log "Inicio                : $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Log "Fim                   : $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Log "Duracao total         : ${duration}s"
Write-Log "IP publico de origem  : $publicIp"
Write-Log "Alvo                  : $Target ($targetIp)"
Write-Log ""
Write-Log "Para validar no Cisco Secure Access:"
Write-Log "  1. Va em Monitor > Activity Search"
Write-Log "  2. Filtre por Event Type = Intrusion"
Write-Log "  3. Filtre por Source IP   = $publicIp"
Write-Log "  4. Filtre janela de tempo = $($startTime.ToString('HH:mm')) - $($endTime.ToString('HH:mm'))"
Write-Log ""
Write-Log "Assinaturas Snort que costumam disparar:"
Write-Log "  - INDICATOR-SCAN TCP portscan"
Write-Log "  - INDICATOR-SCAN PROTOCOL-ICMP echo reply"
Write-Log "  - PROTOCOL-SCAN nmap-style probe"
Write-Log "  - Classification: Attempted Information Leak"
Write-Log ""
Write-Log "Log completo salvo em : $LogPath"
