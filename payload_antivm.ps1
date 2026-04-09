# ================================
# 1. Anti-VM / Anti-Sandbox checks
# ================================

$vmIndicators = @("vbox", "vmware", "xen", "qemu")

$processes = Get-Process | Select-Object -ExpandProperty ProcessName
foreach ($p in $processes) {
    foreach ($vm in $vmIndicators) {
        if ($p.ToLower().Contains($vm)) {
            Start-Sleep -Seconds 20
        }
    }
}

# Check memória baixa (sandbox comum)
$ram = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
if ($ram -lt 2) {
    Start-Sleep -Seconds 30
}

# Delay para evasão
Start-Sleep -Seconds 5

# ================================
# 2. Payload ofuscado (Base64)
# ================================

$encoded = "UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAbQBkAC4AZQB4AGUAIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAIgAvAGMAIABlAGMAaABvACAAbwBiAGYAdQBzAGMAYQB0AGUAZAAgAGUAeABlAGMAdQB0AGkAbwBuACIA"

$decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))

# Execução dinâmica
IEX $decoded

# ================================
# 3. Criação de arquivo (artifact)
# ================================

$path = "$env:TEMP\demo_sandbox.txt"
"Sandbox test execution" | Out-File $path

# ================================
# 4. Comunicação externa (com redirect)
# ================================

try {
    Invoke-WebRequest -Uri "http://url-chain-demo.s3-website.us-east-2.amazonaws.com/" `
    -UseBasicParsing
} catch {}

# ================================
# 5. Persistência (registry)
# ================================

New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
-Name "SandboxDemo" -Value "notepad.exe" -PropertyType String -Force

# ================================
# 6. Movimentação lateral (simulada)
# ================================

Start-Process cmd.exe -ArgumentList "/c net use \\192.168.1.100\C$ /user:test test" -WindowStyle Hidden

# ================================
# 7. Named pipe activity (simulação leve)
# ================================

$pipe = new-object System.IO.Pipes.NamedPipeServerStream("testpipe")
$pipe.Dispose()

# ================================
# 8. Pós-execução (cleanup parcial)
# ================================

Start-Sleep -Seconds 2
Remove-Item $path -ErrorAction SilentlyContinue