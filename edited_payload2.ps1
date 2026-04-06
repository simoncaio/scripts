# Simula comportamento suspeito

# 1. Criação de arquivo temporário
$path = "$env:TEMP\test_suspicious.txt"
"test" | Out-File $path

# 2. Execução de comando
Start-Process cmd.exe -ArgumentList "/c echo suspicious activity"

# 4. Persistência simples
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
-Name "TestPersistence" -Value "notepad.exe" -PropertyType String