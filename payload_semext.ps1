# Simula comportamento suspeito

# 1. Cria arquivo em temp
$temp = "$env:TEMP\update.log"
"test" | Out-File $temp

# 2. Executa comando
Start-Process cmd.exe -ArgumentList "/c echo test"

# 4. Aguarda um pouco
Start-Sleep -Seconds 5