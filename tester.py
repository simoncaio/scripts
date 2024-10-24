#!/usr/bin/env python3

import requests

# Defina a URL do endpoint
url = 'http://94.237.62.14:35854/update'

# Defina os dados que você deseja enviar
data = {
    'from': 'Ghostly Support',
    'email': 'support@void-whispers.htb',
    'sendMailPath': '/usr/sbin/sendmail',
    'mailProgram': 'sendmail'
}

# Envie a requisição POST
response = requests.post(url, data=data)

# Verifique a resposta
if response.status_code == 200:
    print(response.status_code,'OK!', 'Requisição enviada com sucesso!')
    print('Resposta:', response.text)
else:
    print('Falha ao enviar requisição. Código de status:', response.status_code)
    print('Resposta:', response.text)

