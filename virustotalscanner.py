
import requests
import hashlib

# Substitua YOUR_API_KEY pela sua chave de API real do VirusTotal
API_KEY = 'YOUR_API_KEY'

# Digite o nome do arquivo que deseja escanear
filename = 'example_file.exe'

# Abra o arquivo 
with open(filename, 'rb') as file:
    file_contents = file.read()

# Calcula o hash SHA-256 do arquivo
file_hash = hashlib.sha256(file_contents).hexdigest()

# Construa a URL da API VirusTotal
url = 'https://www.virustotal.com/api/v3/files/{}'.format(file_hash)

# Defina os cabeçalhos e parâmetros da API
headers = {'x-apikey': API_KEY}
params = {'include': 'scan_results'}

# Envie uma solicitação GET para a API
response = requests.get(url, headers=headers, params=params)

# Verifique se o arquivo foi verificado antes
if response.status_code == 200:
    scan_results = response.json()['data']['attributes']['last_analysis_results']
    print('File has already been scanned!')
    for antivirus, result in scan_results.items():
        print('{}: {}'.format(antivirus, result['category']))
else:
    # O arquivo não foi verificado antes, então carregue-o no VirusTotal
    files = {'file': (filename, file_contents)}
    response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers, files=files)
    if response.status_code == 200:
        data_id = response.json()['data']['id']
        print('File uploaded to VirusTotal. Analysis in progress...')
        
        # Verifique os resultados da verificação a cada 10 segundos até que estejam prontos
        while True:
            response = requests.get('https://www.virustotal.com/api/v3/analyses/{}'.format(data_id), headers=headers)
            analysis_status = response.json()['data']['attributes']['status']
            if analysis_status == 'completed':
                scan_results = response.json()['data']['attributes']['results']
                for antivirus, result in scan_results.items():
                    print('{}: {}'.format(antivirus, result['category']))
                break
            else:
                time.sleep(10)
    else:
        print('Error uploading file to VirusTotal')
