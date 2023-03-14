{
  "nbformat": 4,
  "nbformat_minor": 0,
  "metadata": {
    "colab": {
      "provenance": []
    },
    "kernelspec": {
      "name": "python3",
      "display_name": "Python 3"
    },
    "language_info": {
      "name": "python"
    }
  },
  "cells": [
    {
      "cell_type": "code",
      "execution_count": null,
      "metadata": {
        "id": "KJEZ9LkCXE4K"
      },
      "outputs": [],
      "source": [
        "import requests\n",
        "import hashlib\n",
        "\n",
        "# Substitua YOUR_API_KEY pela sua chave de API real do VirusTotal\n",
        "API_KEY = 'YOUR_API_KEY'\n",
        "\n",
        "# Digite o nome do arquivo que deseja escanear\n",
        "filename = 'example_file.exe'\n",
        "\n",
        "# Abra o arquivo \n",
        "with open(filename, 'rb') as file:\n",
        "    file_contents = file.read()\n",
        "\n",
        "# Calcula o hash SHA-256 do arquivo\n",
        "file_hash = hashlib.sha256(file_contents).hexdigest()\n",
        "\n",
        "# Construa a URL da API VirusTotal\n",
        "url = 'https://www.virustotal.com/api/v3/files/{}'.format(file_hash)\n",
        "\n",
        "# Defina os cabeçalhos e parâmetros da API\n",
        "headers = {'x-apikey': API_KEY}\n",
        "params = {'include': 'scan_results'}\n",
        "\n",
        "# Envie uma solicitação GET para a API\n",
        "response = requests.get(url, headers=headers, params=params)\n",
        "\n",
        "# Verifique se o arquivo foi verificado antes\n",
        "if response.status_code == 200:\n",
        "    scan_results = response.json()['data']['attributes']['last_analysis_results']\n",
        "    print('File has already been scanned!')\n",
        "    for antivirus, result in scan_results.items():\n",
        "        print('{}: {}'.format(antivirus, result['category']))\n",
        "else:\n",
        "    # O arquivo não foi verificado antes, então carregue-o no VirusTotal\n",
        "    files = {'file': (filename, file_contents)}\n",
        "    response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers, files=files)\n",
        "    if response.status_code == 200:\n",
        "        data_id = response.json()['data']['id']\n",
        "        print('File uploaded to VirusTotal. Analysis in progress...')\n",
        "        \n",
        "        # Verifique os resultados da verificação a cada 10 segundos até que estejam prontos\n",
        "        while True:\n",
        "            response = requests.get('https://www.virustotal.com/api/v3/analyses/{}'.format(data_id), headers=headers)\n",
        "            analysis_status = response.json()['data']['attributes']['status']\n",
        "            if analysis_status == 'completed':\n",
        "                scan_results = response.json()['data']['attributes']['results']\n",
        "                for antivirus, result in scan_results.items():\n",
        "                    print('{}: {}'.format(antivirus, result['category']))\n",
        "                break\n",
        "            else:\n",
        "                time.sleep(10)\n",
        "    else:\n",
        "        print('Error uploading file to VirusTotal')\n"
      ]
    }
  ]
}