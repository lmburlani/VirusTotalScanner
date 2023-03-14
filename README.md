# VirusTotalScanner

Este é um script em Python que usa a API do VirusTotal para verificar se um arquivo já foi verificado antes e, se não, fazer o upload e verificar o arquivo em busca de malware.

--Pré-requisitos

Antes de executar o script, você precisará de uma chave de API do VirusTotal. Se você não tem uma chave, pode obtê-la registrando-se em https://www.virustotal.com/gui/join-us.

--Como usar

    Substitua "YOUR_API_KEY" pela sua chave de API real do VirusTotal.

    Digite o nome do arquivo que deseja escanear na variável "filename".

    Execute o script.

O script verifica se o arquivo já foi verificado antes. Se o arquivo já tiver sido verificado, ele imprimirá os resultados do escaneamento. Caso contrário, fará o upload do arquivo e verificará em busca de malware.

--Limitações

A API do VirusTotal tem limitações no número de solicitações que você pode fazer em um determinado período de tempo. Consulte a documentação da API para obter mais informações.
