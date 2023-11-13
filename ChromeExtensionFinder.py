# Script desenvolvido por *Carlos Quintas* com auxílio do GPT4
# O intuito desse script é levantar na internet quais as extensões do 
# Chrome estão relacionadas a um determinado Extension ID coletado do Cortex XDR
# O input são os IDs extraidos do Cortex e o output é uma planilha de Excel contendo as URLs da Google Chrome Extension Store


import requests
from bs4 import BeautifulSoup
import pandas as pd

def buscar_extensao_chrome(extension_id):
    search_url = f"https://www.google.com/search?q=chrome+extension+{extension_id}"
    response = requests.get(search_url, verify=False)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a'):
            href = link.get('href')
            if 'chrome.google.com/webstore/detail' in href:
                return href
    return "Não encontrada"

def processar_ids(ids):
    resultados = []
    for extension_id in ids:
        resultado = buscar_extensao_chrome(extension_id)
        resultados.append({'ID': extension_id, 'Link': resultado})
    return resultados

# Lista de IDs das extensões
extension_ids = ["jlhmfgmfgeifomenelglieieghnjghma", "eaanhanppiifopiabnfmhjbikjmeeale", "gighmmpiobklfepjocnamgkkbiglidom"]  # Substitua pelos IDs reais

# Processando os IDs
resultados = processar_ids(extension_ids)

# Criando um DataFrame e salvando em Excel
df = pd.DataFrame(resultados)
df.to_excel("resultados_extensoes_chrome.xlsx", index=False)
