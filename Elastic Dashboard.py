from elasticsearch import Elasticsearch
import pandas as pd

# Configuração do Elastic Cloud
ELASTIC_CLOUD_URL = "https://suzano.es.us-east1.gcp.elastic-cloud.com:443"
API_KEY = "cE03NzhaZ0JCUGJGYWJqcXZtdXo6S0dqMlRHSXFyM2J3dFZVVXRkZ0dzZw=="

# Conexão com Elasticsearch
es = Elasticsearch(
    ELASTIC_CLOUD_URL,
    api_key=API_KEY,
    verify_certs=False  # somente se houver problema de SSL
)

# Consulta: todos os alertas nas últimas 48h
query = {
    "query": {
        "range": {
            "@timestamp": {
                "gte": "now-48h/h",
                "lte": "now"
            }
        }
    },
    "_source": [
        "@timestamp",
        "kibana.alert.rule.name",
        "kibana.alert.rule.uuid",
        "kibana.alert.severity",
        "kibana.alert.reason",
        "kibana.alert.risk_score",
        "host.name",
        "user.name",
        "source.ip",
        "destination.ip"
    ],
    "size": 1000
}

# Índice padrão de alertas do Elastic SIEM
index_name = ".alerts-security.alerts-default"

# Execução da busca
response = es.search(index=index_name, body=query)

# Extração e transformação para DataFrame
data = [hit["_source"] for hit in response["hits"]["hits"]]
df = pd.DataFrame(data)

# Exporta para Excel
output_file = "alertas_siem_elastic.xlsx"
df.to_excel(output_file, index=False)

print(f"[✔] Exportação finalizada: {output_file}")