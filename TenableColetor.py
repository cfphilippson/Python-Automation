#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Coleta 'findings' (Tenable One Inventory Export API) e envia ao Elastic (ECS).
Env vars necessárias:
  TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY
  ELASTIC_URL (ex.: https://elastic-node:9200)
  ELASTIC_USER, ELASTIC_PASS
  INDEX (ex.: tenable-signals-raw)
"""
import os, time, gzip, io, json, sys
import requests
from datetime import datetime, timezone
from dateutil.parser import isoparse
from elasticsearch import Elasticsearch, helpers

TENABLE_API = "https://cloud.tenable.com"
EXPORT_ENDPOINT = "/api/v1/t1/inventory/export/findings"  # beta
TIMEOUT = 30

def env(name, required=True, default=None):
    v = os.getenv(name, default)
    if required and not v:
        print(f"[ERRO] Variável {name} não definida.", file=sys.stderr)
        sys.exit(2)
    return v

AK = env("TENABLE_ACCESS_KEY")
SK = env("TENABLE_SECRET_KEY")
ELASTIC_URL = env("ELASTIC_URL")
ELASTIC_USER = env("ELASTIC_USER")
ELASTIC_PASS = env("ELASTIC_PASS")
INDEX = env("INDEX", default="tenable-signals-raw")

session = requests.Session()
session.headers.update({
    "X-ApiKeys": f"accessKey={AK}; secretKey={SK}",
    "Accept": "application/json"
})

es = Elasticsearch(ELASTIC_URL, basic_auth=(ELASTIC_USER, ELASTIC_PASS), request_timeout=60)

def start_export(filters=None, format="json", compression=None):
    """
    Inicia export de findings.
    filters: dicionário com filtros Tenable One (ex.: {"severity": ["critical","high"], "updated_at": {"gte": "2025-08-01T00:00:00Z"}})
    """
    body = {"format": format}
    if compression:
        body["compression"] = compression
    if filters:
        body["filters"] = filters
    r = session.post(TENABLE_API + EXPORT_ENDPOINT, json=body, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    return data["export_uuid"]

def get_status(uuid):
    r = session.get(f"{TENABLE_API}{EXPORT_ENDPOINT}/{uuid}/status", timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()

def download_chunk(uuid, chunk_id):
    r = session.get(f"{TENABLE_API}{EXPORT_ENDPOINT}/{uuid}/download/{chunk_id}", timeout=120, stream=True)
    r.raise_for_status()
    content = r.content
    # Se vier gzip:
    if r.headers.get("Content-Encoding","") == "gzip" or r.headers.get("Content-Type","").endswith("gzip"):
        content = gzip.decompress(content)
    # Tente NDJSON; caso contrário JSON array
    text = content.decode("utf-8", errors="replace")
    if text.strip().startswith("["):
        return json.loads(text)
    else:
        return [json.loads(line) for line in text.splitlines() if line.strip()]

def ecs_map(doc):
    """
    Mapeia um 'finding' Tenable One para ECS + campos de risco.
    A estrutura do 'finding' pode evoluir (API beta) — trate chaves ausentes com .get().
    """
    f = doc
    res = {}
    now = datetime.now(timezone.utc).isoformat()

    # Identidade do achado
    res["@timestamp"] = f.get("updated_at") or f.get("created_at") or now
    # Se vier sem timezone, força UTC:
    try:
        res["@timestamp"] = isoparse(res["@timestamp"]).astimezone(timezone.utc).isoformat()
    except Exception:
        res["@timestamp"] = now

    res["event"] = {
        "kind": "state",
        "category": ["vulnerability"],
        "type": ["info"]
    }

    # Severidade / score
    sev = (f.get("severity") or "").lower()
    score = f.get("risk_score") or f.get("cvss", {}).get("base_score")
    res["vulnerability"] = {
        "id": str(f.get("id") or f.get("finding_id") or f.get("signal_id") or ""),
        "scanner": {"vendor": "Tenable"},
        "severity": sev.capitalize() if sev else None,
        "score": score,
        "description": f.get("description") or f.get("title"),
        "reference": f.get("rule", {}).get("id") or f.get("rule_id"),
        "category": f.get("category")  # ex.: cloud_misconfiguration, identity, etc.
    }

    # Regra / sinal / origem
    res["rule"] = {
        "id": f.get("rule", {}).get("id") or f.get("rule_id"),
        "name": f.get("rule", {}).get("name") or f.get("signal_name"),
        "category": f.get("rule", {}).get("category") or f.get("category")
    }

    # Recurso / ativo
    asset = f.get("asset") or {}
    res["asset"] = {
        "id": asset.get("uuid") or asset.get("id"),
        "tags": asset.get("tags")
    }
    res["host"] = {
        "hostname": asset.get("fqdn") or asset.get("hostname"),
        "ip": asset.get("ipv4") or asset.get("ip"),
        "os": asset.get("operating_system")
    }

    # Cloud
    cloud = f.get("cloud") or asset.get("cloud") or {}
    res["cloud"] = {
        "provider": cloud.get("provider"),
        "account": {"id": cloud.get("account_id"), "name": cloud.get("account_name")},
        "region": cloud.get("region")
    }

    # Recurso cloud (quando não é host)
    resource = f.get("resource") or {}
    res["resource"] = {
        "id": resource.get("id"),
        "type": resource.get("type"),
        "name": resource.get("name"),
        "labels": resource.get("labels")
    }

    # Status do finding
    res["labels"] = {
        "finding.status": f.get("status"),
        "finding.state": f.get("state"),
        "exposure.type": f.get("exposure_type")
    }

    # CVE / referências
    cves = []
    if "cve" in f:
        cves = f["cve"] if isinstance(f["cve"], list) else [f["cve"]]
    elif f.get("references", {}).get("cve"):
        cves = f["references"]["cve"]
    res["vulnerability"]["cve"] = cves if cves else None

    # Priorização Tenable (quando houver)
    res["risk"] = {
        "score": score,
        "calculated_level": sev if sev else None
    }

    # Keep original
    res["tenable"] = f
    return res

def bulk_index(docs):
    actions = []
    for d in docs:
        actions.append({
            "_index": INDEX,
            "_op_type": "index",
            "_source": d
        })
    if actions:
        helpers.bulk(es, actions, raise_on_error=False)

def main():
    # Exemplo de filtro incremental por data e severidade
    # Ajuste conforme sua política (ex.: updated_at >= última execução)
    filters = {
        # "updated_at": {"gte": "2025-08-01T00:00:00Z"},
        # Exemplos de filtros possíveis variam; consulte a doc do endpoint (beta).
        # "severity": ["critical", "high"]
    }
    uuid = start_export(filters=filters, format="json")
    print(f"[INFO] Export iniciado: {uuid}")

    # Poll até finalizar
    while True:
        st = get_status(uuid)
        status = st.get("status") or st.get("state") or "RUNNING"
        if status.upper() == "FINISHED":
            chunks = st.get("chunks_available") or st.get("chunks") or []
            print(f"[INFO] Finalizado. Chunks: {chunks}")
            break
        elif status.upper() in ("ERROR","CANCELLED","FAILED"):
            print(f"[ERRO] Export status: {status} - {st}")
            sys.exit(1)
        time.sleep(5)

    # Baixa e indexa
    for chunk_id in chunks:
        rows = download_chunk(uuid, chunk_id)
        ecs_docs = [ecs_map(r) for r in rows]
        bulk_index(ecs_docs)
        print(f"[INFO] Chunk {chunk_id}: {len(ecs_docs)} docs enviados.")

if __name__ == "__main__":
    main()
