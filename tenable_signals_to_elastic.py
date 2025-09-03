{
  "index_patterns": ["tenable-signals-*"],
  "data_stream": {},
  "template": {
    "settings": { "index.refresh_interval": "30s" },
    "mappings": {
      "dynamic": true,
      "properties": {
        "@timestamp": { "type": "date" },
        "cloud.provider": { "type": "keyword" },
        "cloud.account.id": { "type": "keyword" },
        "cloud.region": { "type": "keyword" },
        "host.hostname": { "type": "keyword" },
        "host.ip": { "type": "ip" },
        "vulnerability.id": { "type": "keyword" },
        "vulnerability.severity": { "type": "keyword" },
        "vulnerability.score": { "type": "float" },
        "vulnerability.cve": { "type": "keyword" },
        "rule.id": { "type": "keyword" },
        "rule.name": { "type": "keyword" },
        "risk.score": { "type": "float" },
        "labels.finding.status": { "type": "keyword" },
        "labels.exposure.type": { "type": "keyword" }
      }
    }
  }
}
