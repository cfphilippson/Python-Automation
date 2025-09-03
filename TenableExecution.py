import tenable_signals_to_elastic


export TENABLE_ACCESS_KEY="xxx"
export TENABLE_SECRET_KEY="yyy"
export ELASTIC_URL="https://elastic.example.com:9200"
export ELASTIC_USER="elastic"
export ELASTIC_PASS="senha"
export INDEX="tenable-signals-000001"   # ou data stream 'tenable-signals'

python3 tenable_signals_to_elastic.py