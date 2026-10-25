.PHONY: install test lint backend waf e2e collect train
install:   ; pip install -e ".[dev,ml]"
test:      ; python -m pytest -q
lint:      ; ruff check .
backend:   ; uvicorn backend.app:app --port 9000
waf:       ; SENTINEL_UPSTREAM_URL=http://127.0.0.1:9000 uvicorn sentinel.main:app_factory --factory --port 8080
e2e:       ; scripts/e2e.sh 40
# Collect labeled data: run the WAF with SENTINEL_MODE=monitor SENTINEL_TRUST_FORWARDED_FOR=true
# SENTINEL_TRAINING_LOG_PATH=data/train.jsonl, then run the simulators with --label.
train:     ; python -m ml.train --data data/train.jsonl --out models/behavior.json
