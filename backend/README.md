# Aegis backend: detect API

This document shows how to send a feature vector from an external device (for example, a laptop on your LAN) to the Aegis detection API.

Endpoint
- `POST /api/detect` — accepts JSON body with a `features` object. Example request body is provided in `scripts/example_event.json`.

Minimal curl example
```bash
curl -X POST http://<host>:<port>/api/detect \
  -H "Content-Type: application/json" \
  -d @scripts/example_event.json
```

Python forwarder
- Use the included `scripts/device_forwarder.py` to send JSON from another machine. If `requests` is available the script will use it, otherwise it falls back to the stdlib.

Example:
```bash
python scripts/device_forwarder.py --host 1.2.3.4 --port 8000 --file scripts/example_event.json
```

Notes
- The backend expects the features used at training time. You must map your raw telemetry to the model features (numeric fields) before sending. Incorrect feature mapping will produce invalid detections.
- Secure the API when exposing to other devices: use TLS, an API key, or a VPN. Do not expose an open detection endpoint to the public internet.
- For higher throughput and reliability, route device traffic through an ingestion queue (Kafka, RabbitMQ) and use worker processes for inference.

Same-system / local detection example
- To test detections coming from the same machine (for example, a local attacker process), set `source_ip` to `127.0.0.1` or `localhost` and optionally enable `auto_respond` to exercise the playbook.

```bash
curl -X POST "http://localhost:8000/api/detect?source_ip=127.0.0.1&auto_respond=true" \
  -H "Content-Type: application/json" -d @scripts/example_event.json
```

The server will append the detection to the tamper-evident ledger and, if `auto_respond=true` and the model flags the flow as malicious, run the automated response playbook (ledger entries and response summary included in the JSON reply).

API key (optional)
- To protect the detection endpoint, set `DETECT_API_KEY` in your `.env` or environment. When set, clients must send the header `X-API-Key: <key>` with requests.

Example (curl with API key):
```bash
curl -X POST "http://localhost:8000/api/detect?source_ip=127.0.0.1&auto_respond=true" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${DETECT_API_KEY}" \
  -d @scripts/example_event.json
```

Rate limiting
- The detection endpoint is protected by a default in-memory rate limiter (`RATE_LIMIT_PER_MINUTE` in `backend/app/config.py`, default 60). If the limit is exceeded you'll receive HTTP 429 responses. This is intended to discourage accidental floods in demos; for production use a distributed rate limiter (Redis-based or API gateway) is recommended.

Quota endpoint
- You can query your current quota and reset time with `GET /api/detect/quota`. If using an API key include `X-API-Key: <key>`.

Example:
```bash
curl -H "X-API-Key: ${DETECT_API_KEY}" http://localhost:8000/api/detect/quota
```

Redis-backed limiter
- If you set `REDIS_URL` in `backend/app/config.py` (or `.env`) and have `aioredis` installed, the service will use a Redis-backed counter for rate limiting which works across multiple processes/replicas. If `aioredis` is not installed the server falls back to the in-memory limiter.

To enable Redis locally, install Redis and set `REDIS_URL=redis://localhost:6379/0` in `backend/.env`.

Ingestion queue (prototype)
- The project includes a simple Redis-backed ingestion queue prototype:
  - `POST /api/ingest` will push the event onto Redis list `ingest_queue` when `REDIS_URL` is set; otherwise it processes synchronously.
  - Run the worker to consume and process events:

```bash
# start worker (requires REDIS_URL in backend/.env and aioredis installed)
python backend/ingest_worker.py
```

This prototype is intentionally minimal (uses Redis lists and a single worker). For production use consider Redis Streams/Kafka and robust worker supervision.

Generating a key
- Use the included helper to create a secure key and (optionally) write it to `backend/.env`:

```bash
python backend/generate_api_key.py --write
# then start the backend (it will read backend/.env automatically)
```

Remember: do not commit `backend/.env` to version control. Use `.env.sample` as a template.
