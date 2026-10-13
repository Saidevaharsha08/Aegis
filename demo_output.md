# Aegis Mesh — Live Demo Capture

**Generated:** 2026-08-18T19:26:45+00:00
**Target:** `http://127.0.0.1:8765`
**Duration:** 4s

## Timeline

| t (s) | event | detail |
|------:|-------|--------|
|   0.0 | `start` | target=http://127.0.0.1:8765 duration=4s |
|   0.1 | `share_issued` | /mesh/share/shr_9880ac69/0e6d526f75c1f3afcf2f4d57bc3e8fc9be696efd9dfc384974a8663059c1dc39?exp=1787084801 |
|   0.1 | `attack_ingested` | friend-1 campaign=4aaec68fe0 |
|   0.1 | `attack_ingested` | friend-2 campaign=c53651d111 |
|   0.1 | `attack_ingested` | friend-3 campaign=f6bfdbe704 |
|   4.2 | `countermeasure_deployed` | campaign=4aaec68fe0 solver=QAOA-inspired (classical simulation) |
|   4.2 | `bounty_awarded` | peer=friend-1 amount=12 |
|   4.2 | `federated_accepted` | fed-peer-0 |
|   4.2 | `federated_accepted` | fed-peer-1 |
|   4.2 | `federated_accepted` | fed-peer-2 |
|   4.2 | `federated_accepted` | fed-peer-3 |
|   4.2 | `federated_accepted` | fed-peer-4 |

## Per-second Snapshot

| t (s) | contacts | campaigns | cm | federated peers | bounty issued |
|------:|---------:|----------:|---:|----------------:|--------------:|
|   0.1 | 3 | 3 | 0 | 0 | 0 |
|   1.1 | 3 | 3 | 0 | 0 | 0 |
|   2.1 | 3 | 3 | 0 | 0 | 0 |
|   3.1 | 3 | 3 | 0 | 0 | 0 |

## Final State

```json
{
  "honeypots": {
    "total_contacts": 3,
    "by_service": {
      "http": 2,
      "ssh": 1
    },
    "by_service_session": {
      "ssh": "371310f14f70696316913d6c",
      "http": "4348a8a511f021e7cc8cafb5",
      "smb": "d8d8428cb48a4297984627e2"
    },
    "unique_attackers": 3,
    "active_ml_kem_fingerprint": "a96f64701663d027"
  },
  "campaigns": [
    {
      "campaign_id": "4aaec68fe07bdb15",
      "ja4_hint": "user-agent",
      "fingerprint": "4aaec68fe07bdb15",
      "first_seen": 1787081201.7722046,
      "last_seen": 1787081201.7722046,
      "event_count": 1,
      "attacker_ips": [
        "203.0.113.10"
      ],
      "ml_kem_session_ids": [
        "4348a8a511f021e7cc8cafb5"
      ],
      "services": [
        "http"
      ],
      "severity": 1.0,
      "status": "active",
      "peer": "friend-1"
    },
    {
      "campaign_id": "c53651d11111c2c4",
      "ja4_hint": "user-agent",
      "fingerprint": "c53651d11111c2c4",
      "first_seen": 1787081201.7752051,
      "last_seen": 1787081201.7752051,
      "event_count": 1,
      "attacker_ips": [
        "203.0.113.20"
      ],
      "ml_kem_session_ids": [
        "371310f14f70696316913d6c"
      ],
      "services": [
        "ssh"
      ],
      "severity": 1.0,
      "status": "active",
      "peer": "friend-2"
    },
    {
      "campaign_id": "f6bfdbe70458162b",
      "ja4_hint": "user-agent",
      "fingerprint": "f6bfdbe70458162b",
      "first_seen": 1787081201.7786975,
      "last_seen": 1787081201.7786975,
      "event_count": 1,
      "attacker_ips": [
        "203.0.113.30"
      ],
      "ml_kem_session_ids": [
        "4348a8a511f021e7cc8cafb5"
      ],
      "services": [
        "http"
      ],
      "severity": 1.0,
      "status": "active",
      "peer": "friend-3"
    }
  ],
  "countermeasures": [
    {
      "countermeasure_id": "cea28b8d-d22c-475f-bfa8-37d1389a9ee2",
      "campaign_id": "4aaec68fe07bdb15",
      "ml_kem_session_id": "4348a8a511f021e7cc8cafb5",
      "decoy_token": "022bea12c4f24f5f4f1ac09091ab30f4",
      "rules_applied": [
        {
          "name": "mesh-countermeasure",
          "match": {
            "src_ips": [
              "203.0.113.10"
            ],
            "services": [
              "http"
            ]
          },
          "action": "RATE_LIMIT_AND_DECOY",
          "selected_rule_id": "R02",
          "block_probability": 1.65,
          "solver": "QAOA-inspired (classical simulation)"
        }
      ],
      "block_upstream": true,
      "issued_at": 1787081205.9321113,
      "operator_id": "mesh_user",
      "notes": [],
      "solver": "QAOA-inspired (classical simulation)"
    }
  ],
  "federated": {
    "known_peers": 5,
    "total_updates": 5,
    "total_samples": 250,
    "global_delta_keys": [
      "Flow Bytes/s",
      "SYN Flag Count"
    ],
    "rejected_nan": 0,
    "rejected_inf": 0,
    "peers": [
      {
        "peer_id": "fed-peer-4",
        "first_seen": 1787081205.9446828,
        "last_seen": 1787081205.9446828,
        "updates": 1,
        "samples": 50
      },
      {
        "peer_id": "fed-peer-3",
        "first_seen": 1787081205.9420187,
        "last_seen": 1787081205.9420187,
        "updates": 1,
        "samples": 50
      },
      {
        "peer_id": "fed-peer-2",
        "first_seen": 1787081205.940029,
        "last_seen": 1787081205.940029,
        "updates": 1,
        "samples": 50
      },
      {
        "peer_id": "fed-peer-1",
        "first_seen": 1787081
```
