from typing import Dict, List, Any

PLAYBOOK_MAP: Dict[str, List[str]] = {
    "DOS": [
        "APPLY_QAOA_FIREWALL_RULES",
        "RATE_LIMIT_SYN_FLOOD",
        "ISOLATE_AFFECTED_SUBNET",
        "ROTATE_MLKEM_SESSION_KEYS",
        "LOG_TO_HASH_CHAIN_LEDGER",
        "SEND_SLACK_ALERT"
    ],
    "DDOS": [
        "APPLY_QAOA_FIREWALL_RULES",
        "REROUTE_TRAFFIC_SCRUBBING",
        "ISOLATE_AFFECTED_SUBNET",
        "ROTATE_MLKEM_SESSION_KEYS",
        "LOG_TO_HASH_CHAIN_LEDGER",
        "SEND_SLACK_ALERT"
    ],
    "BRUTEFORCE": [
        "BLOCK_SOURCE_IP",
        "ENABLE_EXPONENTIAL_AUTH_BACKOFF",
        "ROTATE_AFFECTED_SERVICE_KEYS",
        "LOG_TO_HASH_CHAIN_LEDGER"
    ],
    "PORTSCAN": [
        "TEMPORARY_BLOCK_SOURCE_IP_15MIN",
        "INCREASE_LOGGING_VERBOSITY",
        "LOG_TO_HASH_CHAIN_LEDGER"
    ],
    "DATAEXFILTRATION": [
        "ISOLATE_AFFECTED_NODE_IMMEDIATE",
        "ROTATE_ALL_SYSTEM_KEYS",
        "CAPTURE_FORENSIC_TRAFFIC_DUMP",
        "PAGE_SECURITY_TEAM_CRITICAL",
        "LOG_TO_HASH_CHAIN_LEDGER"
    ]
}

def get_playbook_actions(attack_type: str) -> List[str]:
    """Returns mapped response actions for given attack classification."""
    clean_type = attack_type.upper().replace(" ", "").replace("_", "")
    for key, actions in PLAYBOOK_MAP.items():
        if key in clean_type:
            return actions
    # Default fallback playbook for unclassified suspicious traffic
    return [
        "APPLY_QAOA_FIREWALL_RULES",
        "ISOLATE_AFFECTED_NODE_IMMEDIATE",
        "ROTATE_ALL_SYSTEM_KEYS",
        "LOG_TO_HASH_CHAIN_LEDGER"
    ]
