from dataclasses import dataclass
from typing import List

@dataclass
class FirewallRule:
    rule_id: str
    name: str
    action: str  # BLOCK_SRC_IP, RATE_LIMIT_SYN, BLOCK_SUBNET, CAPTCHA, ISOLATE_NODE, etc.
    block_probability: float  # P(attack blocked)
    false_positive_rate: float  # P(legitimate traffic disrupted)
    cost: float  # Computational / operational overhead
    scope: str  # LOCAL or GLOBAL

def get_candidate_rules_pool() -> List[FirewallRule]:
    """
    Returns pre-configured candidate firewall rules (N=30) for combinatorial optimization.
    """
    return [
        FirewallRule("R01", "Block Source IP", "BLOCK_SRC_IP", 0.95, 0.01, 1.0, "LOCAL"),
        FirewallRule("R02", "Rate-limit SYN Packets", "RATE_LIMIT_SYN", 0.80, 0.04, 2.0, "GLOBAL"),
        FirewallRule("R03", "Block /24 Subnet", "BLOCK_SUBNET", 0.97, 0.08, 1.5, "LOCAL"),
        FirewallRule("R04", "Enable CAPTCHA Challenge", "ENABLE_CAPTCHA", 0.70, 0.12, 3.0, "GLOBAL"),
        FirewallRule("R05", "Isolate Affected Node", "ISOLATE_NODE", 0.99, 0.25, 5.0, "LOCAL"),
        FirewallRule("R06", "Drop UDP Flood", "DROP_UDP", 0.88, 0.02, 1.0, "GLOBAL"),
        FirewallRule("R07", "Rate-limit HTTP GET", "RATE_LIMIT_HTTP", 0.75, 0.05, 2.0, "GLOBAL"),
        FirewallRule("R08", "Block Destination Port", "BLOCK_PORT", 0.90, 0.10, 1.5, "LOCAL"),
        FirewallRule("R09", "Enable TCP Cookie Validation", "TCP_COOKIES", 0.85, 0.01, 2.5, "GLOBAL"),
        FirewallRule("R10", "Block Known Botnet User-Agents", "BLOCK_USER_AGENT", 0.82, 0.02, 1.0, "GLOBAL"),
        FirewallRule("R11", "Enforce Strict TLS Handshake", "ENFORCE_TLS", 0.65, 0.03, 3.0, "GLOBAL"),
        FirewallRule("R12", "Blacklist ASN", "BLOCK_ASN", 0.96, 0.15, 2.0, "GLOBAL"),
        FirewallRule("R13", "Throttle Connection Rate per IP", "THROTTLE_IP", 0.78, 0.04, 2.0, "LOCAL"),
        FirewallRule("R14", "Filter ICMP Requests", "DROP_ICMP", 0.50, 0.005, 0.5, "GLOBAL"),
        FirewallRule("R15", "Reroute Traffic through Scrubbing Center", "SCRUB_TRAFFIC", 0.98, 0.06, 6.0, "GLOBAL"),
        FirewallRule("R16", "Disable Vulnerable Service Endpoint", "DISABLE_ENDPOINT", 0.92, 0.18, 4.0, "LOCAL"),
        FirewallRule("R17", "Rotate PQC Encryption Session Keys", "ROTATE_PQC_KEYS", 0.99, 0.001, 1.0, "GLOBAL"),
        FirewallRule("R18", "Enable GeoIP Blocking (High-Risk Regions)", "GEOIP_BLOCK", 0.86, 0.09, 2.0, "GLOBAL"),
        FirewallRule("R19", "Enforce Deep Packet Inspection (DPI)", "DPI_INSPECT", 0.94, 0.03, 4.5, "GLOBAL"),
        FirewallRule("R20", "Block DNS Amplification Vectors", "DROP_DNS_AMP", 0.91, 0.01, 1.2, "GLOBAL"),
        FirewallRule("R21", "Restrict SSH/RDP to Bastion Hosts", "RESTRICT_MANAGEMENT", 0.93, 0.07, 2.0, "LOCAL"),
        FirewallRule("R22", "Drop Fragmented IP Packets", "DROP_FRAGMENTS", 0.84, 0.02, 1.0, "GLOBAL"),
        FirewallRule("R23", "Enable Web Application Firewall (WAF) Strict Mode", "WAF_STRICT", 0.89, 0.08, 3.5, "GLOBAL"),
        FirewallRule("R24", "Isolate Database Subnet", "ISOLATE_DB", 0.99, 0.20, 5.5, "LOCAL"),
        FirewallRule("R25", "Block Null/Invalid TCP Flags", "DROP_INVALID_FLAGS", 0.80, 0.001, 0.8, "GLOBAL"),
        FirewallRule("R26", "Throttle Payload Size > 10KB", "THROTTLE_PAYLOAD", 0.72, 0.04, 1.8, "GLOBAL"),
        FirewallRule("R27", "Enable Exponential Auth Backoff", "AUTH_BACKOFF", 0.85, 0.02, 1.2, "GLOBAL"),
        FirewallRule("R28", "Block Anonymous Proxies and VPNs", "BLOCK_PROXIES", 0.87, 0.06, 2.2, "GLOBAL"),
        FirewallRule("R29", "Drop NTP Monlist Queries", "DROP_NTP_MONLIST", 0.95, 0.001, 0.5, "GLOBAL"),
        FirewallRule("R30", "Trigger Emergency PQC Key Re-Keying", "EMERGENCY_REKEY", 1.00, 0.001, 1.0, "GLOBAL")
    ]
