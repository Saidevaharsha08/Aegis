"""Public share-link module.

A friend on another continent opens ``/mesh/share/<share_id>`` in any
browser. The page renders a tiny inline HTML form that POSTs one
attack back to the mesh, fingerprinted by their browser's real
User-Agent + IP. No installation, no CLI, no API key required — the
HMAC-signed share token vouches for them.

Security model
--------------
* Token = HMAC-SHA256(secret, share_id || expires_at || target_url).
* Verification uses ``hmac.compare_digest`` (constant time).
* TTL defaults to 24h; expired tokens return 410 Gone.
* Each successful visit appends a SHARE_HIT entry to the ledger.
* Optional ``X-Aegis-Peer`` header is forwarded into the correlator
  so bounty rewards can be attributed.

Tokens are not persisted to disk — they are stateless HMACs, so a
server restart does NOT invalidate them (the secret stays). The
operator can rotate ``settings.SECRET_KEY`` to revoke all outstanding
shares instantly.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Any, Optional

from app.config import settings


DEFAULT_TTL_SECONDS = 24 * 3600


@dataclass
class ShareToken:
    share_id: str
    expires_at: int
    target_url: str
    token: str  # the HMAC hex digest


def _sign(share_id: str, expires_at: int, target_url: str) -> str:
    secret = settings.SECRET_KEY.encode()
    msg = f"{share_id}|{expires_at}|{target_url}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def issue_share_token(
    target_url: str = "http://localhost:8000",
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> dict[str, Any]:
    """Mint a share token. Returns a JSON-serializable dict.

    The ``token_url`` field is what the operator shares with friends.
    It includes the expiry in the path so verification can be done
    statelessly (no DB lookup) while still respecting TTL.
    """
    share_id = "shr_" + secrets.token_hex(4)
    expires_at = int(time.time()) + ttl_seconds
    token = _sign(share_id, expires_at, target_url)
    # URL layout: /mesh/share/<share_id>/<token>?exp=<expires_at>
    # The exp query is what enforces TTL — verifier compares against
    # the present moment.
    return {
        "share_id": share_id,
        "expires_at": expires_at,
        "ttl_seconds": ttl_seconds,
        "target_url": target_url,
        "token": token,
        "share_url": f"/mesh/share/{share_id}/{token}?exp={expires_at}",
    }


def verify_share_token(
    share_id: str,
    token: str,
    expires_at: int,
    target_url: str = "http://localhost:8000",
) -> Optional[dict[str, Any]]:
    """Verify a token. Returns the decoded payload or None on failure.

    Constant-time via ``hmac.compare_digest``. Expired tokens return
    None even if the signature matches (treat expired == tampered).
    """
    if not share_id or not token:
        return None
    if expires_at < int(time.time()):
        return None
    expected = _sign(share_id, expires_at, target_url)
    if not hmac.compare_digest(expected, token):
        return None
    return {"share_id": share_id, "target_url": target_url, "expires_at": expires_at}


# ---- HTML page (no template engine, single string) -----------------

SHARE_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Aegis Mesh · Send Attack</title>
<style>
  body {{ font-family: 'JetBrains Mono', monospace; background: #080d1a;
         color: #e4e6f1; margin: 0; padding: 0; min-height: 100vh;
         display: flex; align-items: center; justify-content: center; }}
  .card {{ background: #0f1424; border: 1px solid rgba(124, 92, 255, 0.4);
          border-radius: 18px; padding: 32px; max-width: 480px;
          box-shadow: 0 0 40px rgba(124, 92, 255, 0.15); }}
  h1 {{ color: #7c5cff; font-size: 22px; margin: 0 0 8px; }}
  p {{ color: #94a3b8; font-size: 13px; line-height: 1.6; }}
  button {{ background: #ff7a59; color: #080d1a; border: 0; padding: 12px 24px;
            border-radius: 10px; font-family: inherit; font-weight: bold;
            font-size: 14px; cursor: pointer; width: 100%; margin-top: 16px; }}
  button:hover {{ background: #ff8c70; }}
  .meta {{ color: #475569; font-size: 11px; margin-top: 18px; word-break: break-all; }}
  .ok {{ color: #10b981; }}
  .err {{ color: #f43f5e; }}
</style>
</head>
<body>
  <div class="card">
    <h1>// AEGIS MESH · ATTACK CHALLENGE</h1>
    <p>Your visit fingerprints you as a unique attacker on the live honeypot
       mesh. Press the button to send one HTTP enum probe from this browser.
       Your IP, User-Agent, and the page referrer are recorded.</p>
    <p>You will appear in the operator's <code>/mesh</code> dashboard in
       real-time via SSE.</p>
    <form id="f" method="POST" action="{api_target}/mesh/share/{share_id}/{token}/fire?exp={expires_at}">
      <input type="hidden" name="payload" value="GET /.env HTTP/1.1" />
      <input type="hidden" name="user_agent" value="aegis-share-page/1.0" />
      <input type="hidden" name="service" value="http" />
      <button type="submit">FIRE PROBE FROM THIS BROWSER</button>
    </form>
    <div class="meta">
      share_id = <span style="color:#06b6d4">{share_id}</span><br />
      expires  = <span style="color:#06b6d4">{expires_iso}</span>
    </div>
  </div>
</body>
</html>
"""


def render_share_page(
    share_id: str, token: str, expires_at: int, api_target: str
) -> str:
    from datetime import datetime, timezone
    expires_iso = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()
    return SHARE_PAGE_HTML.format(
        share_id=share_id,
        token=token,
        expires_at=expires_at,
        expires_iso=expires_iso,
        api_target=api_target.rstrip("/"),
    )


__all__ = [
    "ShareToken",
    "issue_share_token",
    "verify_share_token",
    "render_share_page",
    "DEFAULT_TTL_SECONDS",
]