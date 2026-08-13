"""Wazuh SIEM — authenticate and push IOC CDB lists."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import requests

from sentinel.config import WAZUH_DEFAULT_LIST, WAZUH_DEFAULT_PORT
from sentinel.ioc_utils import normalize_iocs_for_wazuh

def build_wazuh_cdb(entries: List[Tuple[str, str]], stamp: str = "") -> str:
    """Build Wazuh CDB list content: `indicator:comment` per line."""
    header = [
        f"# Sentinel Feed IOC list",
        f"# Generated: {stamp or datetime.now(timezone.utc).isoformat()}",
        f"# Entries: {len(entries)}",
        f"# Use in rules via: <list field=\"...\">etc/lists/{WAZUH_DEFAULT_LIST}</list>",
    ]
    lines = header + [f"{key}:{comment}" for key, comment in entries]
    return "\n".join(lines) + "\n"


def _wazuh_base_url(url: str) -> str:
    u = (url or "").strip().rstrip("/")
    if not u:
        return ""
    if not re.match(r"^https?://", u, re.IGNORECASE):
        u = "https://" + u
    return u


def wazuh_authenticate(base_url: str, username: str, password: str,
                       verify_ssl: bool = False, timeout: int = 20) -> Tuple[str, str]:
    """Return (jwt_token, error)."""
    base = _wazuh_base_url(base_url)
    if not base:
        return "", "Wazuh API URL is empty"
    if not username or not password:
        return "", "Username and password are required"
    try:
        resp = requests.post(
            f"{base}/security/user/authenticate",
            auth=(username, password),
            headers={"Content-Type": "application/json"},
            verify=verify_ssl,
            timeout=timeout,
        )
        if resp.status_code >= 400:
            return "", f"Auth failed HTTP {resp.status_code}: {resp.text[:200]}"
        data = resp.json()
        token = ((data.get("data") or {}).get("token")
                 or data.get("token") or "")
        if not token:
            return "", "Auth response did not contain a JWT token"
        return token, ""
    except Exception as exc:  # noqa: BLE001
        return "", f"{type(exc).__name__}: {exc}"[:220]


def wazuh_api(base_url: str, token: str, method: str, path: str,
              *, data=None, raw_body: Optional[bytes] = None,
              content_type: str = "application/json",
              verify_ssl: bool = False, timeout: int = 30) -> Tuple[dict, str]:
    """Low-level Wazuh Manager API call. Returns (json_or_meta, error)."""
    base = _wazuh_base_url(base_url)
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{base}{path if path.startswith('/') else '/' + path}"
    try:
        if raw_body is not None:
            headers["Content-Type"] = content_type
            resp = requests.request(method, url, headers=headers, data=raw_body,
                                    verify=verify_ssl, timeout=timeout)
        elif data is not None:
            headers["Content-Type"] = content_type
            resp = requests.request(method, url, headers=headers, json=data,
                                    verify=verify_ssl, timeout=timeout)
        else:
            resp = requests.request(method, url, headers=headers,
                                    verify=verify_ssl, timeout=timeout)
        if resp.status_code >= 400:
            return {}, f"HTTP {resp.status_code}: {resp.text[:300]}"
        if not resp.content:
            return {"status": resp.status_code}, ""
        try:
            return resp.json(), ""
        except Exception:  # noqa: BLE001
            return {"status": resp.status_code, "text": resp.text[:200]}, ""
    except Exception as exc:  # noqa: BLE001
        return {}, f"{type(exc).__name__}: {exc}"[:220]


def wazuh_test_connection(base_url: str, username: str, password: str,
                          verify_ssl: bool = False, timeout: int = 20) -> Tuple[bool, str]:
    token, err = wazuh_authenticate(base_url, username, password, verify_ssl, timeout)
    if err:
        return False, err
    info, err = wazuh_api(base_url, token, "GET", "/", verify_ssl=verify_ssl, timeout=timeout)
    if err:
        return False, err
    title = (info.get("title") or info.get("data", {}).get("title")
             or "Wazuh API")
    api_ver = info.get("api_version") or (info.get("data") or {}).get("api_version") or ""
    return True, f"Connected to {title}" + (f" (API {api_ver})" if api_ver else "")


def wazuh_push_iocs(base_url: str, username: str, password: str, list_name: str,
                    cdb_body: str, *, verify_ssl: bool = False,
                    restart_manager: bool = True, timeout: int = 30) -> Tuple[bool, str]:
    """Upload IOC CDB list to Wazuh and optionally restart the manager so rules reload it."""
    token, err = wazuh_authenticate(base_url, username, password, verify_ssl, timeout)
    if err:
        return False, f"Authentication failed — {err}"

    fname = re.sub(r"[^A-Za-z0-9._-]", "-", (list_name or WAZUH_DEFAULT_LIST).strip()) or WAZUH_DEFAULT_LIST
    if fname.endswith(".cdb"):
        fname = fname[:-4]

    # Prefer the modern lists API; fall back to legacy path if the manager is older.
    body = cdb_body.encode("utf-8")
    result, err = wazuh_api(
        base_url, token, "PUT", f"/lists/files/{fname}",
        raw_body=body, content_type="application/octet-stream",
        verify_ssl=verify_ssl, timeout=timeout,
    )
    if err and ("404" in err or "405" in err or "not found" in err.lower()):
        # Older managers accept POST /lists with filename + content.
        result, err = wazuh_api(
            base_url, token, "PUT", f"/lists/files/{fname}?overwrite=true",
            raw_body=body, content_type="application/octet-stream",
            verify_ssl=verify_ssl, timeout=timeout,
        )
    if err:
        return False, f"CDB upload failed — {err}"

    msg = f"Uploaded CDB list `{fname}` ({len(cdb_body.splitlines())} lines)."
    detail = ""
    if isinstance(result, dict):
        detail = str((result.get("data") or {}).get("message")
                     or result.get("message") or "")[:160]
        if detail:
            msg += f" {detail}"

    if restart_manager:
        _, rerr = wazuh_api(base_url, token, "PUT", "/manager/restart",
                            verify_ssl=verify_ssl, timeout=timeout)
        if rerr:
            msg += (f" List saved, but manager restart failed ({rerr}). "
                    "Reload analysisd manually or restart wazuh-manager so the list is active.")
        else:
            msg += " Manager restart requested so the new list is loaded."

    return True, msg

