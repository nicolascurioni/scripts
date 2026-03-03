#!/usr/bin/env python3
"""
Wazuh Environment Health Checker
Wazuh Inc.
Nicolás Curioni <nicolas.curioni@wazuh.com>
=================================
Checks the following and appends a JSON result to /var/log/health-checker.json:

   1. Manager API availability (JWT auth)
   2. Indexer API / cluster health
   3. Dashboard accessibility
   4. Disk space usage (alerts at >= 75% by default)
   5. Shards configured per node (max_shards_per_node x node_count)
   6. Active shards closeness to limit (alerts at >= 80% of limit by default)
   7. JVM Xms/Xmx vs total system RAM
   8. Unassigned shards
   9. TCP port reachability (1514 – events, 1515 – enrollment)
  10. Agent summary (active / disconnected / pending / never_connected + %)
  11. ILM policies configured in the Indexer
  12. Cron jobs for alert/archive log rotation in the Manager
  13. Retention feasibility (disk + shards vs ILM retention days)
  14. Filebeat service status
  15. Filebeat output connectivity
  16. Wazuh Manager cluster nodes (cluster_control -l)  [optional]
  17. Wazuh Indexer cluster nodes (_cat/nodes)           [optional]

Usage:
    python3 health_checker.py [options]

Run as root (or a user with read access to /etc/wazuh-indexer/jvm.options
and write access to /var/log/).
"""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

# ── optional but lightweight dependencies ────────────────────────────────────
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # suppress InsecureRequestWarning
except ImportError:
    print("ERROR: 'requests' is not installed. Run: pip3 install requests", file=sys.stderr)
    sys.exit(1)

try:
    import psutil
except ImportError:
    print("ERROR: 'psutil' is not installed. Run: pip3 install psutil", file=sys.stderr)
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Defaults (override via CLI or by editing these constants)
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_MANAGER_URL    = "https://localhost:55000"
DEFAULT_INDEXER_URL    = "https://localhost:9200"
DEFAULT_DASHBOARD_URL  = "https://localhost:443"
DEFAULT_LOG_FILE       = "/var/log/health-checker.json"
DEFAULT_JVM_OPTIONS    = "/etc/wazuh-indexer/jvm.options"
DEFAULT_DISK_PATH      = "/"
DEFAULT_DISK_THRESHOLD = 75      # percent
DEFAULT_SHARD_THRESHOLD = 80     # percent of total shard limit

# Path to the secrets file. The file must be chmod 600 and owned by root.
# Format: one KEY=VALUE per line, lines starting with # are ignored.
# Supported keys: MANAGER_USER, MANAGER_PASS, INDEXER_USER, INDEXER_PASS
# Each key can also be provided as an environment variable with the same name.
DEFAULT_SECRETS_FILE   = "/etc/health-checker.secrets"

# Cluster node IPs – leave empty lists to skip the cluster checks.
# Edit these lists to hardcode your node IPs, or pass them via CLI flags.
# Manager nodes: plain IPs or hostnames (port 55000 is used automatically)
# Example: DEFAULT_MANAGER_NODES = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
DEFAULT_MANAGER_NODES: list[str] = []

# Indexer nodes: IPs or host:port (defaults to port 9200 if port omitted)
# Example: DEFAULT_INDEXER_NODES = ["10.0.0.1", "10.0.0.2:9200"]
DEFAULT_INDEXER_NODES: list[str] = []

REQUEST_TIMEOUT = 10  # seconds


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────
def _gb(value_bytes: int) -> float:
    return round(value_bytes / (1024 ** 3), 2)


def _make_check(status: str, notify: bool, **details: Any) -> dict:
    return {"status": status, "notify": notify, **details}


# ─────────────────────────────────────────────────────────────────────────────
# Secrets loader
# ─────────────────────────────────────────────────────────────────────────────
_REQUIRED_SECRETS = ("MANAGER_USER", "MANAGER_PASS", "INDEXER_USER", "INDEXER_PASS")

def _load_secrets(secrets_file: str) -> dict[str, str]:
    """
    Load credentials from a secrets file and/or environment variables.

    Resolution order (highest priority first):
      1. Environment variable (e.g. MANAGER_USER)
      2. Secrets file entry (KEY=VALUE, one per line)

    The secrets file should be chmod 600 and owned by root.
    Exits with a clear error message if any required key is missing.
    """
    file_values: dict[str, str] = {}

    if os.path.isfile(secrets_file):
        try:
            with open(secrets_file) as f:
                for lineno, raw in enumerate(f, 1):
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        print(f"WARNING: {secrets_file}:{lineno}: skipping invalid line",
                              file=sys.stderr)
                        continue
                    key, _, value = line.partition("=")
                    file_values[key.strip()] = value.strip().strip('"').strip("'")
        except PermissionError:
            print(f"ERROR: Cannot read {secrets_file}. Run as root.", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"INFO: Secrets file '{secrets_file}' not found – relying on environment variables.",
              file=sys.stderr)

    # Env vars override file values
    secrets: dict[str, str] = {}
    missing: list[str] = []
    for key in _REQUIRED_SECRETS:
        value = os.environ.get(key) or file_values.get(key)
        if not value:
            missing.append(key)
        else:
            secrets[key] = value

    if missing:
        print(
            f"ERROR: Missing credentials: {', '.join(missing)}.\n"
            f"  Provide them in '{secrets_file}' or as environment variables.",
            file=sys.stderr,
        )
        sys.exit(1)

    return secrets


# ─────────────────────────────────────────────────────────────────────────────
# Shared helper – Wazuh Manager JWT token
# ─────────────────────────────────────────────────────────────────────────────
def _get_manager_token(url: str, user: str, password: str) -> tuple[str | None, str | None]:
    """
    Returns (token, None) on success, or (None, error_message) on failure.
    """
    auth_endpoint = f"{url}/security/user/authenticate?raw=true"
    try:
        resp = requests.post(
            auth_endpoint,
            auth=(user, password),
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.text.strip(), None
        return None, f"HTTP {resp.status_code} from {auth_endpoint}"
    except requests.exceptions.ConnectionError as exc:
        return None, f"Connection refused: {exc}"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except Exception as exc:
        return None, str(exc)


# ─────────────────────────────────────────────────────────────────────────────
# Check 1 – Wazuh Manager API
# ─────────────────────────────────────────────────────────────────────────────
def check_manager_api(url: str, user: str, password: str) -> dict:
    auth_endpoint = f"{url}/security/user/authenticate?raw=true"
    query_endpoint = f"{url}/?pretty=true"
    try:
        # Step 1 – obtain JWT token
        token, err = _get_manager_token(url, user, password)
        if err:
            return _make_check("error", True,
                               details=f"Authentication failed: {err}",
                               url=f"{url}/security/user/authenticate?raw=true")

        # Step 2 – query the API root with Bearer token
        resp = requests.get(
            query_endpoint,
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            version = data.get("data", {}).get("api_version", "unknown")
            return _make_check("ok", False,
                               http_code=resp.status_code,
                               api_version=version,
                               url=query_endpoint)
        return _make_check("error", True,
                           http_code=resp.status_code,
                           details=f"Unexpected status code: {resp.status_code}",
                           url=query_endpoint)
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True, details=f"Connection refused: {exc}", url=url)
    except requests.exceptions.Timeout:
        return _make_check("error", True, details="Request timed out", url=url)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=url)


# ─────────────────────────────────────────────────────────────────────────────
# Check 2 – Wazuh Indexer API
# ─────────────────────────────────────────────────────────────────────────────
def check_indexer_api(url: str, user: str, password: str) -> dict:
    endpoint = f"{url}/_cluster/health"
    try:
        resp = requests.get(
            endpoint,
            auth=(user, password),
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            return _make_check("ok", False,
                               http_code=resp.status_code,
                               cluster_name=data.get("cluster_name"),
                               cluster_status=data.get("status"),
                               url=endpoint)
        return _make_check("error", True, http_code=resp.status_code,
                           details=f"Unexpected status code: {resp.status_code}", url=endpoint)
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True, details=f"Connection refused: {exc}", url=endpoint)
    except requests.exceptions.Timeout:
        return _make_check("error", True, details="Request timed out", url=endpoint)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=endpoint)


# ─────────────────────────────────────────────────────────────────────────────
# Check 3 – Wazuh Dashboard
# ─────────────────────────────────────────────────────────────────────────────
def check_dashboard(url: str) -> dict:
    endpoint = url
    try:
        resp = requests.get(
            endpoint,
            verify=False,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        if resp.status_code in (200, 302, 301):
            return _make_check("ok", False, http_code=resp.status_code, url=endpoint)
        return _make_check("error", True, http_code=resp.status_code,
                           details=f"Unexpected status code: {resp.status_code}", url=endpoint)
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True, details=f"Connection refused: {exc}", url=endpoint)
    except requests.exceptions.Timeout:
        return _make_check("error", True, details="Request timed out", url=endpoint)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=endpoint)


# ─────────────────────────────────────────────────────────────────────────────
# Check 4 – Disk Space
# ─────────────────────────────────────────────────────────────────────────────
def check_disk_space(path: str, threshold_pct: int) -> dict:
    try:
        usage = shutil.disk_usage(path)
        used_pct = round(usage.used / usage.total * 100, 2)
        notify = used_pct >= threshold_pct
        status  = "warning" if notify else "ok"
        return _make_check(status, notify,
                            path=path,
                            used_pct=used_pct,
                            threshold_pct=threshold_pct,
                            used_gb=_gb(usage.used),
                            total_gb=_gb(usage.total),
                            free_gb=_gb(usage.free))
    except Exception as exc:
        return _make_check("error", True, details=str(exc), path=path)


# ─────────────────────────────────────────────────────────────────────────────
# Check 5 & 6 – Shard counts
# ─────────────────────────────────────────────────────────────────────────────
def _get_max_shards_per_node(indexer_url: str, user: str, password: str) -> int:
    """
    Retrieve cluster.max_shards_per_node from persistent or transient settings,
    falling back to the OpenSearch/Elasticsearch default of 1000.
    """
    try:
        resp = requests.get(
            f"{indexer_url}/_cluster/settings",
            auth=(user, password),
            verify=False,
            timeout=REQUEST_TIMEOUT,
            params={"include_defaults": "true"},
        )
        if resp.status_code == 200:
            data = resp.json()
            for section in ("persistent", "transient", "defaults"):
                val = (data.get(section, {})
                           .get("cluster", {})
                           .get("max_shards_per_node"))
                if val is not None:
                    return int(val)
    except Exception:
        pass
    return 1000  # OpenSearch/Elasticsearch default


def _get_data_node_count(indexer_url: str, user: str, password: str) -> int:
    try:
        resp = requests.get(
            f"{indexer_url}/_nodes/stats",
            auth=(user, password),
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            # Count only data nodes (nodes that hold shards)
            nodes = data.get("nodes", {})
            data_nodes = [
                n for n in nodes.values()
                if "data" in n.get("roles", [])
            ]
            return len(data_nodes) if data_nodes else max(1, len(nodes))
    except Exception:
        pass
    return 1


def check_shards(indexer_url: str, user: str, password: str,
                 shard_threshold_pct: int) -> tuple[dict, dict]:
    """
    Returns two check dicts: (shards_per_node, active_shards).
    """
    max_shards_per_node = _get_max_shards_per_node(indexer_url, user, password)
    node_count = _get_data_node_count(indexer_url, user, password)
    total_limit = max_shards_per_node * node_count

    # Fetch active & unassigned shards from cluster health
    active_shards = 0
    health_error = None
    try:
        resp = requests.get(
            f"{indexer_url}/_cluster/health",
            auth=(user, password),
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            health_data = resp.json()
            active_shards = health_data.get("active_shards", 0)
        else:
            health_error = f"HTTP {resp.status_code}"
    except Exception as exc:
        health_error = str(exc)

    # Build shards_per_node result (informational)
    shards_per_node_result = {
        "status": "ok",
        "notify": False,
        "max_shards_per_node": max_shards_per_node,
        "node_count": node_count,
        "total_limit": total_limit,
        "active_shards": active_shards if not health_error else None,
    }
    if health_error:
        shards_per_node_result["details"] = f"Could not fetch health: {health_error}"

    # Build active_shards result
    if health_error:
        active_shard_result = _make_check("error", True,
                                          details=f"Could not fetch cluster health: {health_error}")
    else:
        pct_used = round(active_shards / total_limit * 100, 2) if total_limit else 0.0
        notify = pct_used >= shard_threshold_pct
        status = "warning" if notify else "ok"
        active_shard_result = _make_check(status, notify,
                                           active=active_shards,
                                           limit=total_limit,
                                           pct_used=pct_used,
                                           threshold_pct=shard_threshold_pct)

    return shards_per_node_result, active_shard_result


# ─────────────────────────────────────────────────────────────────────────────
# Check 7 – JVM Options (Xms / Xmx vs RAM)
# ─────────────────────────────────────────────────────────────────────────────
def _parse_jvm_heap(jvm_options_path: str) -> tuple[int | None, int | None]:
    """
    Parse -Xms and -Xmx values from jvm.options.
    Values are returned in bytes.  Supports k/m/g suffixes.
    """
    def to_bytes(value: str) -> int:
        value = value.strip().lower()
        multipliers = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}
        for suffix, mult in multipliers.items():
            if value.endswith(suffix):
                return int(value[:-1]) * mult
        return int(value)

    xms = xmx = None
    with open(jvm_options_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#"):
                continue
            m = re.match(r"-Xms(.+)", line, re.IGNORECASE)
            if m:
                xms = to_bytes(m.group(1))
            m = re.match(r"-Xmx(.+)", line, re.IGNORECASE)
            if m:
                xmx = to_bytes(m.group(1))
    return xms, xmx


def check_jvm_options(jvm_options_path: str) -> dict:
    total_ram = psutil.virtual_memory().total
    recommended_max = total_ram // 2  # recommended: no more than 50% of RAM

    if not os.path.isfile(jvm_options_path):
        return _make_check("error", True,
                           details=f"File not found: {jvm_options_path}",
                           path=jvm_options_path)
    try:
        xms, xmx = _parse_jvm_heap(jvm_options_path)
    except Exception as exc:
        return _make_check("error", True, details=f"Parse error: {exc}",
                           path=jvm_options_path)

    if xms is None or xmx is None:
        return _make_check("warning", True,
                           details="Could not find -Xms and/or -Xmx in jvm.options",
                           path=jvm_options_path,
                           xms_gb=_gb(xms) if xms else None,
                           xmx_gb=_gb(xmx) if xmx else None,
                           total_ram_gb=_gb(total_ram))

    # Notify if either value is less than recommended_max
    # (i.e. heap is configured under 50% of RAM — potentially under-provisioned)
    # Also notify if heap > total RAM (mis-configuration)
    issues = []
    if xms < recommended_max:
        issues.append(f"Xms ({_gb(xms)} GB) is below 50% of RAM ({_gb(recommended_max)} GB)")
    if xmx < recommended_max:
        issues.append(f"Xmx ({_gb(xmx)} GB) is below 50% of RAM ({_gb(recommended_max)} GB)")
    if xmx > total_ram:
        issues.append(f"Xmx ({_gb(xmx)} GB) exceeds total RAM ({_gb(total_ram)} GB)")

    notify = len(issues) > 0
    status = "warning" if notify else "ok"
    return _make_check(status, notify,
                       path=jvm_options_path,
                       xms_gb=_gb(xms),
                       xmx_gb=_gb(xmx),
                       total_ram_gb=_gb(total_ram),
                       recommended_heap_gb=_gb(recommended_max),
                       issues=issues if issues else None)


# ─────────────────────────────────────────────────────────────────────────────
# Check 8 – Unassigned Shards
# ─────────────────────────────────────────────────────────────────────────────
def check_unassigned_shards(indexer_url: str, user: str, password: str) -> dict:
    endpoint = f"{indexer_url}/_cluster/health"
    try:
        resp = requests.get(
            endpoint,
            auth=(user, password),
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            count = data.get("unassigned_shards", 0)
            notify = count > 0
            status = "warning" if notify else "ok"
            return _make_check(status, notify, count=count)
        return _make_check("error", True,
                           details=f"HTTP {resp.status_code}", url=endpoint)
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True, details=f"Connection refused: {exc}", url=endpoint)
    except requests.exceptions.Timeout:
        return _make_check("error", True, details="Request timed out", url=endpoint)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=endpoint)


# ─────────────────────────────────────────────────────────────────────────────
# Check 9 – Ports 1514 / 1515
# ─────────────────────────────────────────────────────────────────────────────
def check_ports(host: str, ports: list[int], timeout: int = REQUEST_TIMEOUT) -> dict:
    """
    TCP connect check for a list of ports.
    Port 1514 – agent events (TCP/UDP)
    Port 1515 – agent enrollment
    """
    results = {}
    all_ok = True
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                results[str(port)] = "open"
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            results[str(port)] = f"closed/unreachable ({exc})"
            all_ok = False

    notify = not all_ok
    status = "ok" if all_ok else "error"
    return _make_check(status, notify, host=host, ports=results)


# ─────────────────────────────────────────────────────────────────────────────
# Check 10 – Agent summary (connected / disconnected)
# ─────────────────────────────────────────────────────────────────────────────
def check_agents(url: str, user: str, password: str) -> dict:
    """
    Queries /agents/summary/status via the Manager API.
    Reports connected, disconnected, pending, never_connected counts + percentages.
    """
    token, err = _get_manager_token(url, user, password)
    if err:
        return _make_check("error", True,
                           details=f"Authentication failed: {err}",
                           url=url)

    endpoint = f"{url}/agents/summary/status"
    try:
        resp = requests.get(
            endpoint,
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return _make_check("error", True,
                               http_code=resp.status_code,
                               details=f"HTTP {resp.status_code}",
                               url=endpoint)

        conn = resp.json().get("data", {}).get("connection", {})
        total        = conn.get("total", 0)
        active       = conn.get("active", 0)
        disconnected = conn.get("disconnected", 0)
        pending      = conn.get("pending", 0)
        never        = conn.get("never_connected", 0)

        def pct(n: int) -> float:
            return round(n / total * 100, 1) if total else 0.0

        return _make_check(
            "ok", False,
            total=total,
            active=active,
            active_pct=pct(active),
            disconnected=disconnected,
            disconnected_pct=pct(disconnected),
            pending=pending,
            pending_pct=pct(pending),
            never_connected=never,
            never_connected_pct=pct(never),
        )
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True, details=f"Connection refused: {exc}", url=endpoint)
    except requests.exceptions.Timeout:
        return _make_check("error", True, details="Request timed out", url=endpoint)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=endpoint)


# ─────────────────────────────────────────────────────────────────────────────
# Check 11 – ISM Policies (OpenSearch Index State Management)
# ─────────────────────────────────────────────────────────────────────────────
def check_ilm_policies(indexer_url: str, user: str, password: str) -> dict:
    """
    Checks whether any ISM policies are configured in the Indexer.
    Uses the OpenSearch ISM endpoint: GET _plugins/_ism/policies
    notify=True if no policies are found.
    """
    endpoint = f"{indexer_url}/_plugins/_ism/policies"
    try:
        resp = requests.get(
            endpoint,
            auth=(user, password),
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return _make_check("error", True,
                               http_code=resp.status_code,
                               details=f"HTTP {resp.status_code}",
                               url=endpoint)

        data = resp.json()
        raw_policies = data.get("policies", [])
        policies = []

        for item in raw_policies:
            pol = item.get("policy", {})
            name = pol.get("policy_id", item.get("_id", "unknown"))
            states = pol.get("states", [])
            state_names = [s.get("name") for s in states]

            # Find the delete state and the min_index_age before it
            delete_min_age = None
            rollover_age   = None
            for state in states:
                # Look for delete action in this state
                actions = state.get("actions", [])
                if any("delete" in a for a in actions):
                    # The min_age before entering delete is usually in transitions
                    # of the PREVIOUS state pointing here, already captured below
                    pass
                # Look for rollover action
                for action in actions:
                    if "rollover" in action:
                        rollover_age = action["rollover"].get("min_index_age")
                # Look for transitions into a delete state
                for transition in state.get("transitions", []):
                    if transition.get("state_name") == "delete" or \
                       transition.get("state_name", "").lower() in ("delete", "deleted"):
                        cond = transition.get("conditions", {})
                        delete_min_age = cond.get("min_index_age")

            policies.append({
                "name":          name,
                "states":        state_names,
                "delete_min_age": delete_min_age,
                "rollover_age":  rollover_age,
            })

        if not policies:
            return _make_check("warning", True,
                               details="No ISM policies found. Log retention may be unmanaged.",
                               policies=[])

        return _make_check("ok", False, policy_count=len(policies), policies=policies)

    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True, details=f"Connection refused: {exc}", url=endpoint)
    except requests.exceptions.Timeout:
        return _make_check("error", True, details="Request timed out", url=endpoint)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=endpoint)


# ─────────────────────────────────────────────────────────────────────────────
# Check 12 – Cron jobs for log rotation
# ─────────────────────────────────────────────────────────────────────────────
def check_cron_rotation() -> dict:
    """
    Searches common cron locations for jobs that rotate
    /var/ossec/logs/alerts/ and /var/ossec/logs/archives/.
    notify=True if either path has no cron job covering it.
    """
    cron_dirs_files = [
        "/etc/crontab",
        "/etc/cron.d",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
    ]
    TARGETS = {
        "alerts":   "/var/ossec/logs/alerts",
        "archives": "/var/ossec/logs/archives",
    }

    def _scan_file(path: str) -> list[str]:
        """Return non-comment lines from a cron file."""
        lines = []
        try:
            with open(path) as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        lines.append(stripped)
        except (PermissionError, FileNotFoundError):
            pass
        return lines

    all_cron_lines: list[str] = []
    for loc in cron_dirs_files:
        if os.path.isfile(loc):
            all_cron_lines.extend(_scan_file(loc))
        elif os.path.isdir(loc):
            for fname in os.listdir(loc):
                fpath = os.path.join(loc, fname)
                if os.path.isfile(fpath):
                    all_cron_lines.extend(_scan_file(fpath))

    found: dict[str, list[str]] = {k: [] for k in TARGETS}
    for label, target_path in TARGETS.items():
        for line in all_cron_lines:
            if target_path in line:
                found[label].append(line)

    missing = [k for k, v in found.items() if not v]
    notify  = bool(missing)
    status  = "warning" if notify else "ok"

    result = _make_check(
        status, notify,
        alerts_jobs=found["alerts"],
        archives_jobs=found["archives"],
    )
    if missing:
        result["missing_rotation_for"] = missing
        result["details"] = (
            f"No cron job found for: {', '.join('/var/ossec/logs/' + m + '/' for m in missing)}"
        )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Check 13 – Retention feasibility
# ─────────────────────────────────────────────────────────────────────────────
def _parse_age_to_days(age_str: str) -> int | None:
    """
    Convert ILM age strings like '180d', '26w', '6M', '1y' to days.
    Returns None if the format is unrecognised.
    """
    if not age_str:
        return None
    m = re.fullmatch(r"(\d+)([dhwMy])", age_str.strip())
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    multipliers = {"d": 1, "h": 1, "w": 7, "M": 30, "y": 365}
    return n * multipliers[unit]


def _eval_retention(
    label: str,
    retention_days: int,
    scope: str,
    avg_daily_size_gb: float,
    avg_shards_per_day: float,
    total_disk_gb: float | None,
    shard_limit: int,
    analyses: list,
    issues: list,
) -> None:
    """Compute and record a single retention feasibility scenario."""
    projected_disk_gb = round(avg_daily_size_gb * retention_days, 2)
    projected_shards  = round(avg_shards_per_day * retention_days)
    disk_feasible     = (total_disk_gb is None) or projected_disk_gb <= total_disk_gb
    shards_feasible   = projected_shards <= shard_limit

    analysis: dict = {
        "scope":             scope,
        "policy":           label,
        "retention_days":   retention_days,
        "projected_disk_gb": projected_disk_gb,
        "total_disk_gb":    total_disk_gb,
        "disk_feasible":    disk_feasible,
        "projected_shards": projected_shards,
        "shard_limit":      shard_limit,
        "shards_feasible":  shards_feasible,
    }
    if not disk_feasible:
        issues.append(
            f"[{label}] {retention_days}d retention needs ~{projected_disk_gb} GB "
            f"but only {total_disk_gb} GB available on disk"
        )
    if not shards_feasible:
        issues.append(
            f"[{label}] {retention_days}d retention needs ~{projected_shards} shards "
            f"but shard limit is {shard_limit}"
        )
    analyses.append(analysis)


def check_retention_feasibility(
    indexer_url: str,
    user: str,
    password: str,
    disk_path: str = "/",
    default_ism_days: int = 90,
    default_alerts_days: int = 365,
) -> dict:
    """
    Analyses whether the configured ILM retention periods are achievable
    given available disk space and the shard limit.

    Approach:
      - Pull wazuh-alerts-* indices, compute avg daily size and avg shards/index
      - Pull ILM policies, extract delete-phase min_age
      - For each policy: project disk needed and shards needed vs limits
    """
    issues: list[str] = []

    # ── 1. Fetch wazuh indices ───────────────────────────────────────────────
    cat_endpoint = f"{indexer_url}/_cat/indices/wazuh-alerts-*?format=json&bytes=b&h=index,store.size,pri,rep,creation.date.string"
    try:
        resp = requests.get(
            cat_endpoint,
            auth=(user, password),
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return _make_check("error", True,
                               details=f"Could not fetch indices: HTTP {resp.status_code}",
                               url=cat_endpoint)
        indices = resp.json()
    except Exception as exc:
        return _make_check("error", True, details=f"Could not fetch indices: {exc}")

    if not indices:
        return _make_check("warning", False,
                           details="No wazuh-alerts-* indices found yet. Feasibility cannot be computed.",
                           index_count=0)

    # ── 2. Compute averages ──────────────────────────────────────────────────
    total_size_bytes = 0
    total_primaries  = 0
    valid_count      = 0
    for idx in indices:
        try:
            size = int(idx.get("store.size") or 0)
            pri  = int(idx.get("pri") or 1)
            rep  = int(idx.get("rep") or 0)
            total_size_bytes += size
            total_primaries  += pri * (1 + rep)   # total shards incl. replicas
            valid_count += 1
        except (ValueError, TypeError):
            continue

    if valid_count == 0:
        return _make_check("warning", False,
                           details="Could not parse index size data.",
                           index_count=len(indices))

    # Wazuh rolls over daily → one index ≈ one day of data
    avg_daily_size_bytes = total_size_bytes / valid_count
    avg_daily_size_gb    = round(avg_daily_size_bytes / (1024 ** 3), 3)
    avg_shards_per_day   = round(total_primaries / valid_count, 1)

    # ── 3. Fetch shard limit ─────────────────────────────────────────────────
    shard_limit = _get_max_shards_per_node(indexer_url, user, password) * \
                  _get_data_node_count(indexer_url, user, password)

    # ── 4. Disk available ────────────────────────────────────────────────────
    try:
        du = shutil.disk_usage(disk_path)
        total_disk_gb = round(du.total / (1024 ** 3), 2)
        free_disk_gb  = round(du.free  / (1024 ** 3), 2)
    except Exception:
        total_disk_gb = free_disk_gb = None

    # ── 5. Fetch ISM policies → retention days ───────────────────────────────
    retention_analyses: list[dict] = []
    no_ism_policies = False
    try:
        ism_resp = requests.get(
            f"{indexer_url}/_plugins/_ism/policies",
            auth=(user, password),
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        if ism_resp.status_code == 200:
            for item in ism_resp.json().get("policies", []):
                pol = item.get("policy", {})
                policy_name = pol.get("policy_id", "unknown")

                # Find delete transition min_index_age across all states
                delete_age_str = None
                for state in pol.get("states", []):
                    for transition in state.get("transitions", []):
                        target = transition.get("state_name", "").lower()
                        if target in ("delete", "deleted"):
                            delete_age_str = transition.get("conditions", {}).get("min_index_age")

                retention_days = _parse_age_to_days(delete_age_str)
                if retention_days is None:
                    continue

                _eval_retention(policy_name, retention_days, "ism",
                                avg_daily_size_gb, avg_shards_per_day,
                                total_disk_gb, shard_limit,
                                retention_analyses, issues)
    except Exception:
        pass  # ISM fetch failure is non-fatal; already covered by check_ilm_policies

    # ── 6. Fallback: project with default days if no ISM policies found ───────
    if not retention_analyses:
        no_ism_policies = True
        issues.append(
            f"No ISM policies found. Projecting with default {default_ism_days}d retention target."
        )
        _eval_retention(f"default ({default_ism_days}d)", default_ism_days, "ism",
                        avg_daily_size_gb, avg_shards_per_day,
                        total_disk_gb, shard_limit,
                        retention_analyses, issues)

    # ── 7. Local log files feasibility (alerts + archives) ───────────────────
    # Estimate: same avg daily size applies to raw log files on disk too
    local_projected_gb = round(avg_daily_size_gb * default_alerts_days, 2)
    local_disk_feasible = (total_disk_gb is None) or local_projected_gb <= total_disk_gb
    local_analysis = {
        "scope":              "local_logs",
        "source":            "default",
        "retention_days":    default_alerts_days,
        "projected_disk_gb": local_projected_gb,
        "total_disk_gb":     total_disk_gb,
        "disk_feasible":     local_disk_feasible,
        "note":              (
            "Projection for /var/ossec/logs/alerts + archives. "
            "Requires cron job for rotation."
        ),
    }
    if not local_disk_feasible:
        issues.append(
            f"Local logs: {default_alerts_days}d retention needs ~{local_projected_gb} GB "
            f"but only {total_disk_gb} GB on disk. Without cron rotation, disk will fill."
        )
    retention_analyses.append(local_analysis)

    notify = bool(issues)
    status = "warning" if notify else "ok"
    return _make_check(
        status, notify,
        index_count=valid_count,
        avg_daily_size_gb=avg_daily_size_gb,
        avg_shards_per_day=avg_shards_per_day,
        shard_limit=shard_limit,
        total_disk_gb=total_disk_gb,
        free_disk_gb=free_disk_gb,
        no_ism_policies=no_ism_policies,
        retention_analyses=retention_analyses,
        issues=issues if issues else None,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Check 14 – Filebeat service status
# ─────────────────────────────────────────────────────────────────────────────
def check_filebeat_service() -> dict:
    """
    Checks whether the filebeat systemd service is active.
    Uses: systemctl is-active filebeat
    Returns status=ok if active, status=error otherwise.
    """
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "filebeat"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        state = result.stdout.strip()  # e.g. "active", "inactive", "failed"
        if state == "active":
            return _make_check("ok", False, service="filebeat", state=state)
        return _make_check("error", True,
                           service="filebeat",
                           state=state or "unknown",
                           details=f"Filebeat service is '{state}' (expected 'active')")
    except FileNotFoundError:
        return _make_check("error", True,
                           service="filebeat",
                           details="'systemctl' not found – is this a systemd system?")
    except subprocess.TimeoutExpired:
        return _make_check("error", True,
                           service="filebeat",
                           details="systemctl timed out after 10s")
    except Exception as exc:
        return _make_check("error", True, service="filebeat", details=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Check 15 – Filebeat output connectivity
# ─────────────────────────────────────────────────────────────────────────────
def check_filebeat_output() -> dict:
    """
    Runs 'filebeat test output' to verify connectivity with the configured
    output (typically the Wazuh Indexer / OpenSearch).
    Returns status=ok if the command exits 0 and output contains no errors,
    status=error otherwise.
    """
    try:
        result = subprocess.run(
            ["filebeat", "test", "output"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        combined = (stdout + "\n" + stderr).strip()

        if result.returncode == 0:
            return _make_check("ok", False,
                               details="Filebeat output test passed – connection with Indexer is OK",
                               output=combined or None)
        return _make_check("error", True,
                           details="Filebeat output test failed – check Indexer connectivity",
                           output=combined or None,
                           returncode=result.returncode)
    except FileNotFoundError:
        return _make_check("error", True,
                           details="'filebeat' binary not found in PATH")
    except subprocess.TimeoutExpired:
        return _make_check("error", True,
                           details="'filebeat test output' timed out after 30s")
    except Exception as exc:
        return _make_check("error", True, details=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Check 16 – Wazuh Manager cluster nodes
# ─────────────────────────────────────────────────────────────────────────────
def check_manager_cluster_nodes(expected_nodes: list[str]) -> dict:
    """
    Runs /var/ossec/bin/cluster_control -l on the local node and checks that
    all IPs in expected_nodes appear with status 'Connected'.
    """
    cmd = ["/var/ossec/bin/cluster_control", "-l"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15
        )
    except FileNotFoundError:
        return _make_check("error", True,
                           details="cluster_control binary not found at /var/ossec/bin/cluster_control")
    except subprocess.TimeoutExpired:
        return _make_check("error", True,
                           details="cluster_control timed out after 15s")
    except Exception as exc:
        return _make_check("error", True, details=str(exc))

    if result.returncode != 0:
        err = (result.stderr or result.stdout).strip()
        return _make_check("error", True,
                           details=f"cluster_control exited {result.returncode}: {err}")

    # Parse table output – columns: NAME  TYPE  VERSION  ADDRESS  STATUS  …
    nodes_found: list[dict] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("name") or line.startswith("-"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        nodes_found.append({
            "name":    parts[0],
            "type":    parts[1],
            "version": parts[2],
            "address": parts[3],
            "status":  parts[4],
        })

    found_ips = {n["address"] for n in nodes_found}
    issues: list[str] = []

    for ip in expected_nodes:
        match = next((n for n in nodes_found if n["address"] == ip), None)
        if match is None:
            issues.append(f"{ip}: not found in cluster table")
        elif match["status"] != "Connected":
            issues.append(f"{ip} ({match['name']}): status is '{match['status']}' (expected 'Connected')")

    notify = bool(issues)
    status = "error" if issues else "ok"
    return _make_check(
        status, notify,
        node_count=len(nodes_found),
        expected=expected_nodes,
        nodes=nodes_found,
        issues=issues or None,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Check 17 – Wazuh Indexer cluster nodes
# ─────────────────────────────────────────────────────────────────────────────
def check_indexer_nodes(
    expected_nodes: list[str],
    user: str,
    password: str,
    indexer_url: str,
) -> dict:
    """
    Calls GET /_cat/nodes?format=json on the indexer and checks that all IPs
    in expected_nodes appear in the response.
    Uses indexer_url as the primary target (any node returns the full view).
    """
    endpoint = f"{indexer_url}/_cat/nodes?format=json&h=ip,name,node.role,heap.percent,disk.used_percent,master"
    try:
        resp = requests.get(
            endpoint,
            auth=(user, password),
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True,
                           details=f"Connection refused: {exc}", url=endpoint)
    except requests.exceptions.Timeout:
        return _make_check("error", True,
                           details="Request timed out", url=endpoint)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=endpoint)

    if resp.status_code != 200:
        return _make_check("error", True,
                           http_code=resp.status_code,
                           details=f"HTTP {resp.status_code}",
                           url=endpoint)

    raw_nodes = resp.json()   # list of dicts
    found_ips = {n.get("ip", "") for n in raw_nodes}

    nodes_info = [
        {
            "ip":          n.get("ip"),
            "name":        n.get("name"),
            "role":        n.get("node.role"),
            "heap_pct":    n.get("heap.percent"),
            "disk_pct":    n.get("disk.used_percent"),
            "master":      n.get("master"),
        }
        for n in raw_nodes
    ]

    issues: list[str] = []
    for ip in expected_nodes:
        if ip not in found_ips:
            issues.append(f"{ip}: not found in indexer node list")

    notify = bool(issues)
    status = "error" if issues else "ok"
    return _make_check(
        status, notify,
        node_count=len(raw_nodes),
        expected=expected_nodes,
        nodes=nodes_info,
        issues=issues or None,
        url=endpoint,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Wazuh environment health checker."
    )
    parser.add_argument("--manager-url",      default=DEFAULT_MANAGER_URL)
    parser.add_argument("--indexer-url",      default=DEFAULT_INDEXER_URL)
    parser.add_argument("--dashboard-url",    default=DEFAULT_DASHBOARD_URL)
    parser.add_argument("--secrets-file",     default=DEFAULT_SECRETS_FILE,
                        help="Path to credentials file (KEY=VALUE, chmod 600). "
                             "Keys: MANAGER_USER, MANAGER_PASS, INDEXER_USER, INDEXER_PASS. "
                             "Env vars override file values. (default: /etc/health-checker.secrets)")
    parser.add_argument("--disk-path",        default=DEFAULT_DISK_PATH)
    parser.add_argument("--log-file",         default=DEFAULT_LOG_FILE)
    parser.add_argument("--jvm-options",      default=DEFAULT_JVM_OPTIONS)
    parser.add_argument("--disk-threshold",   type=int, default=DEFAULT_DISK_THRESHOLD,
                        help="Disk usage %% that triggers a notification (default: 75)")
    parser.add_argument("--shard-threshold",  type=int, default=DEFAULT_SHARD_THRESHOLD,
                        help="Active shards %% of limit that triggers notification (default: 80)")
    parser.add_argument("--manager-host",          default="localhost",
                        help="Hostname/IP to use for port checks (default: localhost)")
    parser.add_argument("--ports",                  default="1514,1515",
                        help="Comma-separated ports to check (default: 1514,1515)")
    parser.add_argument("--retention-ism-days",     type=int, default=90,
                        help="Default ISM retention target in days when no policy exists (default: 90)")
    parser.add_argument("--retention-alerts-days",  type=int, default=365,
                        help="Default local log retention target for alerts/archives (default: 365)")
    parser.add_argument("--manager-nodes", default="",
                        help="Comma-separated IPs/hostnames of Wazuh Manager cluster nodes "
                             "(overrides DEFAULT_MANAGER_NODES; leave empty to skip check)")
    parser.add_argument("--indexer-nodes", default="",
                        help="Comma-separated IPs (or host:port) of Wazuh Indexer cluster nodes "
                             "(overrides DEFAULT_INDEXER_NODES; leave empty to skip check)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    secrets = _load_secrets(args.secrets_file)
    mgr_user  = secrets["MANAGER_USER"]
    mgr_pass  = secrets["MANAGER_PASS"]
    idx_user  = secrets["INDEXER_USER"]
    idx_pass  = secrets["INDEXER_PASS"]

    print("[*] Starting Wazuh health checks…")

    # ── Run all checks ───────────────────────────────────────────────────────
    print("    [1/15] Manager API…")
    manager_result = check_manager_api(
        args.manager_url, mgr_user, mgr_pass
    )

    print("    [2/15] Indexer API…")
    indexer_result = check_indexer_api(
        args.indexer_url, idx_user, idx_pass
    )

    print("    [3/15] Dashboard…")
    dashboard_result = check_dashboard(args.dashboard_url)

    print("    [4/15] Disk space…")
    disk_result = check_disk_space(args.disk_path, args.disk_threshold)

    print("    [5/15] & [6/15] Shards…")
    shards_per_node_result, active_shards_result = check_shards(
        args.indexer_url, idx_user, idx_pass,
        args.shard_threshold,
    )

    print("    [7/15] JVM options…")
    jvm_result = check_jvm_options(args.jvm_options)

    print("    [8/15] Unassigned shards…")
    unassigned_result = check_unassigned_shards(
        args.indexer_url, idx_user, idx_pass
    )

    print("    [9/15] Ports 1514 / 1515…")
    ports_to_check = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    ports_result = check_ports(args.manager_host, ports_to_check)

    print("    [10/15] Agent summary…")
    agents_result = check_agents(args.manager_url, mgr_user, mgr_pass)

    print("    [11/15] ILM policies…")
    ilm_result = check_ilm_policies(args.indexer_url, idx_user, idx_pass)

    print("    [12/15] Cron rotation jobs…")
    cron_result = check_cron_rotation()

    print("    [13/15] Retention feasibility…")
    retention_result = check_retention_feasibility(
        args.indexer_url, idx_user, idx_pass,
        args.disk_path,
        args.retention_ism_days,
        args.retention_alerts_days,
    )

    print("    [14/15] Filebeat service…")
    filebeat_service_result = check_filebeat_service()

    print("    [15/15] Filebeat output connectivity…")
    filebeat_output_result = check_filebeat_output()

    # ── Optional cluster checks ──────────────────────────────────────────────
    # Resolve node lists: CLI flag takes priority; fall back to hardcoded defaults
    manager_nodes = (
        [ip.strip() for ip in args.manager_nodes.split(",") if ip.strip()]
        if args.manager_nodes.strip()
        else DEFAULT_MANAGER_NODES
    )
    indexer_nodes = (
        [ip.strip() for ip in args.indexer_nodes.split(",") if ip.strip()]
        if args.indexer_nodes.strip()
        else DEFAULT_INDEXER_NODES
    )

    manager_cluster_result = None
    if manager_nodes:
        total = 15 + bool(manager_nodes) + bool(indexer_nodes)
        print(f"    [16/{total}] Manager cluster nodes…")
        manager_cluster_result = check_manager_cluster_nodes(manager_nodes)

    indexer_nodes_result = None
    if indexer_nodes:
        total = 15 + bool(manager_nodes) + bool(indexer_nodes)
        idx_num = 15 + bool(manager_nodes) + 1
        print(f"    [{idx_num}/{total}] Indexer cluster nodes…")
        indexer_nodes_result = check_indexer_nodes(
            indexer_nodes, idx_user, idx_pass, args.indexer_url
        )

    # ── Assemble result ──────────────────────────────────────────────────────
    checks = {
        "manager_api":           manager_result,
        "indexer_api":           indexer_result,
        "dashboard":             dashboard_result,
        "disk_space":            disk_result,
        "shards_per_node":       shards_per_node_result,
        "active_shards":         active_shards_result,
        "jvm_options":           jvm_result,
        "unassigned_shards":     unassigned_result,
        "ports":                 ports_result,
        "agents":                agents_result,
        "ilm_policies":          ilm_result,
        "cron_rotation":         cron_result,
        "retention_feasibility": retention_result,
        "filebeat_service":      filebeat_service_result,
        "filebeat_output":       filebeat_output_result,
    }
    if manager_cluster_result is not None:
        checks["manager_cluster_nodes"] = manager_cluster_result
    if indexer_nodes_result is not None:
        checks["indexer_nodes"] = indexer_nodes_result

    # Top-level notify flag: true if ANY check requires notification
    global_notify = any(c.get("notify", False) for c in checks.values())

    entry = {
        "timestamp": datetime.now(tz=timezone.utc).astimezone().isoformat(),
        "checks":    checks,
        "notify":    global_notify,
    }

    # ── Write to log ─────────────────────────────────────────────────────────
    log_dir = os.path.dirname(args.log_file)
    if log_dir and not os.path.isdir(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except PermissionError:
            print(f"ERROR: Cannot create log directory {log_dir}. Run as root.", file=sys.stderr)
            sys.exit(1)

    try:
        with open(args.log_file, "a") as f:
            # Pretty-printed JSON block + blank line separator between runs
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        print(f"\n[✓] Results appended to {args.log_file}")
    except PermissionError:
        print(f"ERROR: Cannot write to {args.log_file}. Run as root.", file=sys.stderr)
        sys.exit(1)

    # ── Print summary to stdout ──────────────────────────────────────────────
    print("\n── Health Check Summary ─────────────────────────────────────────")
    STATUS_ICONS = {"ok": "✓", "warning": "⚠", "error": "✗"}
    labels = {
        "manager_api":           "Manager API",
        "indexer_api":           "Indexer API",
        "dashboard":             "Dashboard",
        "disk_space":            "Disk Space",
        "shards_per_node":       "Shards / Node config",
        "active_shards":         "Active Shards",
        "jvm_options":           "JVM Options",
        "unassigned_shards":     "Unassigned Shards",
        "ports":                 "Ports (1514/1515)",
        "agents":                "Agent Summary",
        "ilm_policies":          "ILM Policies",
        "cron_rotation":         "Cron Log Rotation",
        "retention_feasibility": "Retention Feasibility",
        "filebeat_service":      "Filebeat Service",
        "filebeat_output":       "Filebeat → Indexer conn.",
    }
    # Add cluster labels only if the checks were actually run
    if "manager_cluster_nodes" in checks:
        labels["manager_cluster_nodes"] = "Manager Cluster Nodes"
    if "indexer_nodes" in checks:
        labels["indexer_nodes"] = "Indexer Nodes"

    def _reason(check: dict) -> list[str]:
        """Extract human-readable reason lines from a check result."""
        lines = []
        # Generic detail message
        if check.get("details"):
            lines.append(str(check["details"]))
        # JVM / generic issues list (rendered once here, NOT repeated below)
        for issue in check.get("issues") or []:
            lines.append(issue)
        # Disk space
        if check.get("used_pct") is not None:
            lines.append(
                f"Used {check['used_pct']}% of {check.get('total_gb')} GB "
                f"(threshold: {check.get('threshold_pct')}%)"
            )
        # Unassigned shards count
        if check.get("count") is not None and check.get("status") != "ok":
            lines.append(f"{check['count']} unassigned shard(s) found")
        # Active shards near limit
        if check.get("pct_used") is not None and check.get("status") != "ok":
            lines.append(
                f"{check['active']} active shards = {check['pct_used']}% of limit "
                f"{check['limit']} (threshold: {check.get('threshold_pct')}%)"
            )
        # HTTP error code
        if check.get("http_code") and check.get("status") != "ok":
            lines.append(f"HTTP {check['http_code']} from {check.get('url', '')}")
        # Port status
        for port, state in (check.get("ports") or {}).items():
            if state != "open":
                lines.append(f"Port {port}: {state}")
        # Agent summary (always shown for context)
        if check.get("total") is not None:
            lines.append(
                f"Total: {check['total']}  "
                f"Active: {check['active']} ({check['active_pct']}%)  "
                f"Disconnected: {check['disconnected']} ({check['disconnected_pct']}%)  "
                f"Pending: {check['pending']} ({check['pending_pct']}%)  "
                f"Never connected: {check['never_connected']} ({check['never_connected_pct']}%)"
            )
        # ILM/ISM policies summary
        if check.get("policies") is not None:
            for p in check["policies"]:
                delete_age = p.get("delete_min_age") or "no delete phase"
                lines.append(f"{p['name']}: states={p.get('states', p.get('phases', []))}, delete_after={delete_age}")
        # Cluster node issues
        for issue in check.get("issues") or []:
            if issue not in lines:   # avoid duplicating generic issues already added above
                lines.append(issue)
        # Per-node status lines (cluster checks)
        if check.get("nodes") and check.get("status") != "ok":
            for n in check["nodes"]:
                ip = n.get("ip") or n.get("address", "?")
                name = n.get("name", "")
                status_str = n.get("status") or n.get("master", "")
                lines.append(f"  {ip} ({name}): {status_str}")
        # Cron rotation missing
        for target in check.get("missing_rotation_for") or []:
            lines.append(f"Missing cron for /var/ossec/logs/{target}/")
        # Retention feasibility context (always shown for this check)
        analyses = check.get("retention_analyses") or []
        for a in analyses:
            disk_ok   = a.get("disk_feasible", True)
            shrd_ok   = a.get("shards_feasible", True)   # missing in local_logs entry
            feasible  = "OK" if (disk_ok and shrd_ok) else "WARN"
            proj_disk = a.get("projected_disk_gb", "?")
            tot_disk  = a.get("total_disk_gb", "?")
            proj_shrd = a.get("projected_shards", "n/a")
            shrd_lim  = a.get("shard_limit", "n/a")
            scope     = a.get("scope", "ism")
            label     = a.get("policy", a.get("scope", "?"))
            days      = a.get("retention_days", "?")
            if scope == "local_logs":
                lines.append(
                    f"[{feasible}] local logs / {days}d: needs {proj_disk} GB (have {tot_disk} GB) on disk"
                )
            else:
                lines.append(
                    f"[{feasible}] {label} / {days}d: "
                    f"needs {proj_disk} GB (have {tot_disk} GB), "
                    f"{proj_shrd} shards (limit {shrd_lim})"
                )
        return lines

    for key, label in labels.items():
        check = checks[key]
        icon  = STATUS_ICONS.get(check.get("status", "error"), "?")
        notif = " ← NOTIFICATION" if check.get("notify") else ""
        print(f"  [{icon}] {label:<25} {check.get('status','?').upper()}{notif}")
        if check.get("notify"):
            for reason in _reason(check):
                print(f"         └─ {reason}")

    if global_notify:
        print("\n  ⚠  One or more checks require attention (notify=true in log).")
    else:
        print("\n  ✓  All checks passed.")
    print("─────────────────────────────────────────────────────────────────\n")


if __name__ == "__main__":
    main()
