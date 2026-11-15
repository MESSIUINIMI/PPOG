#!/usr/bin/env python3
"""Collect public ProxyIP candidates, verify HTTP CONNECT forwarding and enforce BOTH country rules."""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import requests

ROOT = Path(__file__).resolve().parents[1]
SOURCES_FILE = ROOT / os.getenv("SOURCES_FILE", "config/sources.txt")
CUSTOM_FILE = ROOT / "config/custom_candidates.txt"
RESULTS_DIR = ROOT / os.getenv("RESULTS_DIR", "results")
ALLOWED = {x.strip().upper() for x in os.getenv(
    "TARGET_COUNTRIES", "TW,SG,JP,US,KR,GB,DE,FR,AU,BR,IN,NL,TH,CA,TR,ZA,AE"
).split(",") if x.strip()}
MATCH_MODE = os.getenv("COUNTRY_MATCH_MODE", "both").lower()
MAX_CANDIDATES = max(1, int(os.getenv("MAX_CANDIDATES", "300")))
WORKERS = max(1, min(30, int(os.getenv("MAX_WORKERS", "10"))))
TIMEOUT = max(2, int(os.getenv("CONNECT_TIMEOUT", "5")))
UA = "ProxyIP-Optimizer/1.0 (GitHub Actions; bounded validation)"
IPPORT_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?!\d)")

def valid_pair(ip: str, port: str) -> str | None:
    try:
        parsed = ipaddress.ip_address(ip)
        p = int(port)
        if parsed.version != 4 or not (1 <= p <= 65535):
            return None
        # Exclude unspecified, multicast, loopback, link-local and private/reserved ranges.
        if not parsed.is_global:
            return None
        return f"{parsed.compressed}:{p}"
    except ValueError:
        return None

def extract_candidates(text: str) -> set[str]:
    found = set()
    for ip, port in IPPORT_RE.findall(text):
        pair = valid_pair(ip, port)
        if pair:
            found.add(pair)
    return found

def fetch_source(url: str) -> set[str]:
    try:
        r = requests.get(url, timeout=(8, 20), headers={"User-Agent": UA})
        r.raise_for_status()
        # Most sources are plain text/CSV. For JSON, also inspect serialized content.
        return extract_candidates(r.text)
    except Exception as exc:
        print(f"[WARN] Source unavailable: {url} ({exc})")
        return set()

def load_candidates() -> list[str]:
    candidates: set[str] = set()
    if SOURCES_FILE.exists():
        for raw in SOURCES_FILE.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                candidates |= fetch_source(line)
    if CUSTOM_FILE.exists():
        candidates |= extract_candidates(CUSTOM_FILE.read_text(encoding="utf-8", errors="ignore"))
    ordered = sorted(candidates)
    print(f"[INFO] Collected {len(ordered)} unique public IPv4:PORT candidates.")
    return ordered[:MAX_CANDIDATES]

def geo_lookup(ips: list[str]) -> dict[str, str]:
    """Bulk lookup endpoint IP country codes using ip-api.com; unknowns stay unknown."""
    out: dict[str, str] = {}
    # ip-api free batch endpoint allows up to 100 records per request.
    for start in range(0, len(ips), 100):
        batch = ips[start:start + 100]
        try:
            payload = [{"query": ip, "fields": "status,countryCode,query"} for ip in batch]
            resp = requests.post(
                "http://ip-api.com/batch", json=payload, timeout=25,
                headers={"User-Agent": UA}
            )
            resp.raise_for_status()
            for item in resp.json():
                if item.get("status") == "success" and item.get("countryCode"):
                    out[item["query"]] = item["countryCode"].upper()
        except Exception as exc:
            print(f"[WARN] GeoIP batch lookup failed: {exc}")
        time.sleep(1.2)
    return out

def read_trace_over_connect(ip: str, port: int) -> dict[str, str]:
    """Use HTTP CONNECT to tunnel to Cloudflare trace and read the actual egress IP/loc."""
    raw = socket.create_connection((ip, port), timeout=TIMEOUT)
    try:
        raw.settimeout(TIMEOUT)
        request = (
            "CONNECT speed.cloudflare.com:443 HTTP/1.1\r\n"
            "Host: speed.cloudflare.com:443\r\n"
            "Proxy-Connection: Keep-Alive\r\n\r\n"
        ).encode("ascii")
        raw.sendall(request)
        response = b""
        while b"\r\n\r\n" not in response and len(response) < 16384:
            chunk = raw.recv(4096)
            if not chunk:
                break
            response += chunk
        first_line = response.split(b"\r\n", 1)[0].decode("latin1", "replace")
        if not re.search(r"\s200(?:\s|$)", first_line):
            raise RuntimeError(f"CONNECT rejected: {first_line[:120]}")
        context = ssl.create_default_context()
        tls = context.wrap_socket(raw, server_hostname="speed.cloudflare.com")
        raw = None
        try:
            tls.settimeout(TIMEOUT)
            tls.sendall(
                b"GET /cdn-cgi/trace HTTP/1.1\r\n"
                b"Host: speed.cloudflare.com\r\n"
                b"User-Agent: ProxyIP-Optimizer/1.0\r\n"
                b"Connection: close\r\n\r\n"
            )
            data = b""
            while len(data) < 32768:
                part = tls.recv(4096)
                if not part:
                    break
                data += part
            body = data.split(b"\r\n\r\n", 1)[-1].decode("utf-8", "replace")
            fields = {}
            for line in body.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    fields[k.strip()] = v.strip()
            if not fields.get("loc") or not fields.get("ip"):
                raise RuntimeError("Cloudflare trace did not return both ip and loc")
            # The trace's loc is the country reported by Cloudflare for this request.
            return {"exit_ip": fields["ip"], "exit_country": fields["loc"].upper()}
        finally:
            tls.close()
    finally:
        if raw is not None:
            raw.close()

def validate(pair: str, endpoint_country: str) -> dict | None:
    ip, port_s = pair.rsplit(":", 1)
    try:
        trace = read_trace_over_connect(ip, int(port_s))
        exit_country = trace["exit_country"]
        if endpoint_country not in ALLOWED or exit_country not in ALLOWED:
            return None
        if MATCH_MODE == "both" and (endpoint_country not in ALLOWED or exit_country not in ALLOWED):
            return None
        return {
            "pair": pair, "endpoint_country": endpoint_country,
            "exit_country": exit_country, "exit_ip": trace["exit_ip"],
            "verified_at": datetime.now(timezone.utc).isoformat()
        }
    except Exception as exc:
        print(f"[DEBUG] Rejected {pair}: {exc}")
        return None

def write_outputs(valid: list[dict]) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    # Clear stale country files so removed/invalid entries do not linger.
    for path in RESULTS_DIR.glob("*.txt"):
        if path.name != "all.txt":
            path.unlink()
    by_country: dict[str, list[str]] = {}
    for item in valid:
        # Output suffix is the actual egress country; endpoint country remains in audit JSON.
        by_country.setdefault(item["exit_country"], []).append(
            f'{item["pair"]}#{item["exit_country"]}'
        )
    all_lines = sorted({line for lines in by_country.values() for line in lines})
    (RESULTS_DIR / "all.txt").write_text(
        "\n".join(all_lines) + ("\n" if all_lines else ""), encoding="utf-8"
    )
    for country, lines in sorted(by_country.items()):
        (RESULTS_DIR / f"{country}.txt").write_text(
            "\n".join(sorted(set(lines))) + "\n", encoding="utf-8"
        )
    audit = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_countries": sorted(ALLOWED),
        "country_match_mode": MATCH_MODE,
        "candidate_count_checked": getattr(write_outputs, "candidate_count", 0),
        "qualified_count": len(valid),
        "results": valid,
    }
    (RESULTS_DIR / "audit.json").write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[INFO] Wrote {len(all_lines)} qualified entries.")

def main() -> int:
    if MATCH_MODE != "both":
        print("[ERROR] This project currently enforces COUNTRY_MATCH_MODE=both only.")
        return 2
    if not ALLOWED:
        print("[ERROR] TARGET_COUNTRIES is empty.")
        return 2
    candidates = load_candidates()
    write_outputs.candidate_count = len(candidates)
    if not candidates:
        print("[WARN] No candidates collected; preserving existing result files.")
        return 0
    endpoints = sorted({x.split(":", 1)[0] for x in candidates})
    endpoint_countries = geo_lookup(endpoints)
    checkable = [(pair, endpoint_countries.get(pair.split(":", 1)[0], "")) for pair in candidates]
    checkable = [(p, c) for p, c in checkable if c in ALLOWED]
    print(f"[INFO] {len(checkable)} candidates have endpoint countries in target set.")
    valid = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [pool.submit(validate, pair, country) for pair, country in checkable]
        for future in concurrent.futures.as_completed(futures):
            item = future.result()
            if item:
                valid.append(item)
    write_outputs(sorted(valid, key=lambda x: (x["exit_country"], x["pair"])))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
