#!/usr/bin/env python3
import argparse
import json
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import http.client as http_client
except Exception:
    http_client = None

COMMON_WEB_PORTS = {80, 443, 8080, 8000, 8443, 3000, 5000}

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

VERSION_RE = re.compile(r"(?P<name>[A-Za-z][A-Za-z0-9\-\_\.]+)/(?P<ver>[0-9]+(?:\.[0-9]+){0,3})")

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def parse_ports(ports_str: str):
    # Accept: "22,80,443" or "1-1024"
    ports = set()
    parts = [p.strip() for p in ports_str.split(",") if p.strip()]
    for part in parts:
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            for x in range(a, b + 1):
                ports.add(x)
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)

def tcp_connect(host, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass

def grab_banner(host, port, timeout):
    # Very lightweight, best-effort. Avoid intrusive probing.
    # For HTTP ports, we'll use HTTP HEAD separately.
    if port in COMMON_WEB_PORTS:
        return None

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        # Send nothing; just try to read any greeting (e.g., SSH).
        try:
            data = s.recv(256)
            if data:
                return data.decode(errors="replace").strip()
        except Exception:
            return None
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass
    return None

def http_head(host, port, use_https, timeout, path="/"):
    headers = {}
    status = None
    reason = None

    if http_client is None:
        return {"ok": False, "error": "http.client unavailable"}

    try:
        if use_https:
            ctx = ssl.create_default_context()
            conn = http_client.HTTPSConnection(host, port=port, timeout=timeout, context=ctx)
        else:
            conn = http_client.HTTPConnection(host, port=port, timeout=timeout)

        conn.request("HEAD", path, headers={"User-Agent": "mini-vulnscan/1.0"})
        resp = conn.getresponse()
        status, reason = resp.status, resp.reason
        # Convert headers to lower-case keys
        for k, v in resp.getheaders():
            headers[k.lower()] = v
        conn.close()
        return {"ok": True, "status": status, "reason": reason, "headers": headers}
    except Exception as e:
        return {"ok": False, "error": str(e), "status": status, "reason": reason, "headers": headers}

def tls_cert_info(host, port, timeout):
    info = {"ok": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # notAfter format example: 'Jun  1 12:00:00 2026 GMT'
                not_after = cert.get("notAfter")
                info["ok"] = True
                info["not_after"] = not_after
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days = (exp - datetime.now(timezone.utc)).days
                    info["days_remaining"] = days
    except Exception as e:
        info["error"] = str(e)
    return info

def parse_exposed_versions(headers, banner):
    found = []
    for source in [headers.get("server", ""), headers.get("x-powered-by", ""), banner or ""]:
        for m in VERSION_RE.finditer(source):
            found.append({"product": m.group("name"), "version": m.group("ver"), "evidence": source})
    return found

def version_tuple(v):
    return tuple(int(x) for x in v.split("."))

def load_baseline(path):
    # baseline JSON format:
    # { "nginx": "1.24.0", "Apache": "2.4.58", "OpenSSH": "9.6" }
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def assess_outdated(found_versions, baseline):
    findings = []
    for fv in found_versions:
        prod = fv["product"]
        ver = fv["version"]
        # match baseline keys case-insensitively
        key = None
        for k in baseline.keys():
            if k.lower() == prod.lower():
                key = k
                break
        if not key:
            continue
        try:
            if version_tuple(ver) < version_tuple(baseline[key]):
                findings.append({
                    "type": "outdated_software",
                    "severity": "medium",
                    "product": prod,
                    "detected": ver,
                    "baseline_min": baseline[key],
                    "evidence": fv.get("evidence", "")
                })
        except Exception:
            # if parsing fails, ignore
            pass
    return findings

def security_header_findings(headers, is_https):
    findings = []
    for k, friendly in SECURITY_HEADERS.items():
        if k not in headers:
            # HSTS only relevant on HTTPS
            if k == "strict-transport-security" and not is_https:
                continue
            findings.append({
                "type": "missing_security_header",
                "severity": "low",
                "header": friendly
            })
    # Info leakage
    if "server" in headers:
        findings.append({
            "type": "information_disclosure",
            "severity": "info",
            "detail": f"Server header exposed: {headers.get('server')}"
        })
    if "x-powered-by" in headers:
        findings.append({
            "type": "information_disclosure",
            "severity": "info",
            "detail": f"X-Powered-By exposed: {headers.get('x-powered-by')}"
        })
    return findings

def scan_host(host, ports, timeout, workers, baseline):
    report = {
        "target": host,
        "scanned_at": now_iso(),
        "open_ports": [],
        "web_checks": [],
        "findings": [],
        "errors": [],
    }

    def scan_one_port(p):
        open_ = tcp_connect(host, p, timeout)
        banner = None
        if open_:
            banner = grab_banner(host, p, timeout)
        return p, open_, banner

    open_ports = []
    port_banners = {}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(scan_one_port, p) for p in ports]
        for fut in as_completed(futures):
            p, open_, banner = fut.result()
            if open_:
                open_ports.append(p)
                if banner:
                    port_banners[p] = banner

    open_ports.sort()
    for p in open_ports:
        report["open_ports"].append({
            "port": p,
            "banner": port_banners.get(p)
        })

    # Web checks on common web ports that are open
    for p in open_ports:
        if p not in COMMON_WEB_PORTS:
            continue

        # Decide HTTPS vs HTTP based on port
        candidates = []
        if p in (443, 8443):
            candidates.append(("https", True))
        elif p in (80, 8080, 8000, 3000, 5000):
            candidates.append(("http", False))
            # also try https on these ports? keep minimal and safe: only if user asked; skip by default
        else:
            candidates.append(("http", False))

        for scheme, is_https in candidates:
            head = http_head(host, p, is_https, timeout)
            web_entry = {
                "port": p,
                "scheme": scheme,
                "head_ok": head.get("ok", False),
                "status": head.get("status"),
                "headers": head.get("headers", {}),
                "checks": [],
            }

            if not head.get("ok", False):
                web_entry["error"] = head.get("error")
                report["web_checks"].append(web_entry)
                continue

            headers = head["headers"]
            # Header findings
            web_entry["checks"].extend(security_header_findings(headers, is_https))

            # TLS cert info
            if is_https:
                cert = tls_cert_info(host, p, timeout)
                web_entry["tls"] = cert
                if cert.get("ok") and cert.get("days_remaining") is not None:
                    if cert["days_remaining"] < 14:
                        report["findings"].append({
                            "type": "tls_certificate_expiring",
                            "severity": "medium",
                            "detail": f"TLS certificate expires in {cert['days_remaining']} days on {host}:{p}"
                        })

            # Version parsing + outdated comparison
            versions = parse_exposed_versions(headers, port_banners.get(p))
            if versions:
                web_entry["exposed_versions"] = versions
                report["findings"].extend(assess_outdated(versions, baseline))

            report["web_checks"].append(web_entry)

    # Aggregate web_entry checks into findings for convenience
    for w in report["web_checks"]:
        for c in w.get("checks", []):
            c2 = dict(c)
            c2["at"] = f"{host}:{w['port']} ({w['scheme']})"
            report["findings"].append(c2)

    return report

def write_text_report(report, out_path):
    lines = []
    lines.append(f"Mini Vulnerability Report")
    lines.append(f"Target: {report['target']}")
    lines.append(f"Scanned at (UTC): {report['scanned_at']}")
    lines.append("")
    lines.append("Open Ports:")
    if report["open_ports"]:
        for p in report["open_ports"]:
            b = p.get("banner")
            if b:
                lines.append(f"  - {p['port']}/tcp (banner: {b[:120]})")
            else:
                lines.append(f"  - {p['port']}/tcp")
    else:
        lines.append("  (none found)")

    lines.append("")
    lines.append("Findings:")
    if report["findings"]:
        for f in report["findings"]:
            sev = f.get("severity", "info").upper()
            t = f.get("type", "finding")
            detail = f.get("detail") or f.get("header") or ""
            at = f.get("at", "")
            where = f" @ {at}" if at else ""
            if t == "outdated_software":
                detail = f"{f['product']} {f['detected']} < baseline {f['baseline_min']}"
            lines.append(f"  - [{sev}] {t}{where}: {detail}")
    else:
        lines.append("  (none)")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

def main():
    ap = argparse.ArgumentParser(description="Mini vulnerability scanner (safe, non-intrusive checks).")
    ap.add_argument("target", help="Hostname or IP (e.g., 192.168.1.10 or example.com)")
    ap.add_argument("--ports", default="22,80,443,8080,8443,3000,5000",
                    help='Ports list "22,80,443" or range "1-1024"')
    ap.add_argument("--timeout", type=float, default=1.0, help="Socket timeout seconds")
    ap.add_argument("--workers", type=int, default=200, help="Concurrency level")
    ap.add_argument("--baseline", default="", help="Path to baseline JSON for outdated checks")
    ap.add_argument("--out", default="report", help="Output prefix (writes <out>.json and <out>.txt)")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    baseline = load_baseline(args.baseline) if args.baseline else {}

    report = scan_host(args.target, ports, args.timeout, args.workers, baseline)

    json_path = f"{args.out}.json"
    txt_path = f"{args.out}.txt"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    write_text_report(report, txt_path)

    print(f"Wrote {json_path} and {txt_path}")

if __name__ == "__main__":
    sys.exit(main())
