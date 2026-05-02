# vulnscan

A small Python vulnerability scanner that performs **safe, non-intrusive checks** against a single target you own or have explicit permission to test.

It can:
- Detect **open TCP ports** (simple TCP connect scan)
- Perform basic **HTTP/HTTPS configuration checks** (security headers, simple TLS info)
- Collect limited **service/banner information** when exposed
- Generate a **report** in both JSON and plain text

## Requirements

- Python 3.8+
- No third-party dependencies (standard library only)

## Usage

Run the scanner by providing a target (IP/hostname). By default it scans a small set of common ports.

```bash
python3 vulnscan.py <target>
```

### Arguments

| Argument | Required | Default | Description |
|---|---:|---|---|
| `target` | Yes | — | Target hostname or IP address (example: `192.168.1.2`, `example.com`). |
| `--ports` | No | `22,80,443,8080,8443,3000,5000` | Ports to scan. Accepts a comma-separated list (e.g. `22,80,443`) or a range (e.g. `1-1024`). |
| `--timeout` | No | `1.0` | Socket timeout in seconds used for port checks and HTTP(S) requests. |
| `--workers` | No | `200` | Number of concurrent worker threads used during port scanning. Increase for faster scans; reduce if you hit resource limits. |
| `--baseline` | No | *(empty)* | Path to a JSON file containing minimum versions for “potentially outdated” checks when versions are exposed in banners/headers. If omitted, no outdated checks are performed. |
| `--out` | No | `report` | Output prefix. The script writes `<out>.json` and `<out>.txt`. |

### Examples

Scan the default ports and write `report.json` / `report.txt`:

```bash
python3 vulnscan.py 192.168.1.2
```

Scan a port range and change output prefix:

```bash
python3 vulnscan.py 192.168.1.2 --ports 1-1024 --out myscan
```

Run with a baseline version file:

```bash
python3 vulnscan.py 192.168.1.2 --baseline baseline.json --out myscan
```

## Output

Two files are generated:

- **JSON report** (`<out>.json`): structured output suitable for automation
- **Text report** (`<out>.txt`): a human-readable summary

### Sample JSON output

(From `sample.json`)

```json
{
  "target": "192.168.1.2",
  "scanned_at": "2026-05-02T01:44:15.238605+00:00",
  "open_ports": [
    {
      "port": 22,
      "banner": "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u2"
    },
    {
      "port": 53,
      "banner": null
    },
    {
      "port": 80,
      "banner": null
    },
    {
      "port": 222,
      "banner": "SSH-2.0-OpenSSH_10.2"
    },
    {
      "port": 443,
      "banner": null
    }
  ],
  "web_checks": [
    {
      "port": 80,
      "scheme": "http",
      "head_ok": true,
      "status": 403,
      "headers": {
        "cache-control": "no-cache, no-store, must-revalidate, private, max-age=0",
        "expires": "0",
        "pragma": "no-cache",
        "x-dns-prefetch-control": "off",
        "content-security-policy": "default-src 'none'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; img-src 'self'; manifest-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'",
        "x-frame-options": "DENY",
        "x-xss-protection": "0",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "content-type": "text/html; charset=utf-8",
        "date": "Sat, 02 May 2026 01:44:21 GMT",
        "connection": "close"
      },
      "checks": [
        {
          "type": "missing_security_header",
          "severity": "low",
          "header": "Permissions-Policy"
        }
      ]
    },
    {
      "port": 443,
      "scheme": "https",
      "head_ok": false,
      "status": null,
      "headers": {},
      "checks": [],
      "error": "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in certificate chain (_ssl.c:1081)"
    }
  ],
  "findings": [
    {
      "type": "missing_security_header",
      "severity": "low",
      "header": "Permissions-Policy",
      "at": "192.168.1.2:80 (http)"
    }
  ],
  "errors": []
}
```

### Sample text output

(From `sample.txt`)

```text
Mini Vulnerability Report
Target: 192.168.1.2
Scanned at (UTC): 2026-05-02T01:44:15.238605+00:00

Open Ports:
  - 22/tcp (banner: SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u2)
  - 53/tcp
  - 80/tcp
  - 222/tcp (banner: SSH-2.0-OpenSSH_10.2)
  - 443/tcp

Findings:
  - [LOW] missing_security_header @ 192.168.1.2:80 (http): Permissions-Policy
```

## Notes

- This tool is intended for learning and basic assessment. It does **not** exploit vulnerabilities.
- Run scans only on systems you are authorized to test.
