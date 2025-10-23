#!/usr/bin/env python3
"""

Usage examples:
    python3 mailscope.py pantero.id
    python3 mailscope.py pantero.id --allow-active
    python3 mailscope.py pantero.id --enum --enum-max 100
    python3 mailscope.py -i list.txt --enum --enum-max 500

Notes:
    - Passive: MX / A / AAAA / TXT (uses dnspython).
    - Active (optional, disabled by default): TCP connect to SMTP ports, read banner,
      EHLO, check STARTTLS support, fetch TLS cert for SMTPS.
    - Enumeration (--enum) collects subdomains from crt.sh (Certificate Transparency).
"""
from __future__ import annotations
import argparse
import dns.resolver
import dns.exception
import json
import sys
import socket
import ssl
import smtplib
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

# optional dependency for enumeration (crt.sh)
try:
    import requests
except Exception:
    requests = None  # we'll handle later

# --------------------------
# Config
# --------------------------
RESOLVER = dns.resolver.Resolver()
RESOLVER.timeout = 3
RESOLVER.lifetime = 5

COMMON_MAIL_NAMES = ("mail", "smtp", "mx", "mailserver", "mx1", "mx2", "smtp1")
DEFAULT_SMTP_PORTS = [25, 587, 465]


# --------------------------
# Helpers / DNS
# --------------------------
def iso_ts() -> str:
    return datetime.now(timezone.utc).isoformat()

def load_list_file(path: str) -> List[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    return [line.strip() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]

def query_dns(name: str, rdtype: str):
    try:
        return RESOLVER.resolve(name, rdtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None

def get_mx_records(domain: str) -> List[Dict[str, Any]]:
    ans = query_dns(domain, "MX")
    if not ans:
        return []
    recs = []
    for r in ans:
        try:
            recs.append({"preference": int(r.preference), "exchange": str(r.exchange).rstrip(".")})
        except Exception:
            recs.append({"preference": 0, "exchange": str(r).strip()})
    recs.sort(key=lambda x: x["preference"])
    return recs

def resolve_ips(name: str) -> List[str]:
    ips: List[str] = []
    for t in ("A", "AAAA"):
        ans = query_dns(name, t)
        if ans:
            for r in ans:
                ips.append(str(r))
    return ips

def get_txt_records(name: str) -> List[str]:
    ans = query_dns(name, "TXT")
    if not ans:
        return []
    txts: List[str] = []
    for r in ans:
        try:
            if hasattr(r, "strings"):
                parts = []
                for p in r.strings:
                    if isinstance(p, bytes):
                        parts.append(p.decode(errors="ignore"))
                    else:
                        parts.append(str(p))
                txts.append("".join(parts))
            else:
                txts.append(str(r))
        except Exception:
            txts.append(str(r))
    return txts

def is_name_maily(name: str) -> bool:
    label = name.split(".")[0].lower()
    return any(label.startswith(k) or k in label for k in COMMON_MAIL_NAMES)

def score_mail_likelihood(subdomain: str, mx_records: List[Dict[str, Any]], mx_ips: List[str], txts: List[str], sub_a: List[str]) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []
    if mx_records:
        score += 50
        reasons.append("has_mx")
        for mx in mx_records:
            if mx["exchange"].lower().rstrip(".") == subdomain.lower().rstrip("."):
                score += 20
                reasons.append("mx_points_to_subdomain")
    if is_name_maily(subdomain):
        score += 15
        reasons.append("name_looks_like_mail")
    spf_found = False
    for t in txts:
        tl = t.lower()
        if "v=spf1" in tl and ("mx" in tl or "include" in tl or "ip4" in tl or "ip6" in tl):
            score += 20
            reasons.append("spf_mx_include_ip")
            spf_found = True
            break
    if mx_records and mx_ips:
        score += 10
        reasons.append("mx_resolves_to_ips")
    if sub_a:
        score += 5
        reasons.append("subdomain_has_a")
    score = max(0, min(100, score))
    return {"score": score, "reasons": reasons, "spf_found": spf_found}


# --------------------------
# Active SMTP helpers (safe)
# --------------------------
def tcp_banner(address: str, port: int, timeout: float = 5.0) -> Optional[str]:
    try:
        with socket.create_connection((address, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(2048)
                if data:
                    return data.decode(errors="ignore").strip()
            except socket.timeout:
                return None
            except Exception:
                return None
    except Exception:
        return None

def fetch_tls_cert(host: str, port: int, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                try:
                    cert = ssock.getpeercert()
                    return cert
                except Exception:
                    return None
    except Exception:
        return None

def smtp_starttls_check(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    result: Dict[str, Any] = {"host": host, "port": port, "reachable": False, "ehlo_ok": False, "starttls": False, "error": None}
    server = None
    try:
        server = smtplib.SMTP(host=host, port=port, timeout=timeout)
        try:
            ehlo_resp = server.ehlo()
            if isinstance(ehlo_resp, tuple) and ehlo_resp[0] < 400:
                result["ehlo_ok"] = True
        except Exception:
            result["ehlo_ok"] = False
        try:
            features = getattr(server, "esmtp_features", {}) or {}
            if "starttls" in features:
                result["starttls"] = True
        except Exception:
            result["starttls"] = False
        result["reachable"] = result["ehlo_ok"]
    except Exception as e:
        result["error"] = str(e)
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass
    return result

def smtp_ssl_check(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    result: Dict[str, Any] = {"host": host, "port": port, "reachable": False, "ehlo_ok": False, "tls_cert": None, "error": None}
    server = None
    try:
        server = smtplib.SMTP_SSL(host=host, port=port, timeout=timeout)
        try:
            ehlo_resp = server.ehlo()
            if isinstance(ehlo_resp, tuple) and ehlo_resp[0] < 400:
                result["ehlo_ok"] = True
            result["reachable"] = True
        except Exception:
            pass
        try:
            ssock = getattr(server, "sock", None)
            if ssock is not None:
                try:
                    cert = ssock.getpeercert()
                    result["tls_cert"] = cert
                except Exception:
                    result["tls_cert"] = None
        except Exception:
            result["tls_cert"] = None
    except Exception as e:
        result["error"] = str(e)
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass
    return result

def active_smtp_checks(target_host: str, ports: List[int], timeout: float = 5.0) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for p in ports:
        entry: Dict[str, Any] = {"port": p, "tcp_banner": None, "smtp_probe": None, "tls_cert": None}
        entry["tcp_banner"] = tcp_banner(target_host, p, timeout=timeout)
        if p == 465:
            smtp_res = smtp_ssl_check(target_host, p, timeout=timeout)
            entry["smtp_probe"] = smtp_res
            if smtp_res.get("tls_cert") is None:
                entry["tls_cert"] = fetch_tls_cert(target_host, p, timeout=timeout)
            else:
                entry["tls_cert"] = smtp_res.get("tls_cert")
        else:
            smtp_res = smtp_starttls_check(target_host, p, timeout=timeout)
            entry["smtp_probe"] = smtp_res
            entry["tls_cert"] = None
        out.append(entry)
    return out


# --------------------------
# Vendor detection heuristics
# --------------------------
VENDOR_RULES = [
    # (mx_regex, txt_regex, banner_regex, vendor_name)
    (r"aspmx\.l\.google\.com$", r"include:_spf\.google\.com", r"google", "Google Workspace"),
    (r".*\.google\.com$", r"_spf\.google\.com", r"google", "Google Workspace"),
    (r".*\.mail\.protection\.outlook\.com$", r"include:spf\.protection\.outlook\.com", r"outlook|microsoft", "Microsoft 365 / Exchange Online"),
    (r".*\.zoho\.com$", r"include:zoho", r"zoho", "Zoho Mail"),
    (r".*sendgrid\.net$", r"include:sendgrid", r"sendgrid", "SendGrid"),
    (r".*mailgun\.org$", r"include:mailgun", r"mailgun", "Mailgun"),
    (r".*amazonses\.com$", r"include:amazonses", r"amazonses", "Amazon SES"),
    (r".*fastmail\..*$", r"include:fastmail", r"fastmail", "FastMail"),
    (r".*yandex\..*$", r"include:_yandex", r"yandex", "Yandex Mail"),
    (r".*protonmail\..*$", r"protonmail", r"protonmail", "ProtonMail"),
    (r".*idcloudhosting\.com$", r"idcloudhosting", r"idcloudhosting|cprapid", "IDCloudHosting"),
    (r".*cprapid\.com$", r"cprapid", r"cprapid", "IDCloudHosting / CPRapid"),
    (r".*mail\.zen\.co\.id$", r"zen", r"zen", "Zen / Local Provider"),
    (r".*mx[0-9]*\.plesk.*$", r"", r"plesk", "Plesk Mail"),
    (r".*smtp.*\.host.*$", r"", r"smtp", "Generic SMTP Provider"),
]

def detect_vendor(mx_records: List[Dict[str, Any]], txts: List[str], banners: List[str]) -> Dict[str, Any]:
    evidence: List[str] = []
    name: Optional[str] = None
    mx_hosts = [m["exchange"].lower() for m in mx_records]
    txt_join = " ".join([t.lower() for t in txts])
    banner_join = " ".join([b.lower() for b in banners if b])
    for mx_pat, txt_pat, banner_pat, vendor_name in VENDOR_RULES:
        # MX check
        for mx in mx_hosts:
            try:
                if re.search(mx_pat, mx):
                    evidence.append(f"mx={mx} matches {mx_pat}")
                    if not name:
                        name = vendor_name
            except re.error:
                continue
        # TXT check
        if txt_pat:
            try:
                if re.search(txt_pat, txt_join):
                    evidence.append(f"txt contains {txt_pat}")
                    if not name:
                        name = vendor_name
            except re.error:
                pass
        # banner check
        if banner_pat:
            try:
                if re.search(banner_pat, banner_join):
                    evidence.append(f"banner matches {banner_pat}")
                    if not name:
                        name = vendor_name
            except re.error:
                pass

    # fallback heuristics
    if not name:
        if any(re.search(r"idcloudhosting|cprapid", m) for m in mx_hosts):
            name = "IDCloudHosting"
            evidence.append("mx pattern suggests idcloudhosting/cprapid")
        elif any(re.search(r"google|gmail", m) for m in mx_hosts):
            name = "Google Workspace"
            evidence.append("mx pattern suggests google")
        elif any(re.search(r"outlook|office365|protection\.outlook", m) for m in mx_hosts):
            name = "Microsoft 365 / Exchange Online"
            evidence.append("mx pattern suggests outlook/office365")

    return {"name": name, "evidence": evidence}


# --------------------------
# Enumeration via crt.sh (Certificate Transparency)
# --------------------------
def enum_crt_sh(domain: str, limit: int = 500) -> List[str]:
    """
    Query crt.sh for certificates matching the domain and extract subject/common names.
    Returns unique subdomains (no wildcards), limited by `limit`.
    """
    if requests is None:
        print("[!] requests module not installed. Install with: pip install requests", file=sys.stderr)
        return []

    # crt.sh JSON endpoint (query for all entries like %.domain)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return []
        # sometimes crt.sh returns newline delimited json objects or a list
        try:
            data = r.json()
        except Exception:
            # fallback: try to parse lines of JSON
            data = []
            for line in r.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data.append(json.loads(line))
                except Exception:
                    continue
        names = set()
        for item in data:
            # name_value may contain multiple names separated by newlines
            nv = item.get("name_value") or item.get("common_name") or ""
            for candidate in str(nv).splitlines():
                candidate = candidate.strip().lower()
                if not candidate or candidate.startswith("*."):
                    candidate = candidate.lstrip("*.")  # keep the concrete hostname
                # only keep subdomains of domain (exact suffix)
                if candidate.endswith("." + domain) or candidate == domain:
                    names.add(candidate)
                # also accept bare domain
                if candidate == domain:
                    names.add(candidate)
                if len(names) >= limit:
                    break
            if len(names) >= limit:
                break
        # return sorted list
        return sorted(names)
    except Exception:
        return []


# --------------------------
# Analysis pipeline
# --------------------------
def analyze_target(subdomain: str, do_active: bool = False, active_ports: Optional[List[int]] = None, active_timeout: float = 5.0) -> Dict[str, Any]:
    result: Dict[str, Any] = {"subdomain": subdomain, "timestamp": iso_ts()}
    mx = get_mx_records(subdomain)
    result["mx"] = mx
    mx_ips: List[str] = []
    for r in mx:
        mx_ips.extend(resolve_ips(r["exchange"]))
    result["mx_ips"] = sorted(set(mx_ips))
    txt_sub = get_txt_records(subdomain)
    parts = subdomain.split(".")
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else subdomain
    txt_root: List[str] = []
    if apex != subdomain:
        txt_root = get_txt_records(apex)
    result["txt_subdomain"] = txt_sub
    result["txt_root_candidate"] = txt_root
    txts_all = txt_sub + txt_root
    a_ips = resolve_ips(subdomain)
    result["a_records"] = a_ips
    result["analysis"] = score_mail_likelihood(subdomain, mx, result["mx_ips"], txts_all, a_ips)

    # Active probes
    result["active"] = None
    banners_collected: List[str] = []
    if do_active:
        result["active"] = {"probed": True, "targets": []}
        targets: List[str] = []
        for r in mx:
            targets.append(r["exchange"])
        for ip_or_host in a_ips:
            targets.append(ip_or_host)
        # dedupe preserving order
        seen = set()
        targets_clean: List[str] = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                targets_clean.append(t)
        ports = active_ports if active_ports else DEFAULT_SMTP_PORTS
        for t in targets_clean:
            host_entry: Dict[str, Any] = {"target": t, "probes": []}
            probes = active_smtp_checks(t, ports, timeout=active_timeout)
            for p in probes:
                if p.get("tcp_banner"):
                    banners_collected.append(p["tcp_banner"])
                smtp_probe = p.get("smtp_probe")
                if smtp_probe:
                    if smtp_probe.get("error"):
                        banners_collected.append(str(smtp_probe.get("error")))
            host_entry["probes"].append({"by": "hostname", "results": probes})
            resolved_ips = resolve_ips(t)
            if resolved_ips:
                for ip in resolved_ips:
                    probes_ip = active_smtp_checks(ip, ports, timeout=active_timeout)
                    for p in probes_ip:
                        if p.get("tcp_banner"):
                            banners_collected.append(p["tcp_banner"])
                        smtp_probe = p.get("smtp_probe")
                        if smtp_probe and smtp_probe.get("error"):
                            banners_collected.append(str(smtp_probe.get("error")))
                    host_entry["probes"].append({"by": "ip", "ip": ip, "results": probes_ip})
            result["active"]["targets"].append(host_entry)

    vendor = detect_vendor(mx, txts_all, banners_collected)
    result["vendor"] = vendor
    return result


# --------------------------
# CLI
# --------------------------
def parse_ports(s: str) -> List[int]:
    out: List[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(int(part))
        except ValueError:
            continue
    return out

def print_banner():
    banner = r"""
             _ _                      
  _ __  __ _(_) |___ __ ___ _ __  ___ 
 | '  \/ _` | | (_-</ _/ _ \ '_ \/ -_)
 |_|_|_\__,_|_|_/__/\__\___/ .__/\___|
                           |_|   
 Because every domain hides a mailbox.      
    """
    print(banner)

def main():
    print_banner()

    ap = argparse.ArgumentParser(prog="mailscope", description="")
    ap.add_argument("positional", nargs="?", help="Optional single domain/subdomain (e.g. example.com). If -i provided, this is ignored.")
    ap.add_argument("-i", "--input", required=False, help="File with domains/subdomains (one per line). If provided, positional arg is ignored.")
    ap.add_argument("-o", "--output", required=False, help="Output JSONL file. If omitted, prints to stdout.")
    ap.add_argument("-c", "--csv", required=False, help="Also write summary CSV (subdomain,score,vendor,evidence)")
    ap.add_argument("--max", type=int, default=0, help="Max number of targets to process (0 = all).")
    ap.add_argument("--allow-active", action="store_true", help="Enable active SMTP checks (explicit safety flag).")
    ap.add_argument("--active-ports", type=str, default="25,587,465", help="Comma-separated ports to probe when --allow-active is set. Default: 25,587,465")
    ap.add_argument("--active-timeout", type=float, default=5.0, help="Timeout (seconds) for active probes.")
    ap.add_argument("--pretty", action="store_true", help="Print human-friendly pretty JSON output instead of raw JSON.")
    ap.add_argument("--enum", action="store_true", help="Automatically enumerate subdomains via crt.sh before scanning.")
    ap.add_argument("--enum-max", type=int, default=200, help="Maximum number of subdomains to enumerate from crt.sh (default 200).")
    args = ap.parse_args()    

    # Build targets
    targets: List[str] = []
    if args.input:
        try:
            targets = load_list_file(args.input)
        except FileNotFoundError:
            print(f"[!] Input file not found: {args.input}", file=sys.stderr)
            sys.exit(2)
    elif args.positional:
        targets = [args.positional.strip()]

    if args.enum:
        # If enum requested, we need a base domain to query crt.sh.
        # If user supplied a single positional domain, use its apex (example.com).
        # If user provided -i file, we will enumerate each domain in the list (careful).
        enum_candidates: List[str] = []
        if args.input:
            # enumerate for each domain in the file (could be many; user must use --enum-max)
            enum_candidates = targets.copy()
        else:
            if not targets:
                print("[!] No domain provided to enumerate.", file=sys.stderr)
                sys.exit(2)
            enum_candidates = targets.copy()

        enumerated_set = set()
        for base in enum_candidates:
            # normalize base to apex (domain.tld)
            parts = base.split(".")
            if len(parts) >= 2:
                apex = ".".join(parts[-2:])
            else:
                apex = base
            if requests is None:
                print("[!] 'requests' not installed; enumeraton disabled. Install: pip install requests", file=sys.stderr)
                break
            print(f"[+] Enumerating crt.sh for {apex} (limit {args.enum_max}) ...", file=sys.stderr)
            found = enum_crt_sh(apex, limit=args.enum_max)
            for f in found:
                enumerated_set.add(f)
            # small local throttling - crt.sh may block aggressive queries
        # set targets to enumerated results (if not empty), otherwise keep original
        if enumerated_set:
            targets = sorted(enumerated_set)
            print(f"[+] Enumerated {len(targets)} subdomains from crt.sh.", file=sys.stderr)
        else:
            print("[!] No subdomains found via crt.sh (or requests missing).", file=sys.stderr)

    if not targets:
        ap.print_help()
        sys.exit(2)

    if args.max and args.max > 0:
        targets = targets[: args.max]

    out_f = open(args.output, "w", encoding="utf-8") if args.output else None
    csv_f = open(args.csv, "w", encoding="utf-8") if args.csv else None
    if csv_f:
        csv_f.write("subdomain,score,vendor,evidence\n")

    active_ports = parse_ports(args.active_ports) if args.active_ports else DEFAULT_SMTP_PORTS

    try:
        for t in targets:
            print(f"[>] Scanning {t} ...", file=sys.stderr)
            res = analyze_target(t, do_active=args.allow_active, active_ports=active_ports, active_timeout=args.active_timeout)
            if args.pretty:
                line = json.dumps(res, ensure_ascii=False, indent=2, sort_keys=True)
            else:
                line = json.dumps(res, ensure_ascii=False)

            if out_f:
                out_f.write(line + "\n")
            else:
                print(line)

            if csv_f:
                vendor_name = res.get("vendor", {}).get("name") or ""
                evidence = ";".join(res.get("vendor", {}).get("evidence", []))
                csv_f.write(f"{res['subdomain']},{res['analysis']['score']},{vendor_name},{evidence}\n")

    finally:
        if out_f:
            out_f.close()
        if csv_f:
            csv_f.close()

if __name__ == "__main__":
    main()
