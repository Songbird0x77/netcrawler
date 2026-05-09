"""SSL/TLS audit — testssl.sh or nmap ssl scripts fallback."""
from __future__ import annotations
import subprocess
import shutil
import re
from typing import Callable
from core.context import ScanContext

# Only flag these if they appear as OFFERED/ENABLED ciphers, not just mentioned
WEAK_CIPHERS = {
    "rc4":    ("RC4",    "high"),
    "des":    ("DES",    "high"),
    "3des":   ("3DES",   "high"),
    "export": ("EXPORT", "critical"),
    "null":   ("NULL",   "critical"),
    "anon":   ("ANON",   "high"),
}

WEAK_PROTOCOLS = {
    "sslv2":   ("SSLv2",   "critical"),
    "sslv3":   ("SSLv3",   "high"),
    "tlsv1.0": ("TLSv1.0", "high"),
    "tlsv1.1": ("TLSv1.1", "medium"),
}


def _run(cmd: list[str], timeout: int = 120) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except FileNotFoundError:
        return f"[{cmd[0]} not installed]"


def _parse_nmap_ssl(raw: str, ctx: ScanContext, host: str, port: int):
    """
    Parse nmap ssl-enum-ciphers output carefully.
    Only flag ciphers that are actually listed as offered, not just mentioned
    in context (e.g. as part of certificate signature algorithm descriptions).
    """
    lines = raw.splitlines()

    # Find the cipher section for this port
    in_cipher_section = False
    offered_ciphers   = []
    offered_protocols = []

    for line in lines:
        line_stripped = line.strip()
        line_lower    = line_stripped.lower()

        # Detect cipher section start
        if "ssl-enum-ciphers" in line_lower:
            in_cipher_section = True
            continue

        # Detect protocol headers (e.g. "TLSv1.2:")
        if re.match(r'^\s*(TLSv[\d\.]+|SSLv[\d\.]+):\s*$', line, re.IGNORECASE):
            proto = re.match(r'^\s*(TLSv[\d\.]+|SSLv[\d\.]+)', line, re.IGNORECASE)
            if proto:
                offered_protocols.append(proto.group(1))
            continue

        # Cipher lines look like: "TLS_RSA_WITH_RC4_128_MD5 - C"
        # Only parse lines inside the cipher section that look like cipher entries
        if in_cipher_section and re.match(r'^\s*(TLS|SSL)_', line_stripped, re.IGNORECASE):
            offered_ciphers.append(line_stripped.lower())

        # Stop if we hit a different script section
        if in_cipher_section and line_stripped.startswith("|_"):
            in_cipher_section = False

    # Now check offered ciphers and protocols for weaknesses
    for key, (name, severity) in WEAK_CIPHERS.items():
        # Check if this weak cipher appears in an OFFERED cipher suite name
        for cipher_line in offered_ciphers:
            # Match as a word boundary in the cipher name
            if re.search(rf'_with_{key}_|_{key}_|_{key}\b', cipher_line):
                ctx.add_finding(
                    severity=severity,
                    title=f"Weak cipher offered: {name} on port {port}",
                    description=(
                        f"Cipher suite using {name} is offered on {host}:{port}. "
                        f"Cipher: {cipher_line[:80]}"
                    ),
                    source="ssl_audit",
                    host=host,
                    port=port,
                    tags=["ssl", "weak-cipher", key],
                    raw=cipher_line,
                )
                break  # Only report once per cipher type

    for key, (name, severity) in WEAK_PROTOCOLS.items():
        for proto in offered_protocols:
            if key in proto.lower():
                ctx.add_finding(
                    severity=severity,
                    title=f"Weak protocol offered: {name} on port {port}",
                    description=f"{name} is offered on {host}:{port}. Should be disabled.",
                    source="ssl_audit",
                    host=host,
                    port=port,
                    tags=["ssl", "weak-protocol", key],
                    raw=f"Protocol {name} found in nmap ssl-enum-ciphers",
                )

    # Check for Heartbleed explicitly
    for line in lines:
        if "heartbleed" in line.lower() and "vulnerable" in line.lower():
            ctx.add_finding(
                severity="critical",
                title=f"Heartbleed (CVE-2014-0160) on port {port}",
                description=f"Heartbleed confirmed on {host}:{port}.",
                source="ssl_audit",
                host=host,
                port=port,
                tags=["ssl", "heartbleed", "cve-2014-0160"],
                raw=line,
            )

    # Check cipher grade — nmap rates with A/B/C/D/F
    grade_match = re.search(r'least strength:\s*([A-F])', raw, re.IGNORECASE)
    if grade_match:
        grade = grade_match.group(1).upper()
        if grade in ("C", "D", "F"):
            ctx.add_finding(
                severity="high" if grade == "C" else "critical",
                title=f"Poor SSL cipher grade: {grade} on port {port}",
                description=f"Nmap rates the cipher suite strength as {grade} on {host}:{port}.",
                source="ssl_audit",
                host=host,
                port=port,
                tags=["ssl", "cipher-grade", grade.lower()],
                raw=f"Least strength: {grade}",
            )


def run_ssl_audit(ctx: ScanContext, status: Callable[[str], None]) -> str:
    host      = ctx.target_host
    ssl_ports = [p for p in ctx.ports if p in (443, 8443, 465, 993, 995)]

    if not ssl_ports:
        return "[skipped — no SSL ports open]"

    output = []

    for port in ssl_ports:
        status(f"Auditing SSL/TLS on {host}:{port}...")

        if shutil.which("testssl") or shutil.which("testssl.sh"):
            binary = "testssl" if shutil.which("testssl") else "testssl.sh"
            raw = _run([
                binary, "--severity", "MEDIUM",
                "--color", "0", "--fast", f"{host}:{port}",
            ], timeout=180)
            output.append(f"=== TESTSSL {host}:{port} ===\n{raw[:3000]}")

        elif shutil.which("nmap"):
            status(f"Running Nmap SSL scripts on {host}:{port}...")
            raw = _run([
                "nmap", "-p", str(port),
                "--script", "ssl-enum-ciphers,ssl-cert,ssl-heartbleed",
                "-T4", host,
            ], timeout=120)
            output.append(f"=== NMAP SSL {host}:{port} ===\n{raw}")
            _parse_nmap_ssl(raw, ctx, host, port)

            # Certificate info
            cert_cn = re.search(r'Subject:\s*commonName=([^\s,/]+)', raw)
            cert_exp = re.search(r'Not valid after:\s*(.+)', raw)
            if cert_cn:
                output.append(f"  CN: {cert_cn.group(1)}")
            if cert_exp:
                output.append(f"  Expires: {cert_exp.group(1).strip()}")
                ctx.add_finding(
                    severity="info",
                    title=f"SSL certificate expiry on port {port}",
                    description=f"Certificate on {host}:{port} expires: {cert_exp.group(1).strip()}",
                    source="ssl_audit",
                    host=host,
                    port=port,
                    tags=["ssl", "certificate", "expiry"],
                    raw=cert_exp.group(0),
                )
        else:
            output.append(f"[no SSL audit tools available for port {port}]")

    return "\n\n".join(output)
