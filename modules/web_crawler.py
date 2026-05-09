"""Web crawler — robots.txt, sitemap.xml, and interesting path discovery."""
from __future__ import annotations
import urllib.request
import urllib.error
import re
import xml.etree.ElementTree as ET
from typing import Callable
from core.context import ScanContext

INTERESTING_PATHS = [
    "/.env", "/.git/HEAD", "/.git/config", "/config.php", "/wp-config.php",
    "/web.config", "/phpinfo.php", "/.htaccess", "/backup.zip", "/backup.sql",
    "/admin", "/administrator", "/login", "/wp-admin", "/phpmyadmin",
    "/api", "/api/v1", "/api/v2", "/swagger", "/swagger-ui.html",
    "/actuator", "/actuator/health", "/actuator/env",
    "/.DS_Store", "/crossdomain.xml", "/server-status", "/server-info",
]

# Content signatures — what the response must contain to be a real match
PATH_SIGNATURES = {
    "/.git/HEAD":    ["ref:", "HEAD"],
    "/.git/config":  ["[core]", "[remote", "repositoryformatversion"],
    "/.env":         ["APP_", "DB_", "SECRET", "KEY=", "PASSWORD="],
    "/phpinfo.php":  ["PHP Version", "phpinfo()"],
    "/backup.zip":   None,  # Any 200 is suspicious
    "/backup.sql":   ["INSERT INTO", "CREATE TABLE", "DROP TABLE"],
    "/wp-config.php":["DB_NAME", "DB_PASSWORD", "table_prefix"],
    "/config.php":   ["password", "database", "db_"],
}

SENSITIVE_PATTERNS = [
    (r'(password|passwd|pwd)\s*=\s*\S+',       "Possible password exposed"),
    (r'(api[_-]?key|apikey)\s*[:=]\s*\S+',     "Possible API key exposed"),
    (r'(secret[_-]?key)\s*[:=]\s*\S+',         "Possible secret key exposed"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Private key exposed"),
    (r'(aws_access_key_id|aws_secret)',         "AWS credentials pattern"),
]


def _fetch(url: str, timeout: int = 8) -> tuple[int, str | None]:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; NetCrawler/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(50000).decode(errors="ignore")
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return 0, None


def _content_matches(path: str, content: str) -> bool:
    """Verify the response body actually matches what we expect for this path."""
    if path not in PATH_SIGNATURES:
        return True  # No signature defined — accept any 200
    sigs = PATH_SIGNATURES[path]
    if sigs is None:
        return True  # Explicitly accept any 200
    content_lower = content.lower()
    return any(sig.lower() in content_lower for sig in sigs)


def _is_cdn_default_page(content: str) -> bool:
    """Detect Cloudflare/CDN default pages serving as 200 for all paths."""
    cdn_indicators = [
        "attention required! | cloudflare",
        "cf-ray",
        "error 1020",
        "access denied",
        "please enable cookies",
        "checking your browser",
        "just a moment",
    ]
    content_lower = content.lower()
    return any(indicator in content_lower for indicator in cdn_indicators)


def run_web_crawler(ctx: ScanContext, status: Callable[[str], None]) -> str:
    if not ctx.is_web:
        return "[skipped — not a web target]"

    base   = ctx.target_url.rstrip("/")
    output = []

    # --- robots.txt ---
    status("Fetching robots.txt...")
    code, robots = _fetch(f"{base}/robots.txt")
    if code == 200 and robots and "disallow" in robots.lower():
        output.append(f"=== robots.txt (HTTP {code}) ===\n{robots[:1000]}")

        # Parse actual paths — filter out bare "/" entries
        disallowed = []
        for line in robots.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                # Only keep meaningful paths (not bare "/" or empty)
                if path and path != "/" and len(path) > 1:
                    disallowed.append(path)

        sitemaps = re.findall(r'(?i)Sitemap:\s*(\S+)', robots)

        if disallowed:
            ctx.add_finding(
                severity="info",
                title=f"robots.txt reveals {len(disallowed)} disallowed path(s)",
                description="Disallowed paths: " + ", ".join(disallowed[:15]),
                source="web_crawler",
                host=ctx.target_host,
                url=f"{base}/robots.txt",
                tags=["robots", "paths", "recon"],
                raw=robots[:500],
            )
            for path in disallowed[:20]:
                clean = path.lstrip("/")
                if clean and clean not in ctx.directories:
                    ctx.directories.append(clean)
        else:
            output.append("  [robots.txt found but no meaningful disallowed paths]")
    else:
        output.append(f"=== robots.txt === [HTTP {code} — not found or blocked]")

    # --- sitemap.xml ---
    status("Fetching sitemap.xml...")
    all_urls = []
    for sm_path in ["/sitemap.xml", "/sitemap_index.xml"]:
        code, sitemap = _fetch(f"{base}{sm_path}")
        if code == 200 and sitemap:
            try:
                root = ET.fromstring(sitemap)
                ns   = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                locs = [l.text for l in root.findall('.//sm:loc', ns) if l.text]
                all_urls.extend(locs[:50])
            except ET.ParseError:
                all_urls += [l.strip() for l in sitemap.splitlines() if l.startswith("http")]

    if all_urls:
        output.append(f"\n=== SITEMAP ({len(all_urls)} URLs) ===")
        for u in all_urls[:20]:
            output.append(f"  {u}")
        ctx.add_finding(
            severity="info",
            title=f"Sitemap found — {len(all_urls)} URLs indexed",
            description=f"Sitemap reveals {len(all_urls)} URLs.",
            source="web_crawler",
            host=ctx.target_host,
            url=f"{base}/sitemap.xml",
            tags=["sitemap", "recon"],
            raw="\n".join(all_urls[:20]),
        )

    # --- Probe interesting paths ---
    status(f"Probing {len(INTERESTING_PATHS)} interesting paths...")
    confirmed_found  = []
    access_forbidden = []

    for path in INTERESTING_PATHS:
        code, content = _fetch(f"{base}{path}", timeout=5)

        if code == 200 and content is not None:
            # Skip CDN default pages masquerading as 200
            if _is_cdn_default_page(content):
                output.append(f"  CDN-BLOCKED [200]: {base}{path}")
                continue

            # Verify content actually matches what we expect
            if not _content_matches(path, content):
                output.append(f"  FALSE-POS   [200]: {base}{path} (content mismatch)")
                continue

            confirmed_found.append((path, code, content))
            output.append(f"  CONFIRMED   [200]: {base}{path}")

            # Scan for sensitive data patterns
            for pattern, description in SENSITIVE_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    ctx.add_finding(
                        severity="critical",
                        title=f"Sensitive data at {path}: {description}",
                        description=f"{description} found at {base}{path} (HTTP 200, content verified)",
                        source="web_crawler",
                        host=ctx.target_host,
                        url=f"{base}{path}",
                        tags=["sensitive-data", "exposure"],
                        raw=content[:300],
                    )

            # Specific file findings
            if path in ("/.git/HEAD", "/.git/config"):
                ctx.add_finding(
                    severity="critical",
                    title=f"Git repository exposed: {path}",
                    description=(
                        f"Git file confirmed at {base}{path} (HTTP 200, content verified). "
                        "Source code likely downloadable with git-dumper."
                    ),
                    source="web_crawler",
                    host=ctx.target_host,
                    url=f"{base}{path}",
                    tags=["git", "source-code", "exposure"],
                    raw=content[:300],
                )
            elif path == "/.env":
                ctx.add_finding(
                    severity="critical",
                    title=".env file exposed",
                    description=f".env confirmed at {base}{path}. Contains credentials/config.",
                    source="web_crawler",
                    host=ctx.target_host,
                    url=f"{base}{path}",
                    tags=[".env", "credentials", "exposure"],
                    raw=content[:300],
                )
            elif path == "/phpinfo.php":
                ctx.add_finding(
                    severity="medium",
                    title="phpinfo() page exposed",
                    description=f"phpinfo() confirmed at {base}{path}. Reveals server config.",
                    source="web_crawler",
                    host=ctx.target_host,
                    url=f"{base}{path}",
                    tags=["phpinfo", "info-disclosure"],
                    raw=content[:200],
                )
            elif path in ("/backup.zip", "/backup.sql"):
                ctx.add_finding(
                    severity="critical",
                    title=f"Backup file accessible: {path}",
                    description=f"Backup file confirmed at {base}{path} (HTTP 200).",
                    source="web_crawler",
                    host=ctx.target_host,
                    url=f"{base}{path}",
                    tags=["backup", "exposure"],
                    raw=f"HTTP 200 confirmed at {base}{path}",
                )

        elif code in (401, 403):
            access_forbidden.append((path, code))

    # Summary findings
    if confirmed_found:
        ctx.add_finding(
            severity="medium",
            title=f"Paths confirmed accessible — HTTP 200 ({len(confirmed_found)})",
            description=(
                "Content-verified accessible paths: "
                + ", ".join(p for p, _, _ in confirmed_found)
            ),
            source="web_crawler",
            host=ctx.target_host,
            url=base,
            tags=["paths", "confirmed"],
            raw="\n".join(f"{p} [200 verified]" for p, _, _ in confirmed_found),
        )

    if access_forbidden:
        ctx.add_finding(
            severity="info",
            title=f"Protected paths ({len(access_forbidden)}) — 401/403",
            description=(
                "Paths that exist but require auth: "
                + ", ".join(p for p, _ in access_forbidden[:10])
            ),
            source="web_crawler",
            host=ctx.target_host,
            url=base,
            tags=["paths", "protected"],
            raw="\n".join(f"{p} [{c}]" for p, c in access_forbidden),
        )

    return "\n".join(output) if output else "[no content found]"
