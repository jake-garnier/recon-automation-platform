#!/usr/bin/env python3
"""
Migrate HackerOne bug bounty notes from recon_notes/ to an Obsidian vault.

Parses existing markdown reports, generates frontmatter, creates wiki-links,
and places files in the structured vault directory.

Usage:
    python migrate_to_obsidian.py                    # dry-run (prints what would happen)
    python migrate_to_obsidian.py --run               # actually migrate
    python migrate_to_obsidian.py --run --programs     # also create program stubs from DB
"""

import os
import re
import sys
import json
import shutil
import sqlite3
import argparse
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).resolve().parents[2]
VAULT_ROOT = Path.home() / "obsidian-vault" / "hackerone-bounties"
DB_PATH = REPO_ROOT / "bounties.db"

# Mapping from observed vulnerability keywords to technique note filenames
VULN_TYPE_MAP = {
    # Information disclosure
    "source map": "source-map-exposure",
    "source-map": "source-map-exposure",
    "sourcemap": "source-map-exposure",
    "information disclosure": "information-disclosure",
    "info disclosure": "information-disclosure",
    "config disclosure": "configuration-disclosure",
    "configuration disclosure": "configuration-disclosure",
    "api key": "api-key-exposure",
    "hardcoded": "api-key-exposure",
    "actuator": "actuator-exposure",
    "spring boot actuator": "actuator-exposure",
    "openapi": "openapi-exposure",
    "swagger": "openapi-exposure",
    # Access control
    "broken access control": "broken-access-control",
    "unauthenticated": "broken-access-control",
    "unauthed": "broken-access-control",
    "auth bypass": "authentication-bypass",
    "authentication bypass": "authentication-bypass",
    "authorization bypass": "authorization-bypass",
    # CORS
    "cors": "cors-misconfiguration",
    "cors misconfiguration": "cors-misconfiguration",
    "origin reflection": "cors-misconfiguration",
    # XSS
    "xss": "xss",
    "cross-site scripting": "xss",
    "stored xss": "xss",
    "reflected xss": "xss",
    # Injection
    "sqli": "sql-injection",
    "sql injection": "sql-injection",
    "sql schema": "sql-injection",
    "command injection": "command-injection",
    "commix": "command-injection",
    "ssti": "ssti",
    "server-side template injection": "ssti",
    # SSRF
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    # Takeover
    "subdomain takeover": "subdomain-takeover",
    "s3 takeover": "subdomain-takeover",
    "s3-takeover": "subdomain-takeover",
    "bucket takeover": "subdomain-takeover",
    # OAuth/OIDC
    "oauth": "oauth-misconfiguration",
    "oidc": "oauth-misconfiguration",
    "redirect_uri": "oauth-misconfiguration",
    "device code": "oauth-misconfiguration",
    "device-code": "oauth-misconfiguration",
    # GraphQL
    "graphql": "graphql-misconfiguration",
    "introspection": "graphql-misconfiguration",
    # Open redirect
    "open redirect": "open-redirect",
    "open-redirect": "open-redirect",
    # Secrets
    "secret": "secret-exposure",
    "credential": "secret-exposure",
    "gitleaks": "secret-exposure",
    "trufflehog": "secret-exposure",
    "vault": "secret-exposure",
    # Supply chain
    "supply chain": "supply-chain",
    "artifactory": "supply-chain",
    "ci/cd": "supply-chain",
    "argocd": "supply-chain",
    # CMS
    "wordpress": "cms-vulnerability",
    "wp-": "cms-vulnerability",
    "wpscan": "cms-vulnerability",
    "joomla": "cms-vulnerability",
    # Enumeration
    "enumeration": "user-enumeration",
    "user enum": "user-enumeration",
    "username enum": "user-enumeration",
    "brute force": "brute-force",
    "brute-force": "brute-force",
    # Request smuggling
    "smuggling": "request-smuggling",
    "haproxy": "request-smuggling",
    # Miscellaneous
    "sentry": "sentry-misconfiguration",
    "keycloak": "keycloak-misconfiguration",
    "dos": "denial-of-service",
    "denial of service": "denial-of-service",
    "race condition": "race-condition",
    "idor": "idor",
    "insecure direct object": "idor",
    "account takeover": "account-takeover",
    "otp": "account-takeover",
    "password reset": "account-takeover",
    "password hash": "account-takeover",
    "stack overflow": "memory-corruption",
    "buffer overflow": "memory-corruption",
    "oob read": "memory-corruption",
    "out-of-bounds": "memory-corruption",
}

# Technology keywords to detect in report content
TECH_KEYWORDS = {
    "react": "react",
    "next.js": "nextjs",
    "nextjs": "nextjs",
    "angular": "angular",
    "vue": "vuejs",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "express": "nodejs",
    "python": "python",
    "flask": "python",
    "django": "python",
    "java": "java",
    "spring": "spring-boot",
    "spring boot": "spring-boot",
    "golang": "golang",
    "ruby": "ruby",
    "rails": "ruby-on-rails",
    "php": "php",
    "laravel": "php",
    "elasticsearch": "elasticsearch",
    "kibana": "kibana",
    "graphql": "graphql",
    "grpc": "grpc",
    "argocd": "argocd",
    "keycloak": "keycloak",
    "okta": "okta",
    "auth0": "auth0",
    "sentry": "sentry",
    "nginx": "nginx",
    "apache": "apache",
    "haproxy": "haproxy",
    "docker": "docker",
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "aws": "aws",
    "s3": "aws-s3",
    "cloudfront": "aws-cloudfront",
    "gcp": "gcp",
    "azure": "azure",
    "algolia": "algolia",
    "akamai": "akamai",
    "fastly": "fastly",
    "cloudflare": "cloudflare",
    "hashicorp vault": "hashicorp-vault",
    "vault": "hashicorp-vault",
    "terraform": "terraform",
    "ansible": "ansible",
    "jfrog": "jfrog-artifactory",
    "artifactory": "jfrog-artifactory",
    "wordpress": "wordpress",
    "strapi": "strapi",
    "magento": "magento",
    "salesforce": "salesforce",
    "redis": "redis",
    "postgres": "postgresql",
    "mysql": "mysql",
    "mongodb": "mongodb",
    "couchdb": "couchdb",
    "appdynamics": "appdynamics",
    "datadog": "datadog",
    "prometheus": "prometheus",
    "grafana": "grafana",
    "github enterprise": "github-enterprise",
    "gitlab": "gitlab",
    "teamcity": "teamcity",
    "jenkins": "jenkins",
    "discourse": "discourse",
    "pingfederate": "pingfederate",
    "descope": "descope",
}

# CWE to OWASP mapping
CWE_OWASP = {
    "CWE-79": "A03:2021",
    "CWE-89": "A03:2021",
    "CWE-200": "A01:2021",
    "CWE-284": "A01:2021",
    "CWE-287": "A07:2021",
    "CWE-312": "A02:2021",
    "CWE-319": "A02:2021",
    "CWE-352": "A01:2021",
    "CWE-400": "A05:2021",
    "CWE-434": "A04:2021",
    "CWE-502": "A08:2021",
    "CWE-540": "A05:2021",
    "CWE-601": "A01:2021",
    "CWE-611": "A05:2021",
    "CWE-639": "A01:2021",
    "CWE-693": "A05:2021",
    "CWE-732": "A01:2021",
    "CWE-798": "A07:2021",
    "CWE-862": "A01:2021",
    "CWE-863": "A01:2021",
    "CWE-918": "A10:2021",
    "CWE-942": "A05:2021",
}


def parse_report_metadata(content, filepath):
    """Extract metadata from a report's markdown content."""
    meta = {
        "title": "",
        "severity": "",
        "asset": "",
        "cwes": [],
        "weakness_text": "",
        "cvss": "",
        "program": "",
        "target": "",
    }

    lines = content.split("\n")

    # Title: first H1 heading
    for line in lines[:5]:
        if line.startswith("# "):
            meta["title"] = line[2:].strip()
            break

    # Check for Title: field (some reports use this)
    for line in lines[:20]:
        if line.startswith("## Title"):
            idx = lines.index(line)
            if idx + 1 < len(lines) and lines[idx + 1].strip():
                meta["title"] = lines[idx + 1].strip()
                break

    # Program from **Program**: field or directory name
    program_match = re.search(r'\*\*Program\*\*:\s*(.+)', content[:2000])
    if program_match:
        meta["program"] = program_match.group(1).strip().lower()
    else:
        # Extract from filepath: recon_notes/<program>/...
        parts = filepath.relative_to(REPO_ROOT).parts
        if len(parts) >= 2 and parts[0] == "recon_notes":
            meta["program"] = parts[1].replace("-findings.md", "")

    # Severity
    sev_patterns = [
        r'\*\*Severity\*\*:\s*(.+)',
        r'## Severity\s*\n+\*\*(.+?)\*\*',
        r'## Severity\s*\n+(.+?)[\n(]',
        r'Severity:\s*(.+)',
    ]
    for pat in sev_patterns:
        m = re.search(pat, content[:3000])
        if m:
            sev_text = m.group(1).strip().rstrip("*").strip()
            sev_lower = sev_text.lower()
            if "critical" in sev_lower:
                meta["severity"] = "critical"
            elif "high" in sev_lower:
                meta["severity"] = "high"
            elif "medium" in sev_lower:
                meta["severity"] = "medium"
            elif "low" in sev_lower:
                meta["severity"] = "low"
            elif "informational" in sev_lower or "info" in sev_lower:
                meta["severity"] = "informational"
            break

    # CVSS score
    cvss_match = re.search(r'CVSS[:\s]*[\d.]+/.*?(\d+\.\d+)', content[:3000])
    if cvss_match:
        meta["cvss"] = float(cvss_match.group(1))
    else:
        cvss_match = re.search(r'CVSS\s+(\d+\.\d+)', content[:3000])
        if cvss_match:
            meta["cvss"] = float(cvss_match.group(1))

    # Asset
    asset_patterns = [
        r'\*\*Asset\*\*:\s*`?([^`\n]+)`?',
        r'## Asset\s*\n+`([^`]+)`',
    ]
    for pat in asset_patterns:
        m = re.search(pat, content[:3000])
        if m:
            meta["asset"] = m.group(1).strip()
            break

    # Target from asset or affected assets section
    if meta["asset"]:
        # Extract the domain from the asset field
        asset = meta["asset"]
        # Remove wildcards and scope notes
        asset = re.sub(r'\(.*?\)', '', asset).strip()
        asset = asset.replace("*.", "").strip()
        meta["target"] = asset

    # CWE
    cwe_matches = re.findall(r'CWE-(\d+)', content[:5000])
    meta["cwes"] = list(set(f"CWE-{c}" for c in cwe_matches))

    # Weakness text
    weakness_match = re.search(r'\*\*Weakness\*\*:\s*(.+)', content[:3000])
    if weakness_match:
        meta["weakness_text"] = weakness_match.group(1).strip()
    else:
        weakness_match = re.search(r'## Weakness\s*\n+(.+)', content[:3000])
        if weakness_match:
            meta["weakness_text"] = weakness_match.group(1).strip()

    return meta


def detect_vuln_types(content, title, meta):
    """Detect vulnerability types from content, title, and metadata."""
    detected = set()
    search_text = (title + " " + meta.get("weakness_text", "") + " " + content[:5000]).lower()

    for keyword, technique in VULN_TYPE_MAP.items():
        if keyword in search_text:
            detected.add(technique)

    # If nothing detected, use generic
    if not detected:
        detected.add("information-disclosure")

    return sorted(detected)


def detect_technologies(content):
    """Detect technology stack from report content."""
    detected = set()
    content_lower = content.lower()

    for keyword, tech in TECH_KEYWORDS.items():
        # Use word boundary-ish matching to avoid false positives
        if re.search(r'\b' + re.escape(keyword) + r'\b', content_lower):
            detected.add(tech)

    return sorted(detected)


def determine_status(filepath):
    """Determine report status from its directory location."""
    parts = filepath.parts
    for part in parts:
        if part == "submitted":
            return "submitted"
        if part == "not-vulnerable":
            return "not-vulnerable"
        if part == "in-progress":
            return "draft"
    # Root-level findings files
    if filepath.name.endswith("-findings.md"):
        return "discovery"
    return "draft"


def slugify(text, max_len=60):
    """Convert text to a filename-safe slug."""
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s-]', '', text)
    text = re.sub(r'[\s]+', '-', text.strip())
    text = re.sub(r'-+', '-', text)
    return text[:max_len].rstrip('-')


def generate_report_filename(meta, filepath):
    """Generate a vault-friendly filename for a report."""
    program = meta.get("program", "unknown")
    title = meta.get("title", filepath.stem)
    slug = slugify(title)
    if not slug:
        slug = slugify(filepath.stem)
    return f"{program}-{slug}.md"


def build_frontmatter(meta, vuln_types, technologies, status):
    """Build YAML frontmatter for a report note."""
    lines = ["---"]

    title = meta.get("title", "Untitled")
    # Escape quotes in title
    title = title.replace('"', '\\"')
    lines.append(f'title: "{title}"')

    program = meta.get("program", "unknown")
    lines.append(f'program: "[[{program}]]"')

    if meta.get("target"):
        lines.append(f'target: {meta["target"]}')

    lines.append(f"status: {status}")

    if meta.get("severity"):
        lines.append(f'severity: {meta["severity"]}')

    if meta.get("cvss"):
        lines.append(f"cvss: {meta['cvss']}")

    if vuln_types:
        lines.append("vuln_type:")
        for vt in vuln_types:
            lines.append(f'  - "[[{vt}]]"')

    if meta.get("cwes"):
        lines.append("cwe:")
        for cwe in sorted(meta["cwes"]):
            lines.append(f"  - {cwe}")

    lines.append('h1_report_id: ""')
    lines.append("submitted_date:")
    lines.append("triaged_date:")
    lines.append("resolved_date:")
    lines.append("bounty: 0")

    if technologies:
        lines.append("technologies:")
        for tech in technologies:
            lines.append(f'  - "[[{tech}]]"')

    # Tags from program + severity + vuln types
    tags = [program]
    if meta.get("severity"):
        tags.append(meta["severity"])
    tags.extend(vuln_types)
    lines.append("tags:")
    for tag in tags:
        lines.append(f"  - {tag}")

    lines.append("---")
    return "\n".join(lines)


def inject_wikilinks(content, vuln_types, technologies, program):
    """Add a Related Notes section with wiki-links at the bottom of the content."""
    links = []
    links.append(f"**Program**: [[{program}]]")

    if vuln_types:
        vt_links = ", ".join(f"[[{vt}]]" for vt in vuln_types)
        links.append(f"**Techniques**: {vt_links}")

    if technologies:
        tech_links = ", ".join(f"[[{t}]]" for t in technologies)
        links.append(f"**Technologies**: {tech_links}")

    if links:
        section = "\n\n---\n\n## Related\n\n" + "\n".join(links) + "\n"
        return content + section

    return content


def strip_existing_frontmatter(content):
    """Remove existing YAML frontmatter if present."""
    if content.startswith("---"):
        end = content.find("---", 3)
        if end != -1:
            return content[end + 3:].lstrip("\n")
    return content


def create_program_stub(handle, db_row=None):
    """Create a program note with frontmatter."""
    lines = ["---"]
    lines.append(f"handle: {handle}")
    lines.append("platform: hackerone")

    if db_row:
        lines.append(f'name: "{db_row["name"] or handle}"')
        sr = db_row.get("signal_required")
        lines.append(f"signal_required: {'true' if sr == 1 else 'false' if sr is not None else 'unknown'}")
        if db_row.get("bounty_max"):
            lines.append(f"max_bounty: {int(db_row['bounty_max'])}")
        if db_row.get("bounty_min"):
            lines.append(f"min_bounty: {int(db_row['bounty_min'])}")
        if db_row.get("url"):
            lines.append(f'url: "{db_row["url"]}"')
    else:
        lines.append(f"name: {handle}")
        lines.append("signal_required: unknown")

    lines.append("recon_status: unknown")
    lines.append("pipeline_id:")
    lines.append("last_scanned:")
    lines.append("tags:")
    lines.append(f"  - {handle}")
    lines.append("---")
    lines.append("")
    lines.append(f"# {handle}")
    lines.append("")
    lines.append("## Reports")
    lines.append("")
    lines.append("```dataview")
    lines.append(f'TABLE status, severity, target FROM "02-Reports"')
    lines.append(f'WHERE program = [[{handle}]]')
    lines.append("SORT severity ASC")
    lines.append("```")
    lines.append("")
    lines.append("## Scope")
    lines.append("")
    lines.append("*(Add in-scope domains and assets here)*")
    lines.append("")

    return "\n".join(lines)


def create_technique_stub(technique_slug):
    """Create a technique note."""
    # Determine OWASP category from any associated CWEs
    title = technique_slug.replace("-", " ").title()

    lines = ["---"]
    lines.append(f"technique: {technique_slug}")
    lines.append("prevalence: unknown")
    lines.append("tags:")
    lines.append(f"  - technique")
    lines.append(f"  - {technique_slug}")
    lines.append("---")
    lines.append("")
    lines.append(f"# {title}")
    lines.append("")
    lines.append("## Description")
    lines.append("")
    lines.append(f"*(Add notes on how to find and exploit {title.lower()} vulnerabilities)*")
    lines.append("")
    lines.append("## Reports Using This Technique")
    lines.append("")
    lines.append("```dataview")
    lines.append(f'TABLE program, severity, target FROM "02-Reports"')
    lines.append(f'WHERE contains(vuln_type, [[{technique_slug}]])')
    lines.append("SORT severity ASC")
    lines.append("```")
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append("### Detection")
    lines.append("")
    lines.append("### Exploitation")
    lines.append("")
    lines.append("### Bypasses")
    lines.append("")

    return "\n".join(lines)


def create_technology_stub(tech_slug):
    """Create a technology note."""
    title = tech_slug.replace("-", " ").title()

    lines = ["---"]
    lines.append(f"technology: {tech_slug}")
    lines.append("tags:")
    lines.append(f"  - technology")
    lines.append(f"  - {tech_slug}")
    lines.append("---")
    lines.append("")
    lines.append(f"# {title}")
    lines.append("")
    lines.append("## Known Vulnerability Patterns")
    lines.append("")
    lines.append(f"*(Add common vulnerabilities found in {title} applications)*")
    lines.append("")
    lines.append("## Reports Involving This Technology")
    lines.append("")
    lines.append("```dataview")
    lines.append(f'TABLE program, severity, vuln_type FROM "02-Reports"')
    lines.append(f'WHERE contains(technologies, [[{tech_slug}]])')
    lines.append("SORT severity ASC")
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


def collect_reports():
    """Collect all report files from recon_notes/."""
    reports = []

    recon_dir = REPO_ROOT / "recon_notes"
    if not recon_dir.exists():
        return reports

    # Collect from program subdirectories
    for program_dir in sorted(recon_dir.iterdir()):
        if not program_dir.is_dir():
            continue
        # Skip non-program directories
        if program_dir.name in ("topSix", "bulk", "crypto"):
            # Include these too but handle specially
            pass

        for subdir_name in ("in-progress", "submitted", "not-vulnerable", "findings"):
            subdir = program_dir / subdir_name
            if subdir.exists() and subdir.is_dir():
                for md_file in sorted(subdir.glob("*.md")):
                    # Skip investigation plans and acceptance odds
                    if any(skip in md_file.name.upper() for skip in ["INVESTIGATION-PLAN", "ACCEPTANCE-ODDS"]):
                        continue
                    reports.append(md_file)

    # Collect root-level consolidated findings
    for md_file in sorted(recon_dir.glob("*-findings.md")):
        reports.append(md_file)

    return reports


def collect_hacktivity():
    """Collect hacktivity write-ups."""
    hacktivity_dir = REPO_ROOT / "hacktivity"
    if not hacktivity_dir.exists():
        return []
    return sorted(hacktivity_dir.glob("*.md"))


def migrate_report(filepath, dry_run=True):
    """Migrate a single report file to the vault."""
    content = filepath.read_text(encoding="utf-8")

    meta = parse_report_metadata(content, filepath)
    vuln_types = detect_vuln_types(content, meta.get("title", ""), meta)
    technologies = detect_technologies(content)
    status = determine_status(filepath)

    # Generate filename
    filename = generate_report_filename(meta, filepath)

    # Destination path
    dest_dir = VAULT_ROOT / "02-Reports" / status
    dest_path = dest_dir / filename

    # Handle duplicates
    if dest_path.exists():
        base = dest_path.stem
        ext = dest_path.suffix
        counter = 2
        while dest_path.exists():
            dest_path = dest_dir / f"{base}-{counter}{ext}"
            counter += 1

    # Strip any existing frontmatter and rebuild
    body = strip_existing_frontmatter(content)

    # Build new frontmatter
    frontmatter = build_frontmatter(meta, vuln_types, technologies, status)

    # Add wiki-links section
    body = inject_wikilinks(body, vuln_types, technologies, meta.get("program", "unknown"))

    new_content = frontmatter + "\n\n" + body

    result = {
        "source": str(filepath.relative_to(REPO_ROOT)),
        "dest": str(dest_path.relative_to(VAULT_ROOT)),
        "program": meta.get("program", "unknown"),
        "severity": meta.get("severity", "unknown"),
        "status": status,
        "vuln_types": vuln_types,
        "technologies": technologies,
        "title": meta.get("title", filepath.stem),
    }

    if not dry_run:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_text(new_content, encoding="utf-8")

    return result


def migrate_hacktivity(filepath, dry_run=True):
    """Migrate a hacktivity write-up to the vault."""
    content = filepath.read_text(encoding="utf-8")
    meta = parse_report_metadata(content, filepath)
    vuln_types = detect_vuln_types(content, meta.get("title", ""), meta)
    technologies = detect_technologies(content)

    dest_path = VAULT_ROOT / "05-Hacktivity" / filepath.name

    body = strip_existing_frontmatter(content)

    # Build frontmatter
    lines = ["---"]
    title = meta.get("title", filepath.stem).replace('"', '\\"')
    lines.append(f'title: "{title}"')
    program = meta.get("program", "unknown")
    lines.append(f'program: "[[{program}]]"')
    lines.append("type: hacktivity")
    if meta.get("severity"):
        lines.append(f'severity: {meta["severity"]}')
    if vuln_types:
        lines.append("vuln_type:")
        for vt in vuln_types:
            lines.append(f'  - "[[{vt}]]"')
    lines.append("tags:")
    lines.append("  - hacktivity")
    lines.append(f"  - {program}")
    lines.append("---")

    frontmatter = "\n".join(lines)
    body = inject_wikilinks(body, vuln_types, technologies, program)
    new_content = frontmatter + "\n\n" + body

    result = {
        "source": str(filepath.relative_to(REPO_ROOT)),
        "dest": str(dest_path.relative_to(VAULT_ROOT)),
        "program": program,
    }

    if not dry_run:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_text(new_content, encoding="utf-8")

    return result


def create_program_stubs(programs_from_reports, dry_run=True):
    """Create program notes, optionally enriched from the database."""
    created = []
    db_programs = {}

    if DB_PATH.exists():
        try:
            conn = sqlite3.connect(str(DB_PATH))
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT handle, name, url, bounty_min, bounty_max, signal_required "
                "FROM programs WHERE offers_bounties = 1"
            ).fetchall()
            for row in rows:
                db_programs[row["handle"]] = row
            conn.close()
        except Exception as e:
            print(f"  Warning: Could not read database: {e}")

    # Merge DB programs with programs found in reports
    all_programs = set(programs_from_reports)
    all_programs.update(db_programs.keys())

    for handle in sorted(all_programs):
        dest_path = VAULT_ROOT / "01-Programs" / f"{handle}.md"
        if dest_path.exists():
            continue

        db_row = db_programs.get(handle)
        content = create_program_stub(handle, db_row)

        if not dry_run:
            dest_path.write_text(content, encoding="utf-8")

        created.append(handle)

    return created


def create_technique_stubs(all_techniques, dry_run=True):
    """Create technique notes for all observed vulnerability types."""
    created = []
    for tech in sorted(all_techniques):
        dest_path = VAULT_ROOT / "03-Techniques" / f"{tech}.md"
        if dest_path.exists():
            continue

        content = create_technique_stub(tech)

        if not dry_run:
            dest_path.write_text(content, encoding="utf-8")

        created.append(tech)

    return created


def create_technology_stubs(all_technologies, dry_run=True):
    """Create technology notes for all observed tech stacks."""
    created = []
    for tech in sorted(all_technologies):
        dest_path = VAULT_ROOT / "04-Technologies" / f"{tech}.md"
        if dest_path.exists():
            continue

        content = create_technology_stub(tech)

        if not dry_run:
            dest_path.write_text(content, encoding="utf-8")

        created.append(tech)

    return created


def main():
    parser = argparse.ArgumentParser(description="Migrate HackerOne notes to Obsidian vault")
    parser.add_argument("--run", action="store_true", help="Actually perform the migration (default: dry-run)")
    parser.add_argument("--programs", action="store_true", help="Also create program stubs from DB")
    args = parser.parse_args()

    dry_run = not args.run

    if dry_run:
        print("=== DRY RUN (pass --run to actually migrate) ===\n")
    else:
        print("=== MIGRATING ===\n")

    # Collect all reports
    reports = collect_reports()
    hacktivity = collect_hacktivity()
    print(f"Found {len(reports)} reports and {len(hacktivity)} hacktivity files\n")

    # Migrate reports
    all_programs = set()
    all_techniques = set()
    all_technologies = set()
    results = []

    print("--- Reports ---")
    for filepath in reports:
        result = migrate_report(filepath, dry_run)
        results.append(result)
        all_programs.add(result["program"])
        all_techniques.update(result["vuln_types"])
        all_technologies.update(result["technologies"])

        status_icon = {"draft": "D", "submitted": "S", "not-vulnerable": "X", "discovery": "?"}
        icon = status_icon.get(result["status"], "?")
        sev = result["severity"][:1].upper() if result["severity"] else "?"
        print(f"  [{icon}] [{sev}] {result['source']}")
        print(f"       -> {result['dest']}")

    # Migrate hacktivity
    print("\n--- Hacktivity ---")
    for filepath in hacktivity:
        result = migrate_hacktivity(filepath, dry_run)
        all_programs.add(result["program"])
        print(f"  {result['source']}")
        print(f"       -> {result['dest']}")

    # Create program stubs
    print(f"\n--- Programs ({len(all_programs)} from reports) ---")
    if args.programs:
        print("  (including DB programs)")
    created_programs = create_program_stubs(all_programs, dry_run)
    for p in created_programs:
        print(f"  + 01-Programs/{p}.md")

    # Create technique stubs
    print(f"\n--- Techniques ({len(all_techniques)}) ---")
    created_techniques = create_technique_stubs(all_techniques, dry_run)
    for t in created_techniques:
        print(f"  + 03-Techniques/{t}.md")

    # Create technology stubs
    print(f"\n--- Technologies ({len(all_technologies)}) ---")
    created_techs = create_technology_stubs(all_technologies, dry_run)
    for t in created_techs:
        print(f"  + 04-Technologies/{t}.md")

    # Summary
    print(f"\n=== SUMMARY ===")
    print(f"Reports migrated: {len(results)}")
    print(f"Hacktivity migrated: {len(hacktivity)}")
    print(f"Programs created: {len(created_programs)}")
    print(f"Techniques created: {len(created_techniques)}")
    print(f"Technologies created: {len(created_techs)}")

    by_status = {}
    for r in results:
        by_status.setdefault(r["status"], []).append(r)
    print("\nBy status:")
    for status, items in sorted(by_status.items()):
        print(f"  {status}: {len(items)}")

    by_severity = {}
    for r in results:
        by_severity.setdefault(r["severity"] or "unknown", []).append(r)
    print("\nBy severity:")
    for sev, items in sorted(by_severity.items()):
        print(f"  {sev}: {len(items)}")

    if dry_run:
        print(f"\n(Dry run — no files written. Pass --run to execute.)")


if __name__ == "__main__":
    main()
