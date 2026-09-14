#!/usr/bin/env python3
"""
Socket.dev comprehensive requirements live tester (standalone)
==============================================================

No external requirements CSV needed — all PoC requirements are embedded.

Required env:
  SOCKET_API_TOKEN
  SOCKET_ORG_SLUG

Optional env:
  SOCKET_FIREWALL_URL   Registry Mode base URL, e.g. https://socket-fw.internal
  SOCKET_OUT_DIR        output directory (default: ./live_results_<timestamp>)
  SOCKET_SCREENSHOTS=1  macOS screenshots (default: 1)
  SOCKET_TIMEOUT=45

Usage:
  export SOCKET_API_TOKEN='...'
  export SOCKET_ORG_SLUG='your-org'
  # export SOCKET_FIREWALL_URL='https://...'
  python3 test_socket_requirements.py
"""

from __future__ import annotations

import base64
import csv
import json
import os
import platform
import re
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

API_BASE = "https://api.socket.dev/v0"

# ---------------------------------------------------------------------------
# Embedded PoC requirements (no external CSV required)
# ---------------------------------------------------------------------------
REQUIREMENTS: List[Dict[str, str]] = [
    {
        "id": "A.EC.1",
        "priority": "Must",
        "description": "Supports NPM",
        "vendor_response": "Yes"
    },
    {
        "id": "A.EC.2",
        "priority": "Must",
        "description": "Supports PyPI",
        "vendor_response": "Yes"
    },
    {
        "id": "A.EC.3",
        "priority": "Must",
        "description": "Supports Maven",
        "vendor_response": "Yes"
    },
    {
        "id": "A.EC.4",
        "priority": "Must",
        "description": "Supports Go",
        "vendor_response": "Yes"
    },
    {
        "id": "A.EC.5",
        "priority": "Must",
        "description": "Supports Nuget",
        "vendor_response": "Yes"
    },
    {
        "id": "A.EC.6",
        "priority": "Should",
        "description": "Supports CocoaPod",
        "vendor_response": "No"
    },
    {
        "id": "A.EC.7",
        "priority": "Should",
        "description": "Supports Cargo",
        "vendor_response": "Yes"
    },
    {
        "id": "A.EC.8",
        "priority": "Should",
        "description": "Supports Packagist",
        "vendor_response": "No"
    },
    {
        "id": "A.EC.9",
        "priority": "Should",
        "description": "Supports Gem",
        "vendor_response": "Yes"
    },
    {
        "id": "A.EC.10",
        "priority": "Should",
        "description": "Supports Swift",
        "vendor_response": "No"
    },
    {
        "id": "A.EC.12",
        "priority": "Must",
        "description": "Allow restrictions based on source. Example- For the source https://repository.springsource.com/maven/libraries/release/, Atlassian should only pick up packages with the prefix com/springsource/**,org/springframework/**",
        "vendor_response": "Partial"
    },
    {
        "id": "A.PC.1",
        "priority": "Must",
        "description": "Coverage must include packages actively consumed by Atlassian- both direct and transitive dependencies - not just popular/top-N packages.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.PC.2",
        "priority": "Must",
        "description": "Latest and newly published versions must be prioritized, since the primary risk is future consumption, not only historical inventory.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.SCG.1",
        "priority": "Must",
        "description": "All packages must be scanned for malware, behavioral anomalies, and malicious code injection before they are available for consumption \u2014 not reliant on post-install discovery or waiting for formal CVE advisories. Detection must use multiple methods and signals.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.SCG.2",
        "priority": "Must",
        "description": "Detection must cover major attack classes: dependency confusion, maintainer compromise, malicious install scripts, code injection, and social-engineering-enabled package takeover",
        "vendor_response": "Yes"
    },
    {
        "id": "A.SCG.3",
        "priority": "Must",
        "description": "Previously consumed artifacts must be continuously reassessed as new threat intelligence emerges, with retroactive alerting when a previously safe package is found to be malicious.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.SCG.4",
        "priority": "Must",
        "description": "Allow blocking packages that were previously safe but later reassessed as malicious.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.SCG.5",
        "priority": "Must",
        "description": "Allow delaying consumption of newer packages from 24 hours up to 7 days, and permit newer packages that fix critical-severity vulnerabilities to bypass this delay",
        "vendor_response": "Yes"
    },
    {
        "id": "A.SCG.6",
        "priority": "Must",
        "description": "Vendor must provide transparency into blocked packages - what was blocked, why, and when.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.SCG.7",
        "priority": "Must",
        "description": "The solution must support overrides for both false positives and accepted-risk exceptions at the package/version level, with a dispute process and full audit trail (who approved, when, why)",
        "vendor_response": "Partial"
    },
    {
        "id": "A.SCG.8",
        "priority": "Must",
        "description": "Security policies (block, warn, allow) must be configurable per ecosystem, per risk tier, or per environment.",
        "vendor_response": "Partial"
    },
    {
        "id": "A.SCG.9",
        "priority": "Must",
        "description": "Policies must be manageable through both a UI and an API to support automation",
        "vendor_response": "Yes"
    },
    {
        "id": "A.SCG.10",
        "priority": "Must",
        "description": "The vendor must not inject additional code, dependencies, or behavioral modifications into upstream packages. If the vendor rebuilds from source, the output must be functionally equivalent to the upstream artifact with verifiable provenance.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.SCG.11",
        "priority": "Must",
        "description": "The solution must detect package installations on developer workstations and IDEs that resolve directly from public registries, bypassing Artifactory.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.SCG.12",
        "priority": "Should",
        "description": "The solution must detect configuration overrides (e.g., .npmrc, pip.conf, GOPROXY) that redirect package resolution away from the governed path.",
        "vendor_response": "No"
    },
    {
        "id": "A.SCG.13",
        "priority": "Should",
        "description": "The solution must provide measurable visibility into what percentage of package resolutions flow through the governed path versus bypass paths.",
        "vendor_response": "Partial"
    },
    {
        "id": "A.SCG.14",
        "priority": "Must",
        "description": "The vendor must provide reporting on attacks prevented \u2014 including number of malicious packages blocked, packages that would have been consumed without the solution, and affected ecosystems \u2014 to demonstrate operational value and support ongoing risk reporting.",
        "vendor_response": "Partial"
    },
    {
        "id": "A.SCG.15",
        "priority": "Must",
        "description": "An emergency break-glass capability must exist for urgent patching or incident response, allowing governed consumption of an unvetted package with strong auditability and automatic follow-up vetting.",
        "vendor_response": "Partial"
    },
    {
        "id": "A.SCG.16",
        "priority": "Must",
        "description": "When a package or version is identified as malicious whether by the upstream registry, the vendor\u2019s own analysis, or third-party threat intelligence , the vendor must block it within 1 hour of the earliest signal. The vendor must publish SLA commitments for threat intelligence ingestion and provide metrics on actual propagation times.",
        "vendor_response": "Partial"
    },
    {
        "id": "A.SCG.17",
        "priority": "Must",
        "description": "Security policies must support custom rules, version history, rollback to a previous state, and an audit trail of all changes.",
        "vendor_response": "Partial"
    },
    {
        "id": "A.SCG.RISK",
        "priority": "Must",
        "description": "The solution must support blocking based on distinct risk categories including: malicious packages, known vulnerabilities (by severity), license non-compliance, and packages with no verifiable maintainer or provenance. Blocking must be independently configurable per category.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.PT.1",
        "priority": "Must",
        "description": "Artifact integrity must be cryptographically verifiable so that tampering between source and consumed package can be detected.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.PT.2",
        "priority": "Must",
        "description": "Artifacts must align to SLSA framework standards (Level 2 or higher) or an equivalent supply chain integrity model.",
        "vendor_response": "No"
    },
    {
        "id": "A.PT.3",
        "priority": "Must",
        "description": "A cryptographically-signed attestation must link the consumed package to its source code, build process, and builder identity.",
        "vendor_response": "No"
    },
    {
        "id": "A.PT.4",
        "priority": "Must",
        "description": "The solution must verify that packages originate from the authentic upstream project, detecting typosquats, malicious forks, namespace confusion, and package identity impersonation.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.PT.5",
        "priority": "Should",
        "description": "Vendor must provide a way to inspect a package\u2019s provenance and verification status before adoption.",
        "vendor_response": "Partial"
    },
    {
        "id": "A.AI.1",
        "priority": "Must",
        "description": "The solution must integrate as a remote repository within JFrog Artifactory with no changes to developer or CI/CD build configurations.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.AI.2",
        "priority": "Must",
        "description": "Integration must support enterprise SSO, OIDC, identity tokens, or equivalent secure authentication compatible with Artifactory and Atlassian\u2019s identity stack",
        "vendor_response": "Yes"
    },
    {
        "id": "A.AI.3",
        "priority": "Must",
        "description": "Packages already in the vendor\u2019s vetted set must be available within 4 hours of upstream publication.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.AI.4",
        "priority": "Must",
        "description": "A blocked package must not result in a \u201cPackage Not Found\u201d response that causes Artifactory to fall back to the unvetted upstream registry. The block decision must propagate to Artifactory to prevent bypass.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.AI.5",
        "priority": "Must",
        "description": "For packages not yet in the vendor\u2019s vetted set, on-demand vetting must exist so developers are not indefinitely blocked without a resolution path",
        "vendor_response": "Yes"
    },
    {
        "id": "A.AI.6",
        "priority": "Must",
        "description": "All relevant artifact formats for a supported package version must be consistently available \u2014 builds must not fail due to missing formats when upgrading or downgrading. e.g if a package has .tar.gz, .whl, and .egg formats on PyPI, the vendor must serve all of them, not just one",
        "vendor_response": "Yes"
    },
    {
        "id": "A.AI.7",
        "priority": "Must",
        "description": "The solution must not break consumption of internally forked, patched, or private packages that Atlassian maintains outside public upstreams.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.AI.8",
        "priority": "Must",
        "description": "The solution must operate within Artifactory timeout constraints so that the vetting layer does not become a failure amplifier during outages or delays.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.AI.9",
        "priority": "Must",
        "description": "Block events and threat signals must be exportable to Splunk, incident response workflows (Jira), and team communication channels (Slack) via API, webhook, or native integration. Other integrations with analytics platform like Databricks is preferred.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.AI.10",
        "priority": "Must",
        "description": "The solution must support a configurable quarantine period for newly published upstream packages, allowing a defined hold window before packages are made available for consumption. This window must be configurable (including zero for opted-out ecosystems) and must not be the sole protection mechanism.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.AI.11",
        "priority": "Must",
        "description": "When a package is blocked, the developer must receive a clear, actionable response \u2014 the reason for the block, the specific version affected, and a resolution path (alternative version, override request). Not a generic 404, 403 or timeout.",
        "vendor_response": "Yes"
    },
    {
        "id": "A.AI.12",
        "priority": "Must",
        "description": "When the vendor vetting layer is unavailable, degraded, or exceeds timeout thresholds, the solution must support a configurable failure mode \u2014 fail-closed (block all unvetted packages) or fail-open (allow packages through) \u2014 with the default behavior being fail-closed. The active failure mode and any packages allowed or blocked during degraded operation must be logged for audit.",
        "vendor_response": "Yes"
    }
]

ECOSYSTEM_SAMPLES: Dict[str, Dict[str, Any]] = {
    "npm": {
        "purl_type": "npm",
        "clean": ("lodash", "4.17.21"),
        "suspect": ("event-stream", "3.3.6"),
        "firewall_clean": "/npm/lodash/-/lodash-4.17.21.tgz",
        "firewall_suspect": "/npm/event-stream/-/event-stream-3.3.6.tgz",
    },
    "pypi": {
        "purl_type": "pypi",
        "clean": ("requests", "2.31.0"),
        "suspect": None,
        "firewall_clean": "/pypi/packages/source/r/requests/requests-2.31.0.tar.gz",
        "firewall_suspect": None,
    },
    "maven": {
        "purl_type": "maven",
        "clean": ("org.apache.commons:commons-lang3", "3.14.0"),
        "suspect": None,
        "firewall_clean": "/maven/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
        "firewall_suspect": None,
    },
    "go": {
        "purl_type": "golang",
        "clean": ("golang.org/x/text", "v0.14.0"),
        "suspect": None,
        "firewall_clean": "/go/golang.org/x/text/@v/v0.14.0.mod",
        "firewall_suspect": None,
    },
    "nuget": {
        "purl_type": "nuget",
        "clean": ("Newtonsoft.Json", "13.0.3"),
        "suspect": None,
        "firewall_clean": "/nuget/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
        "firewall_suspect": None,
    },
    "cargo": {
        "purl_type": "cargo",
        "clean": ("serde", "1.0.197"),
        "suspect": None,
        "firewall_clean": "/cargo/api/v1/crates/serde/1.0.197/download",
        "firewall_suspect": None,
    },
    "gem": {
        "purl_type": "gem",
        "clean": ("rack", "2.2.8"),
        "suspect": None,
        "firewall_clean": "/gem/gems/rack-2.2.8.gem",
        "firewall_suspect": None,
    },
}


@dataclass
class TestResult:
    requirement_id: str
    priority: str
    description: str
    vendor_response: str
    test_method: str
    verdict: str
    http_status: str = ""
    expected: str = ""
    observed: str = ""
    evidence_files: str = ""
    screenshot: str = ""
    notes: str = ""
    duration_ms: int = 0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class EvidenceStore:
    def __init__(self, out_dir: Path, enable_screenshots: bool):
        self.out_dir = out_dir
        self.evidence = out_dir / "evidence"
        self.screenshots = out_dir / "screenshots"
        self.logs = out_dir / "logs"
        for d in (self.evidence, self.screenshots, self.logs):
            d.mkdir(parents=True, exist_ok=True)
        self.enable_screenshots = enable_screenshots and platform.system() == "Darwin"
        self.term_log = self.logs / "terminal_session.log"
        self._fh = self.term_log.open("a", encoding="utf-8")
        self.banner(f"Socket live requirements test @ {datetime.now().isoformat()}")

    def close(self) -> None:
        self._fh.close()

    def banner(self, msg: str) -> None:
        block = f"\n{'=' * 78}\n{msg}\n{'=' * 78}\n"
        print(block, flush=True)
        self._fh.write(block)
        self._fh.flush()

    def log(self, msg: str) -> None:
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        print(line, flush=True)
        self._fh.write(line + "\n")
        self._fh.flush()

    def save_json(self, name: str, payload: Any) -> str:
        path = self.evidence / name
        path.write_text(
            json.dumps(payload, indent=2, default=str)[:2_000_000], encoding="utf-8"
        )
        return str(path)

    def save_text(self, name: str, text: str) -> str:
        path = self.evidence / name
        path.write_text(text[:2_000_000], encoding="utf-8")
        return str(path)

    def screenshot(self, label: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", label)[:80]
        png = self.screenshots / f"{safe}.png"
        time.sleep(0.2)
        if self.enable_screenshots:
            try:
                win_id = self._front_window_id()
                cmd = ["screencapture", "-x"]
                if win_id:
                    cmd += ["-l", str(win_id)]
                cmd.append(str(png))
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
                if proc.returncode == 0 and png.exists() and png.stat().st_size > 0:
                    self.log(f"screenshot ok: {png.name}")
                    return str(png)
                proc2 = subprocess.run(
                    ["screencapture", "-x", str(png)],
                    capture_output=True,
                    text=True,
                    timeout=25,
                )
                if proc2.returncode == 0 and png.exists() and png.stat().st_size > 0:
                    self.log(f"screenshot (display) ok: {png.name}")
                    return str(png)
            except Exception as e:
                self.log(f"screenshot exception: {e}")
        snap = self.screenshots / f"{safe}.log.txt"
        try:
            tail = self.term_log.read_text(encoding="utf-8")[-12000:]
        except Exception:
            tail = "(no log)"
        snap.write_text(tail, encoding="utf-8")
        return str(snap)

    @staticmethod
    def _front_window_id() -> Optional[int]:
        if platform.system() != "Darwin":
            return None
        script = (
            'tell application "System Events"\n'
            "  set frontApp to first application process whose frontmost is true\n"
            "  set winId to 0\n"
            "  try\n"
            "    set winId to id of front window of frontApp\n"
            "  end try\n"
            "  return winId\n"
            "end tell"
        )
        try:
            proc = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                val = proc.stdout.strip()
                if val.isdigit() and int(val) > 0:
                    return int(val)
        except Exception:
            return None
        return None


class SocketClient:
    def __init__(self, token: str, org: str, timeout: float = 45.0):
        self.token = token
        self.org = org
        self.timeout = timeout
        basic = base64.b64encode(f"{token}:".encode()).decode()
        self.auth_header = f"Basic {basic}"

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        query: Optional[Dict[str, Any]] = None,
    ) -> Tuple[int, Any, bytes]:
        url = API_BASE.rstrip("/") + path
        if query:
            url += "?" + urllib.parse.urlencode(
                {k: v for k, v in query.items() if v is not None}
            )
        data = None
        headers = {
            "Accept": "application/json",
            "Authorization": self.auth_header,
            "User-Agent": "atlassian-socket-poc-tester/1.1",
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method.upper())
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                status = resp.getcode()
        except urllib.error.HTTPError as e:
            raw = e.read() if e.fp else b""
            status = e.code
        except Exception as e:
            return 0, {"error": str(e)}, b""
        if not raw:
            return status, None, raw
        try:
            return status, json.loads(raw.decode("utf-8", "replace")), raw
        except json.JSONDecodeError:
            return status, {"_text": raw.decode("utf-8", "replace")[:8000]}, raw


def make_purl(eco: str, name: str, version: str) -> str:
    ptype = ECOSYSTEM_SAMPLES[eco]["purl_type"]
    if ptype == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        return f"pkg:maven/{group}/{artifact}@{version}"
    if ptype == "golang":
        return f"pkg:golang/{name}@{version}"
    return f"pkg:{ptype}/{name}@{version}"


class SocketRequirementsTester:
    def __init__(
        self, client: SocketClient, store: EvidenceStore, firewall_url: str = ""
    ):
        self.client = client
        self.store = store
        self.firewall_url = firewall_url.rstrip("/")
        self.results: List[TestResult] = []

    def _evidence(self, req_id: str, label: str, payload: Any) -> str:
        return self.store.save_json(f"{req_id}_{label}.json", payload)

    def firewall_get(self, path: str) -> Tuple[int, Dict[str, str], bytes]:
        if not self.firewall_url:
            return 0, {"error": "SOCKET_FIREWALL_URL unset"}, b""
        url = self.firewall_url + path
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "atlassian-socket-poc-tester/1.1")
        try:
            with urllib.request.urlopen(req, timeout=self.client.timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return resp.getcode(), headers, resp.read(64_000)
        except urllib.error.HTTPError as e:
            headers = {
                k.lower(): v for k, v in (e.headers.items() if e.headers else [])
            }
            body = e.read(64_000) if e.fp else b""
            return e.code, headers, body
        except Exception as e:
            return 0, {"error": str(e)}, b""

    def fetch_package(self, eco: str, name: str, version: str) -> Tuple[int, Any]:
        purl = make_purl(eco, name, version)
        org = self.client.org
        attempts = [
            ("POST", f"/orgs/{org}/packages/batch", [{"purl": purl}]),
            ("POST", "/purl", [{"purl": purl}]),
            ("POST", f"/orgs/{org}/purl", [{"purl": purl}]),
        ]
        last_status, last_data = 0, None
        for method, path, body in attempts:
            status, data, _ = self.client.request(method, path, body=body)
            last_status, last_data = status, data
            if status == 200:
                return status, {"endpoint": path, "purl": purl, "data": data}
            if status in (401, 403):
                return status, {"endpoint": path, "purl": purl, "data": data}
        return last_status, {"endpoint": "batch/purl", "purl": purl, "data": last_data}

    def threat_feed(self, **query: Any) -> Tuple[int, Any]:
        org = self.client.org
        status, data = 404, None
        for path in (f"/orgs/{org}/threat-feed", f"/orgs/{org}/threat-feed/items"):
            status, data, _ = self.client.request("GET", path, query=query)
            if status != 404:
                return status, {"endpoint": path, "query": query, "data": data}
        return status, {"endpoint": "threat-feed", "query": query, "data": data}

    def policies(self) -> Tuple[int, Any]:
        org = self.client.org
        status, data = 404, None
        for path in (
            f"/orgs/{org}/alert-policies",
            f"/orgs/{org}/policies",
            f"/orgs/{org}/settings",
            f"/orgs/{org}/security-policy",
        ):
            status, data, _ = self.client.request("GET", path)
            if status == 200 or status in (401, 403):
                return status, {"endpoint": path, "data": data}
        return status, {"endpoint": "policies", "data": data}

    def _run(
        self,
        req: Dict[str, str],
        method: str,
        expected: str,
        fn: Callable[[], Tuple[str, str, str, str, str]],
    ) -> None:
        self.store.banner(f"{req['id']} | {(req['description'] or '')[:100]}")
        self.store.log(f"vendor={req.get('vendor_response')!r} method={method}")
        t0 = time.time()
        try:
            verdict, http_status, observed, notes, evidence = fn()
        except Exception:
            verdict = "ERROR"
            http_status = ""
            observed = traceback.format_exc()[-2000:]
            notes = "unhandled exception"
            evidence = ""
        ms = int((time.time() - t0) * 1000)
        shot = self.store.screenshot(f"{req['id']}_{verdict}")
        self.store.log(f"-> {verdict} [{http_status}] {ms}ms")
        self.store.log(f"observed: {observed[:400]}")
        self.results.append(
            TestResult(
                requirement_id=req["id"],
                priority=req["priority"],
                description=req["description"],
                vendor_response=req.get("vendor_response", ""),
                test_method=method,
                verdict=verdict,
                http_status=str(http_status),
                expected=expected,
                observed=observed[:4000],
                evidence_files=evidence,
                screenshot=shot,
                notes=notes[:4000],
                duration_ms=ms,
            )
        )

    def _manual(self, req: Dict[str, str], reason: str) -> None:
        self._run(
            req,
            "MANUAL",
            "Human / Artifactory / IdP / network validation",
            lambda: ("MANUAL", "", reason, reason, ""),
        )

    def _partial(self, req: Dict[str, str], method: str, note: str) -> None:
        self._run(
            req,
            method,
            "Needs Firewall/Artifactory live validation beyond API",
            lambda: ("PARTIAL", "", note, note, ""),
        )

    def _unsupported(self, req: Dict[str, str], reason: str) -> None:
        self._run(
            req,
            "Negative expectation",
            "Unsupported as documented by vendor",
            lambda: ("PASS", "", reason, "Aligns with vendor No/N/A", ""),
        )

    def test_ecosystem(self, req: Dict[str, str], eco: str, supported: bool) -> None:
        def fn():
            if not supported:
                return (
                    "PASS",
                    "",
                    f"{eco} expected unsupported in Firewall",
                    "Matches vendor gap",
                    "",
                )
            if eco not in ECOSYSTEM_SAMPLES:
                return ("SKIP", "", f"no sample for {eco}", "add sample", "")

            name, ver = ECOSYSTEM_SAMPLES[eco]["clean"]
            status, payload = self.fetch_package(eco, name, ver)
            ev = [self._evidence(req["id"], f"{eco}_api_clean", payload)]
            notes = [f"API clean package status={status}"]
            verdict = "PARTIAL"
            if status == 200:
                verdict = "PASS"
                notes.append("package intel retrieved")
            elif status in (401, 403):
                verdict = "FAIL"
                notes.append("auth/permission failure")
            else:
                notes.append("unexpected API status / endpoint variance")

            if self.firewall_url:
                path = ECOSYSTEM_SAMPLES[eco]["firewall_clean"]
                fstatus, fheaders, fbody = self.firewall_get(path)
                ev.append(
                    self._evidence(
                        req["id"],
                        f"{eco}_fw_clean",
                        {
                            "path": path,
                            "status": fstatus,
                            "headers": fheaders,
                            "body_prefix": fbody[:400].decode("latin1", "replace"),
                        },
                    )
                )
                notes.append(f"firewall clean GET -> {fstatus}")
                if fstatus and fstatus < 400:
                    verdict = "PASS"
                elif fstatus in (401, 403, 407):
                    verdict = "PARTIAL"
                    notes.append("firewall auth may be required")
                elif fstatus == 0:
                    verdict = "PARTIAL"
                    notes.append("firewall unreachable")
            else:
                notes.append("SOCKET_FIREWALL_URL unset — registry path not live-tested")
                if verdict == "PASS":
                    verdict = "PARTIAL"

            return (
                verdict,
                str(status),
                " | ".join(notes),
                "Clean package API (+ optional Firewall) probe",
                ";".join(ev),
            )

        self._run(
            req,
            f"API+Firewall ecosystem probe ({eco})",
            "Supported ecosystem returns intel / Firewall serves clean artifacts",
            fn,
        )

    def test_threat_feed(self, req: Dict[str, str]) -> None:
        def fn():
            status, data = self.threat_feed(per_page=30, filter="mal")
            if status != 200:
                status2, data2 = self.threat_feed(per_page=30)
                ev = self._evidence(
                    req["id"],
                    "threat_feed",
                    {"filtered": {"status": status, "data": data}, "unfiltered": data2},
                )
                if status2 == 200:
                    return (
                        "PARTIAL",
                        str(status2),
                        "feed OK without mal filter; filtered call failed",
                        "Threat feed reachable",
                        ev,
                    )
                if status in (401, 403) or status2 in (401, 403):
                    return (
                        "FAIL",
                        str(status or status2),
                        str(data)[:1000],
                        "threat-feed forbidden — check license/scope",
                        ev,
                    )
                return (
                    "PARTIAL",
                    str(status or status2),
                    str(data)[:1000],
                    "threat-feed endpoint not available on this plan/token",
                    ev,
                )

            ev = self._evidence(req["id"], "threat_feed_mal", data)
            payload = data.get("data", data)
            items = (
                payload.get("results")
                or payload.get("items")
                or payload.get("rows")
                or payload
            )
            n = len(items) if isinstance(items, list) else -1
            blob = json.dumps(payload).lower()
            classes = [
                k
                for k in (
                    "malware",
                    "typosquat",
                    "install",
                    "obfuscat",
                    "telemetry",
                    "shell",
                    "critical",
                )
                if k in blob
            ]
            if n == 0:
                return (
                    "PARTIAL",
                    "200",
                    "empty page",
                    "Feed reachable but empty for filter=mal",
                    ev,
                )
            return (
                "PASS",
                "200",
                f"count={n} classes={classes}",
                "Threat feed returned malware-related items",
                ev,
            )

        self._run(req, "GET org threat-feed", "Malware threat intel available via API", fn)

    def test_attack_classes(self, req: Dict[str, str]) -> None:
        def fn():
            status_f, feed = self.threat_feed(per_page=50)
            status_p, pkg = self.fetch_package("npm", "event-stream", "3.3.6")
            ev1 = self._evidence(req["id"], "feed", feed)
            ev2 = self._evidence(req["id"], "event_stream", pkg)
            blob = (json.dumps(feed) + json.dumps(pkg)).lower()
            wanted = {
                "typosquat": ["typosquat", "typo", "didyoumean"],
                "install_scripts": ["install", "postinstall", "preinstall"],
                "obfuscation": ["obfuscat"],
                "malware": ["malware", "malicious"],
                "shell_or_network": ["shell", "network", "exfil", "telemetry"],
                "maintainer": ["maintainer", "compromise", "hijack"],
            }
            hits = {k: any(s in blob for s in syns) for k, syns in wanted.items()}
            n = sum(1 for v in hits.values() if v)
            observed = json.dumps(
                {"feed_status": status_f, "pkg_status": status_p, "hits": hits}
            )
            if (status_f == 200 or status_p == 200) and n >= 2:
                return (
                    "PASS",
                    f"{status_f}/{status_p}",
                    observed,
                    f"{n} attack-class keyword groups observed",
                    f"{ev1};{ev2}",
                )
            if status_f == 200 or status_p == 200:
                return (
                    "PARTIAL",
                    f"{status_f}/{status_p}",
                    observed,
                    "Limited class keywords in sampled payloads",
                    f"{ev1};{ev2}",
                )
            return (
                "FAIL",
                f"{status_f}/{status_p}",
                observed,
                "Unable to retrieve signals",
                f"{ev1};{ev2}",
            )

        self._run(
            req,
            "Threat feed + historical malware package inspection",
            "Multiple attack classes represented in Socket signals",
            fn,
        )

    def test_policies(self, req: Dict[str, str]) -> None:
        def fn():
            status, data = self.policies()
            ev = self._evidence(req["id"], "policies", data)
            if status == 200:
                return (
                    "PASS",
                    "200",
                    json.dumps(data)[:1500],
                    "Policy/settings readable via API",
                    ev,
                )
            if status in (401, 403):
                return (
                    "FAIL",
                    str(status),
                    str(data)[:1000],
                    "No permission to read policies",
                    ev,
                )
            return (
                "PARTIAL",
                str(status),
                str(data)[:1000],
                "Policy API path/plan variance — UI may still exist",
                ev,
            )

        self._run(
            req,
            "GET org alert-policies/settings",
            "Policies readable via API (UI+API req)",
            fn,
        )

    def test_firewall_block(self, req: Dict[str, str]) -> None:
        def fn():
            if not self.firewall_url:
                return (
                    "SKIP",
                    "",
                    "SOCKET_FIREWALL_URL unset",
                    "Deploy Registry Mode Firewall and re-run",
                    "",
                )
            path = ECOSYSTEM_SAMPLES["npm"]["firewall_suspect"]
            status, headers, body = self.firewall_get(path)
            reason = ""
            for k, v in headers.items():
                if "block" in k and "reason" in k:
                    reason = v
                    break
            reason = reason or headers.get("x-socket-block-reason", "")
            ev = self._evidence(
                req["id"],
                "firewall_suspect",
                {
                    "path": path,
                    "status": status,
                    "headers": headers,
                    "reason": reason,
                    "body_prefix": body[:800].decode("latin1", "replace"),
                },
            )
            if status == 403:
                if reason:
                    return (
                        "PASS",
                        "403",
                        f"reason={reason}",
                        "Hard block with reason header",
                        ev,
                    )
                return (
                    "PARTIAL",
                    "403",
                    "403 without parseable reason header",
                    "Block OK; reason header missing/different name",
                    ev,
                )
            if status == 404:
                return (
                    "FAIL",
                    "404",
                    "Package Not Found style response",
                    "Must not present as missing package",
                    ev,
                )
            if status and status < 400:
                return (
                    "FAIL",
                    str(status),
                    "suspect package allowed",
                    "Expected block (sample may no longer be considered malicious)",
                    ev,
                )
            return (
                "PARTIAL",
                str(status),
                json.dumps(headers)[:800],
                "Inconclusive — unpublished sample or firewall auth required",
                ev,
            )

        self._run(
            req,
            "Firewall GET historical malware package",
            "HTTP 403 (+ X-Socket-Block-Reason), not 404",
            fn,
        )

    def test_clean_vs_suspect(self, req: Dict[str, str]) -> None:
        def fn():
            c_status, c_payload = self.fetch_package("npm", "lodash", "4.17.21")
            m_status, m_payload = self.fetch_package("npm", "event-stream", "3.3.6")
            ev1 = self._evidence(req["id"], "clean", c_payload)
            ev2 = self._evidence(req["id"], "suspect", m_payload)
            c_blob = json.dumps(c_payload).lower()
            m_blob = json.dumps(m_payload).lower()
            markers = ["malware", "critical", "alert", "supplychain", "typosquat"]
            c_hits = sum(1 for k in markers if k in c_blob)
            m_hits = sum(1 for k in markers if k in m_blob)
            observed = (
                f"clean={c_status}/{c_hits} markers; suspect={m_status}/{m_hits} markers"
            )
            if c_status == 200 and m_status == 200 and m_hits > c_hits:
                return (
                    "PASS",
                    f"{c_status}/{m_status}",
                    observed,
                    "Suspect sample has stronger risk markers than clean control",
                    f"{ev1};{ev2}",
                )
            if c_status == 200 and m_status == 200:
                return (
                    "PARTIAL",
                    f"{c_status}/{m_status}",
                    observed,
                    "Both retrieved; discrimination weak in payload shape",
                    f"{ev1};{ev2}",
                )
            return (
                "PARTIAL",
                f"{c_status}/{m_status}",
                observed,
                "Could not fully compare",
                f"{ev1};{ev2}",
            )

        self._run(
            req,
            "Compare clean vs historical malware package API payloads",
            "Suspect risk markers > clean",
            fn,
        )

    def test_package_inspect(self, req: Dict[str, str]) -> None:
        def fn():
            status, payload = self.fetch_package("npm", "lodash", "4.17.21")
            ev = self._evidence(req["id"], "inspect", payload)
            blob = json.dumps(payload).lower()
            ok = any(k in blob for k in ("score", "license", "alert", "risk", "supply"))
            if status == 200 and ok:
                return (
                    "PASS",
                    str(status),
                    "risk/license/score fields present",
                    "Inspectable via API (build provenance not expected)",
                    ev,
                )
            return (
                "PARTIAL",
                str(status),
                str(payload)[:1000],
                "Limited inspectability",
                ev,
            )

        self._run(
            req,
            "Package metadata inspect",
            "Risk/license visible pre-adoption",
            fn,
        )

    def dispatch(self, req: Dict[str, str]) -> None:
        rid = req["id"]

        eco_map = {
            "A.EC.1": ("npm", True),
            "A.EC.2": ("pypi", True),
            "A.EC.3": ("maven", True),
            "A.EC.4": ("go", True),
            "A.EC.5": ("nuget", True),
            "A.EC.6": ("cocoapods", False),
            "A.EC.7": ("cargo", True),
            "A.EC.8": ("packagist", False),
            "A.EC.9": ("gem", True),
            "A.EC.10": ("swift", False),
        }
        if rid in eco_map:
            eco, supported = eco_map[rid]
            self.test_ecosystem(req, eco, supported)
            return

        if rid == "A.EC.12":
            self._manual(
                req,
                "Source URL + path-prefix allowlist is Artifactory/Firewall config; validate in PoC UI/config",
            )
            return
        if rid in ("A.PC.1", "A.PC.2"):
            self.test_clean_vs_suspect(req)
            return
        if rid == "A.SCG.1":
            self.test_threat_feed(req)
            return
        if rid == "A.SCG.2":
            self.test_attack_classes(req)
            return
        if rid in ("A.SCG.3", "A.SCG.4"):
            self._partial(
                req,
                "Threat-feed + Firewall cache TTL observation",
                "Reassessment/re-block needs timed Firewall re-fetch after IoC publish",
            )
            return
        if rid == "A.SCG.5":
            self._manual(
                req,
                "Set recentlyPublished/cooldown in policy and attempt brand-new package install",
            )
            return
        if rid == "A.SCG.6":
            if self.firewall_url:
                self.test_firewall_block(req)
            else:
                self.test_threat_feed(req)
            return
        if rid == "A.SCG.7":
            self._manual(req, "Create triage exception in UI/API and confirm audit trail")
            return
        if rid == "A.SCG.8":
            self._partial(
                req,
                "Policy model review",
                "Per-ecosystem rules exist; per-repo Firewall scoping often Default-policy limited",
            )
            return
        if rid == "A.SCG.9":
            self.test_policies(req)
            return
        if rid == "A.SCG.10":
            self._partial(
                req,
                "Checksum compare Firewall vs upstream",
                "Compare digest of artifact via Firewall vs direct upstream in PoC",
            )
            return
        if rid in ("A.SCG.11", "A.SCG.12", "A.SCG.13"):
            self._manual(
                req,
                "Workstation bypass / client config override / governed-path metrics need network controls",
            )
            return
        if rid == "A.SCG.14":
            self._partial(
                req,
                "Dashboard/export review",
                "Pull org alerts/firewall logs and confirm attacks-prevented reporting fields",
            )
            return
        if rid == "A.SCG.15":
            self._manual(
                req,
                "Break-glass: toggle fail_open / triage allow; confirm audit + follow-up",
            )
            return
        if rid == "A.SCG.16":
            self.test_threat_feed(req)
            return
        if rid == "A.SCG.17":
            self._partial(
                req,
                "Policy lifecycle review",
                "Custom rules via API/UI; version history/rollback may be missing — verify in product",
            )
            return
        if rid == "A.SCG.RISK":
            self.test_attack_classes(req)
            return
        if rid in ("A.PT.1", "A.PT.2", "A.PT.3"):
            self._unsupported(
                req,
                "SLSA/signature/attestation not provided by Socket Firewall (vendor No/N/A)",
            )
            return
        if rid == "A.PT.4":
            self.test_clean_vs_suspect(req)
            return
        if rid == "A.PT.5":
            self.test_package_inspect(req)
            return
        if rid == "A.AI.1":
            self._manual(
                req,
                "Configure Artifactory remote -> Socket Firewall; confirm route sync",
            )
            return
        if rid == "A.AI.2":
            self._manual(
                req,
                "Validate SAML/OIDC SSO against Atlassian IdP in Socket org settings",
            )
            return
        if rid == "A.AI.3":
            self._partial(
                req,
                "Latency measurement",
                "Real-time proxy model — measure p95 latency through Firewall",
            )
            return
        if rid == "A.AI.4":
            self.test_firewall_block(req)
            return
        if rid == "A.AI.5":
            self._partial(
                req,
                "Unscanned package behavior",
                "Test never-seen package + fail_open_unscanned on Firewall",
            )
            return
        if rid == "A.AI.6":
            self._partial(
                req,
                "Multi-format artifact fetch",
                "Fetch multiple formats for one version through Firewall vs upstream",
            )
            return
        if rid == "A.AI.7":
            self._manual(req, "Passthrough/private registry route for internal packages")
            return
        if rid == "A.AI.8":
            self._manual(
                req,
                "Load/latency under Artifactory timeouts; exercise circuit breaker",
            )
            return
        if rid == "A.AI.9":
            self._manual(
                req, "Enable Splunk HEC/webhook and confirm block event delivery"
            )
            return
        if rid == "A.AI.10":
            self._manual(
                req, "Set cooldown>0 and attempt to pull a brand-new package version"
            )
            return
        if rid == "A.AI.11":
            self.test_firewall_block(req)
            return
        if rid == "A.AI.12":
            self._manual(
                req,
                "Toggle fail_open true/false with API denied and observe allow vs block",
            )
            return

        self._manual(req, f"No automated mapper for {rid}")

    def write_csv(self, path: Path) -> None:
        fields = list(asdict(self.results[0]).keys()) if self.results else [
            "requirement_id",
            "priority",
            "description",
            "vendor_response",
            "test_method",
            "verdict",
            "http_status",
            "expected",
            "observed",
            "evidence_files",
            "screenshot",
            "notes",
            "duration_ms",
            "timestamp",
        ]
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in self.results:
                w.writerow(asdict(r))

    def write_summary(self, path: Path) -> None:
        counts = Counter(r.verdict for r in self.results)
        lines = [
            "# Socket live requirements test summary",
            "",
            f"- When: {datetime.now().isoformat()}",
            f"- Org: `{self.client.org}`",
            f"- Firewall URL set: `{bool(self.firewall_url)}`",
            f"- Embedded requirements: {len(REQUIREMENTS)}",
            f"- Counts: `{dict(counts)}`",
            "",
            "## Verdict counts",
        ]
        for k, v in sorted(counts.items()):
            lines.append(f"- **{k}**: {v}")
        lines += ["", "## Per requirement", ""]
        for r in self.results:
            lines.append(f"- `{r.requirement_id}` **{r.verdict}** — {r.notes[:180]}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    token = os.environ.get("SOCKET_API_TOKEN", "").strip()
    org = os.environ.get("SOCKET_ORG_SLUG", "").strip()
    if not token or not org:
        print(
            "ERROR: Set SOCKET_API_TOKEN and SOCKET_ORG_SLUG.",
            file=sys.stderr,
        )
        return 2

    firewall = os.environ.get("SOCKET_FIREWALL_URL", "").strip()
    timeout = float(os.environ.get("SOCKET_TIMEOUT", "45"))
    shots = os.environ.get("SOCKET_SCREENSHOTS", "1") != "0"

    if os.environ.get("SOCKET_OUT_DIR"):
        out_dir = Path(os.environ["SOCKET_OUT_DIR"]).expanduser().resolve()
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = Path(__file__).resolve().parent / f"live_results_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    store = EvidenceStore(out_dir, enable_screenshots=shots)
    store.log(f"embedded_requirements={len(REQUIREMENTS)}")
    store.log(
        f"org={org} firewall_set={bool(firewall)} screenshots={store.enable_screenshots}"
    )
    store.save_text(
        "run_config.txt",
        "\n".join(
            [
                f"org={org}",
                f"firewall={firewall}",
                f"requirements=embedded:{len(REQUIREMENTS)}",
                f"timeout={timeout}",
                f"platform={platform.platform()}",
                f"python={sys.version.split()[0]}",
            ]
        )
        + "\n",
    )
    store.save_json("embedded_requirements.json", REQUIREMENTS)

    client = SocketClient(token, org, timeout=timeout)
    store.banner("Auth / org smoke test")
    status, data, _ = client.request("GET", f"/orgs/{org}")
    store.save_json("auth_org.json", {"status": status, "data": data})
    store.log(f"GET /orgs/{org} -> {status}")
    store.screenshot("00_auth_smoke")
    if status in (401, 403):
        store.log("ERROR: authentication/authorization failed")
        store.close()
        return 3
    if status == 404:
        store.log("WARN: /orgs/{slug} returned 404 — continuing with other endpoints")

    tester = SocketRequirementsTester(client, store, firewall_url=firewall)
    for req in REQUIREMENTS:
        tester.dispatch(req)

    csv_path = out_dir / "Socket_Live_Test_Results.csv"
    summary_path = out_dir / "SUMMARY.md"
    tester.write_csv(csv_path)
    tester.write_summary(summary_path)
    store.banner(f"DONE — {csv_path}")
    store.screenshot("zz_complete")
    store.close()

    print(f"\nCSV:         {csv_path}")
    print(f"Summary:     {summary_path}")
    print(f"Evidence:    {out_dir / 'evidence'}")
    print(f"Screenshots: {out_dir / 'screenshots'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
