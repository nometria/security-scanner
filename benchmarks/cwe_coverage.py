#!/usr/bin/env python3
"""
CWE Top 25 (2024) coverage mapping and OWASP Benchmark-style scoring.

Maps each SEC rule to CWE IDs, calculates per-CWE True Positive Rate (TPR)
and False Positive Rate (FPR), and computes Youden's Index (J = TPR - FPR).

Youden's Index is the metric used by the OWASP Benchmark project to score
scanners. A perfect scanner has J=1.0 (TPR=100%, FPR=0%). A random scanner
has J=0.0.

Reference: https://owasp.org/www-project-benchmark/

Usage:
    python benchmarks/cwe_coverage.py
"""

import json
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Add scanner to path
sys.path.insert(0, str(Path("/tmp/nometria-security-scanner/src")))

from security_scanner.scanner import scan_project, Finding


# ── CWE Top 25 (2024) relevant to web/JS/Python apps ──────────────────────

@dataclass
class CWEEntry:
    """A CWE from the Top 25 list."""
    cwe_id: int
    name: str
    sec_rules: List[str]  # SEC-XXX rules that cover this CWE
    rank: int  # position in CWE Top 25


# Web-relevant subset of CWE Top 25 (2024)
CWE_TOP_25_WEB: List[CWEEntry] = [
    CWEEntry(79, "Improper Neutralization of Input During Web Page Generation (XSS)", ["SEC-013"], 2),
    CWEEntry(89, "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)", ["SEC-004"], 3),
    CWEEntry(22, "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)", ["SEC-014"], 8),
    CWEEntry(78, "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)", ["SEC-003"], 5),
    CWEEntry(862, "Missing Authorization", ["SEC-005"], 11),
    CWEEntry(94, "Improper Control of Generation of Code (Code Injection)", ["SEC-003"], 12),
    CWEEntry(287, "Improper Authentication", ["SEC-005", "SEC-008"], 13),
    CWEEntry(918, "Server-Side Request Forgery (SSRF)", ["SEC-015"], 19),
    CWEEntry(798, "Use of Hard-coded Credentials", ["SEC-001"], 16),
    CWEEntry(306, "Missing Authentication for Critical Function", ["SEC-008"], 18),
    CWEEntry(200, "Exposure of Sensitive Information to an Unauthorized Actor", ["SEC-010", "SEC-011"], 17),
    CWEEntry(352, "Cross-Site Request Forgery (CSRF)", ["SEC-017"], 9),
    CWEEntry(502, "Deserialization of Untrusted Data", ["SEC-018"], 15),
    CWEEntry(434, "Unrestricted Upload of File with Dangerous Type", ["SEC-019"], 10),
]

# Full SEC rule -> CWE mapping (including rules not in Top 25 web subset)
SEC_TO_CWE: Dict[str, List[int]] = {
    "SEC-001": [798],          # Hard-coded credentials
    "SEC-002": [538],          # .env committed (info exposure via files)
    "SEC-003": [94, 78],       # eval/exec -> code injection + OS command injection
    "SEC-004": [89],           # SQL injection
    "SEC-005": [862, 287],     # Missing auth -> missing authorization + improper auth
    "SEC-006": [942],          # CORS wildcard (overly permissive cross-domain policy)
    "SEC-007": [319],          # HTTP URLs (cleartext transmission)
    "SEC-008": [306, 287],     # Exposed admin routes -> missing auth critical function
    "SEC-009": [922],          # localStorage auth (insecure storage)
    "SEC-010": [200, 532],     # console.log env (info exposure + log info exposure)
    "SEC-011": [200],          # Supabase service key client-side
    "SEC-012": [427],          # Dependency confusion (uncontrolled search path)
    "SEC-013": [79],           # XSS
    "SEC-014": [22],           # Path traversal
    "SEC-015": [918],          # SSRF / open redirect
    "SEC-016": [943],          # NoSQL injection
    "SEC-017": [352],          # CSRF
    "SEC-018": [502],          # Deserialization
    "SEC-019": [434],          # Unrestricted file upload
}


# ── Test fixtures: True Positive (vulnerable) and True Negative (safe) ─────

@dataclass
class CWETestCase:
    """A test case for a specific CWE."""
    cwe_id: int
    is_vulnerable: bool  # True = should be detected, False = should NOT be detected
    files: Dict[str, str]
    expected_rule: str
    description: str


def build_cwe_fixtures() -> List[CWETestCase]:
    """Build test fixtures for each CWE with both TP and TN cases."""
    fixtures = []

    # ── CWE-79: XSS ───────────────────────────────────────────────────────
    fixtures.append(CWETestCase(
        cwe_id=79, is_vulnerable=True,
        files={"src/xss.js": 'document.getElementById("out").innerHTML = userInput;'},
        expected_rule="SEC-013",
        description="innerHTML with user input",
    ))
    fixtures.append(CWETestCase(
        cwe_id=79, is_vulnerable=True,
        files={"src/xss2.js": 'document.write(msg);'},
        expected_rule="SEC-013",
        description="document.write",
    ))
    fixtures.append(CWETestCase(
        cwe_id=79, is_vulnerable=False,
        files={"src/safe_xss.js": 'document.getElementById("out").textContent = userInput;'},
        expected_rule="SEC-013",
        description="textContent (safe)",
    ))

    # ── CWE-89: SQL Injection ──────────────────────────────────────────────
    fixtures.append(CWETestCase(
        cwe_id=89, is_vulnerable=True,
        files={"src/sqli.js": 'const q = `SELECT * FROM users WHERE id = ${userId}`;'},
        expected_rule="SEC-004",
        description="Template literal SQL injection",
    ))
    fixtures.append(CWETestCase(
        cwe_id=89, is_vulnerable=True,
        files={"src/sqli2.py": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'},
        expected_rule="SEC-004",
        description="Python f-string SQL injection",
    ))
    fixtures.append(CWETestCase(
        cwe_id=89, is_vulnerable=False,
        files={"src/safe_sql.js": 'const result = await db.query("SELECT * FROM users WHERE id = $1", [userId]);'},
        expected_rule="SEC-004",
        description="Parameterized query (safe)",
    ))

    # ── CWE-22: Path Traversal ─────────────────────────────────────────────
    fixtures.append(CWETestCase(
        cwe_id=22, is_vulnerable=True,
        files={"src/path.js": textwrap.dedent('''\
            app.get("/download", (req, res) => {
              const filePath = req.query.file;
              res.sendFile(filePath);
            });
        ''')},
        expected_rule="SEC-014",
        description="sendFile with user input",
    ))
    fixtures.append(CWETestCase(
        cwe_id=22, is_vulnerable=False,
        files={"src/safe_path.js": textwrap.dedent('''\
            app.get("/download", (req, res) => {
              const safeName = path.basename(req.query.file);
              res.sendFile(path.join(__dirname, "uploads", safeName));
            });
        ''')},
        expected_rule="SEC-014",
        description="basename-validated path (safe)",
    ))

    # ── CWE-78: OS Command Injection ───────────────────────────────────────
    fixtures.append(CWETestCase(
        cwe_id=78, is_vulnerable=True,
        files={"src/cmd.js": 'function run(input) { return eval(input); }'},
        expected_rule="SEC-003",
        description="eval with user input",
    ))
    fixtures.append(CWETestCase(
        cwe_id=78, is_vulnerable=False,
        files={"src/safe_cmd.js": 'const data = JSON.parse(rawInput);'},
        expected_rule="SEC-003",
        description="JSON.parse (safe)",
    ))

    # ── CWE-862: Missing Authorization ─────────────────────────────────────
    fixtures.append(CWETestCase(
        cwe_id=862, is_vulnerable=True,
        files={"src/noauth.js": 'app.get("/api/users", (req, res) => { res.json(users); });'},
        expected_rule="SEC-005",
        description="API route without auth middleware",
    ))
    fixtures.append(CWETestCase(
        cwe_id=862, is_vulnerable=False,
        files={"src/auth_ok.js": 'app.get("/api/users", verifyToken, (req, res) => { res.json(users); });'},
        expected_rule="SEC-005",
        description="Route with auth middleware (safe)",
    ))

    # ── CWE-94: Code Injection ─────────────────────────────────────────────
    fixtures.append(CWETestCase(
        cwe_id=94, is_vulnerable=True,
        files={"src/codeinj.js": 'const fn = new Function("return " + expr);'},
        expected_rule="SEC-003",
        description="new Function constructor",
    ))
    fixtures.append(CWETestCase(
        cwe_id=94, is_vulnerable=True,
        files={"src/codeinj2.py": 'exec(user_code)'},
        expected_rule="SEC-003",
        description="Python exec with user input",
    ))

    # ── CWE-287: Improper Authentication ───────────────────────────────────
    fixtures.append(CWETestCase(
        cwe_id=287, is_vulnerable=True,
        files={"src/badauth.js": 'app.get("/admin/dashboard", (req, res) => { res.render("panel"); });'},
        expected_rule="SEC-008",
        description="Admin route without auth check",
    ))
    fixtures.append(CWETestCase(
        cwe_id=287, is_vulnerable=False,
        files={"src/goodauth.js": 'app.get("/admin/dashboard", isAdmin, (req, res) => { res.render("panel"); });'},
        expected_rule="SEC-008",
        description="Admin route with isAdmin middleware (safe)",
    ))

    # ── CWE-918: SSRF ──────────────────────────────────────────────────────
    fixtures.append(CWETestCase(
        cwe_id=918, is_vulnerable=True,
        files={"src/ssrf.js": textwrap.dedent('''\
            app.get("/proxy", async (req, res) => {
              const response = await fetch(req.query.url);
              res.json(await response.json());
            });
        ''')},
        expected_rule="SEC-015",
        description="fetch with user-supplied URL",
    ))
    fixtures.append(CWETestCase(
        cwe_id=918, is_vulnerable=False,
        files={"src/safe_fetch.js": 'const response = await fetch("https://api.example.com/data");'},
        expected_rule="SEC-015",
        description="Hardcoded URL fetch (safe)",
    ))

    # ── CWE-798: Hard-coded Credentials ────────────────────────────────────
    fixtures.append(CWETestCase(
        cwe_id=798, is_vulnerable=True,
        files={"src/creds.ts": 'const awsKey = "AKIAIOSFODNN7EXAMPLE";'},
        expected_rule="SEC-001",
        description="AWS Access Key ID hardcoded",
    ))
    fixtures.append(CWETestCase(
        cwe_id=798, is_vulnerable=True,
        files={"src/creds2.ts": 'const password = "MyS3cur3P@ssw0rd!";'},
        expected_rule="SEC-001",
        description="Hardcoded password",
    ))
    fixtures.append(CWETestCase(
        cwe_id=798, is_vulnerable=False,
        files={"src/safe_creds.ts": 'const apiKey = process.env.OPENAI_API_KEY;'},
        expected_rule="SEC-001",
        description="Env var reference (safe)",
    ))

    # ── CWE-306: Missing Auth for Critical Function ────────────────────────
    fixtures.append(CWETestCase(
        cwe_id=306, is_vulnerable=True,
        files={"src/critical.js": 'app.post("/internal/manage", (req, res) => { manage(req.body); });'},
        expected_rule="SEC-008",
        description="Internal management route without auth",
    ))

    # ── CWE-200: Sensitive Info Exposure ───────────────────────────────────
    fixtures.append(CWETestCase(
        cwe_id=200, is_vulnerable=True,
        files={"src/leak.js": 'console.log("DB URL:", process.env.DATABASE_URL);'},
        expected_rule="SEC-010",
        description="console.log leaking env var",
    ))
    fixtures.append(CWETestCase(
        cwe_id=200, is_vulnerable=True,
        files={"src/components/supa.ts": 'const adminClient = createClient(url, service_role);'},
        expected_rule="SEC-011",
        description="Supabase service_role client-side",
    ))
    fixtures.append(CWETestCase(
        cwe_id=200, is_vulnerable=False,
        files={"src/safe_log.js": 'console.log("Server started on port", PORT);'},
        expected_rule="SEC-010",
        description="Safe console.log (no env vars)",
    ))

    # ── CWE-352: CSRF (NEW) ───────────────────────────────────────────────
    fixtures.append(CWETestCase(
        cwe_id=352, is_vulnerable=True,
        files={"src/csrf_vuln.js": textwrap.dedent('''\
            app.post("/api/transfer", (req, res) => {
              transferFunds(req.body.amount, req.body.to);
              res.json({ ok: true });
            });
        ''')},
        expected_rule="SEC-017",
        description="POST route without CSRF protection",
    ))
    fixtures.append(CWETestCase(
        cwe_id=352, is_vulnerable=True,
        files={"src/csrf_vuln2.js": textwrap.dedent('''\
            app.delete("/api/account", (req, res) => {
              deleteAccount(req.user.id);
              res.json({ deleted: true });
            });
        ''')},
        expected_rule="SEC-017",
        description="DELETE route without CSRF protection",
    ))
    fixtures.append(CWETestCase(
        cwe_id=352, is_vulnerable=True,
        files={"src/csrf_vuln3.py": textwrap.dedent('''\
            from fastapi import FastAPI
            app = FastAPI()

            @app.post("/api/transfer")
            def transfer(data: dict):
                return {"ok": True}
        ''')},
        expected_rule="SEC-017",
        description="Python POST without CSRF",
    ))
    fixtures.append(CWETestCase(
        cwe_id=352, is_vulnerable=False,
        files={"src/csrf_safe.js": textwrap.dedent('''\
            const csrfProtection = csrf({ cookie: true });
            app.post("/api/transfer", csrfProtection, (req, res) => {
              transferFunds(req.body.amount, req.body.to);
              res.json({ ok: true });
            });
        ''')},
        expected_rule="SEC-017",
        description="POST with CSRF middleware (safe)",
    ))

    # ── CWE-502: Deserialization (NEW) ────────────────────────────────────
    fixtures.append(CWETestCase(
        cwe_id=502, is_vulnerable=True,
        files={"src/deser.py": textwrap.dedent('''\
            import pickle
            data = pickle.loads(request.data)
        ''')},
        expected_rule="SEC-018",
        description="pickle.loads on user data",
    ))
    fixtures.append(CWETestCase(
        cwe_id=502, is_vulnerable=True,
        files={"src/deser2.py": textwrap.dedent('''\
            import yaml
            config = yaml.load(user_input)
        ''')},
        expected_rule="SEC-018",
        description="yaml.load without SafeLoader",
    ))
    fixtures.append(CWETestCase(
        cwe_id=502, is_vulnerable=True,
        files={"src/deser3.js": 'const obj = serialize.unserialize(req.body.data);'},
        expected_rule="SEC-018",
        description="node-serialize unserialize",
    ))
    fixtures.append(CWETestCase(
        cwe_id=502, is_vulnerable=False,
        files={"src/safe_deser.py": textwrap.dedent('''\
            import yaml
            config = yaml.safe_load(user_input)
        ''')},
        expected_rule="SEC-018",
        description="yaml.safe_load (safe)",
    ))
    fixtures.append(CWETestCase(
        cwe_id=502, is_vulnerable=False,
        files={"src/safe_deser2.js": 'const data = JSON.parse(req.body.data);'},
        expected_rule="SEC-018",
        description="JSON.parse (safe)",
    ))

    # ── CWE-434: Unrestricted File Upload (NEW) ──────────────────────────
    fixtures.append(CWETestCase(
        cwe_id=434, is_vulnerable=True,
        files={"src/upload.js": textwrap.dedent('''\
            const upload = multer({ dest: "uploads/" });
            app.post("/upload", upload.single("file"), (req, res) => {
              res.json({ path: req.file.path });
            });
        ''')},
        expected_rule="SEC-019",
        description="Multer without fileFilter",
    ))
    fixtures.append(CWETestCase(
        cwe_id=434, is_vulnerable=True,
        files={"src/upload2.py": textwrap.dedent('''\
            from flask import request
            @app.route("/upload", methods=["POST"])
            def upload():
                f = request.files["document"]
                f.save(os.path.join("uploads", f.filename))
        ''')},
        expected_rule="SEC-019",
        description="Flask file upload without validation",
    ))
    fixtures.append(CWETestCase(
        cwe_id=434, is_vulnerable=False,
        files={"src/safe_upload.js": textwrap.dedent('''\
            const upload = multer({
              dest: "uploads/",
              fileFilter: (req, file, cb) => {
                const allowed = /jpeg|jpg|png|gif/;
                cb(null, allowed.test(file.mimetype));
              }
            });
            app.post("/upload", upload.single("file"), (req, res) => {
              res.json({ path: req.file.path });
            });
        ''')},
        expected_rule="SEC-019",
        description="Multer with fileFilter (safe)",
    ))

    return fixtures


# ── Benchmark runner ────────────────────────────────────────────────────────

@dataclass
class CWEResult:
    """Results for a single CWE."""
    cwe_id: int
    name: str
    rank: int
    sec_rules: List[str]
    true_positives: int   # vulnerable cases correctly detected
    false_negatives: int  # vulnerable cases missed
    true_negatives: int   # safe cases correctly not flagged
    false_positives: int  # safe cases incorrectly flagged
    tpr: float  # True Positive Rate = TP / (TP + FN)
    fpr: float  # False Positive Rate = FP / (FP + TN)
    youdens_j: float  # Youden's Index = TPR - FPR


def make_project(files: dict) -> Path:
    """Create a temporary project directory with the given files."""
    tmp = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp


def run_cwe_benchmark(cwe: CWEEntry, test_cases: List[CWETestCase]) -> CWEResult:
    """Run all test cases for a single CWE and calculate metrics."""
    tp = 0
    fn = 0
    tn = 0
    fp = 0

    for tc in test_cases:
        project = make_project(tc.files)
        result = scan_project(project)

        found_expected = any(f.rule_id == tc.expected_rule for f in result.findings)

        if tc.is_vulnerable:
            if found_expected:
                tp += 1
            else:
                fn += 1
        else:
            if found_expected:
                fp += 1
            else:
                tn += 1

    # Calculate rates
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 1.0  # perfect if no vulnerable cases
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0  # perfect if no safe cases
    youdens_j = tpr - fpr

    return CWEResult(
        cwe_id=cwe.cwe_id,
        name=cwe.name,
        rank=cwe.rank,
        sec_rules=cwe.sec_rules,
        true_positives=tp,
        false_negatives=fn,
        true_negatives=tn,
        false_positives=fp,
        tpr=tpr,
        fpr=fpr,
        youdens_j=youdens_j,
    )


def main():
    print("=" * 90)
    print("  CWE Top 25 (2024) Coverage & OWASP Benchmark Scoring")
    print("=" * 90)
    print()

    # Group test cases by CWE
    all_fixtures = build_cwe_fixtures()
    cwe_fixtures: Dict[int, List[CWETestCase]] = {}
    for tc in all_fixtures:
        cwe_fixtures.setdefault(tc.cwe_id, []).append(tc)

    results: List[CWEResult] = []
    t0 = time.monotonic()

    for cwe in sorted(CWE_TOP_25_WEB, key=lambda c: c.rank):
        cases = cwe_fixtures.get(cwe.cwe_id, [])
        if cases:
            res = run_cwe_benchmark(cwe, cases)
            results.append(res)

    elapsed = time.monotonic() - t0

    # ── Coverage summary ────────────────────────────────────────────────────
    total_web_cwes = len(CWE_TOP_25_WEB)
    covered = sum(1 for r in results if r.true_positives > 0 or (r.true_positives == 0 and r.false_negatives == 0))
    coverage_pct = covered / total_web_cwes * 100

    print(f"Coverage: {covered}/{total_web_cwes} web-relevant CWE Top 25 entries ({coverage_pct:.0f}%)")
    print()

    # ── Per-CWE results table ───────────────────────────────────────────────
    header = f"{'Rank':<6} {'CWE':<10} {'SEC Rules':<20} {'TP':<4} {'FN':<4} {'TN':<4} {'FP':<4} {'TPR':<8} {'FPR':<8} {'J':<8}"
    print(header)
    print("-" * 90)

    total_tp = 0
    total_fn = 0
    total_tn = 0
    total_fp = 0
    j_scores = []

    for r in sorted(results, key=lambda x: x.rank):
        rules_str = ",".join(r.sec_rules)
        print(
            f"{r.rank:<6} CWE-{r.cwe_id:<6} {rules_str:<20} "
            f"{r.true_positives:<4} {r.false_negatives:<4} {r.true_negatives:<4} {r.false_positives:<4} "
            f"{r.tpr:<8.2f} {r.fpr:<8.2f} {r.youdens_j:<8.2f}"
        )
        total_tp += r.true_positives
        total_fn += r.false_negatives
        total_tn += r.true_negatives
        total_fp += r.false_positives
        j_scores.append(r.youdens_j)

    print("-" * 90)

    # ── Aggregate scores ────────────────────────────────────────────────────
    overall_tpr = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    overall_fpr = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0
    overall_j = overall_tpr - overall_fpr
    avg_j = sum(j_scores) / len(j_scores) if j_scores else 0

    print(f"{'':6} {'OVERALL':<10} {'':20} "
          f"{total_tp:<4} {total_fn:<4} {total_tn:<4} {total_fp:<4} "
          f"{overall_tpr:<8.2f} {overall_fpr:<8.2f} {overall_j:<8.2f}")
    print()

    print("OWASP Benchmark-Style Scoring:")
    print(f"  Overall Youden's Index (J):     {overall_j:.2f}")
    print(f"  Average per-CWE J:              {avg_j:.2f}")
    print(f"  Overall TPR:                    {overall_tpr:.1%}")
    print(f"  Overall FPR:                    {overall_fpr:.1%}")
    print(f"  CWE Top 25 web coverage:        {covered}/{total_web_cwes} ({coverage_pct:.0f}%)")
    print(f"  Benchmark time:                 {elapsed:.2f}s")
    print()

    # ── Interpretation ──────────────────────────────────────────────────────
    print("Score interpretation (Youden's Index):")
    print("  J = 1.00  Perfect (TPR=100%, FPR=0%)")
    print("  J > 0.80  Excellent")
    print("  J > 0.60  Good")
    print("  J > 0.40  Fair")
    print("  J = 0.00  Random (no better than coin flip)")
    print("  J < 0.00  Worse than random")
    print()

    # ── SEC Rule to CWE mapping ─────────────────────────────────────────────
    print("SEC Rule -> CWE Mapping:")
    print("-" * 60)
    for rule_id in sorted(SEC_TO_CWE.keys()):
        cwes = SEC_TO_CWE[rule_id]
        cwe_strs = [f"CWE-{c}" for c in cwes]
        print(f"  {rule_id}: {', '.join(cwe_strs)}")
    print()

    # ── JSON output ─────────────────────────────────────────────────────────
    output = {
        "coverage": {
            "total_web_cwes": total_web_cwes,
            "covered": covered,
            "coverage_pct": round(coverage_pct, 1),
        },
        "scoring": {
            "overall_youdens_j": round(overall_j, 4),
            "avg_per_cwe_j": round(avg_j, 4),
            "overall_tpr": round(overall_tpr, 4),
            "overall_fpr": round(overall_fpr, 4),
        },
        "per_cwe": [],
        "sec_to_cwe": SEC_TO_CWE,
        "benchmark_time_sec": round(elapsed, 2),
    }
    for r in sorted(results, key=lambda x: x.rank):
        output["per_cwe"].append({
            "cwe_id": r.cwe_id,
            "name": r.name,
            "rank": r.rank,
            "sec_rules": r.sec_rules,
            "tp": r.true_positives,
            "fn": r.false_negatives,
            "tn": r.true_negatives,
            "fp": r.false_positives,
            "tpr": round(r.tpr, 4),
            "fpr": round(r.fpr, 4),
            "youdens_j": round(r.youdens_j, 4),
        })

    json_path = Path("/tmp/nometria-security-scanner/benchmarks/cwe_results.json")
    with open(json_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Results saved to: {json_path}")

    return output


if __name__ == "__main__":
    output = main()
    # Exit code based on coverage
    sys.exit(0 if output["coverage"]["coverage_pct"] >= 50 else 1)
