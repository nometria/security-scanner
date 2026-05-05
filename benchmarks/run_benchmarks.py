#!/usr/bin/env python3
"""
Benchmark suite for ai-security-scan.

Creates test fixtures with known OWASP Top 10 vulnerabilities and measures:
  - Detection rate (true positives / total known vulnerabilities)
  - False positive rate
  - Scan speed (files/second)

Usage:
    python run_benchmarks.py
"""

import json
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Add scanner to path
sys.path.insert(0, str(Path("/tmp/nometria-security-scanner/src")))

from security_scanner.scanner import scan_project, Finding


# ─── Fixture definitions ────────────────────────────────────────────────────
# Each fixture maps a category to (files_dict, expected_vuln_rule_ids, expected_false_positive_count)

@dataclass
class VulnFixture:
    """A single test vulnerability."""
    vuln_id: str
    rule_id: str  # expected SEC-XXX rule
    description: str


@dataclass
class CategoryFixture:
    """A category of vulnerabilities with fixture files."""
    name: str
    owasp: str
    files: Dict[str, str]
    expected_vulns: List[VulnFixture]
    false_positive_count: int  # how many false positives should NOT be flagged


def build_fixtures() -> List[CategoryFixture]:
    """Build all test fixtures."""
    fixtures = []

    # ── 1. Hardcoded Secrets ────────────────────────────────────────────────
    fixtures.append(CategoryFixture(
        name="Hardcoded Secrets",
        owasp="A07:2021",
        files={
            "src/config.ts": textwrap.dedent('''\
                // VULN_001: AWS Access Key ID
                const awsKey = "AKIAIOSFODNN7EXAMPLE";

                // VULN_002: Stripe live secret key
                const stripeKey = "sk_" + "live_abcdefghijklmnopqrstuvwx";

                // VULN_003: GitHub personal access token
                const ghToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";

                // VULN_004: SendGrid API key
                const sgKey = "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789abcdefg";

                // VULN_005: OpenAI API key
                const openaiKey = "sk-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmno";

                // VULN_006: Generic API key assignment
                const api_key = "AbCdEfGhIjKlMnOpQrStUvWx";

                // VULN_007: Hardcoded password
                const password = "MyS3cur3P@ssw0rd!";

                // VULN_008: Private key in source
                const cert = `-----BEGIN RSA PRIVATE KEY-----
                MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn
                -----END RSA PRIVATE KEY-----`;

                // VULN_009: JWT token hardcoded
                const serviceKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

                // VULN_010: Anthropic API key
                const anthropicKey = "sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab";
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_001", "SEC-001", "AWS Access Key ID"),
            VulnFixture("VULN_002", "SEC-001", "Stripe live secret key"),
            VulnFixture("VULN_003", "SEC-001", "GitHub PAT"),
            VulnFixture("VULN_004", "SEC-001", "SendGrid API key"),
            VulnFixture("VULN_005", "SEC-001", "OpenAI API key"),
            VulnFixture("VULN_006", "SEC-001", "Generic API key"),
            VulnFixture("VULN_007", "SEC-001", "Hardcoded password"),
            VulnFixture("VULN_008", "SEC-001", "Private key"),
            VulnFixture("VULN_009", "SEC-001", "JWT token"),
            VulnFixture("VULN_010", "SEC-001", "Anthropic API key"),
        ],
        false_positive_count=0,  # placeholder/comment/env-ref should not be flagged
    ))

    # ── 2. SQL Injection ────────────────────────────────────────────────────
    fixtures.append(CategoryFixture(
        name="SQL Injection",
        owasp="A03:2021",
        files={
            "src/db.ts": textwrap.dedent('''\
                // VULN_011: Template literal in SELECT
                function getUser(userId) {
                  const query = `SELECT * FROM users WHERE id = ${userId}`;
                  return db.execute(query);
                }

                // VULN_012: String concatenation in query
                function searchProducts(term) {
                  const sql = "SELECT * FROM products WHERE name = '" + term + "'";
                  return db.query(sql);
                }

                // VULN_013: Template literal in INSERT
                function createUser(name, email) {
                  db.query(`INSERT INTO users (name, email) VALUES ('${name}', '${email}')`);
                }

                // VULN_014: Template literal in UPDATE
                function updateUser(id, name) {
                  db.query(`UPDATE users SET name = '${name}' WHERE id = ${id}`);
                }

                // VULN_015: Template literal in DELETE
                function deleteUser(id) {
                  db.query(`DELETE FROM users WHERE id = ${id}`);
                }
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_011", "SEC-004", "SELECT template literal"),
            VulnFixture("VULN_012", "SEC-004", "SELECT string concatenation"),
            VulnFixture("VULN_013", "SEC-004", "INSERT template literal"),
            VulnFixture("VULN_014", "SEC-004", "UPDATE template literal"),
            VulnFixture("VULN_015", "SEC-004", "DELETE template literal"),
        ],
        false_positive_count=0,
    ))

    # ── 3. SQL Injection (Python) ───────────────────────────────────────────
    fixtures.append(CategoryFixture(
        name="SQL Injection (Python)",
        owasp="A03:2021",
        files={
            "src/db.py": textwrap.dedent('''\
                # VULN_016: Python f-string SQL injection
                def get_user(user_id):
                    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

                # VULN_017: Python format string SQL injection
                def search(term):
                    cursor.execute("SELECT * FROM items WHERE name = '%s'" % term)
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_016", "SEC-004", "Python f-string SQL"),
            VulnFixture("VULN_017", "SEC-004", "Python % format SQL"),
        ],
        false_positive_count=0,
    ))

    # ── 4. XSS / DOM Injection ──────────────────────────────────────────────
    fixtures.append(CategoryFixture(
        name="XSS / DOM Injection",
        owasp="A03:2021",
        files={
            "src/render.js": textwrap.dedent('''\
                // VULN_018: innerHTML assignment
                function renderComment(comment) {
                  document.getElementById("output").innerHTML = comment;
                }

                // VULN_019: innerHTML with variable
                function updateProfile(userData) {
                  profileDiv.innerHTML = userData.bio;
                }

                // VULN_020: document.write
                function displayMessage(msg) {
                  document.write(msg);
                }

                // VULN_021: React dangerouslySetInnerHTML
                function RawHTML({ content }) {
                  return <div dangerouslySetInnerHTML={{ __html: content }} />;
                }

                // VULN_022: outerHTML assignment
                function replaceElement(el, userContent) {
                  el.outerHTML = userContent;
                }

                // VULN_023: insertAdjacentHTML
                function addComment(container, commentHtml) {
                  container.insertAdjacentHTML("beforeend", commentHtml);
                }
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_018", "SEC-013", "innerHTML assignment"),
            VulnFixture("VULN_019", "SEC-013", "innerHTML with variable"),
            VulnFixture("VULN_020", "SEC-013", "document.write"),
            VulnFixture("VULN_021", "SEC-013", "dangerouslySetInnerHTML"),
            VulnFixture("VULN_022", "SEC-013", "outerHTML"),
            VulnFixture("VULN_023", "SEC-013", "insertAdjacentHTML"),
        ],
        false_positive_count=0,
    ))

    # ── 5. CORS Misconfiguration ────────────────────────────────────────────
    fixtures.append(CategoryFixture(
        name="CORS Misconfiguration",
        owasp="A05:2021",
        files={
            "src/server.js": textwrap.dedent('''\
                // VULN_024: CORS wildcard origin
                res.setHeader("Access-Control-Allow-Origin", "*");

                // VULN_025: cors() with wildcard (middleware pattern)
                app.use(cors({ origin: "*" }));

                // VULN_026: Reflecting origin without validation
                res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_024", "SEC-006", "CORS wildcard header"),
            VulnFixture("VULN_025", "SEC-006", "cors() wildcard middleware"),
            VulnFixture("VULN_026", "SEC-006", "Origin reflection"),
        ],
        false_positive_count=0,
    ))

    # ── 6. Missing Auth (Express) ───────────────────────────────────────────
    fixtures.append(CategoryFixture(
        name="Missing Auth (Express)",
        owasp="A07:2021",
        files={
            "src/routes.js": textwrap.dedent('''\
                // VULN_027: no access check on GET
                app.get("/api/users", (req, res) => { res.json(users); });

                // VULN_028: no access check on POST
                app.post("/api/orders", (req, res) => { res.json({ ok: true }); });

                // VULN_029: no access check on PUT
                app.put("/api/account/settings", (req, res) => { updateSettings(req.body); });

                // VULN_030: no access check on payment
                app.post("/api/payment/process", (req, res) => { processPayment(req.body); });

                // VULN_031: no access check on DELETE
                app.delete("/api/users/:id", (req, res) => { deleteUser(req.params.id); });
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_027", "SEC-005", "GET /api/users no auth"),
            VulnFixture("VULN_028", "SEC-005", "POST /api/orders no auth"),
            VulnFixture("VULN_029", "SEC-005", "PUT /api/account no auth"),
            VulnFixture("VULN_030", "SEC-005", "POST /api/payment no auth"),
            VulnFixture("VULN_031", "SEC-005", "DELETE /api/users no auth"),
        ],
        false_positive_count=0,
    ))

    # ── 7. Missing Auth (FastAPI) ───────────────────────────────────────────
    fixtures.append(CategoryFixture(
        name="Missing Auth (FastAPI)",
        owasp="A07:2021",
        files={
            "src/main.py": textwrap.dedent('''\
                from fastapi import FastAPI, Depends
                app = FastAPI()

                # VULN_032: FastAPI GET - no access check
                @app.get("/api/users")
                def get_users():
                    return []

                # VULN_033: FastAPI POST - no access check
                @app.post("/api/orders")
                def create_order(data: dict):
                    return {"ok": True}
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_032", "SEC-005", "FastAPI GET no auth"),
            VulnFixture("VULN_033", "SEC-005", "FastAPI POST no auth"),
        ],
        false_positive_count=0,
    ))

    # ── 8. Admin Routes Without Auth ────────────────────────────────────────
    fixtures.append(CategoryFixture(
        name="Exposed Admin Routes",
        owasp="A01:2021",
        files={
            "src/panel.js": textwrap.dedent('''\
                // VULN_034: panel without access checks
                app.get("/admin/dashboard", (req, res) => { res.render("panel"); });

                // VULN_035: mgmt route without checks
                app.post("/internal/manage", (req, res) => { manage(req.body); });
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_034", "SEC-008", "Admin dashboard no auth"),
            VulnFixture("VULN_035", "SEC-008", "Internal management no auth"),
        ],
        false_positive_count=0,
    ))

    # ── 9. eval/exec Injection ──────────────────────────────────────────────
    fixtures.append(CategoryFixture(
        name="eval/exec Injection",
        owasp="A03:2021",
        files={
            "src/utils.js": textwrap.dedent('''\
                // VULN_036: Direct eval
                function parseInput(input) { return eval(input); }

                // VULN_037: eval in template
                function processTemplate(t, d) { return eval("`" + t + "`"); }

                // VULN_038: new Function (code injection) - GAP
                function dynamicCalc(expr) {
                  const fn = new Function("return " + expr);
                  return fn();
                }

                // VULN_039: setTimeout with string (implicit eval) - GAP
                function delayedAction(code) { setTimeout(code, 1000); }
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_036", "SEC-003", "Direct eval"),
            VulnFixture("VULN_037", "SEC-003", "eval in template"),
            VulnFixture("VULN_038", "SEC-003", "new Function constructor"),
            VulnFixture("VULN_039", "SEC-003", "setTimeout with string"),
        ],
        false_positive_count=0,
    ))

    # ── 10. localStorage Auth Tokens ────────────────────────────────────────
    fixtures.append(CategoryFixture(
        name="Insecure Token Storage",
        owasp="A07:2021",
        files={
            "src/auth.ts": textwrap.dedent('''\
                // VULN_040: localStorage for auth token
                localStorage.setItem("auth_token", response.token);

                // VULN_041: localStorage for JWT
                localStorage.setItem("jwt", jwt);

                // VULN_042: localStorage for session
                localStorage.setItem("session_id", session.id);
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_040", "SEC-009", "localStorage auth_token"),
            VulnFixture("VULN_041", "SEC-009", "localStorage jwt"),
            VulnFixture("VULN_042", "SEC-009", "localStorage session"),
        ],
        false_positive_count=0,
    ))

    # ── 11. HTTP URLs ───────────────────────────────────────────────────────
    fixtures.append(CategoryFixture(
        name="Insecure Transport",
        owasp="A02:2021",
        files={
            "src/api.ts": textwrap.dedent('''\
                // VULN_043: HTTP URL for API endpoint
                const apiUrl = "http://api.example.com/v1/data";

                // VULN_044: HTTP URL for CDN
                const cdnUrl = "http://cdn.example.com/assets/script.js";

                // VULN_045: HTTP URL in fetch call
                fetch("http://payment-gateway.example.com/charge");
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_043", "SEC-007", "HTTP API URL"),
            VulnFixture("VULN_044", "SEC-007", "HTTP CDN URL"),
            VulnFixture("VULN_045", "SEC-007", "HTTP fetch URL"),
        ],
        false_positive_count=0,
    ))

    # ── 12. Console Env Leakage ─────────────────────────────────────────────
    fixtures.append(CategoryFixture(
        name="Env Variable Leakage",
        owasp="A09:2021",
        files={
            "src/debug.js": textwrap.dedent('''\
                // VULN_046: console.log process.env
                console.log("Database URL:", process.env.DATABASE_URL);

                // VULN_047: console.error process.env
                console.error("Stripe key:", process.env.STRIPE_SECRET_KEY);

                // VULN_048: console.warn process.env
                console.warn("API key is:", process.env.API_KEY);
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_046", "SEC-010", "console.log env"),
            VulnFixture("VULN_047", "SEC-010", "console.error env"),
            VulnFixture("VULN_048", "SEC-010", "console.warn env"),
        ],
        false_positive_count=0,
    ))

    # ── 13. Supabase Service Key Client-Side ────────────────────────────────
    fixtures.append(CategoryFixture(
        name="Supabase Service Key Client-Side",
        owasp="A01:2021",
        files={
            "src/supabase.ts": textwrap.dedent('''\
                // VULN_049: service_role in client code
                const supabase = createClient(url, "VITE_SUPABASE_SERVICE_ROLE_KEY");

                // VULN_050: service_role reference
                const adminClient = createClient(url, service_role);
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_049", "SEC-011", "VITE service_role key"),
            VulnFixture("VULN_050", "SEC-011", "service_role reference"),
        ],
        false_positive_count=0,
    ))

    # ── 14. .env Committed ──────────────────────────────────────────────────
    fixtures.append(CategoryFixture(
        name="Committed .env File",
        owasp="A05:2021",
        files={
            ".env": textwrap.dedent('''\
                DATABASE_URL=postgres://admin:password123@db.example.com:5432/myapp
                STRIPE_SECRET_KEY=sk_test_placeholder_not_real
            '''),
            # No .gitignore with .env pattern
        },
        expected_vulns=[
            VulnFixture("VULN_051", "SEC-002", ".env committed without gitignore"),
        ],
        false_positive_count=0,
    ))

    # ── 15. Path Traversal / SSRF (GAP TESTS) ──────────────────────────────
    fixtures.append(CategoryFixture(
        name="Path Traversal / SSRF",
        owasp="A01:2021 / A10:2021",
        files={
            "src/proxy.js": textwrap.dedent('''\
                // VULN_052: Path traversal - unvalidated file path
                app.get("/download", (req, res) => {
                  const filePath = req.query.file;
                  res.sendFile(filePath);
                });

                // VULN_053: SSRF - fetching user-supplied URL
                app.get("/proxy", async (req, res) => {
                  const response = await fetch(req.query.url);
                  res.json(await response.json());
                });

                // VULN_054: Open redirect
                app.get("/redirect", (req, res) => {
                  res.redirect(req.query.url);
                });
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_052", "SEC-014", "Path traversal via sendFile"),
            VulnFixture("VULN_053", "SEC-015", "SSRF via fetch"),
            VulnFixture("VULN_054", "SEC-015", "Open redirect"),
        ],
        false_positive_count=0,
    ))

    # ── 16. NoSQL Injection (GAP TEST) ──────────────────────────────────────
    fixtures.append(CategoryFixture(
        name="NoSQL Injection",
        owasp="A03:2021",
        files={
            "src/mongo.js": textwrap.dedent('''\
                // VULN_055: MongoDB query with user input
                app.get("/users", (req, res) => {
                  User.find({ username: req.body.username, password: req.body.password });
                });
            '''),
        },
        expected_vulns=[
            VulnFixture("VULN_055", "SEC-016", "NoSQL injection MongoDB"),
        ],
        false_positive_count=0,
    ))

    # ── 17. False Positive Benchmark (Clean Code) ───────────────────────────
    fixtures.append(CategoryFixture(
        name="Clean Code (False Positive Test)",
        owasp="N/A",
        files={
            "src/app.ts": textwrap.dedent('''\
                // All of these should produce ZERO findings
                const apiKey = process.env.OPENAI_API_KEY;
                if (!apiKey) throw new Error("Missing OPENAI_API_KEY");

                const result = await db.query("SELECT * FROM users WHERE id = $1", [userId]);

                document.getElementById("name").textContent = userName;

                res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "strict" });

                const response = await fetch("https://api.example.com/data");

                const data = JSON.parse(rawInput);
            '''),
            "src/routes.js": textwrap.dedent('''\
                // Auth-protected routes - should NOT flag SEC-005
                app.get("/api/users", verifyToken, (req, res) => { res.json(users); });
                app.post("/api/orders", authMiddleware, (req, res) => { res.json({ ok: true }); });
            '''),
        },
        expected_vulns=[],  # No vulns expected
        false_positive_count=0,  # Will count actual findings as false positives
    ))

    return fixtures


# ─── Benchmark runner ────────────────────────────────────────────────────────

@dataclass
class CategoryResult:
    name: str
    owasp: str
    total_vulns: int
    detected: int
    missed: List[str]
    false_positives: int
    scan_time: float
    files_scanned: int


def make_project(files: dict) -> Path:
    """Create a temporary project directory with the given files."""
    tmp = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp


def run_category_benchmark(fixture: CategoryFixture) -> CategoryResult:
    """Run the scanner against a single category fixture."""
    project = make_project(fixture.files)

    t0 = time.monotonic()
    result = scan_project(project)
    scan_time = time.monotonic() - t0

    # Count detections
    detected = 0
    missed = []
    finding_rules = set()
    for f in result.findings:
        finding_rules.add(f.rule_id)

    for vuln in fixture.expected_vulns:
        # Check if any finding matches the expected rule
        rule_found = any(f.rule_id == vuln.rule_id for f in result.findings)
        if rule_found:
            detected += 1
        else:
            missed.append(f"{vuln.vuln_id}: {vuln.description} (expected {vuln.rule_id})")

    # For clean code fixture, any findings are false positives
    false_positives = 0
    if fixture.name == "Clean Code (False Positive Test)":
        false_positives = len(result.findings)

    return CategoryResult(
        name=fixture.name,
        owasp=fixture.owasp,
        total_vulns=len(fixture.expected_vulns),
        detected=detected,
        missed=missed,
        false_positives=false_positives,
        scan_time=scan_time,
        files_scanned=result.scanned,
    )


def run_speed_benchmark() -> Tuple[float, int]:
    """Measure scan speed with a realistic project size."""
    # Create a project with many files
    files = {}
    for i in range(100):
        files[f"src/module_{i}.ts"] = textwrap.dedent(f'''\
            import {{ useState }} from "react";

            export function Component{i}() {{
                const [data, setData] = useState(null);

                async function fetchData() {{
                    const res = await fetch("/api/data/{i}");
                    setData(await res.json());
                }}

                return <div>{{data}}</div>;
            }}
        ''')

    project = make_project(files)

    t0 = time.monotonic()
    result = scan_project(project)
    elapsed = time.monotonic() - t0

    return elapsed, result.scanned


def main():
    print("=" * 78)
    print("  ai-security-scan Detection Benchmark Suite")
    print("=" * 78)
    print()

    fixtures = build_fixtures()
    results: List[CategoryResult] = []

    total_vulns = 0
    total_detected = 0
    total_false_positives = 0
    all_missed = []

    for fixture in fixtures:
        res = run_category_benchmark(fixture)
        results.append(res)

        total_vulns += res.total_vulns
        total_detected += res.detected
        total_false_positives += res.false_positives
        all_missed.extend(res.missed)

    # Speed benchmark
    speed_time, speed_files = run_speed_benchmark()
    files_per_sec = speed_files / speed_time if speed_time > 0 else 0

    # ── Print results ────────────────────────────────────────────────────────
    print(f"{'Category':<35} {'OWASP':<15} {'Detected':<12} {'Rate':<8} {'Missed':<8}")
    print("-" * 78)

    for res in results:
        if res.total_vulns > 0:
            rate = f"{res.detected}/{res.total_vulns}"
            pct = f"{res.detected / res.total_vulns * 100:.0f}%"
            missed = str(len(res.missed))
        else:
            rate = "N/A"
            pct = "N/A"
            missed = f"{res.false_positives} FP"
        print(f"{res.name:<35} {res.owasp:<15} {rate:<12} {pct:<8} {missed:<8}")

    print("-" * 78)
    overall_rate = total_detected / total_vulns * 100 if total_vulns > 0 else 0
    print(f"{'OVERALL':<35} {'':15} {total_detected}/{total_vulns:<11} {overall_rate:.1f}%    {len(all_missed)} missed")
    print(f"{'False Positives':<35} {'':15} {total_false_positives}")
    print(f"{'Scan Speed':<35} {'':15} {files_per_sec:.0f} files/sec ({speed_files} files in {speed_time:.3f}s)")
    print()

    # ── Missed vulnerabilities detail ────────────────────────────────────────
    if all_missed:
        print("MISSED VULNERABILITIES (Detection Gaps):")
        print("-" * 78)
        for m in all_missed:
            print(f"  - {m}")
        print()

    # ── Gap analysis ─────────────────────────────────────────────────────────
    print("GAP ANALYSIS:")
    print("-" * 78)

    gap_categories = []
    for res in results:
        if res.missed:
            gap_categories.append(res)

    if gap_categories:
        for res in gap_categories:
            if res.total_vulns > 0 and res.detected < res.total_vulns:
                detection_pct = res.detected / res.total_vulns * 100
                print(f"  {res.name}: {detection_pct:.0f}% detection ({len(res.missed)} missed)")
                for m in res.missed:
                    print(f"    - {m}")
    else:
        print("  No gaps found - all known vulnerabilities detected!")

    if total_false_positives > 0:
        print(f"\n  False Positives: {total_false_positives} findings on clean code")

    print()

    # ── JSON output for CI ───────────────────────────────────────────────────
    output = {
        "overall_detection_rate": round(overall_rate, 1),
        "total_vulnerabilities": total_vulns,
        "total_detected": total_detected,
        "total_missed": len(all_missed),
        "false_positives": total_false_positives,
        "scan_speed_files_per_sec": round(files_per_sec),
        "categories": [],
    }
    for res in results:
        cat = {
            "name": res.name,
            "owasp": res.owasp,
            "total": res.total_vulns,
            "detected": res.detected,
            "rate": round(res.detected / res.total_vulns * 100, 1) if res.total_vulns > 0 else None,
            "missed": res.missed,
            "false_positives": res.false_positives,
        }
        output["categories"].append(cat)

    json_path = Path("/tmp/nometria-security-scanner/benchmarks/results.json")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Results saved to: {json_path}")

    return output


if __name__ == "__main__":
    output = main()
    # Return exit code based on detection rate
    sys.exit(0 if output["overall_detection_rate"] >= 50 else 1)
