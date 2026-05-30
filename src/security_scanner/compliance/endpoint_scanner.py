"""
endpoint_scanner.py - AST-based FastAPI endpoint vulnerability mapper.

Parses Python source files with AST to identify every route handler,
then cross-references it with the scan findings to produce a per-endpoint
vulnerability report.

Usage:
    from security_scanner.compliance.endpoint_scanner import EndpointScanner
    from pathlib import Path

    scanner = EndpointScanner()
    endpoints = scanner.scan_files([Path("server/main.py"), Path("api/app.py")])
    for ep in endpoints:
        print(ep.method, ep.path, ep.vulnerabilities)
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from security_scanner.compliance.rules.base import Finding


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class EndpointParam:
    """A single parameter in a route handler function signature."""
    name: str
    annotation: str          # Type annotation as string, e.g. 'dict', 'ExtractRequest'
    has_body: bool = False   # True if it uses Body(...)
    is_pydantic: bool = False  # True if annotation is a BaseModel subclass name
    is_depends: bool = False  # True if it uses Depends(...)
    default_repr: str = ""


@dataclass
class EndpointInfo:
    """
    A single discovered API endpoint with its security metadata.

    Attributes:
        method:       HTTP verb (GET, POST, PUT, DELETE, PATCH)
        path:         Route path string, e.g. '/extract_file'
        handler:      Python function name
        file_path:    Absolute path to the source file
        line_number:  Line of the route decorator
        params:       Parsed parameters from the handler signature
        has_auth:     True when a Depends() auth guard was found
        has_rate_limit: True when a rate-limit dependency/decorator was found
        raw_dict_body: True when any parameter is typed as plain dict
        exposes_error_detail: True when the handler returns str(e) directly
        findings:     Cross-referenced Finding objects from the main scanner
    """
    method: str
    path: str
    handler: str
    file_path: Path
    line_number: int
    params: List[EndpointParam] = field(default_factory=list)
    has_auth: bool = False
    has_rate_limit: bool = False
    raw_dict_body: bool = False
    exposes_error_detail: bool = False
    findings: List[Finding] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        """Overall risk level for this endpoint based on findings."""
        from security_scanner.compliance.config import Severity
        severities = [f.severity for f in self.findings]
        if Severity.CRITICAL in severities:
            return "CRITICAL"
        if Severity.HIGH in severities:
            return "HIGH"
        if Severity.MEDIUM in severities:
            return "MEDIUM"
        if Severity.LOW in severities:
            return "LOW"
        return "CLEAN"

    @property
    def vulnerability_summary(self) -> List[str]:
        """Human-readable list of vulnerability descriptions for this endpoint."""
        issues = []
        if not self.has_auth:
            issues.append("❌ No authentication - endpoint is publicly accessible")
        if self.raw_dict_body:
            issues.append("❌ Raw dict body - no input schema validation (SI-10)")
        if not self.has_rate_limit:
            issues.append("⚠️  No rate limiting - susceptible to brute-force/DoS")
        if self.exposes_error_detail:
            issues.append("⚠️  May expose internal error details in HTTP response")
        for f in self.findings:
            issues.append(f"🔍 [{f.rule_id}] {f.title}")
        if not issues:
            issues.append("✅ No issues detected")
        return issues


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------

# Patterns recognised as authentication Depends()
_AUTH_DEPENDS_NAMES = re.compile(
    r'get_current_user|require_auth|authenticated|jwt_required|login_required'
    r'|oauth2_scheme|bearer_token|verify_token|check_auth|auth_required'
    r'|get_user|current_user|user_auth',
    re.IGNORECASE,
)

# Patterns recognised as rate-limit decorators or dependencies
_RATE_LIMIT_NAMES = re.compile(
    r'RateLimiter|rate_limit|limiter|slowapi|Throttle|throttle|RateLimit',
    re.IGNORECASE,
)

# Patterns that indicate a raw dict body
_DICT_BODY_TYPES = {"dict", "Dict", "typing.Dict", "Any"}

# Pydantic BaseModel subclass indicators (heuristic: CamelCase names that
# are NOT standard FastAPI types)
_STANDARD_FASTAPI_TYPES = {
    "str", "int", "float", "bool", "bytes", "list", "tuple", "set",
    "List", "Optional", "Union", "Any", "Request", "Response",
    "UploadFile", "File", "Form", "Header", "Cookie", "Query", "Path",
    "BackgroundTasks", "HTTPException", "dict", "Dict",
}

# Route decorator methods
_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}

# Pattern for returning raw error details
_ERROR_DETAIL_PATTERN = re.compile(
    r'detail\s*=\s*(str\(e\)|str\(err\)|str\(ex\)|f".*\{e\}|f\'.*\{e\}'
    r'|e\.args|e\.message|str\(exception\))',
    re.IGNORECASE,
)


class _RouteVisitor(ast.NodeVisitor):
    """
    AST visitor that collects FastAPI route decorators and their handler info.

    Handles:
    - @app.get("/path")  @app.post("/path")  etc.
    - @router.get("/path")  (sub-routers)
    """

    def __init__(self, source_lines: List[str], file_path: Path):
        self.source_lines = source_lines
        self.file_path = file_path
        self.endpoints: List[EndpointInfo] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            route_info = self._extract_route_info(decorator)
            if route_info is None:
                continue

            method, path, deco_line = route_info
            params = self._extract_params(node)
            has_auth = self._check_has_auth(params, node)
            has_rate_limit = self._check_has_rate_limit(decorator, node)
            raw_dict_body = any(p.raw_dict_body_detected for p in params)
            exposes_error = self._check_exposes_error(node)

            self.endpoints.append(EndpointInfo(
                method=method,
                path=path,
                handler=node.name,
                file_path=self.file_path,
                line_number=deco_line,
                params=params,
                has_auth=has_auth,
                has_rate_limit=has_rate_limit,
                raw_dict_body=raw_dict_body,
                exposes_error_detail=exposes_error,
            ))

    def _extract_route_info(
        self, decorator: ast.expr
    ) -> Optional[tuple[str, str, int]]:
        """
        Return (METHOD, path_string, line_number) if this decorator is a
        route decorator like @app.get("/foo") or @router.post("/bar").
        Return None if it is not a route decorator.
        """
        if not isinstance(decorator, ast.Call):
            return None

        func = decorator.func
        if not isinstance(func, ast.Attribute):
            return None

        method_name = func.attr.lower()
        if method_name not in _HTTP_METHODS:
            return None

        # Extract the path string (first positional arg)
        path = "/"
        if decorator.args:
            first_arg = decorator.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                path = first_arg.value
        else:
            # Check keyword args
            for kw in decorator.keywords:
                if kw.arg == "path" and isinstance(kw.value, ast.Constant):
                    path = kw.value.value
                    break

        return method_name.upper(), path, decorator.lineno

    def _extract_params(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> List[_Param]:
        """Parse the function signature into _Param objects."""
        params = []
        args = node.args

        all_args = list(args.args)

        # Collect defaults (right-aligned)
        defaults = args.defaults
        offset = len(all_args) - len(defaults)

        for i, arg in enumerate(all_args):
            annotation_str = self._annotation_to_str(arg.annotation)
            default_repr = ""
            default_idx = i - offset
            if default_idx >= 0 and default_idx < len(defaults):
                default_repr = ast.unparse(defaults[default_idx])

            is_body = "Body(" in default_repr or ": dict" in annotation_str
            is_depends = "Depends(" in default_repr
            raw_detected = annotation_str in _DICT_BODY_TYPES and is_body

            # Heuristic: if annotation is CamelCase and not a standard type → Pydantic
            is_pydantic = (
                annotation_str not in _STANDARD_FASTAPI_TYPES
                and annotation_str
                and annotation_str[0].isupper()
                and not is_depends
            )

            params.append(_Param(
                name=arg.arg,
                annotation=annotation_str,
                has_body=is_body,
                is_pydantic=is_pydantic,
                is_depends=is_depends,
                default_repr=default_repr,
                raw_dict_body_detected=raw_detected,
            ))

        return params

    def _annotation_to_str(self, annotation: Optional[ast.expr]) -> str:
        if annotation is None:
            return ""
        try:
            return ast.unparse(annotation)
        except Exception:
            return ""

    def _check_has_auth(
        self,
        params: List[_Param],
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        """True when any Depends() param matches an auth pattern."""
        for p in params:
            if p.is_depends and _AUTH_DEPENDS_NAMES.search(p.default_repr):
                return True
        # Also do a text search in the raw source lines for this function
        func_src = "\n".join(self.source_lines[node.lineno - 1: node.end_lineno])
        return bool(_AUTH_DEPENDS_NAMES.search(func_src))

    def _check_has_rate_limit(
        self,
        decorator: ast.expr,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        """True when a rate-limit decorator or dependency is present."""
        func_src = "\n".join(self.source_lines[node.lineno - 1: node.end_lineno])
        return bool(_RATE_LIMIT_NAMES.search(func_src))

    def _check_exposes_error(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        """True when the handler body contains `detail=str(e)` patterns."""
        func_src = "\n".join(self.source_lines[node.lineno - 1: node.end_lineno])
        return bool(_ERROR_DETAIL_PATTERN.search(func_src))


@dataclass
class _Param:
    """Internal representation of a handler parameter."""
    name: str
    annotation: str
    has_body: bool
    is_pydantic: bool
    is_depends: bool
    default_repr: str
    raw_dict_body_detected: bool


# Convert _Param to public EndpointParam
def _to_endpoint_param(p: _Param) -> EndpointParam:
    return EndpointParam(
        name=p.name,
        annotation=p.annotation,
        has_body=p.has_body,
        is_pydantic=p.is_pydantic,
        is_depends=p.is_depends,
        default_repr=p.default_repr,
    )


# ---------------------------------------------------------------------------
# Public scanner class
# ---------------------------------------------------------------------------

class EndpointScanner:
    """
    Scans Python source files to build a per-endpoint vulnerability map.

    Example:
        scanner = EndpointScanner()
        endpoints = scanner.scan_files([Path("server/main.py")])
        for ep in endpoints:
            print(ep.method, ep.path, ep.risk_level)
    """

    def scan_files(self, file_paths: List[Path]) -> List[EndpointInfo]:
        """
        Scan multiple Python files and return all discovered endpoints,
        sorted by file then line number.
        """
        all_endpoints: List[EndpointInfo] = []
        for path in file_paths:
            all_endpoints.extend(self._scan_file(path))
        all_endpoints.sort(key=lambda e: (str(e.file_path), e.line_number))
        return all_endpoints

    def correlate_findings(
        self,
        endpoints: List[EndpointInfo],
        findings: List[Finding],
    ) -> List[EndpointInfo]:
        """
        Associate scan findings with endpoints by proximity (file + line range).

        A finding is attached to an endpoint when:
        - It is in the same file, AND
        - Its line_number falls within [endpoint.line_number, next_endpoint.line_number)
        """
        # Group findings by file
        findings_by_file: Dict[Path, List[Finding]] = {}
        for f in findings:
            findings_by_file.setdefault(f.file_path, []).append(f)

        # Group endpoints by file
        endpoints_by_file: Dict[Path, List[EndpointInfo]] = {}
        for ep in endpoints:
            endpoints_by_file.setdefault(ep.file_path, []).append(ep)

        for file_path, file_endpoints in endpoints_by_file.items():
            file_findings = findings_by_file.get(file_path, [])
            # Sort by line
            file_endpoints.sort(key=lambda e: e.line_number)

            for idx, ep in enumerate(file_endpoints):
                end_line = (
                    file_endpoints[idx + 1].line_number
                    if idx + 1 < len(file_endpoints)
                    else float("inf")
                )
                for finding in file_findings:
                    if ep.line_number <= finding.line_number < end_line:
                        ep.findings.append(finding)

            # File-level findings (line 0 or 1) → attach to first endpoint
            if file_endpoints:
                for finding in file_findings:
                    if finding.line_number <= file_endpoints[0].line_number:
                        if finding not in file_endpoints[0].findings:
                            file_endpoints[0].findings.append(finding)

        return endpoints

    def _scan_file(self, file_path: Path) -> List[EndpointInfo]:
        """Parse a single Python file and extract endpoint info."""
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
            source_lines = source.splitlines()
        except (SyntaxError, OSError):
            return []

        visitor = _RouteVisitor(source_lines, file_path)
        visitor.visit(tree)

        # Convert internal _Param → public EndpointParam
        for ep in visitor.endpoints:
            ep.params = [_to_endpoint_param(p) for p in ep.params]

        return visitor.endpoints


# ---------------------------------------------------------------------------
# Deno / JavaScript endpoint scanner
# ---------------------------------------------------------------------------

# Patterns that indicate authentication is checked in a Deno/JS handler
_JS_AUTH_PATTERNS = re.compile(
    r'auth\.me\(\)|base44\.auth|createClientFromRequest|getUser\(\)'
    r'|verifyToken|checkAuth|isAuthenticated|req\.user|currentUser',
    re.IGNORECASE,
)

# Patterns that indicate a 401/403 guard is present
_JS_AUTHZ_RETURN = re.compile(
    r"return\s+Response\.json\s*\(\s*\{[^}]*error[^}]*\}\s*,\s*\{\s*status\s*:\s*40[13]",
    re.IGNORECASE,
)

# Patterns for input validation
_JS_NO_VALIDATION = re.compile(
    r'await\s+req\.json\(\)',  # raw JSON parse with no schema
    re.IGNORECASE,
)

_JS_HAS_VALIDATION = re.compile(
    r'zod|z\.object|schema\.parse|validate\(|ajv|yup|joi',
    re.IGNORECASE,
)

# Rate limiting patterns
_JS_RATE_LIMIT = re.compile(
    r'rateLimit|rate_limit|throttle|slowDown|RateLimiter',
    re.IGNORECASE,
)

# Error detail exposure
_JS_ERROR_DETAIL = re.compile(
    r'error\.message|err\.message|e\.message|exception\.message'
    r'|Response\.json\(\{[^}]*error\s*:\s*error\b',
    re.IGNORECASE,
)

# VITE_ secret in Deno context
_JS_VITE_SECRET = re.compile(
    r'Deno\.env\.get\(["\']VITE_SUPABASE_SERVICE_ROLE_KEY["\']',
)

# Sentry / logging / console-only
_JS_CONSOLE_ONLY = re.compile(r'console\.(log|error|warn)\(', re.IGNORECASE)


@dataclass
class DenoEndpointInfo:
    """
    A single Deno function endpoint derived from the src/functions/ directory.

    Each .js file in src/functions/ that exports a handler is treated as
    one endpoint routed at the file-name-derived path.
    """
    function_name: str          # e.g. "extractFile"
    handler_export: str         # e.g. "extractFileHandler"
    file_path: Path
    route_path: str             # e.g. "/extract_file"  (derived from filename)
    has_auth: bool = False
    has_authz_guard: bool = False  # 401/403 early-return present
    has_schema_validation: bool = False
    has_rate_limit: bool = False
    exposes_error_detail: bool = False
    uses_vite_service_key: bool = False
    uses_console_log_only: bool = False
    findings: List[Finding] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        from security_scanner.compliance.config import Severity
        severities = [f.severity for f in self.findings]
        if not self.has_auth and not self.has_authz_guard:
            severities.append(Severity.HIGH)
        if self.uses_vite_service_key:
            severities.append(Severity.MEDIUM)
        if Severity.CRITICAL in severities:
            return "CRITICAL"
        if Severity.HIGH in severities:
            return "HIGH"
        if Severity.MEDIUM in severities:
            return "MEDIUM"
        if Severity.LOW in severities:
            return "LOW"
        return "CLEAN"

    @property
    def vulnerability_summary(self) -> List[str]:
        issues = []
        if not self.has_auth and not self.has_authz_guard:
            issues.append("❌ No authentication check - function is publicly callable")
        elif self.has_auth and not self.has_authz_guard:
            issues.append("⚠️  Auth client initialised but no 401/403 early-return guard found")
        if not self.has_schema_validation:
            issues.append("⚠️  No schema validation - req.json() parsed without type checking")
        if not self.has_rate_limit:
            issues.append("⚠️  No rate limiting")
        if self.exposes_error_detail:
            issues.append("⚠️  error.message may leak internal details in HTTP response")
        if self.uses_vite_service_key:
            issues.append(
                "🔑 Reads VITE_SUPABASE_SERVICE_ROLE_KEY - acceptable server-side "
                "but env var name is misleading (FEDRAMP-001 context)"
            )
        if self.uses_console_log_only:
            issues.append("📋 Uses console.log() only - no structured audit logging (AU-2)")
        for f in self.findings:
            issues.append(f"🔍 [{f.rule_id}] {f.title}")
        if not issues:
            issues.append("✅ No issues detected")
        return issues


def _function_name_to_route(filename: str) -> str:
    """
    Convert a camelCase filename to a kebab-case route path.
    e.g. "extractFile" → "/extract-file", "invokeLLM" → "/invoke-llm"
    """
    name = Path(filename).stem  # remove .js
    # Insert hyphen before each uppercase letter sequence
    route = re.sub(r'(?<=[a-z])([A-Z])', r'-\1', name)
    route = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1-\2', route)
    return "/" + route.lower()


class DenoEndpointScanner:
    """
    Scans a directory of Deno function files (src/functions/*.js) to
    build a per-function vulnerability map.

    Each exported *Handler function is treated as one HTTP endpoint.

    Usage:
        scanner = DenoEndpointScanner()
        endpoints = scanner.scan_directory(Path("base44-downloader/src/functions"))
        for ep in endpoints:
            print(ep.route_path, ep.risk_level)
            for vuln in ep.vulnerability_summary:
                print(" ", vuln)
    """

    # Skip utility/helper files that don't define HTTP endpoints
    _SKIP_FILES = frozenset({"server.js", "githubToken.js", "billingLinkToken.js"})

    # Export pattern: `export async function fooHandler(req) {`
    _HANDLER_EXPORT = re.compile(
        r'export\s+(?:async\s+)?function\s+(\w+Handler)\s*\(',
    )

    def scan_directory(self, functions_dir: Path) -> List[DenoEndpointInfo]:
        """
        Scan all .js files in functions_dir (non-recursive) and return
        endpoint info sorted by function name.
        """
        if not functions_dir.exists():
            return []
        results: List[DenoEndpointInfo] = []
        for js_file in sorted(functions_dir.glob("*.js")):
            if js_file.name in self._SKIP_FILES:
                continue
            info = self._scan_file(js_file)
            if info is not None:
                results.append(info)
        return results

    def scan_files(self, file_paths: List[Path]) -> List[DenoEndpointInfo]:
        """Scan an explicit list of JS files."""
        results = []
        for p in file_paths:
            info = self._scan_file(p)
            if info is not None:
                results.append(info)
        return results

    def correlate_findings(
        self,
        endpoints: List[DenoEndpointInfo],
        findings: List[Finding],
    ) -> List[DenoEndpointInfo]:
        """Attach security findings to the endpoint from the same file."""
        findings_by_file: Dict[Path, List[Finding]] = {}
        for f in findings:
            findings_by_file.setdefault(f.file_path, []).append(f)
        for ep in endpoints:
            ep.findings = findings_by_file.get(ep.file_path, [])
        return endpoints

    def _scan_file(self, file_path: Path) -> Optional[DenoEndpointInfo]:
        """Parse a single .js Deno function file."""
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        # Must export a handler to be an endpoint
        handler_match = self._HANDLER_EXPORT.search(source)
        if not handler_match:
            return None

        handler_name = handler_match.group(1)
        # Derive the function name (strip "Handler" suffix)
        function_name = re.sub(r"Handler$", "", handler_name)

        return DenoEndpointInfo(
            function_name=function_name,
            handler_export=handler_name,
            file_path=file_path,
            route_path=_function_name_to_route(file_path.name),
            has_auth=bool(_JS_AUTH_PATTERNS.search(source)),
            has_authz_guard=bool(_JS_AUTHZ_RETURN.search(source)),
            has_schema_validation=bool(_JS_HAS_VALIDATION.search(source)),
            has_rate_limit=bool(_JS_RATE_LIMIT.search(source)),
            exposes_error_detail=bool(_JS_ERROR_DETAIL.search(source)),
            uses_vite_service_key=bool(_JS_VITE_SECRET.search(source)),
            uses_console_log_only=(
                bool(_JS_CONSOLE_ONLY.search(source))
                and not bool(re.search(r'logger\.|log4|winston|pino|structlog', source))
            ),
        )
