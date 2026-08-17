import ast
import re


# =========================================================
# SECURITY SCORING
# =========================================================

SEVERITY_DEDUCTIONS = {
    "CRITICAL": 30,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 2,
}


def calculate_score(issues):
    """
    Calculate a security score from 0-100.
    Higher score = safer code.
    """

    total = sum(
        SEVERITY_DEDUCTIONS.get(
            issue.get("severity", "INFO"),
            0,
        )
        for issue in issues
    )

    return max(
        0,
        100 - min(total, 100),
    )


def get_risk_level(score):
    """Convert security score into a risk level."""

    if score >= 80:
        return "Low Risk"

    if score >= 60:
        return "Medium Risk"

    if score >= 35:
        return "High Risk"

    return "Critical Risk"


def get_security_grade(score):
    """Convert security score into a simple A-F security grade."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def build_security_summary(issues, score):
    """Build a compact professional security summary for the UI."""
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    counts = {severity: 0 for severity in severity_order}
    for issue in issues:
        severity = str(issue.get("severity", "INFO")).upper()
        counts[severity] = counts.get(severity, 0) + 1

    most_dangerous = None
    for severity in severity_order:
        matches = [issue for issue in issues if str(issue.get("severity", "INFO")).upper() == severity]
        if matches:
            most_dangerous = matches[0]
            break

    categories = {}
    for issue in issues:
        owasp = issue.get("owasp", "N/A")
        if owasp and owasp != "N/A":
            categories[owasp] = categories.get(owasp, 0) + 1

    primary_category = max(categories, key=categories.get) if categories else "No major category detected"

    confidences = [
        issue.get("confidence") for issue in issues
        if isinstance(issue.get("confidence"), (int, float))
    ]
    average_confidence = round(sum(confidences) / len(confidences), 1) if confidences else 0

    affected_lines = sorted({
        issue.get("line") for issue in issues
        if isinstance(issue.get("line"), int)
    })

    return {
        "grade": get_security_grade(score),
        "critical": counts.get("CRITICAL", 0),
        "high": counts.get("HIGH", 0),
        "medium": counts.get("MEDIUM", 0),
        "low": counts.get("LOW", 0),
        "info": counts.get("INFO", 0),
        "total": len(issues),
        "most_dangerous": most_dangerous.get("title") if most_dangerous else "No vulnerabilities detected",
        "primary_category": primary_category,
        "average_confidence": average_confidence,
        "affected_lines": affected_lines,
    }


# =========================================================
# FINDING CREATOR
# =========================================================

def make_issue(
    severity,
    title,
    description,
    recommendation,
    line=None,
    cwe=None,
    owasp=None,
    confidence=90,
    evidence=None,
):
    """
    Create a standardized professional security finding.
    """

    return {
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "line": line,
        "cwe": cwe or "N/A",
        "owasp": owasp or "N/A",
        "confidence": confidence,
        "evidence": evidence or "",
    }


# =========================================================
# PYTHON ANALYZER
# =========================================================

class PythonAnalyzer(ast.NodeVisitor):

    def __init__(self, code):
        self.code = code
        self.issues = []

    def add_issue(
        self,
        severity,
        title,
        description,
        recommendation,
        line=None,
        cwe=None,
        owasp=None,
        confidence=90,
        evidence=None,
    ):

        self.issues.append(
            make_issue(
                severity=severity,
                title=title,
                description=description,
                recommendation=recommendation,
                line=line,
                cwe=cwe,
                owasp=owasp,
                confidence=confidence,
                evidence=evidence,
            )
        )

    # -----------------------------------------------------
    # FUNCTION CALLS
    # -----------------------------------------------------

    def visit_Call(self, node):

        # eval()
        if isinstance(node.func, ast.Name):

            if node.func.id == "eval":

                self.add_issue(
                    "CRITICAL",
                    "Unsafe eval() usage",
                    "eval() can execute dynamically supplied Python code.",
                    "Avoid eval(). Use explicit parsing or safer alternatives.",
                    node.lineno,
                    cwe="CWE-95",
                    owasp="A03:2021 – Injection",
                    confidence=99,
                    evidence="eval(...)",
                )

            elif node.func.id == "exec":

                self.add_issue(
                    "CRITICAL",
                    "Unsafe exec() usage",
                    "exec() can execute arbitrary Python code.",
                    "Avoid exec() and use controlled program logic instead.",
                    node.lineno,
                    cwe="CWE-95",
                    owasp="A03:2021 – Injection",
                    confidence=99,
                    evidence="exec(...)",
                )

        # -------------------------------------------------
        # os.system()
        # -------------------------------------------------

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "system"
        ):

            self.add_issue(
                "HIGH",
                "Potentially unsafe os.system()",
                "Shell commands executed through os.system() can become dangerous when user input reaches them.",
                "Prefer subprocess APIs with argument lists and validate user-controlled input.",
                node.lineno,
                cwe="CWE-78",
                owasp="A03:2021 – Injection",
                confidence=96,
                evidence="os.system(...)",
            )

        # -------------------------------------------------
        # subprocess shell=True
        # -------------------------------------------------

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {
                "run",
                "call",
                "Popen",
                "check_output",
                "check_call",
            }
        ):

            for keyword in node.keywords:

                if (
                    keyword.arg == "shell"
                    and isinstance(
                        keyword.value,
                        ast.Constant,
                    )
                    and keyword.value.value is True
                ):

                    self.add_issue(
                        "HIGH",
                        "subprocess shell execution",
                        "shell=True can introduce command injection risks when input is not strictly controlled.",
                        "Avoid shell=True where possible and pass commands as argument lists.",
                        node.lineno,
                        cwe="CWE-78",
                        owasp="A03:2021 – Injection",
                        confidence=95,
                        evidence="shell=True",
                    )

        self.generic_visit(node)

    # -----------------------------------------------------
    # HARDCODED SECRETS
    # -----------------------------------------------------

    def visit_Assign(self, node):

        for target in node.targets:

            if isinstance(target, ast.Name):

                name = target.id.lower()

                secret_words = [
                    "password",
                    "passwd",
                    "secret",
                    "api_key",
                    "apikey",
                    "token",
                    "access_key",
                ]

                if any(
                    word in name
                    for word in secret_words
                ):

                    if (
                        isinstance(
                            node.value,
                            ast.Constant,
                        )
                        and isinstance(
                            node.value.value,
                            str,
                        )
                        and len(node.value.value) >= 4
                    ):

                        self.add_issue(
                            "HIGH",
                            "Possible hardcoded secret",
                            f"The variable '{target.id}' appears to contain a hardcoded credential or secret.",
                            "Move secrets to environment variables or a secure secret manager.",
                            node.lineno,
                            cwe="CWE-798",
                            owasp="A07:2021 – Identification and Authentication Failures",
                            confidence=94,
                            evidence=f"{target.id} = \"...\"",
                        )

        self.generic_visit(node)

    # -----------------------------------------------------
    # SQL INJECTION
    # -----------------------------------------------------

    def visit_BinOp(self, node):

        if isinstance(
            node.op,
            (
                ast.Add,
                ast.Mod,
            ),
        ):

            try:
                source = ast.unparse(node)
            except Exception:
                source = ""

            sql_words = [
                "select ",
                "insert ",
                "update ",
                "delete ",
                " from ",
                " where ",
            ]

            if any(
                word in source.lower()
                for word in sql_words
            ):

                self.add_issue(
                    "HIGH",
                    "Potential SQL injection pattern",
                    "SQL statements appear to be constructed dynamically.",
                    "Use parameterized queries instead of string concatenation.",
                    node.lineno,
                    cwe="CWE-89",
                    owasp="A03:2021 – Injection",
                    confidence=91,
                    evidence=source[:120],
                )

        self.generic_visit(node)


def analyze_python(code):
    """Analyze Python code."""

    if not code.strip():

        return {
            "language": "Python",
            "score": 0,
            "risk": "Unknown",
            "issues": [],
            "summary": build_security_summary([], 0),
            "error": "No code provided.",
        }

    issues = []

    try:

        tree = ast.parse(code)

        analyzer = PythonAnalyzer(code)

        analyzer.visit(tree)

        issues = analyzer.issues

    except SyntaxError as error:

        issues.append(
            make_issue(
                "MEDIUM",
                "Python syntax error",
                str(error),
                "Fix the syntax error before running the code.",
                error.lineno,
                cwe="CWE-116",
                owasp="A05:2021 – Security Misconfiguration",
                confidence=99,
                evidence=str(error),
            )
        )

    score = calculate_score(
        issues
    )

    return {
        "language": "Python",
        "score": score,
        "risk": get_risk_level(score),
        "issues": issues,
        "summary": build_security_summary(issues, score),
    }


# =========================================================
# HTML ANALYZER
# =========================================================

def analyze_html(code):
    """Analyze HTML for common security warning signs."""

    if not code.strip():

        return {
            "language": "HTML",
            "score": 0,
            "risk": "Unknown",
            "issues": [],
            "summary": build_security_summary([], 0),
        }

    issues = []

    # -----------------------------------------------------
    # INLINE JAVASCRIPT
    # -----------------------------------------------------

    inline_script_pattern = re.compile(
        r"<script[^>]*>.*?</script>",
        re.IGNORECASE | re.DOTALL,
    )

    for match in inline_script_pattern.finditer(code):

        line = (
            code[:match.start()].count("\n")
            + 1
        )

        issues.append(
            make_issue(
                "MEDIUM",
                "Inline JavaScript detected",
                "JavaScript is embedded directly inside the HTML document.",
                "Prefer external JavaScript files and apply a restrictive Content Security Policy.",
                line,
                cwe="CWE-79",
                owasp="A03:2021 – Injection",
                confidence=92,
                evidence="<script>...</script>",
            )
        )

    # -----------------------------------------------------
    # INLINE EVENT HANDLERS
    # -----------------------------------------------------

    event_pattern = re.compile(
        r"\bon[a-z]+\s*=",
        re.IGNORECASE,
    )

    for match in event_pattern.finditer(code):

        line = (
            code[:match.start()].count("\n")
            + 1
        )

        issues.append(
            make_issue(
                "MEDIUM",
                "Inline event handler detected",
                "Inline event handlers can make security policies and code auditing harder.",
                "Use external JavaScript event listeners instead.",
                line,
                cwe="CWE-79",
                owasp="A03:2021 – Injection",
                confidence=93,
                evidence=match.group(0),
            )
        )

    # -----------------------------------------------------
    # JAVASCRIPT URL
    # -----------------------------------------------------

    javascript_url_pattern = re.compile(
        r"(href|src)\s*=\s*[\"']\s*javascript:",
        re.IGNORECASE,
    )

    for match in javascript_url_pattern.finditer(code):

        line = (
            code[:match.start()].count("\n")
            + 1
        )

        issues.append(
            make_issue(
                "HIGH",
                "javascript: URL detected",
                "A javascript: URL can execute code directly from an HTML attribute.",
                "Avoid javascript: URLs and use normal JavaScript event handlers.",
                line,
                cwe="CWE-79",
                owasp="A03:2021 – Injection",
                confidence=98,
                evidence=match.group(0),
            )
        )

    # -----------------------------------------------------
    # IFRAME
    # -----------------------------------------------------

    iframe_pattern = re.compile(
        r"<iframe\b",
        re.IGNORECASE,
    )

    for match in iframe_pattern.finditer(code):

        line = (
            code[:match.start()].count("\n")
            + 1
        )

        issues.append(
            make_issue(
                "LOW",
                "External iframe detected",
                "Embedded frames can introduce third-party content and tracking risks.",
                "Only embed trusted sources and consider sandbox restrictions.",
                line,
                cwe="CWE-829",
                owasp="A05:2021 – Security Misconfiguration",
                confidence=88,
                evidence="<iframe>",
            )
        )

    # -----------------------------------------------------
    # TARGET BLANK WITHOUT NOOPENER
    # -----------------------------------------------------

    target_blank_pattern = re.compile(
        r'target\s*=\s*["\']_blank["\']',
        re.IGNORECASE,
    )

    for match in target_blank_pattern.finditer(code):

        line = (
            code[:match.start()].count("\n")
            + 1
        )

        nearby = code[
            max(0, match.start() - 200):
            match.end() + 200
        ]

        if "noopener" not in nearby.lower():

            issues.append(
                make_issue(
                    "LOW",
                    "Potential reverse tabnabbing risk",
                    "A target=_blank link does not appear to use rel=noopener.",
                    "Add rel=\"noopener noreferrer\" to external target=_blank links.",
                    line,
                    cwe="CWE-1022",
                    owasp="A05:2021 – Security Misconfiguration",
                    confidence=90,
                    evidence='target="_blank"',
                )
            )

    score = calculate_score(
        issues
    )

    return {
        "language": "HTML",
        "score": score,
        "risk": get_risk_level(score),
        "issues": issues,
        "summary": build_security_summary(issues, score),
    }


# =========================================================
# JAVASCRIPT ANALYZER
# =========================================================

def analyze_javascript(code):
    """Analyze JavaScript for common security warning signs."""

    if not code.strip():

        return {
            "language": "JavaScript",
            "score": 0,
            "risk": "Unknown",
            "issues": [],
            "summary": build_security_summary([], 0),
        }

    issues = []

    patterns = [

        (
            r"\beval\s*\(",
            "CRITICAL",
            "Unsafe eval() usage",
            "eval() can execute dynamically generated JavaScript.",
            "Avoid eval() and use safer explicit program logic.",
            "CWE-95",
            "A03:2021 – Injection",
            99,
        ),

        (
            r"\bdocument\.write\s*\(",
            "HIGH",
            "document.write() detected",
            "document.write() can create unsafe DOM behavior and complicate content security.",
            "Use safe DOM APIs such as createElement() and textContent.",
            "CWE-79",
            "A03:2021 – Injection",
            96,
        ),

        (
            r"\.innerHTML\s*=",
            "HIGH",
            "innerHTML assignment detected",
            "Assigning untrusted content to innerHTML can create XSS vulnerabilities.",
            "Prefer textContent or sanitize trusted HTML before insertion.",
            "CWE-79",
            "A03:2021 – Injection",
            95,
        ),

        (
            r"\.outerHTML\s*=",
            "HIGH",
            "outerHTML assignment detected",
            "Dynamic HTML insertion can introduce cross-site scripting risks.",
            "Prefer safe DOM APIs or properly sanitize content.",
            "CWE-79",
            "A03:2021 – Injection",
            94,
        ),

        (
            r"setTimeout\s*\(\s*[\"']",
            "MEDIUM",
            "String-based setTimeout() detected",
            "String-based timer execution behaves similarly to dynamic code execution.",
            "Pass a function instead of a string.",
            "CWE-95",
            "A03:2021 – Injection",
            93,
        ),

        (
            r"setInterval\s*\(\s*[\"']",
            "MEDIUM",
            "String-based setInterval() detected",
            "String-based interval execution can execute dynamic code.",
            "Pass a function instead of a string.",
            "CWE-95",
            "A03:2021 – Injection",
            93,
        ),

        (
            r"localStorage\.setItem\s*\(",
            "LOW",
            "localStorage usage detected",
            "Sensitive information stored in localStorage may be accessible to JavaScript running on the page.",
            "Avoid storing passwords, tokens, or sensitive credentials in localStorage.",
            "CWE-922",
            "A02:2021 – Cryptographic Failures",
            80,
        ),
    ]

    for (
        pattern,
        severity,
        title,
        description,
        recommendation,
        cwe,
        owasp,
        confidence,
    ) in patterns:

        for match in re.finditer(
            pattern,
            code,
            re.IGNORECASE,
        ):

            line = (
                code[:match.start()].count("\n")
                + 1
            )

            issues.append(
                make_issue(
                    severity,
                    title,
                    description,
                    recommendation,
                    line,
                    cwe=cwe,
                    owasp=owasp,
                    confidence=confidence,
                    evidence=match.group(0),
                )
            )

    # -----------------------------------------------------
    # HARDCODED SECRETS
    # -----------------------------------------------------

    secret_pattern = re.compile(
        r"""
        (api[_-]?key|apikey|password|passwd|secret|token)
        \s*[:=]\s*
        ["'][^"']{4,}["']
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    for match in secret_pattern.finditer(code):

        line = (
            code[:match.start()].count("\n")
            + 1
        )

        issues.append(
            make_issue(
                "HIGH",
                "Possible hardcoded secret",
                "A variable appears to contain a hardcoded credential or secret.",
                "Move secrets to environment variables or a secure secret manager.",
                line,
                cwe="CWE-798",
                owasp="A07:2021 – Identification and Authentication Failures",
                confidence=94,
                evidence="Hardcoded credential pattern",
            )
        )

    # -----------------------------------------------------
    # URL HANDLING
    # -----------------------------------------------------

    if (
        "location.href" in code.lower()
        and (
            "location.search" in code.lower()
            or "location.hash" in code.lower()
        )
    ):

        issues.append(
            make_issue(
                "MEDIUM",
                "Potentially unsafe URL handling",
                "User-controlled URL components appear to influence navigation.",
                "Validate and allowlist destinations before navigation.",
                cwe="CWE-601",
                owasp="A10:2021 – Server-Side Request Forgery",
                confidence=82,
                evidence="location.href + location.search/hash",
            )
        )

    score = calculate_score(
        issues
    )

    return {
        "language": "JavaScript",
        "score": score,
        "risk": get_risk_level(score),
        "issues": issues,
        "summary": build_security_summary(issues, score),
    }


# =========================================================
# UNIFIED ANALYZER
# =========================================================

def analyze_code(
    code,
    language,
):
    """
    Main entry point for CodeGuard AI.
    """

    language = language.lower().strip()

    if language == "python":

        return analyze_python(
            code
        )

    if language == "html":

        return analyze_html(
            code
        )

    if language in [
        "javascript",
        "js",
    ]:

        return analyze_javascript(
            code
        )

    return {
        "language": language,
        "score": 0,
        "risk": "Unknown",
        "issues": [],
        "summary": build_security_summary([], 0),
        "error": "Unsupported language.",
    }