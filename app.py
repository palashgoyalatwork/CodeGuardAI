from datetime import datetime
import streamlit as st
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from analyzer import analyze_code


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="CodeGuard AI | Code Security Analyzer",
    page_icon="🛡️",
    layout="wide",
)


# =========================================================
# SESSION STATE
# =========================================================

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None

if "analysis_language" not in st.session_state:
    st.session_state.analysis_language = None

if "baseline_result" not in st.session_state:
    st.session_state.baseline_result = None

if "baseline_language" not in st.session_state:
    st.session_state.baseline_language = None

if "rescan_result" not in st.session_state:
    st.session_state.rescan_result = None

if "rescan_language" not in st.session_state:
    st.session_state.rescan_language = None


# =========================================================
# CSS
# =========================================================

st.markdown(
    """
    <style>

    .block-container {
        max-width: 1250px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    .hero-title {
        font-size: 3rem;
        font-weight: 800;
        margin-bottom: 0.2rem;
    }

    .hero-subtitle {
        font-size: 1.05rem;
        opacity: 0.7;
        margin-bottom: 1.5rem;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# CONSTANTS
# =========================================================

LANGUAGES = {
    "🐍 Python": "Python",
    "🌐 HTML": "HTML",
    "⚡ JavaScript": "JavaScript",
}


EXAMPLES = {

    "Python": """import os

password = "admin123"

user_input = input("Command: ")

os.system(user_input)

result = eval(user_input)
""",

    "HTML": """<!DOCTYPE html>

<html>

<head>
    <title>User Profile</title>
</head>

<body>

    <h1>Welcome</h1>

    <button onclick="alert('Hello')">
        Click Me
    </button>

    <a href="javascript:alert('XSS')">
        Open
    </a>

    <iframe src="https://example.com"></iframe>

</body>

</html>
""",

    "JavaScript": """const password = "admin123";

const userInput = location.hash;

eval(userInput);

document.getElementById("output").innerHTML = userInput;

document.write(userInput);

localStorage.setItem("token", password);
""",
}


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def get_risk_icon(risk):

    if risk == "Low Risk":
        return "🟢"

    if risk == "Medium Risk":
        return "🟠"

    if risk == "High Risk":
        return "🔴"

    if risk == "Critical Risk":
        return "🚨"

    return "⚪"


def get_severity_count(issues, severity):

    return sum(
        1
        for issue in issues
        if issue["severity"] == severity
    )


def get_security_metadata(issue):
    """Map detected issue patterns to common security standards."""
    title = str(issue.get("title", "")).lower()
    description = str(issue.get("description", "")).lower()
    combined = f"{title} {description}"

    if "hardcoded" in combined or "hard-coded" in combined or "secret" in combined:
        return {
            "cwe": "CWE-798",
            "cwe_name": "Use of Hard-coded Credentials",
            "owasp": "A07:2021",
            "owasp_name": "Identification and Authentication Failures",
            "confidence": "95%",
        }

    if "eval" in combined:
        return {
            "cwe": "CWE-95",
            "cwe_name": "Improper Neutralization of Directives in Dynamically Evaluated Code",
            "owasp": "A03:2021",
            "owasp_name": "Injection",
            "confidence": "98%",
        }

    if "os.system" in combined or "shell execution" in combined or "shell=true" in combined:
        return {
            "cwe": "CWE-78",
            "cwe_name": "OS Command Injection",
            "owasp": "A03:2021",
            "owasp_name": "Injection",
            "confidence": "96%",
        }

    if "sql injection" in combined or "sql statements" in combined:
        return {
            "cwe": "CWE-89",
            "cwe_name": "SQL Injection",
            "owasp": "A03:2021",
            "owasp_name": "Injection",
            "confidence": "94%",
        }

    if (
        "xss" in combined
        or "cross-site scripting" in combined
        or "innerhtml" in combined
        or "document.write" in combined
        or "javascript:" in combined
    ):
        return {
            "cwe": "CWE-79",
            "cwe_name": "Cross-site Scripting",
            "owasp": "A03:2021",
            "owasp_name": "Injection",
            "confidence": "93%",
        }

    if "dangerous" in combined or "unsafe" in combined:
        return {
            "cwe": "CWE-676",
            "cwe_name": "Use of Potentially Dangerous Function",
            "owasp": "A06:2021",
            "owasp_name": "Vulnerable and Outdated Components",
            "confidence": "82%",
        }

    return {
        "cwe": "CWE-N/A",
        "cwe_name": "No direct CWE mapping",
        "owasp": "N/A",
        "owasp_name": "No direct OWASP mapping",
        "confidence": "70%",
    }



def build_security_report(result):
    """Create a professional PDF security report from an analysis result."""
    buffer = BytesIO()

    language = result.get("language", "Unknown")
    score = result.get("score", 0)
    risk = result.get("risk", "Unknown")
    issues = result.get("issues", [])
    summary = result.get("summary", {})
    error = result.get("error")

    critical = summary.get("critical", get_severity_count(issues, "CRITICAL"))
    high = summary.get("high", get_severity_count(issues, "HIGH"))
    medium = summary.get("medium", get_severity_count(issues, "MEDIUM"))
    low = summary.get("low", get_severity_count(issues, "LOW"))

    grade = summary.get(
        "grade",
        "F" if score < 60 else "D" if score < 70 else "C"
        if score < 80 else "B" if score < 90 else "A",
    )

    most_dangerous = summary.get("most_dangerous", "None identified")
    primary_category = summary.get(
        "primary_category",
        "No major category detected",
    )
    average_confidence = summary.get("average_confidence", 0)
    affected_lines = summary.get("affected_lines", [])

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="CodeGuard AI Security Report",
        author="CodeGuard AI",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=23,
        leading=28,
        alignment=TA_CENTER,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#555555"),
        spaceAfter=18,
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=15,
        leading=19,
        spaceBefore=10,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=9.5,
        leading=14,
        spaceAfter=5,
    )

    small_style = ParagraphStyle(
        "ReportSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#555555"),
    )

    story = []

    story.append(Paragraph("CodeGuard AI", title_style))
    story.append(Paragraph("Security Analysis Report", subtitle_style))

    overview_data = [
        ["Language", language, "Security Grade", str(grade)],
        ["Risk Level", risk, "Security Score", f"{score}/100"],
        ["Critical", str(critical), "High", str(high)],
        ["Medium", str(medium), "Low", str(low)],
        ["Total Issues", str(len(issues)), "Avg. Confidence", f"{average_confidence}%"],
    ]

    overview_table = Table(
        overview_data,
        colWidths=[34 * mm, 50 * mm, 38 * mm, 50 * mm],
        repeatRows=1,
    )

    overview_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172033")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#202020")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7F8FA")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ])
    )

    story.append(overview_table)
    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph("Security Intelligence", heading_style))

    intelligence_data = [
        ["Most Dangerous Finding", str(most_dangerous)],
        ["Primary OWASP Category", str(primary_category)],
        [
            "Affected Lines",
            ", ".join(str(x) for x in affected_lines)
            if affected_lines else "None",
        ],
    ]

    intelligence_table = Table(
        intelligence_data,
        colWidths=[55 * mm, 117 * mm],
    )

    intelligence_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF2FB")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ])
    )

    story.append(intelligence_table)
    story.append(Spacer(1, 5 * mm))

    if error:
        story.append(Paragraph("Analysis Error", heading_style))
        story.append(Paragraph(str(error), body_style))

    if issues:
        story.append(Paragraph("Detected Vulnerabilities", heading_style))

        for index, issue in enumerate(issues, start=1):
            severity = str(issue.get("severity", "INFO"))
            title = str(issue.get("title", "Issue"))
            description = str(issue.get("description", ""))
            recommendation = str(issue.get("recommendation", ""))
            line = issue.get("line", "N/A")
            cwe = issue.get("cwe", "N/A")
            owasp = issue.get("owasp", "N/A")
            confidence = issue.get("confidence", 0)
            evidence = issue.get("evidence", "")

            issue_rows = [
                ["Finding", f"{title} ({severity})"],
                ["Line", str(line)],
                ["CWE", str(cwe)],
                ["OWASP", str(owasp)],
                ["Confidence", f"{confidence}%"],
                ["Description", description],
                ["Recommendation", recommendation],
            ]

            if evidence:
                issue_rows.append(["Evidence", str(evidence)])

            issue_table = Table(
                issue_rows,
                colWidths=[35 * mm, 137 * mm],
            )

            issue_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F0F2F5")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D0D0D0")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("LEADING", (0, 0), (-1, -1), 11),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ])
            )

            story.append(
                Paragraph(
                    f"{index}. {title}",
                    ParagraphStyle(
                        f"IssueHeading{index}",
                        parent=heading_style,
                        fontSize=11,
                        spaceBefore=6,
                        spaceAfter=5,
                    ),
                )
            )
            story.append(issue_table)
            story.append(Spacer(1, 3 * mm))

    else:
        story.append(Paragraph("Result", heading_style))
        story.append(
            Paragraph(
                "No major security or quality issues were detected.",
                body_style,
            )
        )

    story.append(Spacer(1, 6 * mm))
    story.append(
        Paragraph(
            "CodeGuard AI provides automated static pattern-based analysis. "
            "This report is not a complete security audit and findings should "
            "be manually reviewed before production decisions.",
            small_style,
        )
    )

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawString(
            16 * mm,
            9 * mm,
            "CodeGuard AI • Automated Security Analysis",
        )
        canvas.drawRightString(
            A4[0] - 16 * mm,
            9 * mm,
            f"Page {document.page}",
        )
        canvas.restoreState()

    doc.build(
        story,
        onFirstPage=footer,
        onLaterPages=footer,
    )

    buffer.seek(0)
    return buffer.getvalue()


def render_fix_rescan_panel(result, language, current_code):
    """Interactive before/after security improvement workflow."""

    if not result:
        return

    st.divider()
    st.markdown("### 🔧 Fix & Rescan")
    st.caption(
        "Edit the detected vulnerabilities below, then rescan the revised "
        "code to measure the security improvement."
    )

    fix_key = f"fix_code_input_{language}"

    if (
        fix_key not in st.session_state
        or st.session_state.get("baseline_language") != language
    ):
        st.session_state[fix_key] = current_code

    fixed_code = st.text_area(
        "Paste your fixed code",
        height=300,
        key=fix_key,
        placeholder=f"Paste your corrected {language} code here...",
    )

    action_col1, action_col2, action_col3 = st.columns([2, 2, 3])

    with action_col1:
        rescan_button = st.button(
            "🔄 Rescan Fixed Code",
            type="primary",
            use_container_width=True,
            key=f"rescan_{language}",
        )

    with action_col2:
        restore_button = st.button(
            "↩️ Restore Original",
            use_container_width=True,
            key=f"restore_original_{language}",
        )

    with action_col3:
        st.caption(
            "Compare the original scan with the improved version."
        )

    if restore_button:
        st.session_state[fix_key] = current_code
        st.session_state.rescan_result = None
        st.session_state.rescan_language = None
        st.rerun()

    if rescan_button:
        if not fixed_code.strip():
            st.warning("Please enter the fixed code before rescanning.")
        else:
            with st.spinner(f"Rescanning {language} code..."):
                rescanned = analyze_code(
                    fixed_code,
                    language,
                )

            rescanned["language"] = language
            rescanned["scan_time"] = datetime.now().strftime("%d %b %Y • %I:%M %p")

            st.session_state.rescan_result = rescanned
            st.session_state.rescan_language = language
            st.session_state.analysis_result = rescanned
            st.session_state.analysis_language = language

    # -----------------------------------------------------
    # BEFORE / AFTER SECURITY COMPARISON
    # -----------------------------------------------------

    if (
        st.session_state.rescan_result
        and st.session_state.rescan_language == language
        and st.session_state.baseline_result
        and st.session_state.baseline_language == language
    ):
        baseline = st.session_state.baseline_result
        after = st.session_state.rescan_result

        before_score = int(baseline.get("score", 0) or 0)
        after_score = int(after.get("score", 0) or 0)

        before_issues = len(baseline.get("issues", []) or [])
        after_issues = len(after.get("issues", []) or [])

        score_change = after_score - before_score
        issues_resolved = before_issues - after_issues

        before_summary = baseline.get("summary", {}) or {}
        after_summary = after.get("summary", {}) or {}

        before_grade = before_summary.get(
            "grade",
            "F" if before_score < 60 else
            "D" if before_score < 70 else
            "C" if before_score < 80 else
            "B" if before_score < 90 else "A",
        )

        after_grade = after_summary.get(
            "grade",
            "F" if after_score < 60 else
            "D" if after_score < 70 else
            "C" if after_score < 80 else
            "B" if after_score < 90 else "A",
        )

        st.markdown("### 📈 Security Improvement")

        comparison_col1, comparison_col2, comparison_col3, comparison_col4 = st.columns(4)

        with comparison_col1:
            st.metric(
                "Security Score",
                f"{after_score}/100",
                delta=f"{score_change:+d}",
            )

        with comparison_col2:
            st.metric(
                "Issues Remaining",
                after_issues,
                delta=f"{-issues_resolved:+d}",
                delta_color="inverse",
            )

        with comparison_col3:
            st.metric(
                "Grade",
                after_grade,
                delta=f"{before_grade} → {after_grade}",
            )

        with comparison_col4:
            st.metric(
                "Issues Resolved",
                max(issues_resolved, 0),
            )

        if after_score == 100 and after_issues == 0:
            st.success(
                "🎉 Security check passed. No detected issues remain — "
                "CodeGuard AI rates this code 100/100."
            )
        elif score_change > 0 or issues_resolved > 0:
            st.success(
                f"✅ Security improved: {before_score}/100 → "
                f"{after_score}/100. "
                f"{max(issues_resolved, 0)} issue(s) resolved."
            )
        elif score_change == 0 and before_issues == after_issues:
            st.warning(
                "⚠️ The rescan found the same number of issues. "
                "More fixes may be required."
            )
        else:
            st.error(
                "❌ The rescan detected a weaker security posture. "
                "Review the remaining findings before proceeding."
            )

        with st.expander("🔍 Compare Scan Results"):
            compare_col1, compare_col2 = st.columns(2)

            with compare_col1:
                st.markdown("**Original Scan**")
                st.write(f"Score: **{before_score}/100**")
                st.write(f"Grade: **{before_grade}**")
                st.write(f"Issues: **{before_issues}**")

            with compare_col2:
                st.markdown("**Latest Rescan**")
                st.write(f"Score: **{after_score}/100**")
                st.write(f"Grade: **{after_grade}**")
                st.write(f"Issues: **{after_issues}**")



def render_results(result):

    if not result:
        return

    language = result.get("language", "Unknown")
    score = result.get("score", 0)
    risk = result.get("risk", "Unknown")
    issues = result.get("issues", [])
    error = result.get("error")
    summary = result.get("summary", {})

    st.divider()

    # -----------------------------------------------------
    # SECURITY OVERVIEW
    # -----------------------------------------------------

    st.subheader(f"{get_risk_icon(risk)} {risk}")
    st.caption(f"{language} Security Analysis")

    critical = summary.get(
        "critical",
        get_severity_count(issues, "CRITICAL"),
    )
    high = summary.get(
        "high",
        get_severity_count(issues, "HIGH"),
    )
    medium = summary.get(
        "medium",
        get_severity_count(issues, "MEDIUM"),
    )
    low = summary.get(
        "low",
        get_severity_count(issues, "LOW"),
    )

    grade = summary.get(
        "grade",
        "F" if score < 60 else "D" if score < 70 else "C" if score < 80 else "B" if score < 90 else "A",
    )

    most_dangerous = summary.get(
        "most_dangerous",
        "No vulnerabilities detected",
    )

    primary_category = summary.get(
        "primary_category",
        "No major category detected",
    )

    average_confidence = summary.get(
        "average_confidence",
        0,
    )

    affected_lines = summary.get(
        "affected_lines",
        [],
    )

    # -----------------------------------------------------
    # SCORE + GRADE
    # -----------------------------------------------------

    overview_col1, overview_col2 = st.columns([3, 1])

    with overview_col1:
        st.markdown("### 🛡️ Security Overview")

        metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)

        with metric_col1:
            st.metric("Security Score", f"{score}/100")

        with metric_col2:
            st.metric("Critical", critical)

        with metric_col3:
            st.metric("High", high)

        with metric_col4:
            st.metric("Total Issues", len(issues))

        st.progress(
            max(
                0.0,
                min(score / 100, 1.0),
            )
        )

    with overview_col2:
        st.markdown("### 🎯 Grade")
        st.markdown(
            f"""
            <div style="
                border: 1px solid rgba(128,128,128,0.35);
                border-radius: 14px;
                padding: 1.1rem;
                text-align: center;
                margin-top: 0.4rem;
            ">
                <div style="font-size: 3.2rem; font-weight: 800;">{grade}</div>
                <div style="opacity: 0.7;">Security Grade</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # -----------------------------------------------------
    # RISK BREAKDOWN
    # -----------------------------------------------------

    with st.expander("📊 Risk Breakdown", expanded=True):

        breakdown_col1, breakdown_col2, breakdown_col3, breakdown_col4 = st.columns(4)

        with breakdown_col1:
            st.metric("🚨 Critical", critical)

        with breakdown_col2:
            st.metric("🔴 High", high)

        with breakdown_col3:
            st.metric("🟠 Medium", medium)

        with breakdown_col4:
            st.metric("🟡 Low", low)

    # -----------------------------------------------------
    # SECURITY INTELLIGENCE
    # -----------------------------------------------------

    intel_col1, intel_col2 = st.columns(2)

    with intel_col1:
        st.markdown("### 🔎 Security Intelligence")

        st.markdown(
            f"""
            **Most Dangerous Finding**  
            {most_dangerous}

            **Primary OWASP Category**  
            {primary_category}
            """
        )

    with intel_col2:
        st.markdown("### 📈 Analysis Confidence")

        st.metric(
            "Average Detection Confidence",
            f"{average_confidence}%",
        )

        if affected_lines:
            line_text = ", ".join(
                str(line) for line in affected_lines
            )
            st.caption(
                f"📍 Affected lines: {line_text}"
            )
        else:
            st.caption("📍 No affected lines identified.")

    # -----------------------------------------------------
    # SYNTAX / ANALYSIS ERROR
    # -----------------------------------------------------

    if error:
        st.error(f"Analysis error: {error}")
        return

    # -----------------------------------------------------
    # NO ISSUES
    # -----------------------------------------------------

    if not issues:
        st.success(
            "✅ No major security or quality issues were detected."
        )

        st.info(
            "This does not guarantee that the code is completely secure."
        )

        return

    # -----------------------------------------------------
    # ISSUES
    # -----------------------------------------------------

    st.markdown("### 🔍 Detected Issues")

    for index, issue in enumerate(issues):

        severity = issue.get(
            "severity",
            "INFO",
        )

        title = issue.get(
            "title",
            "Issue",
        )

        description = issue.get(
            "description",
            "",
        )

        recommendation = issue.get(
            "recommendation",
            "",
        )

        line = issue.get(
            "line",
        )

        cwe = issue.get(
            "cwe",
            "N/A",
        )

        owasp = issue.get(
            "owasp",
            "N/A",
        )

        confidence = issue.get(
            "confidence",
            0,
        )

        evidence = issue.get(
            "evidence",
            "",
        )

        if severity == "CRITICAL":
            icon = "🚨"
        elif severity == "HIGH":
            icon = "🔴"
        elif severity == "MEDIUM":
            icon = "🟠"
        elif severity == "LOW":
            icon = "🟡"
        else:
            icon = "🔵"

        with st.container(border=True):

            col1, col2 = st.columns([1, 7])

            with col1:
                st.markdown(f"## {icon}")
                st.caption(severity)

            with col2:

                st.markdown(
                    f"**{title}**"
                )

                if line:
                    st.caption(
                        f"Line {line}"
                    )

                st.write(
                    description
                )

                meta_col1, meta_col2, meta_col3 = st.columns(3)

                with meta_col1:
                    st.caption("CWE")
                    st.markdown(
                        f"**{cwe}**"
                    )

                with meta_col2:
                    st.caption("OWASP")
                    st.markdown(
                        f"**{owasp}**"
                    )

                with meta_col3:
                    st.caption("Confidence")
                    st.markdown(
                        f"**{confidence}%**"
                    )

                if evidence:
                    with st.expander("View evidence"):
                        st.code(
                            str(evidence),
                            language="text",
                        )

                st.info(
                    f"💡 {recommendation}"
                )

    # -----------------------------------------------------
    # SECURITY REPORT EXPORT
    # -----------------------------------------------------

    st.markdown("### 📄 Security Report")

    report_bytes = build_security_report(result)

    safe_language = str(language).lower().replace(" ", "_")

    st.download_button(
        "⬇️ Download Security Report (PDF)",
        data=report_bytes,
        file_name=f"codeguard_security_report_{safe_language}.pdf",
        mime="application/pdf",
        use_container_width=True,
        key="download_security_report",
    )

    # -----------------------------------------------------
    # FINAL SECURITY DISCLAIMER
    # -----------------------------------------------------

    st.warning(
        "⚠️ Static analysis identifies known patterns and warning signs. "
        "It is not a complete security audit."
    )


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.markdown(
        "# 🛡️ CodeGuard AI"
    )

    st.caption(
        "Multi-language code security analyzer"
    )

    st.divider()

    st.markdown(
        "### Supported Languages"
    )

    st.write(
        "🐍 Python"
    )

    st.write(
        "🌐 HTML"
    )

    st.write(
        "⚡ JavaScript"
    )

    st.divider()

    st.caption(
        "CodeGuard AI v1.0"
    )


# =========================================================
# HERO
# =========================================================

st.markdown(
    '<div class="hero-title">'
    '🛡️ CodeGuard AI'
    '</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="hero-subtitle">'
    'Analyze code for common security vulnerabilities, '
    'risky patterns and potential weaknesses.'
    '</div>',
    unsafe_allow_html=True,
)


# =========================================================
# LANGUAGE SELECTOR
# =========================================================

st.markdown(
    "### Choose Language"
)

language_option = st.radio(
    "Select the code language",
    list(LANGUAGES.keys()),
    horizontal=True,
    label_visibility="collapsed",
    key="language_selector",
)

language = LANGUAGES[
    language_option
]


# =========================================================
# CODE EDITOR AREA
# =========================================================

st.markdown(
    f"### {language} Code"
)

code = st.text_area(
    "Paste your code below",
    height=380,
    placeholder=(
        f"Paste your {language} code here..."
    ),
    key=f"code_input_{language}",
)


# =========================================================
# EXAMPLE / CLEAR BUTTONS
# =========================================================

col1, col2, col3 = st.columns(
    [2, 2, 4]
)

with col1:

    analyze_button = st.button(
        "🔍 Analyze Code",
        type="primary",
        use_container_width=True,
        key=f"analyze_{language}",
    )

with col2:

    example_button = st.button(
        "🧪 Load Example",
        use_container_width=True,
        key=f"example_{language}",
    )

with col3:

    st.caption(
        "CodeGuard performs static pattern-based security analysis."
    )


# =========================================================
# LOAD EXAMPLE
# =========================================================

if example_button:

    st.session_state[
        f"code_input_{language}"
    ] = EXAMPLES[language]

    st.rerun()


# =========================================================
# ANALYZE
# =========================================================

if analyze_button:

    if not code.strip():

        st.warning(
            "Please enter some code first."
        )

    else:

        with st.spinner(
            f"Analyzing {language} code..."
        ):

            result = analyze_code(
                code,
                language,
            )

        result["language"] = language
        result["scan_time"] = datetime.now().strftime("%d %b %Y • %I:%M %p")

        st.session_state.analysis_result = result
        st.session_state.analysis_language = language

        # A fresh analysis becomes the baseline for Fix & Rescan.
        st.session_state.baseline_result = result
        st.session_state.baseline_language = language
        st.session_state.rescan_result = None
        st.session_state.rescan_language = None

        # Start the fix editor with the code that was just analyzed.
        st.session_state[f"fix_code_input_{language}"] = code


# =========================================================
# RESULTS
# =========================================================

if (
    st.session_state.analysis_result
    and st.session_state.analysis_language
    == language
):

    render_fix_rescan_panel(
        st.session_state.analysis_result,
        language,
        st.session_state.get(
            f"fix_code_input_{language}",
            code,
        ),
    )

    render_results(
        st.session_state.analysis_result
    )


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    "⚠️ CodeGuard AI provides automated static analysis "
    "and should not be treated as a complete security audit."
)