from flask import Flask, request, render_template, send_from_directory, make_response
import subprocess
import os
import time
import json
from io import BytesIO
from xml.sax.saxutils import escape
from urllib.parse import urlparse
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

app = Flask(__name__)

RESULTS_DIR = "results"
HISTORY_FILE = os.path.join(RESULTS_DIR, "scan_history.json")
MAX_HISTORY = 20


def valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ["http", "https"] and parsed.netloc


def normalize_severity(value):
    if not value:
        return "info"

    value = str(value).lower().strip()
    valid_levels = ["critical", "high", "medium", "low", "info"]

    if value in valid_levels:
        return value

    return "info"


def classify_severity(finding):
    native_severity = normalize_severity(
        finding.get("info", {}).get("severity", "info")
    )

    if native_severity in ["critical", "high", "medium", "low"]:
        return native_severity

    matcher_name = finding.get("matcher-name", "")
    template_id = finding.get("template-id", "")
    template_name = finding.get("info", {}).get("name", "")
    description = finding.get("info", {}).get("description", "")

    text = f"{matcher_name} {template_id} {template_name} {description}".lower()

    critical_keywords = [
        "remote code execution",
        "rce",
        "command injection",
        "sql injection",
        "sqli",
        "authentication bypass",
        "unauthenticated admin",
        "default admin credential",
        "critical"
    ]

    high_keywords = [
        "strict-transport-security",
        "hsts",
        "content-security-policy",
        "csp",
        "frame-ancestors",
        "cors misconfiguration",
        "wildcard cors",
        "open cors",
        "access-control-allow-origin: *",
        "exposed secret",
        "api key",
        "private key",
        "password disclosure",
        "token disclosure",
        "directory traversal",
        "path traversal",
        "server-side request forgery",
        "ssrf",
        "high"
    ]

    medium_keywords = [
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "feature-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "cross-origin-embedder-policy",
        "x-permitted-cross-domain-policies",
        "clear-site-data",
        "origin-agent-cluster",
        "clickjacking",
        "mime sniffing",
        "missing security header",
        "open redirect",
        "directory listing",
        "medium"
    ]

    low_keywords = [
        "x-xss-protection",
        "x-download-options",
        "x-dns-prefetch-control",
        "expect-ct",
        "nel",
        "report-to",
        "reporting-endpoints",
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "powered-by",
        "technology disclosure",
        "information disclosure",
        "cache-control",
        "pragma",
        "expires",
        "low"
    ]

    info_keywords = [
        "robots.txt",
        "sitemap.xml",
        "favicon",
        "waf detect",
        "cdn detect",
        "technology detect",
        "http title",
        "tls",
        "ssl",
        "whois",
        "dns",
        "fingerprint",
        "info",
        "website response check",
        "security.txt"
    ]

    for keyword in critical_keywords:
        if keyword in text:
            return "critical"

    for keyword in high_keywords:
        if keyword in text:
            return "high"

    for keyword in medium_keywords:
        if keyword in text:
            return "medium"

    for keyword in low_keywords:
        if keyword in text:
            return "low"

    for keyword in info_keywords:
        if keyword in text:
            return "info"

    return native_severity or "info"


def build_severity_data(findings):
    severity_count = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for finding in findings:
        level = normalize_severity(finding.get("display_severity", "info"))

        if level in severity_count:
            severity_count[level] += 1
        else:
            severity_count["info"] += 1

    total = len(findings)
    severity_data = []

    for level in ["critical", "high", "medium", "low", "info"]:
        count = severity_count[level]
        percent = int((count / total) * 100) if total > 0 else 0

        severity_data.append({
            "level": level,
            "count": count,
            "percent": percent
        })

    return severity_data


def generate_ai_explanation(finding):
    header = finding.get("matcher-name", "").lower().strip()
    severity = finding.get("display_severity", "info")
    template_name = finding.get("info", {}).get("name", "Security finding")
    description = finding.get("info", {}).get("description", "")

    explanations = {
        "strict-transport-security": {
            "meaning": "The website is missing the Strict-Transport-Security header. This header tells browsers to only use HTTPS when connecting to the site.",
            "risk": "Without it, users may be more exposed to protocol downgrade attacks or insecure HTTP connections.",
            "fix": "Add the Strict-Transport-Security header with a safe max-age value after confirming HTTPS works correctly across the site."
        },
        "content-security-policy": {
            "meaning": "The website is missing a Content-Security-Policy header. CSP helps control which scripts, styles, images, and resources the browser is allowed to load.",
            "risk": "Without CSP, the site may have weaker protection against cross-site scripting and content injection attacks.",
            "fix": "Create a Content-Security-Policy that only allows trusted sources for scripts, styles, images, frames, and connections."
        },
        "x-frame-options": {
            "meaning": "The website is missing the X-Frame-Options header. This header helps prevent the page from being embedded inside a malicious frame.",
            "risk": "Without it, the site may be more exposed to clickjacking attacks.",
            "fix": "Add X-Frame-Options with DENY or SAMEORIGIN, or use the frame-ancestors directive in Content-Security-Policy."
        },
        "x-content-type-options": {
            "meaning": "The website is missing the X-Content-Type-Options header. This header prevents browsers from guessing file types incorrectly.",
            "risk": "Without it, browsers may perform MIME sniffing, which can increase the risk of unwanted script execution in some cases.",
            "fix": "Add X-Content-Type-Options with the value nosniff."
        },
        "referrer-policy": {
            "meaning": "The website is missing the Referrer-Policy header. This header controls how much referrer information is shared when users click links.",
            "risk": "Without it, sensitive URL information may be leaked to third-party websites.",
            "fix": "Add a Referrer-Policy such as strict-origin-when-cross-origin or no-referrer depending on the application requirement."
        },
        "permissions-policy": {
            "meaning": "The website is missing the Permissions-Policy header. This header controls access to browser features such as camera, microphone, geolocation, and sensors.",
            "risk": "Without it, the browser may allow more features than the site actually needs.",
            "fix": "Add a Permissions-Policy header and disable browser features that are not required."
        },
        "cross-origin-opener-policy": {
            "meaning": "The website is missing the Cross-Origin-Opener-Policy header. This header helps isolate browsing contexts between different origins.",
            "risk": "Without it, the site may have weaker protection against cross-origin interaction risks.",
            "fix": "Add Cross-Origin-Opener-Policy with a value such as same-origin if compatible with the application."
        },
        "cross-origin-resource-policy": {
            "meaning": "The website is missing the Cross-Origin-Resource-Policy header. This header controls whether other origins can load the site's resources.",
            "risk": "Without it, resources may be more easily shared or embedded across origins.",
            "fix": "Add Cross-Origin-Resource-Policy with a suitable value such as same-origin, same-site, or cross-origin depending on the use case."
        },
        "cross-origin-embedder-policy": {
            "meaning": "The website is missing the Cross-Origin-Embedder-Policy header. This header helps control how cross-origin resources are embedded.",
            "risk": "Without it, the site may not benefit from stronger browser isolation features.",
            "fix": "Add Cross-Origin-Embedder-Policy after confirming that required third-party resources still load correctly."
        },
        "x-permitted-cross-domain-policies": {
            "meaning": "The website is missing the X-Permitted-Cross-Domain-Policies header. This header controls how Adobe products handle cross-domain policy files.",
            "risk": "Without it, old clients may allow cross-domain data access in ways the site owner did not intend.",
            "fix": "Add X-Permitted-Cross-Domain-Policies with a restrictive value such as none."
        }
    }

    if header in explanations:
        item = explanations[header]
        return (
            f"{item['meaning']} "
            f"Risk level: {severity.upper()}. "
            f"{item['risk']} "
            f"Recommended fix: {item['fix']}"
        )

    if header:
        return (
            f"This finding is related to {header}. "
            f"Risk level: {severity.upper()}. "
            f"Nuclei detected this as part of the scan result. "
            f"Review the finding details and apply the recommended security configuration for this item."
        )

    return (
        f"This result was detected by the template '{template_name}'. "
        f"Risk level: {severity.upper()}. "
        f"{description if description else 'Review the finding and confirm whether it affects the target application.'}"
    )


def process_finding(finding):
    display_severity = classify_severity(finding)
    finding["display_severity"] = display_severity
    finding["ai_explanation"] = generate_ai_explanation(finding)
    return finding


def read_findings_from_jsonl(file_path):
    findings = []

    if not os.path.exists(file_path):
        return findings

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                try:
                    finding = json.loads(line)
                    findings.append(process_finding(finding))
                except json.JSONDecodeError:
                    pass

    return findings


def load_scan_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            history = json.load(file)

        if isinstance(history, list):
            return history

        return []

    except Exception:
        return []


def save_scan_history(history):
    os.makedirs(RESULTS_DIR, exist_ok=True)

    with open(HISTORY_FILE, "w", encoding="utf-8") as file:
        json.dump(history[:MAX_HISTORY], file, indent=2)


def add_scan_history(target, output_file, findings, severity_data):
    history = load_scan_history()

    severity_counts = {}

    for item in severity_data:
        level = item.get("level", "info")
        label = "advisory" if level == "info" else level
        severity_counts[label] = item.get("count", 0)

    entry = {
        "scan_id": int(time.time()),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "output_file": output_file,
        "total_findings": len(findings),
        "severity_counts": severity_counts
    }

    history.insert(0, entry)
    history = history[:MAX_HISTORY]

    save_scan_history(history)

    return history


def safe_pdf_text(value):
    if value is None:
        return ""

    return escape(str(value))


def severity_display_name(level):
    if level == "info":
        return "Advisory"

    return str(level).capitalize()


def generate_pdf_report(target, findings, severity_data):
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=28,
        spaceAfter=18
    )

    heading_style = ParagraphStyle(
        "CustomHeading",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        spaceBefore=14,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "CustomNormal",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        spaceAfter=8
    )

    small_style = ParagraphStyle(
        "CustomSmall",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12,
        spaceAfter=6
    )

    story = []

    story.append(Paragraph("Nuclei Security Scan Report", title_style))
    story.append(Paragraph(f"<b>Target:</b> {safe_pdf_text(target)}", normal_style))
    story.append(Paragraph(f"<b>Total Findings:</b> {len(findings)}", normal_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Severity Summary", heading_style))

    for item in severity_data:
        level = item.get("level", "info")
        count = item.get("count", 0)
        label = severity_display_name(level)
        story.append(Paragraph(f"<b>{label}:</b> {count}", normal_style))

    story.append(Spacer(1, 12))
    story.append(Paragraph("Findings and AI-Style Explanations", heading_style))

    if not findings:
        story.append(Paragraph("No findings were detected for this target.", normal_style))
    else:
        for index, finding in enumerate(findings, start=1):
            severity = severity_display_name(finding.get("display_severity", "info"))
            template_name = finding.get("info", {}).get("name", "Security Finding")
            detected_item = finding.get("matcher-name", "N/A")
            matched_url = finding.get("matched-at", target)
            explanation = finding.get("ai_explanation", "No explanation available.")

            story.append(Paragraph(f"Finding {index}: {safe_pdf_text(template_name)}", heading_style))
            story.append(Paragraph(f"<b>Severity:</b> {safe_pdf_text(severity)}", small_style))
            story.append(Paragraph(f"<b>Detected Item:</b> {safe_pdf_text(detected_item)}", small_style))
            story.append(Paragraph(f"<b>URL:</b> {safe_pdf_text(matched_url)}", small_style))
            story.append(Paragraph(f"<b>Explanation:</b> {safe_pdf_text(explanation)}", small_style))
            story.append(Spacer(1, 8))

    story.append(Spacer(1, 14))
    story.append(Paragraph(
        "Educational use only. This report is generated from Nuclei scan results and should be reviewed before applying security changes.",
        small_style
    ))

    document.build(story)
    buffer.seek(0)

    return buffer


@app.route("/")
def home():
    return render_template(
        "index.html",
        scan_history=load_scan_history()
    )


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()

    if not valid_url(target):
        return render_template(
            "index.html",
            scan_history=load_scan_history(),
            error="Please enter a valid URL starting with http:// or https://"
        )

    os.makedirs(RESULTS_DIR, exist_ok=True)

    output_filename = f"output_{int(time.time())}.jsonl"
    output = os.path.join(RESULTS_DIR, output_filename)

    templates = [
        "/root/nuclei-templates/http/misconfiguration/http-missing-security-headers.yaml",
        "scanner-templates/basic-http-check.yaml",
        "scanner-templates/security-txt-check.yaml"
    ]

    cmd = [
        "nuclei",
        "-u", target
    ]

    for template in templates:
        if template.startswith("/root/") or os.path.exists(template):
            cmd.extend(["-t", template])

    cmd.extend([
        "-jsonl",
        "-o", output,
        "-c", "1",
        "-rl", "1",
        "-timeout", "10",
        "-retries", "0",
        "-silent",
        "-duc"
    ])

    try:
        scan_result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=45
        )

    except subprocess.TimeoutExpired:
        return render_template(
            "index.html",
            scan_history=load_scan_history(),
            error="The scan timed out. Try a smaller or faster target."
        )

    except Exception as e:
        return render_template(
            "index.html",
            scan_history=load_scan_history(),
            error=f"Scan error: {str(e)}"
        )

    findings = read_findings_from_jsonl(output)
    severity_data = build_severity_data(findings)
    scan_history = add_scan_history(target, output_filename, findings, severity_data)

    return render_template(
        "index.html",
        target=target,
        findings=findings,
        stderr=scan_result.stderr,
        output_file=output_filename,
        severity_data=severity_data,
        scan_history=scan_history
    )


@app.route("/download/<filename>")
def download_result(filename):
    safe_filename = secure_filename(filename)
    return send_from_directory(RESULTS_DIR, safe_filename, as_attachment=True)


@app.route("/pdf/<filename>")
def download_pdf_report(filename):
    safe_filename = secure_filename(filename)
    file_path = os.path.join(RESULTS_DIR, safe_filename)

    if not os.path.exists(file_path):
        return "PDF report could not be generated because the JSONL result file was not found.", 404

    target = request.args.get("target", "Unknown target")

    findings = read_findings_from_jsonl(file_path)
    severity_data = build_severity_data(findings)

    pdf_buffer = generate_pdf_report(target, findings, severity_data)
    pdf_filename = safe_filename.replace(".jsonl", ".pdf")

    response = make_response(pdf_buffer.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename={pdf_filename}"

    return response


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
