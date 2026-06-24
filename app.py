from flask import Flask, request, render_template, send_from_directory
import subprocess
import os
import json
from datetime import datetime
from urllib.parse import urlparse
from werkzeug.utils import secure_filename

app = Flask(__name__)

RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)


def valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ["http", "https"] and parsed.netloc


def read_json_results(file_path):
    results = []

    if not os.path.exists(file_path):
        return results

    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read().strip()

    if not content:
        return results

    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
        return [data]
    except json.JSONDecodeError:
        for line in content.splitlines():
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    return results


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()

    if not valid_url(target):
        return render_template(
            "index.html",
            error="Please enter a valid URL starting with http:// or https://"
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{timestamp}.json"
    output_path = os.path.join(RESULTS_DIR, filename)

    command_display = f"nuclei -u {target}"

    cmd = [
        "nuclei",
        "-u", target,
        "-json-export", output_path,
        "-silent",
        "-c", "1",
        "-rate-limit", "2",
        "-timeout", "5",
        "-retries", "1",
        "-disable-update-check"
    ]

    try:
        scan_process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        results = read_json_results(output_path)

        severity_count = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "unknown": 0
        }

        for item in results:
            severity = item.get("info", {}).get("severity", "unknown").lower()
            if severity in severity_count:
                severity_count[severity] += 1
            else:
                severity_count["unknown"] += 1

        return render_template(
            "index.html",
            target=target,
            command_display=command_display,
            results=results,
            severity_count=severity_count,
            filename=filename,
            total_findings=len(results),
            scan_output=scan_process.stdout,
            scan_error=scan_process.stderr,
            return_code=scan_process.returncode
        )

    except subprocess.TimeoutExpired:
        return render_template(
            "index.html",
            error="The scan timed out. Render Free may be too limited for a full Nuclei scan. Try again."
        )

    except Exception as e:
        return render_template(
            "index.html",
            error=f"Scan failed: {str(e)}"
        )


@app.route("/reports/<filename>")
def download_report(filename):
    safe_filename = secure_filename(filename)
    return send_from_directory(RESULTS_DIR, safe_filename, as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
