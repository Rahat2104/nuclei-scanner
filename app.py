from flask import Flask, request, render_template, send_from_directory
import subprocess
import os
import json
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)


def is_valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ["http", "https"] and parsed.netloc


def load_results(file_path):
    if not os.path.exists(file_path):
        return []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
            if isinstance(data, list):
                return data
            return [data]
    except json.JSONDecodeError:
        results = []
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                if line.strip():
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

    if not is_valid_url(target):
        return render_template(
            "index.html",
            error="Please enter a valid URL starting with http:// or https://"
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{timestamp}.json"
    output_path = os.path.join(RESULTS_DIR, filename)

    cmd = [
        "nuclei",
        "-u",
        target,
        "-json-export",
        output_path,
        "-silent"
    ]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
    except subprocess.TimeoutExpired:
        return render_template(
            "index.html",
            error="Scan timed out. Try a smaller target."
        )

    results = load_results(output_path)

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
        severity_count[severity] = severity_count.get(severity, 0) + 1

    return render_template(
        "index.html",
        target=target,
        results=results,
        filename=filename,
        severity_count=severity_count,
        stderr=completed.stderr
    )


@app.route("/reports/<filename>")
def download_report(filename):
    return send_from_directory(RESULTS_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
