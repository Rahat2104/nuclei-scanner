from flask import Flask, request, render_template, send_from_directory
import subprocess
import os
import time
import json
from werkzeug.utils import secure_filename

app = Flask(__name__)

RESULTS_DIR = "results"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form["target"]

    os.makedirs(RESULTS_DIR, exist_ok=True)

    output_filename = f"output_{int(time.time())}.jsonl"
    output = os.path.join(RESULTS_DIR, output_filename)

    cmd = [
        "nuclei",
        "-u", target,
        "-t", "/root/nuclei-templates/http/misconfiguration/http-missing-security-headers.yaml",
        "-jsonl",
        "-o", output,
        "-c", "1",
        "-rl", "1",
        "-timeout", "10",
        "-retries", "0",
        "-silent",
        "-duc"
    ]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
    except Exception as e:
        return f"Scan error: {e}"

    findings = []

    if os.path.exists(output):
        with open(output, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    return render_template(
        "index.html",
        target=target,
        findings=findings,
        stderr=r.stderr,
        output_file=output_filename
    )


@app.route("/download/<filename>")
def download_result(filename):
    safe_filename = secure_filename(filename)
    return send_from_directory(RESULTS_DIR, safe_filename, as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
