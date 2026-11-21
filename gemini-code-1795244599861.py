import hashlib
import os
import re
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "doom_ai.db")
FIM_SANDBOX_DIR = os.path.join(BASE_DIR, "fim_sandbox")

# --- WAF Pattern Rules (Rule-Based Demo Engine) ---
WAF_RULES = [
    ("SQL Injection", 90, r"(\bunion\b.*\bselect\b|\bor\b\s+1\s*=\s*1|--|;\s*drop\s+table|'[\s]*or[\s]*')"),
    ("Cross-Site Scripting (XSS)", 85, r"(<script\b|javascript:|onerror\s*=|onload\s*=|<iframe\b)"),
    ("Path Traversal", 80, r"(\.\./|\.\.\\|/etc/passwd|boot\.ini)"),
    ("Command Injection", 92, r"(;\s*(ls|cat|whoami|rm|bash|sh)\b|\|\s*(cat|whoami|sh)\b|\$\(.*\))"),
]

SUSPICIOUS_URL_KEYWORDS = ["login", "verify", "update-account", "urgent", "bank", "free-prize", "signin", "wallet"]
SUSPICIOUS_TLDS = (".xyz", ".top", ".zip", ".click", ".ru", ".tk", ".gq")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                module TEXT NOT NULL,
                action TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                title TEXT NOT NULL,
                explanation TEXT NOT NULL,
                is_simulated INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fim_baseline (
                filename TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        if count == 0:
            log_event(
                module="SYSTEM",
                action="ALLOW",
                risk_score=5,
                title="DOOM AI V2 Initialized",
                explanation="Sample setup event: local SQLite database and dashboard ready.",
                is_simulated=True,
                conn=conn,
            )


def init_fim_sandbox():
    os.makedirs(FIM_SANDBOX_DIR, exist_ok=True)
    sample_files = {
        "config_demo.txt": "mode=local_demo\nport=5000\n",
        "policy_demo.txt": "waf=enabled\nlogging=sqlite\n",
    }
    for name, content in sample_files.items():
        path = os.path.join(FIM_SANDBOX_DIR, name)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)


def log_event(module, action, risk_score, title, explanation, is_simulated=False, conn=None):
    ts = datetime.now().strftime("%H:%M:%S")
    sim_flag = 1 if is_simulated else 0
    if conn is not None:
        conn.execute(
            "INSERT INTO events (timestamp, module, action, risk_score, title, explanation, is_simulated) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, module, action, risk_score, title, explanation, sim_flag),
        )
    else:
        with get_db() as c:
            c.execute(
                "INSERT INTO events (timestamp, module, action, risk_score, title, explanation, is_simulated) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ts, module, action, risk_score, title, explanation, sim_flag),
            )


def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/events", methods=["GET"])
def get_events():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 30").fetchall()
        events = [dict(r) for r in rows]

        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM events WHERE action = 'BLOCK'").fetchone()[0]
        review = conn.execute("SELECT COUNT(*) FROM events WHERE action = 'REVIEW'").fetchone()[0]
        allowed = conn.execute("SELECT COUNT(*) FROM events WHERE action = 'ALLOW'").fetchone()[0]
        avg_risk = conn.execute("SELECT COALESCE(ROUND(AVG(risk_score)), 0) FROM events").fetchone()[0]

    return jsonify(
        {
            "metrics": {
                "total": total,
                "blocked": blocked,
                "review": review,
                "allowed": allowed,
                "avg_risk": int(avg_risk),
            },
            "events": events,
        }
    )


@app.route("/api/waf/inspect", methods=["POST"])
def waf_inspect():
    data = request.get_json(silent=True) or {}
    payload = str(data.get("payload", "")).strip()

    if not payload:
        return jsonify({"error": "Provide a request input to inspect."}), 400

    matches = []
    max_risk = 5
    for rule_name, score, pattern in WAF_RULES:
        if re.search(pattern, payload, re.IGNORECASE):
            matches.append(rule_name)
            max_risk = max(max_risk, score)

    if matches:
        action = "BLOCK"
        title = f"WAF Blocked: {', '.join(matches)}"
        explanation = f"Input '{payload[:60]}' matched rule(s): {', '.join(matches)}. Risk score {max_risk}/100."
    else:
        action = "ALLOW"
        title = "WAF Allowed Request"
        explanation = f"Harmless demo input '{payload[:60]}' passed all pattern rules cleanly."

    log_event("WAF", action, max_risk, title, explanation, is_simulated=False)
    return jsonify({"action": action, "risk_score": max_risk, "matches": matches, "explanation": explanation})


@app.route("/api/waf/simulate", methods=["POST"])
def waf_simulate():
    samples = [
        ("SQL Injection", 90, "' OR 1=1 --"),
        ("Cross-Site Scripting (XSS)", 85, "<script>alert('demo')</script>"),
        ("Path Traversal", 80, "../../etc/passwd"),
        ("Command Injection", 92, "hello; cat /etc/passwd"),
    ]
    for name, score, sample in samples:
        log_event(
            module="WAF",
            action="BLOCK",
            risk_score=score,
            title=f"[SIMULATED] {name}",
            explanation=f"Local demo payload '{sample}' triggered {name} rule. Not a live external attack.",
            is_simulated=True,
        )
    return jsonify({"status": "ok", "generated": len(samples)})


@app.route("/api/url/scan", methods=["POST"])
def url_scan():
    data = request.get_json(silent=True) or {}
    raw_url = str(data.get("url", "")).strip()

    if not raw_url:
        return jsonify({"error": "Enter a URL to scan."}), 400

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url

    parsed = urlparse(raw_url)
    host = (parsed.hostname or "").lower()
    reasons = []
    score = 10

    if parsed.scheme != "https":
        score += 20
        reasons.append("Uses unencrypted HTTP instead of HTTPS (+20)")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 35
        reasons.append("Uses raw IP address instead of domain name (+35)")
    if "@" in raw_url:
        score += 25
        reasons.append("Contains '@' symbol often used to mask destinations (+25)")
    if len(raw_url) > 75:
        score += 15
        reasons.append("Unusually long URL length (+15)")
    if host.count(".") >= 3:
        score += 15
        reasons.append("Excessive subdomains detected (+15)")
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 20
        reasons.append("Uses high-risk TLD (+20)")

    hit_words = [kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in raw_url.lower()]
    if hit_words:
        score += 20
        reasons.append(f"Deceptive keyword(s): {', '.join(hit_words)} (+20)")

    score = min(score, 100)
    if score >= 65:
        action = "BLOCK"
    elif score >= 35:
        action = "REVIEW"
    else:
        action = "ALLOW"

    explanation = "; ".join(reasons) if reasons else "No heuristic phishing indicators found."
    log_event("PHISHING", action, score, f"URL Scan: {host or raw_url[:30]}", explanation, is_simulated=False)
    return jsonify({"action": action, "risk_score": score, "reasons": reasons, "explanation": explanation})


@app.route("/api/fim/baseline", methods=["POST"])
def fim_create_baseline():
    init_fim_sandbox()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    files_hashed = 0
    with get_db() as conn:
        conn.execute("DELETE FROM fim_baseline")
        for fname in sorted(os.listdir(FIM_SANDBOX_DIR)):
            fpath = os.path.join(FIM_SANDBOX_DIR, fname)
            if os.path.isfile(fpath):
                conn.execute(
                    "INSERT INTO fim_baseline (filename, sha256, updated_at) VALUES (?, ?, ?)",
                    (fname, sha256_file(fpath), now),
                )
                files_hashed += 1

    log_event(
        "FIM",
        "ALLOW",
        5,
        "SHA-256 Baseline Saved",
        f"Trusted baseline created for {files_hashed} file(s) in fim_sandbox/.",
        is_simulated=False,
    )
    return jsonify({"status": "ok", "files_hashed": files_hashed})


@app.route("/api/fim/check", methods=["POST"])
def fim_check():
    init_fim_sandbox()
    with get_db() as conn:
        rows = conn.execute("SELECT filename, sha256 FROM fim_baseline").fetchall()
        baseline = {r["filename"]: r["sha256"] for r in rows}

    if not baseline:
        return jsonify({"error": "No baseline exists yet. Click 'Save Baseline' first."}), 400

    current = {}
    for fname in sorted(os.listdir(FIM_SANDBOX_DIR)):
        fpath = os.path.join(FIM_SANDBOX_DIR, fname)
        if os.path.isfile(fpath):
            current[fname] = sha256_file(fpath)

    modified = [f for f in baseline if f in current and baseline[f] != current[f]]
    deleted = [f for f in baseline if f not in current]
    added = [f for f in current if f not in baseline]

    if modified or deleted or added:
        changes = []
        if modified:
            changes.append(f"Modified: {', '.join(modified)}")
        if deleted:
            changes.append(f"Deleted: {', '.join(deleted)}")
        if added:
            changes.append(f"Added: {', '.join(added)}")
        explanation = " | ".join(changes)
        log_event("FIM", "REVIEW", 75, "File Integrity Drift Detected", explanation, is_simulated=False)
        return jsonify({"status": "drift", "risk_score": 75, "explanation": explanation})

    explanation = f"All {len(baseline)} monitored file(s) match their trusted SHA-256 hashes."
    log_event("FIM", "ALLOW", 5, "File Integrity Verified", explanation, is_simulated=False)
    return jsonify({"status": "clean", "risk_score": 5, "explanation": explanation})


@app.route("/api/network/simulate", methods=["POST"])
def network_simulate():
    simulated_events = [
        ("ALLOW", 10, "[SIMULATED] Local Health Traffic", "Authorized loopback traffic on 127.0.0.1:5000 within normal rate."),
        ("REVIEW", 62, "[SIMULATED] Port Sweep Pattern", "Local test simulation: rapid connection attempts across ports 22, 80, 443."),
        ("BLOCK", 88, "[SIMULATED] Suspicious Outbound Spike", "Local test simulation: repeated beacon pattern flagged by rate-threshold rule."),
    ]
    for action, score, title, desc in simulated_events:
        log_event("NETWORK", action, score, title, desc, is_simulated=True)
    return jsonify({"status": "ok", "generated": len(simulated_events)})


if __name__ == "__main__":
    init_db()
    init_fim_sandbox()
    app.run(host="127.0.0.1", port=5000, debug=False)