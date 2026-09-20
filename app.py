# ============================================================
# IMPORTS
# ============================================================

from flask import Flask, request, jsonify, send_file, render_template
from dotenv import load_dotenv
from supabase import create_client, Client
import os
import bcrypt
import jwt
import json
import requests
import socket
import ssl

from urllib.parse import urlparse
from html import escape
from datetime import datetime, timedelta, timezone

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER


# ============================================================
# LOAD ENVIRONMENT
# ============================================================

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Supabase environment variables are missing!")

if not JWT_SECRET:
    raise ValueError("JWT_SECRET is missing from .env!")


# ============================================================
# SUPABASE
# ============================================================

supabase: Client = create_client(
    SUPABASE_URL,
    SUPABASE_KEY
)


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)


# ============================================================
# SECURITY RISK SCORE
# ============================================================

def calculate_risk_score(severity_summary):
    """
    WebShield Pro custom risk scoring model.

    Starting score: 100
    Critical: -25 each
    High:     -15 each
    Medium:   -8 each
    Low:      -3 each
    Info:      0

    This is a project-specific heuristic, not a standardized
    industry security rating.
    """

    critical = int(severity_summary.get("critical", 0) or 0)
    high = int(severity_summary.get("high", 0) or 0)
    medium = int(severity_summary.get("medium", 0) or 0)
    low = int(severity_summary.get("low", 0) or 0)

    score = 100

    score -= critical * 25
    score -= high * 15
    score -= medium * 8
    score -= low * 3

    score = max(0, min(100, score))

    if score >= 90:
        level = "EXCELLENT"
    elif score >= 75:
        level = "GOOD"
    elif score >= 50:
        level = "MEDIUM"
    elif score >= 25:
        level = "HIGH RISK"
    else:
        level = "CRITICAL RISK"

    return score, level




# ============================================================
# OWASP-ALIGNED SECURITY CATEGORY MAPPING
# ============================================================

def get_owasp_category(check_type, title=""):
    """
    Map WebShield Pro passive checks to an OWASP Top 10-style
    category without changing the database schema or risk score.

    This is an assessment/reporting mapping, not a claim that the
    scanner provides complete coverage of the selected OWASP category.
    """

    check = str(check_type or "").lower()
    title_lower = str(title or "").lower()

    if check in {"https", "tls", "ssl"}:
        return "A02 - Cryptographic Failures"

    if check == "security_header":
        if "strict-transport-security" in title_lower or "hsts" in title_lower:
            return "A02 - Cryptographic Failures"
        return "A05 - Security Misconfiguration"

    if check in {
        "cors",
        "cookie_security",
        "server_information",
        "redirect",
        "redirect_header",
        "http_methods",
        "cache_control",
        "content_type"
    }:
        return "A05 - Security Misconfiguration"

    if check in {"connection", "availability", "http_status", "dns"}:
        return "General Security Posture"

    return "General Security Posture"


def add_owasp_category(result):
    """Return a result copy enriched with its OWASP-aligned category."""
    enriched = dict(result or {})
    enriched["owasp_category"] = get_owasp_category(
        enriched.get("check_type"),
        enriched.get("title")
    )
    return enriched


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return "WebShield Pro is Running!"


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")


# ============================================================
# TEST DATABASE
# ============================================================

@app.route("/test-db", methods=["GET"])
def test_db():

    try:

        response = (
            supabase
            .table("users")
            .select("*")
            .limit(1)
            .execute()
        )

        return jsonify({
            "status": "success",
            "message": "Supabase connected successfully!",
            "data": response.data
        }), 200

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# JWT TOKEN VERIFICATION
# ============================================================

def verify_token():

    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return None

    try:

        parts = auth_header.split(" ")

        if len(parts) != 2:
            return None

        if parts[0] != "Bearer":
            return None

        token = parts[1]

        decoded = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )

        return decoded

    except Exception:

        return None


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebShield Pro - Register</title>
    <style>
        * { box-sizing: border-box; font-family: Arial, sans-serif; }
        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #111827, #2563eb);
        }
        .card {
            width: 400px;
            max-width: 92%;
            background: white;
            padding: 32px;
            border-radius: 16px;
            box-shadow: 0 15px 40px rgba(0,0,0,0.25);
        }
        h1 { text-align: center; margin-bottom: 8px; color: #111827; }
        .subtitle { text-align: center; color: #6b7280; margin-bottom: 25px; }
        label {
            display: block;
            margin: 14px 0 7px;
            font-weight: bold;
            color: #374151;
        }
        input {
            width: 100%;
            padding: 13px;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            font-size: 15px;
        }
        button {
            width: 100%;
            margin-top: 22px;
            padding: 13px;
            border: none;
            border-radius: 8px;
            background: #2563eb;
            color: white;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
        }
        button:hover { background: #1d4ed8; }
        #message {
            margin-top: 15px;
            padding: 11px;
            border-radius: 8px;
            display: none;
            text-align: center;
        }
        .success { background: #dcfce7; color: #166534; }
        .error { background: #fee2e2; color: #991b1b; }
        .login-link {
            text-align: center;
            margin-top: 20px;
            color: #6b7280;
        }
        .login-link a {
            color: #2563eb;
            font-weight: bold;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="card">
        <h1>🛡️ WebShield Pro</h1>
        <div class="subtitle">Create your security account</div>

        <form id="registerForm">
            <label>Name</label>
            <input type="text" id="name" placeholder="Enter your name" required>

            <label>Email Address</label>
            <input type="email" id="email" placeholder="Enter your email" required>

            <label>Password</label>
            <input type="password" id="password" placeholder="Enter your password" required>

            <button type="submit">Create Account</button>
        </form>

        <div id="message"></div>

        <div class="login-link">
            Already have an account?
            <a href="/login">Login</a>
        </div>
    </div>

    <script>
        document.getElementById("registerForm").addEventListener("submit", async function(event) {
            event.preventDefault();

            const message = document.getElementById("message");

            const name = document.getElementById("name").value.trim();
            const email = document.getElementById("email").value.trim();
            const password = document.getElementById("password").value;

            try {
                const response = await fetch("/register", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        name: name,
                        email: email,
                        password: password
                    })
                });

                const data = await response.json();

                if (!response.ok) {
                    message.className = "error";
                    message.innerText = data.message || "Registration failed.";
                    message.style.display = "block";
                    return;
                }

                message.className = "success";
                message.innerText = "Registration successful! Redirecting to login...";
                message.style.display = "block";

                setTimeout(function() {
                    window.location.href = "/login";
                }, 1200);

            } catch (error) {
                message.className = "error";
                message.innerText = "Server connection failed.";
                message.style.display = "block";
            }
        });
    </script>
</body>
</html>
"""

    try:

        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "JSON data is required"
            }), 400

        name = data.get("name")
        email = data.get("email")
        password = data.get("password")

        if not name or not email or not password:
            return jsonify({
                "status": "error",
                "message": "Name, email and password are required"
            }), 400

        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        response = (
            supabase
            .table("users")
            .insert({
                "name": name,
                "email": email,
                "password_hash": password_hash,
                "role": "user",
                "is_active": True
            })
            .execute()
        )

        return jsonify({
            "status": "success",
            "message": "User registered successfully!",
            "data": response.data
        }), 201

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    try:

        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "JSON data is required"
            }), 400

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({
                "status": "error",
                "message": "Email and password are required"
            }), 400

        response = (
            supabase
            .table("users")
            .select("*")
            .eq("email", email)
            .limit(1)
            .execute()
        )

        if not response.data:
            return jsonify({
                "status": "error",
                "message": "Invalid email or password"
            }), 401

        user = response.data[0]

        if not bcrypt.checkpw(
            password.encode("utf-8"),
            user["password_hash"].encode("utf-8")
        ):
            return jsonify({
                "status": "error",
                "message": "Invalid email or password"
            }), 401

        if not user.get("is_active", True):
            return jsonify({
                "status": "error",
                "message": "User account is inactive"
            }), 403

        token = jwt.encode(
            {
                "user_id": user["id"],
                "email": user["email"],
                "role": user["role"],
                "exp": datetime.now(timezone.utc)
                + timedelta(hours=2)
            },
            JWT_SECRET,
            algorithm="HS256"
        )

        return jsonify({
            "status": "success",
            "message": "Login successful!",
            "data": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"],
                "token": token
            }
        }), 200

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# PROFILE
# ============================================================

@app.route("/profile", methods=["GET"])
def profile():

    user = verify_token()

    if not user:
        return jsonify({
            "status": "error",
            "message": "Invalid or missing token"
        }), 401

    return jsonify({
        "status": "success",
        "message": "Protected profile accessed!",
        "data": user
    }), 200


# ============================================================
# ADD TARGET
# ============================================================

@app.route("/targets", methods=["POST"])
def add_target():

    try:

        user = verify_token()

        if not user:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing token"
            }), 401

        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "JSON data is required"
            }), 400

        name = data.get("name")
        url = data.get("url")
        domain = data.get("domain")
        ip_address = data.get("ip_address")

        if not name or not url or not domain:
            return jsonify({
                "status": "error",
                "message": "Name, URL and domain are required"
            }), 400

        response = (
            supabase
            .table("targets")
            .insert({
                "user_id": user["user_id"],
                "name": name,
                "url": url,
                "domain": domain,
                "ip_address": ip_address
            })
            .execute()
        )

        return jsonify({
            "status": "success",
            "message": "Target added successfully!",
            "data": response.data
        }), 201

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# GET TARGETS
# ============================================================

@app.route("/targets", methods=["GET"])
def get_targets():

    try:

        user = verify_token()

        if not user:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing token"
            }), 401

        response = (
            supabase
            .table("targets")
            .select("*")
            .eq("user_id", user["user_id"])
            .execute()
        )

        return jsonify({
            "status": "success",
            "message": "Targets retrieved successfully!",
            "data": response.data
        }), 200

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# START MANUAL SCAN
# ============================================================

@app.route("/scan", methods=["POST"])
def start_scan():

    try:

        user = verify_token()

        if not user:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing token"
            }), 401

        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "JSON data is required"
            }), 400

        target_id = data.get("target_id")

        if not target_id:
            return jsonify({
                "status": "error",
                "message": "target_id is required"
            }), 400

        target_response = (
            supabase
            .table("targets")
            .select("*")
            .eq("id", target_id)
            .eq("user_id", user["user_id"])
            .limit(1)
            .execute()
        )

        if not target_response.data:
            return jsonify({
                "status": "error",
                "message": "Target not found"
            }), 404

        scan_response = (
            supabase
            .table("scans")
            .insert({
                "target_id": target_id,
                "user_id": user["user_id"],
                "status": "pending"
            })
            .execute()
        )

        return jsonify({
            "status": "success",
            "message": "Scan created successfully!",
            "data": scan_response.data
        }), 201

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# ADD SCAN RESULT
# ============================================================

@app.route("/scan-results", methods=["POST"])
def add_scan_result():

    try:

        user = verify_token()

        if not user:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing token"
            }), 401

        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "JSON data is required"
            }), 400

        scan_id = data.get("scan_id")
        check_type = data.get("check_type")
        title = data.get("title")
        severity = data.get("severity")
        affected_url = data.get("affected_url")
        description = data.get("description")
        evidence = data.get("evidence")
        remediation = data.get("remediation")
        status = data.get("status", "open")

        if not scan_id or not check_type or not title or not severity:
            return jsonify({
                "status": "error",
                "message": "scan_id, check_type, title and severity are required"
            }), 400

        response = (
            supabase
            .table("scan_results")
            .insert({
                "scan_id": scan_id,
                "check_type": check_type,
                "title": title,
                "severity": severity,
                "affected_url": affected_url,
                "description": description,
                "evidence": evidence,
                "remediation": remediation,
                "status": status
            })
            .execute()
        )

        return jsonify({
            "status": "success",
            "message": "Scan result added successfully!",
            "data": response.data
        }), 201

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# GET SCAN RESULTS
# ============================================================

@app.route("/scan-results/<int:scan_id>", methods=["GET"])
def get_scan_results(scan_id):

    try:

        user = verify_token()

        if not user:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing token"
            }), 401

        scan_response = (
            supabase
            .table("scans")
            .select("*")
            .eq("id", scan_id)
            .eq("user_id", user["user_id"])
            .limit(1)
            .execute()
        )

        if not scan_response.data:
            return jsonify({
                "status": "error",
                "message": "Scan not found or access denied"
            }), 404

        response = (
            supabase
            .table("scan_results")
            .select("*")
            .eq("scan_id", scan_id)
            .execute()
        )

        enriched_results = [
            add_owasp_category(result)
            for result in (response.data or [])
        ]

        return jsonify({
            "status": "success",
            "message": "Scan results retrieved successfully!",
            "data": enriched_results
        }), 200

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# SAFE WEB SECURITY SCANNER
# ============================================================

@app.route("/security-scan/<int:scan_id>", methods=["POST"])
def security_scan(scan_id):
    """
    Run security checks for an existing scan.
    The /scan endpoint creates the scan first.
    This endpoint only performs the checks and saves findings
    against that existing scan_id.
    """

    try:
        # ========================================================
        # AUTHENTICATION
        # ========================================================
        user = verify_token()

        if not user:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing token"
            }), 401

        # ========================================================
        # GET EXISTING SCAN
        # ========================================================
        scan_response = (
            supabase
            .table("scans")
            .select("*")
            .eq("id", scan_id)
            .eq("user_id", user["user_id"])
            .limit(1)
            .execute()
        )

        if not scan_response.data:
            return jsonify({
                "status": "error",
                "message": "Scan not found or access denied"
            }), 404

        scan = scan_response.data[0]
        target_id = scan.get("target_id")

        if not target_id:
            return jsonify({
                "status": "error",
                "message": "Target ID missing from scan"
            }), 400

        # ========================================================
        # GET TARGET
        # ========================================================
        target_response = (
            supabase
            .table("targets")
            .select("*")
            .eq("id", target_id)
            .eq("user_id", user["user_id"])
            .limit(1)
            .execute()
        )

        if not target_response.data:
            return jsonify({
                "status": "error",
                "message": "Target not found or access denied"
            }), 404

        target = target_response.data[0]
        target_url = target.get("url")

        if not target_url:
            return jsonify({
                "status": "error",
                "message": "Target URL is missing"
            }), 400

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed_url = urlparse(target_url)

        if not parsed_url.hostname:
            return jsonify({
                "status": "error",
                "message": "Invalid target URL"
            }), 400

        # ========================================================
        # MARK SCAN AS RUNNING
        # ========================================================
        supabase.table("scans").update({
            "status": "running"
        }).eq("id", scan_id).execute()

        findings = []
        response = None

        # ========================================================
        # HTTP / HTTPS CHECKS
        # ========================================================
        try:
            response = requests.get(
                target_url,
                timeout=10,
                allow_redirects=True,
                headers={
                    "User-Agent": "WebShield-Pro-Security-Scanner/1.0"
                }
            )

            final_url = response.url
            headers = response.headers

            # HTTPS
            # Check the FINAL destination as well as the original URL.
            # An HTTP URL that safely redirects to HTTPS should not be
            # reported as "HTTPS Not Enabled".
            final_scheme = urlparse(final_url).scheme.lower()

            if final_scheme == "https":
                if parsed_url.scheme.lower() == "http":
                    https_description = (
                        "The target started over HTTP and redirected to an HTTPS destination."
                    )
                    https_evidence = (
                        f"Original URL: {target_url}\\n"
                        f"Final URL: {final_url}\\n"
                        f"Final scheme: HTTPS"
                    )
                else:
                    https_description = "The target is accessible over HTTPS."
                    https_evidence = (
                        f"Original URL: {target_url}\\n"
                        f"Final URL: {final_url}\\n"
                        f"Final scheme: HTTPS"
                    )

                findings.append({
                    "check_type": "https",
                    "title": "HTTPS Enabled",
                    "severity": "info",
                    "affected_url": final_url,
                    "description": https_description,
                    "evidence": https_evidence,
                    "remediation": "Continue using HTTPS and keep TLS configuration updated.",
                    "status": "open"
                })
            else:
                findings.append({
                    "check_type": "https",
                    "title": "HTTPS Not Enabled",
                    "severity": "high",
                    "affected_url": final_url,
                    "description": "The final destination is accessible without HTTPS.",
                    "evidence": (
                        f"Original URL: {target_url}\\n"
                        f"Final URL: {final_url}\\n"
                        f"Final scheme: {final_scheme.upper() or 'UNKNOWN'}"
                    ),
                    "remediation": "Enable HTTPS and redirect HTTP traffic to HTTPS.",
                    "status": "open"
                })

            # HTTP status
            findings.append({
                "check_type": "http_status",
                "title": "HTTP Response Status",
                "severity": "info",
                "affected_url": final_url,
                "description": f"The server returned HTTP status {response.status_code}.",
                "evidence": f"HTTP {response.status_code}",
                "remediation": "Review the response status and ensure expected application behavior.",
                "status": "open"
            })

            # Security headers
            security_headers = {
                "Strict-Transport-Security": {
                    "severity": "medium",
                    "description": "HSTS helps enforce HTTPS connections.",
                    "remediation": "Add a suitable Strict-Transport-Security header."
                },
                "Content-Security-Policy": {
                    "severity": "medium",
                    "description": "CSP helps reduce risks such as cross-site scripting.",
                    "remediation": "Define and deploy an appropriate Content-Security-Policy."
                },
                "X-Content-Type-Options": {
                    "severity": "low",
                    "description": "This header helps prevent MIME-type sniffing.",
                    "remediation": "Set X-Content-Type-Options to nosniff."
                },
                "X-XSS-Protection": {
                    "severity": "low",
                    "description": "Legacy browser security header related to built-in XSS filtering.",
                    "remediation": "Configure X-XSS-Protection appropriately for legacy browser compatibility. Modern applications should primarily use a strong Content-Security-Policy."
                },
                "X-Frame-Options": {
                    "severity": "low",
                    "description": "This header can help protect against clickjacking.",
                    "remediation": "Set X-Frame-Options or an appropriate CSP frame-ancestors policy."
                },
                "Referrer-Policy": {
                    "severity": "low",
                    "description": "This header controls referrer information.",
                    "remediation": "Configure an appropriate Referrer-Policy."
                },
                "Permissions-Policy": {
                    "severity": "low",
                    "description": "This header controls browser capabilities.",
                    "remediation": "Configure a suitable Permissions-Policy."
                }
            }

            # Check the final HTTP response headers
            for header_name, details in security_headers.items():

                header_value = headers.get(header_name)

                if header_value:
                    findings.append({
                        "check_type": "security_header",
                        "title": f"{header_name} Present",
                        "severity": "info",
                        "affected_url": final_url,
                        "description": details["description"],
                        "evidence": (
                            f"Header: {header_name}\n"
                            f"Status: PRESENT\n"
                            f"Value: {header_value}\n"
                            f"Checked URL: {final_url}"
                        ),
                        "remediation": "Keep the header correctly configured and reviewed.",
                        "status": "open"
                    })

                else:
                    findings.append({
                        "check_type": "security_header",
                        "title": f"Missing {header_name}",
                        "severity": details["severity"],
                        "affected_url": final_url,
                        "description": details["description"],
                        "evidence": (
                            f"Header: {header_name}\n"
                            f"Status: MISSING\n"
                            f"Checked URL: {final_url}"
                        ),
                        "remediation": details["remediation"],
                        "status": "open"
                    })

            # Cookies
            # Parse Set-Cookie attributes instead of searching raw strings.
            # This avoids false positives such as matching "secure" inside a
            # cookie value or another attribute name. Cookie values are masked
            # in evidence so sensitive session data is not exposed in reports.
            try:
                set_cookie_headers = response.raw.headers.get_all("Set-Cookie")
            except Exception:
                set_cookie_headers = []

            if not set_cookie_headers:
                cookie_header = headers.get("Set-Cookie")
                set_cookie_headers = [cookie_header] if cookie_header else []

            if set_cookie_headers:
                for cookie in set_cookie_headers:
                    parts = [part.strip() for part in cookie.split(";")]
                    cookie_pair = parts[0] if parts else ""

                    if "=" in cookie_pair:
                        cookie_name, cookie_value = cookie_pair.split("=", 1)
                        cookie_name = cookie_name.strip() or "Unnamed Cookie"
                    else:
                        cookie_name = cookie_pair.strip() or "Unnamed Cookie"
                        cookie_value = ""

                    attributes = {}
                    flags = set()

                    for attribute in parts[1:]:
                        attribute = attribute.strip()
                        if not attribute:
                            continue

                        if "=" in attribute:
                            attr_name, attr_value = attribute.split("=", 1)
                            attributes[attr_name.strip().lower()] = attr_value.strip()
                        else:
                            flags.add(attribute.lower())

                    secure_present = "secure" in flags
                    httponly_present = "httponly" in flags
                    samesite_value = attributes.get("samesite")
                    samesite_present = samesite_value is not None

                    masked_value = "[masked]" if cookie_value else "[empty]"
                    cookie_evidence = (
                        f"Cookie: {cookie_name}\n"
                        f"Value: {masked_value}\n"
                        f"Secure: {'PRESENT' if secure_present else 'MISSING'}\n"
                        f"HttpOnly: {'PRESENT' if httponly_present else 'MISSING'}\n"
                        f"SameSite: {samesite_value if samesite_present else 'MISSING'}"
                    )

                    if secure_present:
                        findings.append({
                            "check_type": "cookie_security",
                            "title": "Cookie Secure Flag Present",
                            "severity": "info",
                            "affected_url": final_url,
                            "description": f"Cookie '{cookie_name}' includes the Secure attribute.",
                            "evidence": cookie_evidence,
                            "remediation": "Keep the Secure attribute enabled for cookies that should only be sent over HTTPS.",
                            "status": "open"
                        })
                    else:
                        findings.append({
                            "check_type": "cookie_security",
                            "title": "Cookie Missing Secure Flag",
                            "severity": "medium",
                            "affected_url": final_url,
                            "description": f"Cookie '{cookie_name}' does not include the Secure attribute.",
                            "evidence": cookie_evidence,
                            "remediation": "Set the Secure attribute for cookies that should only be sent over HTTPS.",
                            "status": "open"
                        })

                    if httponly_present:
                        findings.append({
                            "check_type": "cookie_security",
                            "title": "Cookie HttpOnly Flag Present",
                            "severity": "info",
                            "affected_url": final_url,
                            "description": f"Cookie '{cookie_name}' includes the HttpOnly attribute.",
                            "evidence": cookie_evidence,
                            "remediation": "Keep HttpOnly enabled for cookies that do not need JavaScript access.",
                            "status": "open"
                        })
                    else:
                        findings.append({
                            "check_type": "cookie_security",
                            "title": "Cookie Missing HttpOnly Flag",
                            "severity": "medium",
                            "affected_url": final_url,
                            "description": f"Cookie '{cookie_name}' does not include the HttpOnly attribute.",
                            "evidence": cookie_evidence,
                            "remediation": "Use HttpOnly for cookies that do not need JavaScript access.",
                            "status": "open"
                        })

                    if samesite_present:
                        normalized_samesite = str(samesite_value).lower()
                        if normalized_samesite in {"strict", "lax", "none"}:
                            findings.append({
                                "check_type": "cookie_security",
                                "title": "Cookie SameSite Attribute Present",
                                "severity": "info",
                                "affected_url": final_url,
                                "description": f"Cookie '{cookie_name}' defines SameSite={samesite_value}.",
                                "evidence": cookie_evidence,
                                "remediation": "Keep the SameSite setting appropriate for the application's cross-site requirements.",
                                "status": "open"
                            })
                        else:
                            findings.append({
                                "check_type": "cookie_security",
                                "title": "Cookie Invalid SameSite Attribute",
                                "severity": "low",
                                "affected_url": final_url,
                                "description": f"Cookie '{cookie_name}' uses an unrecognized SameSite value.",
                                "evidence": cookie_evidence,
                                "remediation": "Use SameSite=Strict, SameSite=Lax, or SameSite=None as appropriate.",
                                "status": "open"
                            })
                    else:
                        findings.append({
                            "check_type": "cookie_security",
                            "title": "Cookie Missing SameSite Attribute",
                            "severity": "low",
                            "affected_url": final_url,
                            "description": f"Cookie '{cookie_name}' does not explicitly define SameSite behavior.",
                            "evidence": cookie_evidence,
                            "remediation": "Set an appropriate SameSite attribute.",
                            "status": "open"
                        })
            else:
                findings.append({
                    "check_type": "cookie_security",
                    "title": "No Set-Cookie Header Observed",
                    "severity": "info",
                    "affected_url": final_url,
                    "description": "No Set-Cookie header was observed.",
                    "evidence": "Set-Cookie header not present.",
                    "remediation": "No action required unless the application is expected to set cookies.",
                    "status": "open"
                })


            # Server / technology information disclosure
            # Check common response headers that may reveal server or framework details.
            technology_headers = [
                "Server",
                "X-Powered-By",
                "X-AspNet-Version",
                "X-AspNetMvc-Version"
            ]

            disclosed_headers = []

            for tech_header in technology_headers:
                tech_value = headers.get(tech_header)
                if tech_value:
                    disclosed_headers.append(
                        f"{tech_header}: {tech_value}"
                    )

            if disclosed_headers:
                findings.append({
                    "check_type": "server_information",
                    "title": "Server / Technology Information Disclosed",
                    "severity": "low",
                    "affected_url": final_url,
                    "description": "The HTTP response exposes one or more headers that may reveal server or technology details.",
                    "evidence": "\n".join(disclosed_headers),
                    "remediation": "Consider minimizing unnecessary server and framework identification headers where practical.",
                    "status": "open"
                })
            else:
                findings.append({
                    "check_type": "server_information",
                    "title": "Server / Technology Information Not Disclosed",
                    "severity": "info",
                    "affected_url": final_url,
                    "description": "No common server or framework identification headers were observed.",
                    "evidence": "Checked: Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version",
                    "remediation": "No action required.",
                    "status": "open"
                })

            # Redirects
            if response.history:
                redirect_chain = [
                    f"{redirect.status_code} -> {redirect.url}"
                    for redirect in response.history
                ]
                redirect_chain.append(
                    f"{response.status_code} -> {response.url}"
                )

                findings.append({
                    "check_type": "redirect",
                    "title": "HTTP Redirect Chain Detected",
                    "severity": "info",
                    "affected_url": final_url,
                    "description": "The target used one or more HTTP redirects.",
                    "evidence": " | ".join(redirect_chain),
                    "remediation": "Review redirects and ensure they lead to the intended destination.",
                    "status": "open"
                })

                # --------------------------------------------------------
                # REDIRECT RESPONSE HEADER CONSISTENCY
                # --------------------------------------------------------
                # Inspect every response in the redirect chain, not only
                # the final response. This is an informational check and
                # does not increase the security risk score.
                redirect_responses = list(response.history) + [response]

                redirect_header_names = [
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Content-Type-Options",
                    "X-XSS-Protection",
                    "X-Frame-Options",
                    "Referrer-Policy",
                    "Permissions-Policy"
                ]

                for hop_index, hop_response in enumerate(redirect_responses, start=1):
                    hop_url = hop_response.url
                    hop_headers = hop_response.headers

                    missing_headers = [
                        header_name
                        for header_name in redirect_header_names
                        if not hop_headers.get(header_name)
                    ]

                    present_headers = [
                        header_name
                        for header_name in redirect_header_names
                        if hop_headers.get(header_name)
                    ]

                    header_evidence = (
                        f"Redirect hop: {hop_index}\\n"
                        f"HTTP status: {hop_response.status_code}\\n"
                        f"URL: {hop_url}\\n"
                        f"Security headers present: "
                        f"{', '.join(present_headers) if present_headers else 'None'}\\n"
                        f"Security headers missing: "
                        f"{', '.join(missing_headers) if missing_headers else 'None'}"
                    )

                    findings.append({
                        "check_type": "redirect_header",
                        "title": f"Redirect Hop {hop_index} Security Headers",
                        "severity": "info",
                        "affected_url": hop_url,
                        "description": (
                            "Security response headers were inspected on this "
                            "redirect response."
                        ),
                        "evidence": header_evidence,
                        "remediation": (
                            "Review security headers across redirect responses "
                            "and keep the final HTTPS response correctly configured."
                        ),
                        "status": "open"
                    })
            else:
                findings.append({
                    "check_type": "redirect",
                    "title": "No Redirect Chain Detected",
                    "severity": "info",
                    "affected_url": final_url,
                    "description": "No HTTP redirect was observed.",
                    "evidence": "Response history is empty.",
                    "remediation": "No action required.",
                    "status": "open"
                })

        except requests.exceptions.SSLError as e:
            findings.append({
                "check_type": "ssl",
                "title": "TLS/SSL Connection Error",
                "severity": "high",
                "affected_url": target_url,
                "description": "The HTTPS connection could not be established because of a TLS/SSL error.",
                "evidence": str(e)[:1000],
                "remediation": "Review the server certificate and TLS configuration.",
                "status": "open"
            })

        except requests.exceptions.Timeout as e:
            findings.append({
                "check_type": "availability",
                "title": "Request Timeout",
                "severity": "medium",
                "affected_url": target_url,
                "description": "The target did not respond within the scanner timeout.",
                "evidence": str(e),
                "remediation": "Verify that the target is reachable and responding normally.",
                "status": "open"
            })

        except requests.exceptions.RequestException as e:
            findings.append({
                "check_type": "connection",
                "title": "Connection Error",
                "severity": "high",
                "affected_url": target_url,
                "description": "The scanner could not complete the HTTP request.",
                "evidence": str(e)[:1000],
                "remediation": "Verify the target URL is reachable.",
                "status": "open"
            })

        # ========================================================
        # DNS CHECK
        # ========================================================
        try:
            hostname = parsed_url.hostname
            addrinfo = socket.getaddrinfo(
                hostname,
                None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM
            )

            resolved_addresses = []
            for item in addrinfo:
                address = item[4][0]
                if address not in resolved_addresses:
                    resolved_addresses.append(address)

            findings.append({
                "check_type": "dns",
                "title": "DNS Resolution",
                "severity": "info",
                "affected_url": target_url,
                "description": "The target hostname resolved successfully.",
                "evidence": (
                    f"Hostname: {hostname}\n"
                    f"Resolved addresses: {', '.join(resolved_addresses)}"
                ),
                "remediation": "No action required.",
                "status": "open"
            })

        except socket.gaierror as e:
            findings.append({
                "check_type": "dns",
                "title": "DNS Resolution Failed",
                "severity": "medium",
                "affected_url": target_url,
                "description": "The target hostname could not be resolved.",
                "evidence": str(e)[:1000],
                "remediation": "Verify the domain name and DNS configuration.",
                "status": "open"
            })

        except Exception as e:
            findings.append({
                "check_type": "dns",
                "title": "DNS Resolution Check Error",
                "severity": "low",
                "affected_url": target_url,
                "description": "The scanner could not complete the DNS resolution check.",
                "evidence": str(e)[:1000],
                "remediation": "Review the target hostname and scanner environment.",
                "status": "open"
            })

        # ========================================================
        # TLS / SSL CERTIFICATE CHECK
        # ========================================================
        if parsed_url.scheme == "https":
            try:
                tls_port = parsed_url.port or 443
                context = ssl.create_default_context()

                with socket.create_connection(
                    (parsed_url.hostname, tls_port),
                    timeout=10
                ) as raw_socket:
                    with context.wrap_socket(
                        raw_socket,
                        server_hostname=parsed_url.hostname
                    ) as tls_socket:
                        certificate = tls_socket.getpeercert()
                        cipher = tls_socket.cipher()
                        protocol = tls_socket.version()

                subject = dict(
                    item[0] for item in certificate.get("subject", [])
                ) if certificate else {}
                issuer = dict(
                    item[0] for item in certificate.get("issuer", [])
                ) if certificate else {}

                findings.append({
                    "check_type": "tls",
                    "title": "TLS Certificate Valid",
                    "severity": "info",
                    "affected_url": final_url,
                    "description": "A trusted TLS connection was established and the certificate was accepted by the system trust store.",
                    "evidence": (
                        f"Hostname: {parsed_url.hostname}\n"
                        f"TLS Version: {protocol or 'Unknown'}\n"
                        f"Cipher: {cipher[0] if cipher else 'Unknown'}\n"
                        f"Subject CN: {subject.get('commonName', 'Unknown')}\n"
                        f"Issuer CN: {issuer.get('commonName', 'Unknown')}"
                    ),
                    "remediation": "Keep the certificate valid, trusted, and renewed before expiration.",
                    "status": "open"
                })

            except ssl.SSLCertVerificationError as e:
                findings.append({
                    "check_type": "tls",
                    "title": "TLS Certificate Verification Failed",
                    "severity": "high",
                    "affected_url": target_url,
                    "description": "The TLS certificate could not be verified against the system trust store.",
                    "evidence": str(e)[:1000],
                    "remediation": "Install a valid certificate chain and ensure the certificate matches the hostname.",
                    "status": "open"
                })

            except (ssl.SSLError, socket.timeout, OSError) as e:
                findings.append({
                    "check_type": "tls",
                    "title": "TLS Connection Check Failed",
                    "severity": "high",
                    "affected_url": target_url,
                    "description": "The scanner could not complete the TLS certificate check.",
                    "evidence": str(e)[:1000],
                    "remediation": "Review the server TLS configuration, certificate chain, hostname, and network connectivity.",
                    "status": "open"
                })

        # ========================================================

        # ========================================================
        # ADDITIONAL PASSIVE WEB SECURITY CHECKS
        # ========================================================
        # These checks inspect normal response headers and use a safe
        # OPTIONS request only to discover advertised HTTP methods.

        # CORS configuration
        cors_origin = headers.get("Access-Control-Allow-Origin")
        cors_credentials = headers.get("Access-Control-Allow-Credentials")

        if cors_origin:
            if cors_origin.strip() == "*":
                if str(cors_credentials).lower() == "true":
                    findings.append({
                        "check_type": "cors",
                        "title": "CORS Wildcard with Credentials",
                        "severity": "medium",
                        "affected_url": final_url,
                        "description": "The response allows any origin while also allowing credentials.",
                        "evidence": (
                            f"Access-Control-Allow-Origin: {cors_origin}\n"
                            f"Access-Control-Allow-Credentials: {cors_credentials}"
                        ),
                        "remediation": "Avoid wildcard origins when credentials are allowed. Restrict allowed origins to trusted application origins.",
                        "status": "open"
                    })
                else:
                    findings.append({
                        "check_type": "cors",
                        "title": "CORS Wildcard Origin",
                        "severity": "low",
                        "affected_url": final_url,
                        "description": "The response allows cross-origin requests from any origin.",
                        "evidence": (
                            f"Access-Control-Allow-Origin: {cors_origin}\n"
                            f"Access-Control-Allow-Credentials: {cors_credentials or 'Not set'}"
                        ),
                        "remediation": "Use an explicit allowlist of trusted origins when unrestricted cross-origin access is not required.",
                        "status": "open"
                    })
            else:
                findings.append({
                    "check_type": "cors",
                    "title": "CORS Restricted Origin",
                    "severity": "info",
                    "affected_url": final_url,
                    "description": "The response specifies an explicit CORS origin.",
                    "evidence": (
                        f"Access-Control-Allow-Origin: {cors_origin}\n"
                        f"Access-Control-Allow-Credentials: {cors_credentials or 'Not set'}"
                    ),
                    "remediation": "Review the allowed origin against the application's trusted-origin policy.",
                    "status": "open"
                })
        else:
            findings.append({
                "check_type": "cors",
                "title": "CORS Header Not Observed",
                "severity": "info",
                "affected_url": final_url,
                "description": "No Access-Control-Allow-Origin header was observed in the response.",
                "evidence": "Access-Control-Allow-Origin header not present.",
                "remediation": "No action required unless the application needs cross-origin resource sharing.",
                "status": "open"
            })

        # Cache-Control
        cache_control = headers.get("Cache-Control")
        pragma = headers.get("Pragma")

        if cache_control:
            cache_lower = cache_control.lower()
            sensitive_cache_controls = (
                "no-store" in cache_lower
                or "private" in cache_lower
            )

            findings.append({
                "check_type": "cache_control",
                "title": "Cache-Control Header Present",
                "severity": "info",
                "affected_url": final_url,
                "description": "The response defines browser/proxy caching behavior.",
                "evidence": (
                    f"Cache-Control: {cache_control}\n"
                    f"Pragma: {pragma or 'Not set'}\n"
                    f"Sensitive-data protection directives: "
                    f"{'PRESENT' if sensitive_cache_controls else 'NOT OBSERVED'}"
                ),
                "remediation": "For sensitive or authenticated content, review caching directives and use no-store/private where appropriate.",
                "status": "open"
            })
        else:
            findings.append({
                "check_type": "cache_control",
                "title": "Cache-Control Header Not Observed",
                "severity": "low",
                "affected_url": final_url,
                "description": "No Cache-Control response header was observed.",
                "evidence": f"Cache-Control: MISSING\nPragma: {pragma or 'Not set'}",
                "remediation": "Define explicit caching behavior, especially for authenticated or sensitive responses.",
                "status": "open"
            })

        # Content-Type
        content_type = headers.get("Content-Type")

        if content_type:
            mime_type = content_type.split(";", 1)[0].strip().lower()
            findings.append({
                "check_type": "content_type",
                "title": "Content-Type Header Present",
                "severity": "info",
                "affected_url": final_url,
                "description": "The response declares a Content-Type.",
                "evidence": f"Content-Type: {content_type}",
                "remediation": "Keep Content-Type accurate for the returned resource.",
                "status": "open"
            })
        else:
            findings.append({
                "check_type": "content_type",
                "title": "Content-Type Header Missing",
                "severity": "low",
                "affected_url": final_url,
                "description": "The response does not declare a Content-Type header.",
                "evidence": "Content-Type header not present.",
                "remediation": "Return an accurate Content-Type header for application responses.",
                "status": "open"
            })

        # Safe HTTP method discovery using OPTIONS
        try:
            options_response = requests.options(
                final_url,
                timeout=10,
                allow_redirects=False,
                headers={
                    "User-Agent": "WebShield-Pro-Security-Scanner/1.0"
                }
            )

            allow_header = options_response.headers.get("Allow")

            if allow_header:
                advertised_methods = [
                    method.strip().upper()
                    for method in allow_header.split(",")
                    if method.strip()
                ]

                risky_methods = [
                    method for method in advertised_methods
                    if method in {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
                ]

                if risky_methods:
                    findings.append({
                        "check_type": "http_methods",
                        "title": "Potentially Sensitive HTTP Methods Advertised",
                        "severity": "low",
                        "affected_url": final_url,
                        "description": "The server advertises one or more HTTP methods that may require additional access-control review.",
                        "evidence": (
                            f"OPTIONS status: {options_response.status_code}\n"
                            f"Allow: {allow_header}\n"
                            f"Methods requiring review: {', '.join(risky_methods)}"
                        ),
                        "remediation": "Disable methods that are not required and ensure required methods enforce authentication and authorization.",
                        "status": "open"
                    })
                else:
                    findings.append({
                        "check_type": "http_methods",
                        "title": "HTTP Methods Reviewed",
                        "severity": "info",
                        "affected_url": final_url,
                        "description": "The OPTIONS response was reviewed and no commonly sensitive methods were advertised.",
                        "evidence": (
                            f"OPTIONS status: {options_response.status_code}\n"
                            f"Allow: {allow_header}"
                        ),
                        "remediation": "Keep only the HTTP methods required by the application.",
                        "status": "open"
                    })
            else:
                findings.append({
                    "check_type": "http_methods",
                    "title": "HTTP Method Allow Header Not Observed",
                    "severity": "info",
                    "affected_url": final_url,
                    "description": "The OPTIONS response did not expose an Allow header.",
                    "evidence": f"OPTIONS status: {options_response.status_code}\nAllow: Not set",
                    "remediation": "No action required. Review enabled HTTP methods separately if the application exposes state-changing endpoints.",
                    "status": "open"
                })

        except requests.exceptions.RequestException as e:
            findings.append({
                "check_type": "http_methods",
                "title": "HTTP Method Discovery Unavailable",
                "severity": "info",
                "affected_url": final_url,
                "description": "The safe OPTIONS request could not determine the server's advertised methods.",
                "evidence": str(e)[:1000],
                "remediation": "Review allowed HTTP methods in the web server configuration if required.",
                "status": "open"
            })

        # SET CORRECT FINDING STATUS
        # ========================================================
        # Informational checks passed; actual security issues remain open.
        for finding in findings:
            severity = str(finding.get("severity", "info")).lower()
            finding["status"] = "passed" if severity == "info" else "open"

        # ========================================================
        # SAVE FINDINGS
        # ========================================================
        saved_results = []

        for finding in findings:
            result_response = (
                supabase
                .table("scan_results")
                .insert({
                    "scan_id": scan_id,
                    "check_type": finding["check_type"],
                    "title": finding["title"],
                    "severity": finding["severity"],
                    "affected_url": finding["affected_url"],
                    "description": finding["description"],
                    "evidence": finding["evidence"],
                    "remediation": finding["remediation"],
                    "status": finding["status"]
                })
                .execute()
            )

            if result_response.data:
                saved_results.extend(result_response.data)

        # ========================================================
        # UPDATE SCAN STATUS
        # ========================================================
        supabase.table("scans").update({
            "status": "completed"
        }).eq("id", scan_id).execute()

        # ========================================================
        # SEVERITY SUMMARY
        # ========================================================
        severity_count = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for finding in findings:
            severity = str(
                finding.get("severity", "info")
            ).lower()

            if severity in severity_count:
                severity_count[severity] += 1

        # ========================================================
        # UPDATE SCAN FINDING COUNTS
        # ========================================================
        # Store the real security issue counts in the scans table.
        # Informational "passed" checks are not counted as findings.
        total_security_findings = (
            severity_count["critical"]
            + severity_count["high"]
            + severity_count["medium"]
            + severity_count["low"]
        )

        supabase.table("scans").update({
            "status": "completed",
            "total_findings": total_security_findings,
            "critical_count": severity_count["critical"],
            "high_count": severity_count["high"],
            "medium_count": severity_count["medium"],
            "low_count": severity_count["low"],
            "completed_at": datetime.now(timezone.utc).isoformat()
        }).eq("id", scan_id).eq(
            "user_id", user["user_id"]
        ).execute()

        # ========================================================
        # SECURITY RISK SCORE
        # ========================================================
        risk_score, risk_level = calculate_risk_score(
            severity_count
        )

        # ========================================================
        # FINAL JSON RESPONSE
        # ========================================================
        enriched_saved_results = [
            add_owasp_category(result)
            for result in saved_results
        ]

        return jsonify({
            "status": "success",
            "message": "Security scan completed successfully!",
            "scan_id": scan_id,
            "target_id": target_id,
            "target_url": target_url,
            "final_url": (
                response.url
                if response is not None
                else target_url
            ),
            "total_findings": total_security_findings,
            "severity_summary": severity_count,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "results": enriched_saved_results
        }), 200

    except Exception as e:
        try:
            supabase.table("scans").update({
                "status": "failed"
            }).eq("id", scan_id).execute()
        except Exception:
            pass

        print("SECURITY SCAN ERROR:", str(e))

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# SCAN HISTORY
# ============================================================

@app.route("/scan-history", methods=["GET"])
def scan_history():

    try:

        user = verify_token()

        if not user:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing token"
            }), 401

        # Get only the logged-in user's scans.
        scan_response = (
            supabase
            .table("scans")
            .select("*")
            .eq("user_id", user["user_id"])
            .order("created_at", desc=True)
            .execute()
        )

        scans = scan_response.data or []

        history = []

        for scan in scans:

            target_url = None
            target_name = None
            target_domain = None

            target_id = scan.get("target_id")

            if target_id:

                target_response = (
                    supabase
                    .table("targets")
                    .select("url,name,domain")
                    .eq("id", target_id)
                    .eq("user_id", user["user_id"])
                    .limit(1)
                    .execute()
                )

                target_data = target_response.data or []

                if target_data:
                    target = target_data[0]

                    target_url = target.get("url")
                    target_name = target.get("name")
                    target_domain = target.get("domain")

            # Recalculate findings from scan_results so the
            # history always shows the real current count.
            result_response = (
                supabase
                .table("scan_results")
                .select("severity")
                .eq("scan_id", scan.get("id"))
                .execute()
            )

            results = result_response.data or []

            critical_count = 0
            high_count = 0
            medium_count = 0
            low_count = 0

            for result in results:

                severity = str(
                    result.get("severity", "info")
                ).lower()

                if severity == "critical":
                    critical_count += 1

                elif severity == "high":
                    high_count += 1

                elif severity == "medium":
                    medium_count += 1

                elif severity == "low":
                    low_count += 1

            total_findings = (
                critical_count
                + high_count
                + medium_count
                + low_count
            )

            history.append({
                "id": scan.get("id"),
                "target_id": target_id,
                "target_url": (
                    target_url
                    or target_domain
                    or target_name
                    or (
                        f"Target #{target_id}"
                        if target_id
                        else "-"
                    )
                ),
                "scan_type": scan.get(
                    "scan_type",
                    "full"
                ),
                "status": scan.get(
                    "status",
                    "unknown"
                ),
                "total_findings": total_findings,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "started_at": scan.get("started_at"),
                "completed_at": scan.get("completed_at"),
                "created_at": scan.get("created_at")
            })

        return jsonify({
            "status": "success",
            "message": "Scan history retrieved successfully!",
            "data": history
        }), 200

    except Exception as e:

        print("SCAN HISTORY ERROR:", str(e))

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500



# ============================================================
# SCAN SUMMARY
# ============================================================

@app.route("/scan-summary/<int:scan_id>", methods=["GET"])
def scan_summary(scan_id):

    try:

        user = verify_token()

        if not user:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing token"
            }), 401

        scan_response = (
            supabase
            .table("scans")
            .select("*")
            .eq("id", scan_id)
            .eq("user_id", user["user_id"])
            .limit(1)
            .execute()
        )

        if not scan_response.data:
            return jsonify({
                "status": "error",
                "message": "Scan not found or access denied"
            }), 404

        scan = scan_response.data[0]

        result_response = (
            supabase
            .table("scan_results")
            .select("*")
            .eq("scan_id", scan_id)
            .execute()
        )

        results = [
            add_owasp_category(result)
            for result in (result_response.data or [])
        ]

        severity_summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for result in results:

            severity = str(
                result.get("severity", "info")
            ).lower()

            if severity in severity_summary:
                severity_summary[severity] += 1

        check_type_summary = {}
        owasp_category_summary = {}

        for result in results:

            check_type = result.get(
                "check_type",
                "unknown"
            )

            check_type_summary[check_type] = (
                check_type_summary.get(
                    check_type,
                    0
                ) + 1
            )

            category = result.get(
                "owasp_category",
                "General Security Posture"
            )

            owasp_category_summary[category] = (
                owasp_category_summary.get(
                    category,
                    0
                ) + 1
            )

        risk_score, risk_level = calculate_risk_score(
            severity_summary
        )

        total_security_findings = (
            severity_summary["critical"]
            + severity_summary["high"]
            + severity_summary["medium"]
            + severity_summary["low"]
        )

        return jsonify({
            "status": "success",
            "message": "Scan summary retrieved successfully!",
            "data": {
                "scan_id": scan_id,
                "target_id": scan.get("target_id"),
                "scan_status": scan.get("status"),
                "total_findings": total_security_findings,
                "severity_summary": severity_summary,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "check_type_summary": check_type_summary,
                "owasp_category_summary": owasp_category_summary,
                "findings": results
            }
        }), 200

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# CREATE JSON REPORT
# ============================================================

@app.route("/reports/<int:scan_id>", methods=["POST"])
def create_report(scan_id):

    try:

        user = verify_token()

        if not user:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing token"
            }), 401

        scan_response = (
            supabase
            .table("scans")
            .select("*")
            .eq("id", scan_id)
            .eq("user_id", user["user_id"])
            .limit(1)
            .execute()
        )

        if not scan_response.data:
            return jsonify({
                "status": "error",
                "message": "Scan not found or access denied"
            }), 404

        response = (
            supabase
            .table("scan_results")
            .select("*")
            .eq("scan_id", scan_id)
            .execute()
        )

        results = [
            add_owasp_category(result)
            for result in (response.data or [])
        ]

        if not results:
            return jsonify({
                "status": "error",
                "message": "No scan results found for this scan."
            }), 404

        reports_dir = "reports"

        os.makedirs(
            reports_dir,
            exist_ok=True
        )

        report_name = f"WebShield_Report_{scan_id}"

        file_path = os.path.join(
            reports_dir,
            f"scan_{scan_id}.json"
        )

        severity_summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for result in results:

            severity = str(
                result.get("severity", "info")
            ).lower()

            if severity in severity_summary:
                severity_summary[severity] += 1

        total_security_findings = (
            severity_summary["critical"]
            + severity_summary["high"]
            + severity_summary["medium"]
            + severity_summary["low"]
        )

        risk_score, risk_level = calculate_risk_score(
            severity_summary
        )

        report_content = {
            "report_name": report_name,
            "scan_id": scan_id,
            "generated_at":
                datetime.now(timezone.utc).isoformat(),
            "total_findings": total_security_findings,
            "severity_summary": severity_summary,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "results": results
        }

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as report_file:

            json.dump(
                report_content,
                report_file,
                indent=4,
                default=str
            )

        report_data = {
            "scan_id": scan_id,
            "report_name": report_name,
            "file_path":
                file_path.replace("\\", "/"),
            "report_format": "JSON",
            "generated_at":
                datetime.now(timezone.utc).isoformat()
        }

        report_response = (
            supabase
            .table("reports")
            .insert(report_data)
            .execute()
        )

        return jsonify({
            "status": "success",
            "message": "Report created successfully!",
            "data": report_response.data,
            "file_path":
                file_path.replace("\\", "/")
        }), 201

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# DOWNLOAD JSON REPORT
# ============================================================

@app.route(
    "/reports/<int:scan_id>/download",
    methods=["GET"]
)
def download_report(scan_id):

    try:

        user = verify_token()

        if not user:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing token"
            }), 401

        scan_response = (
            supabase
            .table("scans")
            .select("*")
            .eq("id", scan_id)
            .eq("user_id", user["user_id"])
            .limit(1)
            .execute()
        )

        if not scan_response.data:
            return jsonify({
                "status": "error",
                "message": "Scan not found or access denied"
            }), 404

        file_path = os.path.join(
            "reports",
            f"scan_{scan_id}.json"
        )

        if not os.path.exists(file_path):
            return jsonify({
                "status": "error",
                "message":
                    "Report file not found. Create the report first."
            }), 404

        return send_file(
            file_path,
            as_attachment=True,
            download_name=f"WebShield_Report_{scan_id}.json",
            mimetype="application/json"
        )

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# GENERATE PDF REPORT
# ============================================================

@app.route(
    "/reports/<int:scan_id>/pdf",
    methods=["POST"]
)
def generate_pdf_report(scan_id):
    """Generate a compact, professional WebShield Pro PDF report."""

    try:
        user = verify_token()

        if not user:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing token"
            }), 401

        # --------------------------------------------------------
        # Get scan
        # --------------------------------------------------------
        scan_response = (
            supabase
            .table("scans")
            .select("*")
            .eq("id", scan_id)
            .eq("user_id", user["user_id"])
            .limit(1)
            .execute()
        )

        if not scan_response.data:
            return jsonify({
                "status": "error",
                "message": "Scan not found or access denied"
            }), 404

        scan = scan_response.data[0]

        # --------------------------------------------------------
        # Get target URL from targets table
        # --------------------------------------------------------
        target_url = "N/A"
        target_id = scan.get("target_id")

        if target_id:
            target_response = (
                supabase
                .table("targets")
                .select("name,url,domain")
                .eq("id", target_id)
                .eq("user_id", user["user_id"])
                .limit(1)
                .execute()
            )

            if target_response.data:
                target = target_response.data[0]
                target_url = (
                    target.get("url")
                    or target.get("domain")
                    or target.get("name")
                    or "N/A"
                )

        # --------------------------------------------------------
        # Get scan results
        # --------------------------------------------------------
        result_response = (
            supabase
            .table("scan_results")
            .select("*")
            .eq("scan_id", scan_id)
            .execute()
        )

        results = result_response.data or []

        if not results:
            return jsonify({
                "status": "error",
                "message": "No scan results found for this scan."
            }), 404

        # --------------------------------------------------------
        # Calculate summary
        # --------------------------------------------------------
        severity_summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for result in results:
            severity = str(
                result.get("severity", "info")
            ).lower()

            if severity in severity_summary:
                severity_summary[severity] += 1

        total_checks = len(results)
        open_findings = sum(
            severity_summary[level]
            for level in ["critical", "high", "medium", "low"]
        )
        passed_checks = severity_summary["info"]

        risk_score, risk_level = calculate_risk_score(
            severity_summary
        )

        # --------------------------------------------------------
        # OWASP summary
        # --------------------------------------------------------
        owasp_summary = {}

        for result in results:
            category = get_owasp_category(
                result.get("check_type"),
                result.get("title")
            )

            if category not in owasp_summary:
                owasp_summary[category] = {
                    "total": 0,
                    "open": 0,
                    "passed": 0
                }

            owasp_summary[category]["total"] += 1

            if str(result.get("severity", "info")).lower() == "info":
                owasp_summary[category]["passed"] += 1
            else:
                owasp_summary[category]["open"] += 1

        # --------------------------------------------------------
        # PDF setup
        # --------------------------------------------------------
        reports_dir = "reports"
        os.makedirs(reports_dir, exist_ok=True)

        pdf_path = os.path.join(
            reports_dir,
            f"scan_{scan_id}.pdf"
        )

        document = SimpleDocTemplate(
            pdf_path,
            pagesize=A4,
            rightMargin=40,
            leftMargin=40,
            topMargin=42,
            bottomMargin=42
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "SimpleReportTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            fontSize=23,
            leading=27,
            textColor=colors.HexColor("#111827"),
            spaceAfter=4
        )

        subtitle_style = ParagraphStyle(
            "SimpleReportSubtitle",
            parent=styles["BodyText"],
            alignment=TA_CENTER,
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=14
        )

        heading_style = ParagraphStyle(
            "SimpleReportHeading",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#172033"),
            spaceBefore=10,
            spaceAfter=7
        )

        normal_style = ParagraphStyle(
            "SimpleReportNormal",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#334155")
        )

        small_style = ParagraphStyle(
            "SimpleReportSmall",
            parent=styles["BodyText"],
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#475569")
        )

        finding_title_style = ParagraphStyle(
            "FindingTitle",
            parent=normal_style,
            fontSize=9.5,
            leading=12,
            textColor=colors.HexColor("#111827"),
            spaceBefore=5,
            spaceAfter=4
        )

        tiny_style = ParagraphStyle(
            "SimpleReportTiny",
            parent=styles["BodyText"],
            fontSize=6.8,
            leading=8.5,
            textColor=colors.HexColor("#64748b")
        )

        story = []

        # --------------------------------------------------------
        # Header
        # --------------------------------------------------------
        story.append(Paragraph("WebShield Pro", title_style))
        story.append(
            Paragraph(
                "Web Security Assessment Report",
                subtitle_style
            )
        )

        metadata = [
            [
                Paragraph("<b>Scan ID</b>", small_style),
                Paragraph(str(scan_id), small_style),
                Paragraph("<b>Status</b>", small_style),
                Paragraph(
                    escape(str(scan.get("status", "completed"))).upper(),
                    small_style
                )
            ],
            [
                Paragraph("<b>Target</b>", small_style),
                Paragraph(escape(str(target_url)), small_style),
                Paragraph("<b>Scan Type</b>", small_style),
                Paragraph(
                    escape(str(scan.get("scan_type", "full"))),
                    small_style
                )
            ],
            [
                Paragraph("<b>Generated</b>", small_style),
                Paragraph(
                    datetime.now(timezone.utc).strftime(
                        "%d %b %Y, %H:%M UTC"
                    ),
                    small_style
                ),
                Paragraph("<b>Tool</b>", small_style),
                Paragraph("WebShield Pro", small_style)
            ]
        ]

        metadata_table = Table(
            metadata,
            colWidths=[55, 215, 55, 115]
        )
        metadata_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2f7")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#eef2f7")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5)
        ]))
        story.append(metadata_table)
        story.append(Spacer(1, 13))

        # --------------------------------------------------------
        # Executive summary
        # --------------------------------------------------------
        story.append(Paragraph("Executive Summary", heading_style))

        summary_rows = [
            [
                Paragraph("<b>Risk Score</b>", small_style),
                Paragraph("<b>Open Findings</b>", small_style),
                Paragraph("<b>Passed</b>", small_style),
                Paragraph("<b>Total Checks</b>", small_style)
            ],
            [
                Paragraph(
                    f"<b>{risk_score}/100</b><br/>{escape(risk_level)}",
                    normal_style
                ),
                Paragraph(str(open_findings), normal_style),
                Paragraph(str(passed_checks), normal_style),
                Paragraph(str(total_checks), normal_style)
            ]
        ]

        summary_table = Table(
            summary_rows,
            colWidths=[110, 110, 110, 110]
        )
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172033")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 7))

        severity_rows = [
            [
                Paragraph("<b>Critical</b>", small_style),
                Paragraph("<b>High</b>", small_style),
                Paragraph("<b>Medium</b>", small_style),
                Paragraph("<b>Low</b>", small_style),
                Paragraph("<b>Info</b>", small_style)
            ],
            [
                str(severity_summary["critical"]),
                str(severity_summary["high"]),
                str(severity_summary["medium"]),
                str(severity_summary["low"]),
                str(severity_summary["info"])
            ]
        ]

        severity_table = Table(
            severity_rows,
            colWidths=[88, 88, 88, 88, 88]
        )
        severity_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f7")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
        ]))
        story.append(severity_table)

        # Short interpretation, not an absolute security claim.
        if open_findings == 0:
            summary_text = (
                "No open findings were recorded in this scan. "
                "The target should still be reviewed periodically."
            )
        else:
            summary_text = (
                f"The scan recorded {open_findings} open finding(s). "
                "Review the detailed findings below and address higher-severity "
                "items first."
            )

        story.append(Spacer(1, 7))
        story.append(Paragraph(summary_text, normal_style))

        # --------------------------------------------------------
        # OWASP summary
        # --------------------------------------------------------
        story.append(Paragraph("OWASP-Aligned Summary", heading_style))

        owasp_rows = [[
            Paragraph("<b>Category</b>", small_style),
            Paragraph("<b>Checks</b>", small_style),
            Paragraph("<b>Open</b>", small_style),
            Paragraph("<b>Passed</b>", small_style)
        ]]

        for category, values in sorted(owasp_summary.items()):
            owasp_rows.append([
                Paragraph(escape(category), small_style),
                Paragraph(str(values["total"]), small_style),
                Paragraph(str(values["open"]), small_style),
                Paragraph(str(values["passed"]), small_style)
            ])

        owasp_table = Table(
            owasp_rows,
            colWidths=[285, 55, 55, 55]
        )
        owasp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ede9fe")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#5b21b6")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 1), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5)
        ]))
        story.append(owasp_table)

        # --------------------------------------------------------
        # Open findings: concise and strong
        # --------------------------------------------------------
        story.append(Paragraph("Open Security Findings", heading_style))

        open_results = [
            result for result in results
            if str(result.get("severity", "info")).lower() != "info"
        ]

        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3
        }

        open_results.sort(
            key=lambda item: severity_order.get(
                str(item.get("severity", "low")).lower(),
                9
            )
        )

        if not open_results:
            story.append(
                Paragraph(
                    "No open security findings were recorded.",
                    normal_style
                )
            )
        else:
            finding_rows = [[
                Paragraph("<b>Severity</b>", small_style),
                Paragraph("<b>Finding</b>", small_style),
                Paragraph("<b>OWASP</b>", small_style)
            ]]

            for result in open_results:
                severity = str(
                    result.get("severity", "low")
                ).upper()
                title = escape(
                    str(result.get("title", "Security Finding"))
                )
                category = escape(
                    get_owasp_category(
                        result.get("check_type"),
                        result.get("title")
                    )
                )

                finding_rows.append([
                    Paragraph(f"<b>{severity}</b>", small_style),
                    Paragraph(title, small_style),
                    Paragraph(category, small_style)
                ])

            finding_table = Table(
                finding_rows,
                colWidths=[65, 245, 140],
                repeatRows=1
            )
            finding_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172033")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5)
            ]))
            story.append(finding_table)

        # --------------------------------------------------------
        # Detailed remediation section: only open findings
        # --------------------------------------------------------
        story.append(Paragraph("Remediation Details", heading_style))

        if not open_results:
            story.append(
                Paragraph(
                    "No remediation actions are currently required based on this scan.",
                    normal_style
                )
            )
        else:
            for index, result in enumerate(open_results, start=1):
                title = escape(
                    str(result.get("title", "Security Finding"))
                )
                severity = escape(
                    str(result.get("severity", "unknown")).upper()
                )
                category = escape(
                    get_owasp_category(
                        result.get("check_type"),
                        result.get("title")
                    )
                )
                description = escape(
                    str(result.get("description", "N/A"))
                )
                evidence = escape(
                    str(result.get("evidence", "N/A"))
                )
                remediation = escape(
                    str(result.get("remediation", "Review and remediate this finding."))
                )
                affected_url = escape(
                    str(result.get("affected_url", target_url))
                )

                story.append(
                    Paragraph(
                        f"<b>{index}. {title}</b> — {severity}",
                        finding_title_style
                    )
                )

                detail_rows = [
                    [
                        Paragraph("<b>OWASP</b>", small_style),
                        Paragraph(category, small_style)
                    ],
                    [
                        Paragraph("<b>Affected URL</b>", small_style),
                        Paragraph(affected_url, small_style)
                    ],
                    [
                        Paragraph("<b>Description</b>", small_style),
                        Paragraph(description, small_style)
                    ],
                    [
                        Paragraph("<b>Evidence</b>", small_style),
                        Paragraph(evidence, small_style)
                    ],
                    [
                        Paragraph("<b>Action</b>", small_style),
                        Paragraph(remediation, small_style)
                    ]
                ]

                detail_table = Table(
                    detail_rows,
                    colWidths=[75, 375]
                )
                detail_table.setStyle(TableStyle([
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d7dee8")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4)
                ]))
                story.append(detail_table)
                story.append(Spacer(1, 7))

        # --------------------------------------------------------
        # Passed checks: compact list
        # --------------------------------------------------------
        story.append(Paragraph("Passed Security Checks", heading_style))

        passed_titles = [
            str(result.get("title", "Security Check"))
            for result in results
            if str(result.get("severity", "info")).lower() == "info"
        ]

        if passed_titles:
            # Keep this section compact. It confirms what was checked without
            # repeating full evidence for every informational result.
            passed_text = " • ".join(
                escape(title) for title in passed_titles
            )
            story.append(Paragraph(passed_text, small_style))
        else:
            story.append(
                Paragraph("No informational/passed checks recorded.", small_style)
            )

        # --------------------------------------------------------
        # Methodology and scope
        # --------------------------------------------------------
        story.append(Paragraph("Assessment Notes", heading_style))
        story.append(
            Paragraph(
                "WebShield Pro performs passive and non-destructive web security "
                "checks against the selected target. The report reflects the "
                "responses observed during this scan and does not represent "
                "complete vulnerability coverage. Only authorized targets "
                "should be tested.",
                small_style
            )
        )

        story.append(Spacer(1, 6))
        story.append(
            Paragraph(
                "Risk score formula: 100 - (Critical × 25) - (High × 15) "
                "- (Medium × 8) - (Low × 3), clamped to 0–100. "
                "This is a project-specific heuristic and not an industry-standard rating.",
                tiny_style
            )
        )

        story.append(Spacer(1, 10))
        story.append(
            Paragraph(
                "WebShield Pro • Security Assessment Report",
                tiny_style
            )
        )

        document.build(story)

        # --------------------------------------------------------
        # Save report record
        # --------------------------------------------------------
        pdf_report_data = {
            "scan_id": scan_id,
            "report_name": f"WebShield_Report_{scan_id}_PDF",
            "file_path": pdf_path.replace("\\", "/"),
            "report_format": "PDF",
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

        supabase.table("reports").insert(pdf_report_data).execute()

        return jsonify({
            "status": "success",
            "message": "Simple professional PDF report generated successfully!",
            "scan_id": scan_id,
            "file_path": pdf_path.replace("\\", "/"),
            "report_format": "PDF",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "total_checks": total_checks,
            "open_findings": open_findings
        }), 201

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# DOWNLOAD PDF REPORT
# ============================================================

@app.route(
    "/reports/<int:scan_id>/pdf/download",
    methods=["GET"]
)
def download_pdf_report(scan_id):

    try:

        user = verify_token()

        if not user:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing token"
            }), 401

        scan_response = (
            supabase
            .table("scans")
            .select("*")
            .eq("id", scan_id)
            .eq("user_id", user["user_id"])
            .limit(1)
            .execute()
        )

        if not scan_response.data:
            return jsonify({
                "status": "error",
                "message": "Scan not found or access denied"
            }), 404

        pdf_path = os.path.join(
            "reports",
            f"scan_{scan_id}.pdf"
        )

        if not os.path.exists(pdf_path):
            return jsonify({
                "status": "error",
                "message":
                    "PDF report not found. Generate the PDF first."
            }), 404

        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=
                f"WebShield_Report_{scan_id}.pdf",
            mimetype="application/pdf"
        )

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)
