import hashlib
import json
import os
import random
import sys
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent
DEPS_DIR = BASE_DIR / ".codex_deps"
if DEPS_DIR.exists():
    sys.path.insert(0, str(DEPS_DIR))

import pandas as pd

from risk_engine import calculate_final_risk


DATASET_PATH = BASE_DIR / "synthetic_login_data_final_audited.csv"
ATTEMPTS_PATH = BASE_DIR / "login_attempts.json"
STATIC_DIR = BASE_DIR / "public"
DEMO_PASSWORDS = {"password123", "wvh-demo"}
DEMO_OTP = "246810"
REFERENCE_SAMPLE_SIZE = 800


DATASET = pd.read_csv(DATASET_PATH)
REFERENCE_ROWS = DATASET.sample(
    n=min(REFERENCE_SAMPLE_SIZE, len(DATASET)),
    random_state=42,
).reset_index(drop=True)


def now_utc():
    return datetime.now(timezone.utc)


def json_default(value):
    if pd.isna(value):
        return None
    if hasattr(value, "item"):
        return value.item()
    return str(value)


def read_json_body(handler):
    length = int(handler.headers.get("Content-Length", "0"))
    if length == 0:
        return {}
    return json.loads(handler.rfile.read(length).decode("utf-8"))


def load_attempts():
    if not ATTEMPTS_PATH.exists():
        return []
    with ATTEMPTS_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_attempts(attempts):
    with ATTEMPTS_PATH.open("w", encoding="utf-8") as file:
        json.dump(attempts, file, indent=2, default=json_default)


def normalize_email(email):
    return str(email or "").strip().lower()


def user_id_for_email(email):
    digest = hashlib.sha256(normalize_email(email).encode("utf-8")).hexdigest()
    return f"U{(int(digest[:8], 16) % 999) + 1:05d}"


def parse_user_agent(user_agent):
    ua = user_agent or ""
    low = ua.lower()

    if "edg/" in low or "edge/" in low:
        browser = "Edge"
    elif "firefox/" in low:
        browser = "Firefox"
    elif "safari/" in low and "chrome/" not in low and "chromium/" not in low:
        browser = "Safari"
    elif "chrome/" in low or "chromium/" in low:
        browser = "Chrome"
    else:
        browser = "Unknown"

    if "windows" in low:
        os_name = "Windows"
        device = "Windows-Laptop"
    elif "mac os" in low or "macintosh" in low:
        os_name = "MacOS"
        device = "MacBook"
    elif "android" in low:
        os_name = "Android"
        device = "Android-Phone"
    elif "iphone" in low:
        os_name = "iOS"
        device = "iPhone"
    elif "ipad" in low:
        os_name = "iOS"
        device = "iPad"
    elif "linux" in low:
        os_name = "Linux"
        device = "Linux-Laptop"
    else:
        os_name = "Unknown"
        device = "Unknown Device"

    device_type = os_name
    if "mobile" in low and os_name == "Windows":
        device = "Windows-Mobile"
    return {"browser": browser, "os": os_name, "device": device, "device_type": device_type}


def country_from_context(context):
    locale = str(context.get("language") or context.get("locale") or "")
    timezone_name = str(context.get("timezone") or "")
    if "-" in locale:
        candidate = locale.split("-")[-1].upper()
        if len(candidate) == 2:
            return candidate
    timezone_map = {
        "kolkata": "IN",
        "calcutta": "IN",
        "new_york": "US",
        "los_angeles": "US",
        "london": "GB",
        "dubai": "AE",
        "singapore": "SG",
        "berlin": "DE",
        "paris": "FR",
        "moscow": "RU",
    }
    lowered = timezone_name.lower()
    for key, country in timezone_map.items():
        if key in lowered:
            return country
    return "IN"


def ip_risk_for_request(ip_address):
    if ip_address in {"127.0.0.1", "::1", "localhost"}:
        return 0.12
    digest = hashlib.sha256(str(ip_address).encode("utf-8")).hexdigest()
    return round((int(digest[:4], 16) % 100) / 100, 3)


def get_user_history(email):
    user_id = user_id_for_email(email)
    generated = [a for a in load_attempts() if a.get("email") == normalize_email(email)]
    dataset_rows = DATASET[DATASET["user_id"] == user_id].tail(12).to_dict("records")
    return user_id, generated, dataset_rows


def build_attempt_row(email, context, handler):
    timestamp = now_utc()
    ua_context = parse_user_agent(handler.headers.get("User-Agent", ""))
    browser_context = context.get("browserContext") or {}
    browser = browser_context.get("browser") or ua_context["browser"]
    os_name = browser_context.get("os") or ua_context["os"]
    device = browser_context.get("device") or ua_context["device"]
    device_type = browser_context.get("deviceType") or ua_context["device_type"]
    country = country_from_context(context)
    ip_address = handler.headers.get("X-Forwarded-For", handler.client_address[0]).split(",")[0].strip()
    user_id, generated_history, dataset_history = get_user_history(email)

    known_devices = {str(row.get("device")) for row in dataset_history}
    known_devices.update(str(item.get("device")) for item in generated_history)
    known_countries = {str(row.get("country")) for row in dataset_history}
    known_countries.update(str(item.get("country")) for item in generated_history)

    last_country = None
    if generated_history:
        last_country = generated_history[-1].get("country")
    elif dataset_history:
        last_country = dataset_history[-1].get("country")

    failed_attempts = 0
    for item in reversed(generated_history):
        if item.get("status") in {"Failed", "Blocked"}:
            failed_attempts += 1
        else:
            break

    login_frequency = 1.0
    historical_behavior = 0.5
    time_since_last_login = 0.0
    if dataset_history:
        last = dataset_history[-1]
        login_frequency = float(last.get("login_frequency_per_day") or 1.0)
        historical_behavior = float(last.get("historical_behavior_score") or 0.5)
        time_since_last_login = float(last.get("time_since_last_login_hrs") or 0.0)

    return {
        "login_id": f"SIM-{uuid.uuid4().hex[:8].upper()}",
        "user_id": user_id,
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "login_hour": timestamp.hour,
        "is_new_device": 1 if device not in known_devices else 0,
        "device": device,
        "device_type": device_type,
        "browser": browser,
        "country": country,
        "is_new_country": 1 if country not in known_countries else 0,
        "location_change": 1 if last_country and country != last_country else 0,
        "ip_risk_score": ip_risk_for_request(ip_address),
        "failed_login_attempts": failed_attempts,
        "time_since_last_login_hrs": time_since_last_login,
        "login_frequency_per_day": login_frequency,
        "historical_behavior_score": historical_behavior,
        "is_first_login": 0 if dataset_history or generated_history else 1,
        "ip_address": ip_address,
        "timezone": context.get("timezone") or "Unknown",
        "language": context.get("language") or "Unknown",
    }


def score_attempt(row):
    scoring_input = pd.concat(
        [pd.DataFrame([row]), REFERENCE_ROWS],
        ignore_index=True,
        sort=False,
    )
    scored = calculate_final_risk(scoring_input).iloc[0].to_dict()
    return scored


def decision_for(scored_row, password_valid):
    level = scored_row["final_risk_level"]
    action = scored_row["required_action"]
    if not password_valid:
        return {
            "status": "FAILED",
            "authenticationStatus": "Failed",
            "method": "Password",
            "message": "Password authentication failed.",
        }
    if level == "LOW":
        return {
            "status": "SUCCESS",
            "authenticationStatus": "Authenticated",
            "method": "Password",
            "message": "Password authentication is sufficient.",
        }
    if level == "MEDIUM":
        return {
            "status": "OTP_REQUIRED",
            "authenticationStatus": "OTP Required",
            "method": "Password + OTP",
            "message": "Additional verification is required.",
        }
    if "BLOCK" in action.upper():
        return {
            "status": "BLOCKED",
            "authenticationStatus": "Blocked",
            "method": "Blocked",
            "message": "Suspicious login detected.",
        }
    return {
        "status": "OTP_REQUIRED",
        "authenticationStatus": "Strong Verification Required",
        "method": "Password + OTP",
        "message": "Strong verification is required.",
    }


def risk_signals(scored_row):
    reasons = str(scored_row.get("risk_reasons") or "Normal")
    reason_set = {item.strip() for item in reasons.split(",")}
    rows = [
        ("Login Time", f"{int(scored_row['login_hour']):02d}:00 UTC", "Medium" if int(scored_row["login_hour"]) < 6 else "Low"),
        ("Device", "New Device" if int(scored_row["is_new_device"]) else scored_row["device"], "High" if "New Device" in reason_set else "Low"),
        ("Country", "New Country" if int(scored_row["is_new_country"]) else scored_row["country"], "High" if "New Country" in reason_set else "Low"),
        ("Location Change", "Changed" if int(scored_row["location_change"]) else "Typical", "High" if "Location Change" in reason_set else "Low"),
        ("IP Reputation", f"{float(scored_row['ip_risk_score']):.2f}", "High" if "High-Risk IP" in reason_set else "Medium"),
        ("Failed Attempts", int(scored_row["failed_login_attempts"]), "High" if "Multiple Failed Attempts" in reason_set else "Low"),
        ("Behavioral Deviation", f"{float(scored_row['if_score']):.0f}%", "High" if int(scored_row["if_anomaly_flag"]) else "Low"),
    ]
    return [{"signal": s, "observedValue": v, "impact": i} for s, v, i in rows]


def public_attempt(scored_row, email, decision):
    risk_score = float(scored_row["final_risk_score"])
    status_label = {
        "Authenticated": "Success",
        "OTP Required": "OTP Required",
        "Strong Verification Required": "OTP Required",
        "Failed": "Failed",
        "Blocked": "Blocked",
    }.get(decision["authenticationStatus"], decision["authenticationStatus"])
    return {
        "attemptId": scored_row["login_id"],
        "email": normalize_email(email),
        "userId": scored_row["user_id"],
        "timestamp": scored_row["timestamp"],
        "loginTime": scored_row["timestamp"],
        "device": scored_row["device"],
        "browser": scored_row["browser"],
        "os": scored_row["device_type"],
        "country": scored_row["country"],
        "ipAddress": scored_row.get("ip_address", "Unavailable"),
        "riskScore": round(risk_score, 2),
        "riskLevel": scored_row["final_risk_level"],
        "requiredAction": scored_row["required_action"],
        "decision": decision["method"],
        "authenticationStatus": decision["authenticationStatus"],
        "status": status_label,
        "message": decision["message"],
        "riskReasons": [r.strip() for r in str(scored_row.get("risk_reasons") or "Normal").split(",")],
        "signals": risk_signals(scored_row),
    }


def to_history_record(item):
    status = item.get("status", "Historical")
    if status == "Authenticated":
        status = "Success"
    return {
        "time": item.get("timestamp") or item.get("loginTime"),
        "user": item.get("email") or item.get("user_id"),
        "location": item.get("country", "Unknown"),
        "device": f"{item.get('device', 'Unknown')}/{item.get('browser', item.get('browserName', 'Unknown'))}",
        "riskScore": round(float(item.get("riskScore", item.get("final_risk_score", item.get("risk_score", 0))) or 0), 2),
        "riskLevel": str(item.get("riskLevel", item.get("final_risk_level", item.get("risk_level", "LOW")))).upper(),
        "decision": item.get("decision", item.get("requiredAction", item.get("required_action", "Password"))),
        "status": status,
    }


def history_for(email, current_attempt_id=None):
    user_id = user_id_for_email(email)
    generated = [a for a in load_attempts() if a.get("email") == normalize_email(email)]
    scored_dataset = calculate_final_risk(DATASET[DATASET["user_id"] == user_id].tail(10).copy())
    dataset_history = []
    for row in scored_dataset.to_dict("records"):
        dataset_history.append(
            {
                "timestamp": row["timestamp"],
                "email": row["user_id"],
                "country": row["country"],
                "device": row["device"],
                "browser": row["browser"],
                "riskScore": row["final_risk_score"],
                "riskLevel": row["final_risk_level"],
                "decision": row["required_action"],
                "status": "Historical",
            }
        )
    combined = dataset_history + generated
    combined.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
    current = None
    for item in generated:
        if item.get("attemptId") == current_attempt_id:
            current = item
            break
    if current is None and generated:
        current = generated[-1]
    return current, [to_history_record(item) for item in combined[:12]]


def summary_for(history):
    scores = [float(row["riskScore"]) for row in history]
    levels = [row["riskLevel"] for row in history]
    devices = sorted({row["device"].split("/")[0] for row in history if row.get("device")})
    locations = sorted({row["location"] for row in history if row.get("location")})
    return {
        "averageRiskScore": round(sum(scores) / len(scores), 2) if scores else 0,
        "recentAttempts": len(history),
        "lowCount": levels.count("LOW"),
        "mediumCount": levels.count("MEDIUM"),
        "highCount": levels.count("HIGH"),
        "knownDevices": devices[:5],
        "commonLocations": locations[:5],
    }


def insights_for(current, history):
    if not current:
        return []
    insights = []
    reasons = set(current.get("riskReasons", []))
    if "New Device" in reasons:
        insights.append("New device detected for this user.")
    if "Location Change" in reasons or "New Country" in reasons:
        insights.append("Location differs from recent login behavior.")
    if current.get("riskLevel") == "HIGH":
        insights.append("Current attempt requires blocking or strong verification.")
    if sum(1 for row in history if row["riskLevel"] == "HIGH") >= 2:
        insights.append("Multiple high-risk attempts appear in recent history.")
    if current.get("signals"):
        for signal in current["signals"]:
            if signal["signal"] == "Behavioral Deviation" and signal["impact"] == "High":
                insights.append("Behavioral deviation increased in the model result.")
    return insights[:4]


class WVHHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def send_json(self, payload, status=HTTPStatus.OK):
        encoded = json.dumps(payload, default=json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/dashboard":
            params = parse_qs(parsed.query)
            email = normalize_email(params.get("email", ["demo@wvh.local"])[0])
            attempt_id = params.get("attemptId", [None])[0]
            current, history = history_for(email, attempt_id)
            self.send_json(
                {
                    "currentAttempt": current,
                    "history": history,
                    "trend": [{"label": row["time"], "score": row["riskScore"]} for row in reversed(history)],
                    "summary": summary_for(history),
                    "insights": insights_for(current, history),
                }
            )
            return
        if parsed.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/login":
            body = read_json_body(self)
            email = normalize_email(body.get("email"))
            if not email:
                self.send_json({"error": "Email or username is required."}, HTTPStatus.BAD_REQUEST)
                return
            password_valid = str(body.get("password") or "") in DEMO_PASSWORDS
            row = build_attempt_row(email, body.get("context") or {}, self)
            scored = score_attempt(row)
            decision = decision_for(scored, password_valid)
            attempt = public_attempt(scored, email, decision)
            attempt["passwordValid"] = password_valid
            attempt["otpVerified"] = False
            if decision["status"] == "OTP_REQUIRED":
                attempt["status"] = "OTP Required"
                attempt["simulatedOtp"] = DEMO_OTP
            attempts = load_attempts()
            attempts.append(attempt)
            save_attempts(attempts)
            self.send_json({"decisionStatus": decision["status"], "attempt": attempt})
            return

        if parsed.path == "/api/verify-otp":
            body = read_json_body(self)
            attempt_id = body.get("attemptId")
            attempts = load_attempts()
            for attempt in attempts:
                if attempt.get("attemptId") == attempt_id:
                    if str(body.get("otp") or "") == DEMO_OTP:
                        attempt["otpVerified"] = True
                        attempt["authenticationStatus"] = "Authenticated"
                        attempt["status"] = "Success"
                        attempt["decision"] = "Password + OTP"
                        save_attempts(attempts)
                        self.send_json({"verified": True, "attempt": attempt})
                    else:
                        self.send_json({"verified": False, "error": "Incorrect OTP. Try again."}, HTTPStatus.BAD_REQUEST)
                    return
            self.send_json({"error": "Attempt not found."}, HTTPStatus.NOT_FOUND)
            return

        self.send_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)


def main():
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("127.0.0.1", port), WVHHandler)
    print(f"WVH prototype running at http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
