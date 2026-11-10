from pathlib import Path
from typing import Literal
import base64
import hashlib
import hmac
import json
import secrets
import time
import sqlite3

from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import FileResponse, RedirectResponse

from database import get_connection, create_tables

app = FastAPI(title="Threat Intelligence Dashboard")

BASE_DIR = Path(__file__).parent
SESSION_COOKIE = "admin_session"
SESSION_DURATION = 8 * 60 * 60

create_tables()

from pydantic import BaseModel, Field


class ThreatActor(BaseModel):
    name: str
    description: str = ""
    country: str = ""
    severity: str = "Medium"


class Malware(BaseModel):
    name: str
    type: str = ""
    description: str = ""
    severity: str = "Medium"


class IOC(BaseModel):
    value: str
    type: str
    description: str = ""
    severity: str = "Medium"


class AdminCredentials(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=8, max_length=128)


class IntelligenceSubmission(BaseModel):
    category: Literal["Threat Actor", "Malware", "IOC"]
    name: str = ""
    value: str = ""
    type: str = ""
    country: str = ""
    description: str = ""
    severity: Literal["Low", "Medium", "High", "Critical"] = "Medium"
    source: str = Field(min_length=5, max_length=1000)


class ReviewDecision(BaseModel):
    review_note: str = Field(default="", max_length=1000)

@app.get("/")
def home():
    return RedirectResponse("/dashboard")


@app.get("/dashboard")
def dashboard():
    return FileResponse(BASE_DIR / "dashboard.html")


@app.get("/threats")
def threats_page():
    return FileResponse(BASE_DIR / "threats.html")


@app.get("/add")
def add_page():
    return FileResponse(BASE_DIR / "add.html")


@app.get("/control-room")
def admin_page():
    return FileResponse(BASE_DIR / "admin.html")


@app.get("/style.css")
def stylesheet():
    return FileResponse(BASE_DIR / "style.css", media_type="text/css")


@app.get("/script.js")
def javascript():
    return FileResponse(BASE_DIR / "script.js", media_type="application/javascript")

def row_to_dict(row):
    return dict(row)


def log_activity(connection, username, action, category="", record_id=None, details=""):
    connection.execute("""
        INSERT INTO activity_logs
        (admin_username, action, category, record_id, details)
        VALUES (?, ?, ?, ?, ?)
    """, (username, action, category, record_id, details))


def get_admin_from_token(token):
    try:
        encoded, signature = token.split(".")
        secret = get_session_secret()
        expected = hmac.new(
            secret.encode(),
            encoded.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected):
            return None

        payload = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )

        if payload["expires"] < time.time():
            return None

        connection = get_connection()
        admin = connection.execute(
            "SELECT username FROM admins WHERE username = ?",
            (payload["username"],)
        ).fetchone()
        connection.close()

        return payload["username"] if admin else None

    except Exception:
        return None


def get_session_secret():
    connection = get_connection()
    row = connection.execute(
        "SELECT setting_value FROM app_settings WHERE setting_name = 'session_secret'"
    ).fetchone()
    connection.close()
    return row["setting_value"]


def create_session(username):
    payload = {
        "username": username,
        "expires": time.time() + SESSION_DURATION
    }

    encoded = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip("=")

    signature = hmac.new(
        get_session_secret().encode(),
        encoded.encode(),
        hashlib.sha256
    ).hexdigest()

    return encoded + "." + signature


def require_admin(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    username = get_admin_from_token(token) if token else None

    if not username:
        raise HTTPException(status_code=401, detail="Administrator login required")

    return username

@app.get("/auth/status")
def auth_status(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    username = get_admin_from_token(token) if token else None

    connection = get_connection()
    admin_exists = connection.execute(
        "SELECT COUNT(*) AS total FROM admins"
    ).fetchone()["total"] > 0
    connection.close()

    return {
        "authenticated": bool(username),
        "username": username,
        "admin_exists": admin_exists
    }


@app.post("/auth/setup")
def setup_admin(data: AdminCredentials, response: Response):
    connection = get_connection()

    existing = connection.execute(
        "SELECT COUNT(*) AS total FROM admins"
    ).fetchone()["total"]

    if existing:
        connection.close()
        raise HTTPException(status_code=403, detail="Administrator already exists")

    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        data.password.encode(),
        salt.encode(),
        310000
    ).hex()

    connection.execute("""
        INSERT INTO admins (username, password_hash, salt)
        VALUES (?, ?, ?)
    """, (data.username, password_hash, salt))

    connection.commit()
    connection.close()

    response.set_cookie(
        SESSION_COOKIE,
        create_session(data.username),
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=SESSION_DURATION,
        path="/"
    )

    return {"message": "Administrator account created successfully"}


@app.post("/auth/login")
def login(data: AdminCredentials, response: Response):
    connection = get_connection()
    admin = connection.execute(
        "SELECT * FROM admins WHERE username = ?",
        (data.username,)
    ).fetchone()
    connection.close()

    if not admin:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        data.password.encode(),
        admin["salt"].encode(),
        310000
    ).hex()

    if not hmac.compare_digest(password_hash, admin["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    response.set_cookie(
        SESSION_COOKIE,
        create_session(data.username),
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=SESSION_DURATION,
        path="/"
    )

    return {"message": "Login successful"}


@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"message": "Logged out successfully"}

@app.get("/threat-actors")
def get_threat_actors():
    connection = get_connection()
    rows = connection.execute(
        "SELECT * FROM threat_actors ORDER BY id ASC"
    ).fetchall()
    connection.close()
    return [row_to_dict(row) for row in rows]


@app.get("/malware")
def get_malware():
    connection = get_connection()
    rows = connection.execute(
        "SELECT * FROM malware ORDER BY id ASC"
    ).fetchall()
    connection.close()
    return [row_to_dict(row) for row in rows]


@app.get("/iocs")
def get_iocs():
    connection = get_connection()
    rows = connection.execute(
        "SELECT * FROM iocs ORDER BY id ASC"
    ).fetchall()
    connection.close()
    return [row_to_dict(row) for row in rows]


@app.post("/threat-actors")
@app.post("/malware")
@app.post("/iocs")
def block_public_insertion():
    raise HTTPException(
        status_code=403,
        detail="Submit intelligence through the Add Intelligence page for review."
    )

@app.post("/submissions")
def create_submission(data: IntelligenceSubmission):
    record_name = data.value if data.category == "IOC" else data.name

    if not record_name.strip():
        raise HTTPException(status_code=400, detail="A name or IOC value is required")

    connection = get_connection()

    if data.category == "Threat Actor":
        table, column = "threat_actors", "name"
    elif data.category == "Malware":
        table, column = "malware", "name"
    else:
        table, column = "iocs", "value"

    existing = connection.execute(
        f"SELECT id FROM {table} WHERE lower(trim({column})) = lower(trim(?))",
        (record_name,)
    ).fetchone()

    pending = connection.execute("""
        SELECT id FROM submissions
        WHERE category = ? AND status = 'Pending'
        AND lower(json_extract(data_json, ?)) = lower(?)
    """, (
        data.category,
        "$.value" if data.category == "IOC" else "$.name",
        record_name.strip()
    )).fetchone()

    if existing or pending:
        connection.close()
        raise HTTPException(
            status_code=409,
            detail="This intelligence record already exists or is awaiting review."
        )

    connection.execute("""
        INSERT INTO submissions (category, data_json, source)
        VALUES (?, ?, ?)
    """, (
        data.category,
        data.model_dump_json(),
        data.source.strip()
    ))

    connection.commit()
    connection.close()

    return {"message": "Submission received and awaiting administrator review."}


@app.get("/admin/submissions")
def get_submissions(status: str = "Pending", username: str = Depends(require_admin)):
    if status not in ["Pending", "Approved", "Rejected"]:
        raise HTTPException(status_code=400, detail="Invalid status")

    connection = get_connection()
    rows = connection.execute("""
        SELECT * FROM submissions
        WHERE status = ?
        ORDER BY id ASC
    """, (status,)).fetchall()
    connection.close()

    results = []

    for row in rows:
        item = row_to_dict(row)
        item["data"] = json.loads(item["data_json"])
        results.append(item)

    return results


@app.get("/admin/submission-counts")
def submission_counts(username: str = Depends(require_admin)):
    connection = get_connection()
    rows = connection.execute("""
        SELECT status, COUNT(*) AS total
        FROM submissions GROUP BY status
    """).fetchall()
    connection.close()

    counts = {"Pending": 0, "Approved": 0, "Rejected": 0}

    for row in rows:
        counts[row["status"]] = row["total"]

    return counts


@app.post("/admin/submissions/{submission_id}/approve")
def approve_submission(
    submission_id: int,
    decision: ReviewDecision,
    username: str = Depends(require_admin)
):
    connection = get_connection()

    submission = connection.execute(
        "SELECT * FROM submissions WHERE id = ?",
        (submission_id,)
    ).fetchone()

    if not submission:
        connection.close()
        raise HTTPException(status_code=404, detail="Submission not found")

    if submission["status"] != "Pending":
        connection.close()
        raise HTTPException(status_code=400, detail="Submission already reviewed")

    data = json.loads(submission["data_json"])
    category = submission["category"]

    if category == "Threat Actor":
        cursor = connection.execute("""
            INSERT INTO threat_actors
            (name, description, country, severity)
            VALUES (?, ?, ?, ?)
        """, (
            data["name"], data["description"],
            data["country"], data["severity"]
        ))

    elif category == "Malware":
        cursor = connection.execute("""
            INSERT INTO malware
            (name, type, description, severity)
            VALUES (?, ?, ?, ?)
        """, (
            data["name"], data["type"],
            data["description"], data["severity"]
        ))

    else:
        cursor = connection.execute("""
            INSERT INTO iocs
            (value, type, description, severity)
            VALUES (?, ?, ?, ?)
        """, (
            data["value"], data["type"],
            data["description"], data["severity"]
        ))

    record_id = cursor.lastrowid

    connection.execute("""
        UPDATE submissions
        SET status = 'Approved',
            reviewed_at = CURRENT_TIMESTAMP,
            review_note = ?
        WHERE id = ?
    """, (decision.review_note, submission_id))

    log_activity(
        connection, username, "Approved submission",
        category, record_id, f"Submission #{submission_id}"
    )

    connection.commit()
    connection.close()

    return {"message": "Submission approved"}


@app.post("/admin/submissions/{submission_id}/reject")
def reject_submission(
    submission_id: int,
    decision: ReviewDecision,
    username: str = Depends(require_admin)
):
    connection = get_connection()

    submission = connection.execute(
        "SELECT * FROM submissions WHERE id = ?",
        (submission_id,)
    ).fetchone()

    if not submission:
        connection.close()
        raise HTTPException(status_code=404, detail="Submission not found")

    if submission["status"] != "Pending":
        connection.close()
        raise HTTPException(status_code=400, detail="Submission already reviewed")

    connection.execute("""
        UPDATE submissions
        SET status = 'Rejected',
            reviewed_at = CURRENT_TIMESTAMP,
            review_note = ?
        WHERE id = ?
    """, (decision.review_note, submission_id))

    log_activity(
        connection, username, "Rejected submission",
        submission["category"], submission_id
    )

    connection.commit()
    connection.close()

    return {"message": "Submission rejected"}

TABLE_COLUMNS = {
    "threat-actors": ("threat_actors", ["name", "description", "country", "severity"]),
    "malware": ("malware", ["name", "type", "description", "severity"]),
    "iocs": ("iocs", ["value", "type", "description", "severity"])
}


def update_record(endpoint, record_id, data, username):
    if endpoint not in TABLE_COLUMNS:
        raise HTTPException(status_code=404, detail="Invalid record type")

    table, allowed = TABLE_COLUMNS[endpoint]
    values = {key: value for key, value in data.items() if key in allowed}

    if not values:
        raise HTTPException(status_code=400, detail="No valid fields supplied")

    connection = get_connection()

    existing = connection.execute(
        f"SELECT id FROM {table} WHERE id = ?",
        (record_id,)
    ).fetchone()

    if not existing:
        connection.close()
        raise HTTPException(status_code=404, detail="Record not found")

    assignments = ", ".join(f"{key} = ?" for key in values)
    parameters = list(values.values()) + [record_id]

    connection.execute(
        f"UPDATE {table} SET {assignments} WHERE id = ?",
        parameters
    )

    log_activity(
        connection, username, "Edited record",
        endpoint, record_id, json.dumps(values)
    )

    connection.commit()
    connection.close()

    return {"message": "Record updated successfully"}


@app.put("/threat-actors/{record_id}")
def edit_actor(record_id: int, data: dict, username: str = Depends(require_admin)):
    return update_record("threat-actors", record_id, data, username)


@app.put("/malware/{record_id}")
def edit_malware(record_id: int, data: dict, username: str = Depends(require_admin)):
    return update_record("malware", record_id, data, username)


@app.put("/iocs/{record_id}")
def edit_ioc(record_id: int, data: dict, username: str = Depends(require_admin)):
    return update_record("iocs", record_id, data, username)


def delete_record(endpoint, record_id, username):
    if endpoint not in TABLE_COLUMNS:
        raise HTTPException(status_code=404, detail="Invalid record type")

    table = TABLE_COLUMNS[endpoint][0]
    connection = get_connection()

    existing = connection.execute(
        f"SELECT id FROM {table} WHERE id = ?",
        (record_id,)
    ).fetchone()

    if not existing:
        connection.close()
        raise HTTPException(status_code=404, detail="Record not found")

    connection.execute(
        f"DELETE FROM {table} WHERE id = ?",
        (record_id,)
    )

    log_activity(
        connection, username, "Deleted record",
        endpoint, record_id
    )

    connection.commit()
    connection.close()

    return {"message": "Record deleted successfully"}


@app.delete("/threat-actors/{record_id}")
def remove_actor(record_id: int, username: str = Depends(require_admin)):
    return delete_record("threat-actors", record_id, username)


@app.delete("/malware/{record_id}")
def remove_malware(record_id: int, username: str = Depends(require_admin)):
    return delete_record("malware", record_id, username)


@app.delete("/iocs/{record_id}")
def remove_ioc(record_id: int, username: str = Depends(require_admin)):
    return delete_record("iocs", record_id, username)

@app.get("/analytics")
def analytics():
    connection = get_connection()

    categories = {
        "Threat Actors": connection.execute(
            "SELECT COUNT(*) AS total FROM threat_actors"
        ).fetchone()["total"],
        "Malware": connection.execute(
            "SELECT COUNT(*) AS total FROM malware"
        ).fetchone()["total"],
        "IOCs": connection.execute(
            "SELECT COUNT(*) AS total FROM iocs"
        ).fetchone()["total"]
    }

    severity = {}

    for table in ["threat_actors", "malware", "iocs"]:
        rows = connection.execute(
            f"SELECT severity, COUNT(*) AS total FROM {table} GROUP BY severity"
        ).fetchall()

        for row in rows:
            key = row["severity"] or "Medium"
            severity[key] = severity.get(key, 0) + row["total"]

    connection.close()

    return {
        "categories": categories,
        "severity": severity,
        "total": sum(categories.values())
    }

@app.get("/admin/activity")
def get_activity(username: str = Depends(require_admin)):
    connection = get_connection()
    rows = connection.execute("""
        SELECT * FROM activity_logs
        ORDER BY id DESC LIMIT 100
    """).fetchall()
    connection.close()

    return [row_to_dict(row) for row in rows]

@app.get("/admin/backup")
def backup_database(username: str = Depends(require_admin)):
    source = get_connection()
    destination = sqlite3.connect(":memory:")

    source.backup(destination)
    backup_data = destination.serialize()

    source.close()
    destination.close()

    return Response(
        content=backup_data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition":
            'attachment; filename="threat_dashboard_backup.db"'
        }
    )