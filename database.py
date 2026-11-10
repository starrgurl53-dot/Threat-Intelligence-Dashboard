import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "threat_dashboard.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def create_tables():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_actors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            country TEXT,
            severity TEXT DEFAULT 'Medium',
            date_recorded TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS malware (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT,
            description TEXT,
            severity TEXT DEFAULT 'Medium',
            date_recorded TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL,
            type TEXT,
            description TEXT,
            severity TEXT DEFAULT 'Medium',
            date_recorded TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            setting_name TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            data_json TEXT NOT NULL,
            source TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            submitted_at TEXT DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TEXT,
            review_note TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_username TEXT,
            action TEXT NOT NULL,
            category TEXT,
            record_id INTEGER,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    migrations = {
        "threat_actors": {
            "severity": "TEXT DEFAULT 'Medium'",
            "date_recorded": "TEXT"
        },
        "malware": {
            "severity": "TEXT DEFAULT 'Medium'",
            "date_recorded": "TEXT"
        },
        "iocs": {
            "severity": "TEXT DEFAULT 'Medium'",
            "date_recorded": "TEXT"
        }
    }

    for table, columns in migrations.items():
        existing = {
            row["name"]
            for row in cursor.execute(
                f"PRAGMA table_info({table})"
            ).fetchall()
        }

        for column, definition in columns.items():
            if column not in existing:
                cursor.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
                )

        cursor.execute(
            f"UPDATE {table} SET date_recorded = CURRENT_TIMESTAMP "
            "WHERE date_recorded IS NULL"
        )

    cursor.execute("""
        INSERT OR IGNORE INTO app_settings
        (setting_name, setting_value)
        VALUES ('session_secret', lower(hex(randomblob(32))))
    """)

    connection.commit()
    connection.close()