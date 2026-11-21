
import sqlite3
import hashlib
import secrets
import json

from pathlib import Path
from datetime import datetime, timezone


# --------------------------------------------------
# DATABASE CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "database" / "evsecure.db"

SUPPORTED_SECURITY_MODES = {
    "LEGACY_MD5",
    "MIGRATION",
    "SECURE_SHA3"
}


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_connection():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def get_current_time():
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chargers (
                charger_id TEXT PRIMARY KEY,
                location TEXT,
                connector_count INTEGER DEFAULT 1,
                protocol TEXT DEFAULT 'OCPP 1.6',
                security_mode TEXT DEFAULT 'LEGACY_MD5',
                credential_hash TEXT,
                created_at TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id TEXT PRIMARY KEY,
                charger_id TEXT,
                energy_kwh REAL,
                status TEXT,
                created_at TEXT,
                FOREIGN KEY (charger_id)
                    REFERENCES chargers(charger_id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                charger_id TEXT,
                message_type TEXT,
                transaction_id TEXT,
                payload TEXT,
                hashes TEXT,
                verification_status TEXT,
                integrity_algorithm TEXT,
                integrity_status TEXT,
                created_at TEXT,
                FOREIGN KEY (charger_id)
                    REFERENCES chargers(charger_id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                charger_id TEXT,
                event_type TEXT,
                description TEXT,
                severity TEXT DEFAULT 'INFO',
                created_at TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS message_replays (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                charger_id TEXT NOT NULL,
                message_type TEXT,
                message_fingerprint TEXT NOT NULL,
                first_seen TEXT,
                created_at TEXT,
                UNIQUE(charger_id, message_fingerprint)
            )
        """)

        # --------------------------------------------------
        # HANDLE EXISTING DATABASE SCHEMAS
        # --------------------------------------------------

        existing_columns = {
            row["name"]
            for row in cursor.execute(
                "PRAGMA table_info(chargers)"
            ).fetchall()
        }

        charger_columns = {
            "location": "TEXT",
            "connector_count": "INTEGER DEFAULT 1",
            "protocol": "TEXT DEFAULT 'OCPP 1.6'",
            "security_mode": "TEXT DEFAULT 'LEGACY_MD5'",
            "credential_hash": "TEXT",
            "created_at": "TEXT"
        }

        for column, definition in charger_columns.items():
            if column not in existing_columns:
                cursor.execute(
                    f"ALTER TABLE chargers ADD COLUMN {column} {definition}"
                )

        existing_message_columns = {
            row["name"]
            for row in cursor.execute(
                "PRAGMA table_info(messages)"
            ).fetchall()
        }

        message_columns = {
            "message_type": "TEXT",
            "transaction_id": "TEXT",
            "payload": "TEXT",
            "hashes": "TEXT",
            "verification_status": "TEXT",
            "integrity_algorithm": "TEXT",
            "integrity_status": "TEXT",
            "created_at": "TEXT"
        }

        for column, definition in message_columns.items():
            if column not in existing_message_columns:
                cursor.execute(
                    f"ALTER TABLE messages ADD COLUMN {column} {definition}"
                )

        existing_replay_columns = {
            row["name"]
            for row in cursor.execute(
                "PRAGMA table_info(message_replays)"
            ).fetchall()
        }

        replay_columns = {
            "message_type": "TEXT",
            "message_fingerprint": "TEXT",
            "first_seen": "TEXT",
            "created_at": "TEXT"
        }

        for column, definition in replay_columns.items():
            if column not in existing_replay_columns:
                cursor.execute(
                    f"ALTER TABLE message_replays ADD COLUMN {column} {definition}"
                )

        connection.commit()

    finally:
        connection.close()


# --------------------------------------------------
# CREDENTIAL MANAGEMENT
# --------------------------------------------------

def hash_credential(secret):
    """
    Hashes a charger credential using SHA-256.
    This is credential hashing, not message encryption.
    """

    return hashlib.sha256(
        secret.encode("utf-8")
    ).hexdigest()


def generate_charger_credential():
    """
    Generates a secure random charger credential.
    """

    return secrets.token_urlsafe(32)


# --------------------------------------------------
# CHARGER REGISTRATION
# --------------------------------------------------

def register_charger(
    charger_id,
    location="Unknown",
    connector_count=1,
    protocol="OCPP 1.6"
):
    """
    Registers a new EV charging station.
    Returns the generated plaintext credential.
    Only its SHA-256 hash is stored.
    """

    credential = generate_charger_credential()
    credential_hash = hash_credential(credential)

    connection = get_connection()

    try:
        connection.execute("""
            INSERT INTO chargers (
                charger_id,
                location,
                connector_count,
                protocol,
                security_mode,
                credential_hash,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            charger_id,
            location,
            connector_count,
            protocol,
            "LEGACY_MD5",
            credential_hash,
            get_current_time()
        ))

        connection.commit()

    finally:
        connection.close()

    return credential


# --------------------------------------------------
# CHARGER AUTHENTICATION
# --------------------------------------------------

def authenticate_charger(charger_id, credential):
    """
    Checks whether the supplied charger credential
    matches the stored credential hash.
    """

    connection = get_connection()

    try:
        charger = connection.execute("""
            SELECT credential_hash
            FROM chargers
            WHERE charger_id = ?
        """, (charger_id,)).fetchone()

    finally:
        connection.close()

    if not charger or not charger["credential_hash"]:
        return False

    supplied_hash = hash_credential(credential)

    return secrets.compare_digest(
        supplied_hash,
        charger["credential_hash"]
    )


# --------------------------------------------------
# CHARGER INFORMATION
# --------------------------------------------------

def get_all_chargers():
    connection = get_connection()

    try:
        rows = connection.execute("""
            SELECT
                charger_id,
                location,
                connector_count,
                protocol,
                security_mode,
                created_at
            FROM chargers
            ORDER BY created_at DESC
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_charger(charger_id):
    connection = get_connection()

    try:
        row = connection.execute("""
            SELECT *
            FROM chargers
            WHERE charger_id = ?
        """, (charger_id,)).fetchone()

        return dict(row) if row else None

    finally:
        connection.close()


# --------------------------------------------------
# SECURITY MODE MANAGEMENT
# --------------------------------------------------

def update_security_mode(charger_id, security_mode):
    """
    Changes the security mode of a registered charger.
    """

    if security_mode not in SUPPORTED_SECURITY_MODES:
        raise ValueError("Unsupported security mode.")

    connection = get_connection()

    try:
        cursor = connection.execute("""
            UPDATE chargers
            SET security_mode = ?
            WHERE charger_id = ?
        """, (security_mode, charger_id))

        connection.commit()

        return cursor.rowcount > 0

    finally:
        connection.close()


# --------------------------------------------------
# TRANSACTION MANAGEMENT
# --------------------------------------------------


def save_transaction(
    transaction_id,
    charger_id,
    energy_kwh=None,
    status=None,
    connector_id=None,
    id_tag=None,
    meter_start=None,
    meter_stop=None,
    started_at=None,
    stopped_at=None
):
    """
    Create or update an EV charging transaction.

    StartTransaction creates the transaction.
    StopTransaction updates the existing transaction.
    """

    connection = get_connection()

    try:
        existing = connection.execute("""
            SELECT *
            FROM transactions
            WHERE transaction_id = ?
              AND charger_id = ?
        """, (str(transaction_id), charger_id)).fetchone()

        if existing:
            connection.execute("""
                UPDATE transactions
                SET
                    connector_id = COALESCE(?, connector_id),
                    id_tag = COALESCE(?, id_tag),
                    meter_start = COALESCE(?, meter_start),
                    meter_stop = COALESCE(?, meter_stop),
                    energy_kwh = COALESCE(?, energy_kwh),
                    started_at = COALESCE(?, started_at),
                    stopped_at = COALESCE(?, stopped_at)
                WHERE transaction_id = ?
                  AND charger_id = ?
            """, (
                connector_id,
                id_tag,
                meter_start,
                meter_stop,
                energy_kwh,
                started_at,
                stopped_at,
                str(transaction_id),
                charger_id
            ))

        else:
            connection.execute("""
                INSERT INTO transactions (
                    transaction_id,
                    charger_id,
                    connector_id,
                    id_tag,
                    meter_start,
                    meter_stop,
                    energy_kwh,
                    started_at,
                    stopped_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(transaction_id),
                charger_id,
                connector_id,
                id_tag,
                meter_start,
                meter_stop,
                energy_kwh,
                started_at,
                stopped_at
            ))

        connection.commit()
        return True

    finally:
        connection.close()



def get_transactions():
    connection = get_connection()

    try:
        rows = connection.execute("""
            SELECT *
            FROM transactions
            ORDER BY created_at DESC
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


# --------------------------------------------------
# MESSAGE STORAGE
# --------------------------------------------------


def save_message(
    charger_id,
    message_type,
    payload,
    hashes=None,
    verification_status="PENDING",
    transaction_id=None,
    integrity_algorithm=None,
    integrity_status=None
):
    """
    Store a received message and its integrity verification result.
    """

    payload_json = (
        json.dumps(payload, sort_keys=True)
        if isinstance(payload, (dict, list))
        else str(payload)
    )

    hashes_json = json.dumps(hashes or {})

    # Keep both status fields synchronized.
    final_status = integrity_status or verification_status

    connection = get_connection()

    try:
        cursor = connection.execute("""
            INSERT INTO messages (
                charger_id,
                message_type,
                transaction_id,
                payload,
                hashes,
                verification_status,
                integrity_algorithm,
                integrity_status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            charger_id,
            message_type,
            str(transaction_id) if transaction_id is not None else None,
            payload_json,
            hashes_json,
            final_status,
            integrity_algorithm,
            final_status,
            get_current_time()
        ))

        connection.commit()
        return cursor.lastrowid

    finally:
        connection.close()



def get_messages(limit=100):
    connection = get_connection()

    try:
        rows = connection.execute("""
            SELECT *
            FROM messages
            ORDER BY id DESC
            LIMIT ?
        """, (int(limit),)).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


# --------------------------------------------------
# SECURITY EVENT LOGGING
# --------------------------------------------------

def save_security_event(
    charger_id,
    event_type,
    description,
    severity="INFO"
):
    connection = get_connection()

    try:
        cursor = connection.execute("""
            INSERT INTO security_events (
                charger_id,
                event_type,
                description,
                severity,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            charger_id,
            event_type,
            description,
            severity,
            get_current_time()
        ))

        connection.commit()

        return cursor.lastrowid

    finally:
        connection.close()


def get_security_events(limit=100):
    connection = get_connection()

    try:
        rows = connection.execute("""
            SELECT *
            FROM security_events
            ORDER BY id DESC
            LIMIT ?
        """, (int(limit),)).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


# --------------------------------------------------
# REPLAY ATTACK DETECTION
# --------------------------------------------------

def check_and_record_replay(
    charger_id,
    message_type,
    payload
):
    """
    Detects exact repeated message payloads.

    Returns:
        False: First time this payload was received.
        True: Duplicate payload detected.
    """

    if isinstance(payload, (dict, list)):
        payload_string = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":")
        )
    else:
        payload_string = str(payload)

    fingerprint = hashlib.sha256(
        payload_string.encode("utf-8")
    ).hexdigest()

    connection = get_connection()

    try:
        current_time = get_current_time()

        connection.execute("""
            INSERT INTO message_replays (
                charger_id,
                message_type,
                message_fingerprint,
                first_seen,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            charger_id,
            message_type,
            fingerprint,
            current_time,
            current_time
        ))

        connection.commit()
        return False

    except sqlite3.IntegrityError as error:
        connection.rollback()

        if "UNIQUE constraint failed" in str(error):
            return True

        raise

    finally:
        connection.close()


# --------------------------------------------------
# DATABASE STATISTICS
# --------------------------------------------------

def get_database_statistics():
    connection = get_connection()

    try:
        chargers = connection.execute(
            "SELECT COUNT(*) FROM chargers"
        ).fetchone()[0]

        transactions = connection.execute(
            "SELECT COUNT(*) FROM transactions"
        ).fetchone()[0]

        messages = connection.execute(
            "SELECT COUNT(*) FROM messages"
        ).fetchone()[0]

        events = connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

        replay_records = connection.execute(
            "SELECT COUNT(*) FROM message_replays"
        ).fetchone()[0]

        return {
            "total_chargers": chargers,
            "total_transactions": transactions,
            "total_messages": messages,
            "total_security_events": events,
            "total_replay_records": replay_records
        }

    finally:
        connection.close()


# --------------------------------------------------
# INITIALIZE DATABASE WHEN MODULE IS IMPORTED
# --------------------------------------------------

initialize_database()


def get_recent_messages(limit=100):
    """
    Retrieve the most recent messages stored in the database.
    """

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM messages
            ORDER BY id DESC
            LIMIT ?
        """, (int(limit),))

        rows = cursor.fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()
