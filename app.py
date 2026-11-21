
import csv
import json
import logging
import subprocess
import sys
from pathlib import Path

from flask import Flask, request, jsonify, render_template

from database.db import (
    initialize_database,
    register_charger,
    authenticate_charger,
    get_charger,
    get_all_chargers,
    update_security_mode,
    save_transaction,
    save_message,
    save_security_event,
    get_security_events,
    get_recent_messages,
    check_and_record_replay
)

from crypto.hash_engine import (
    calculate_all_hashes,
    verify_hash
)

from crypto.migration import (
    generate_integrity_hashes,
    verify_message_integrity,
    compare_migration_results
)

from crypto.collision_demo import (
    analyze_algorithms,
    compare_files
)


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
PROCESSED_DIR = BASE_DIR / "dataset" / "processed"

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

logging.basicConfig(level=logging.INFO)

ALLOWED_MESSAGE_TYPES = {
    "StartTransaction",
    "MeterValues",
    "StopTransaction",
    "Heartbeat",
    "StatusNotification"
}

ALLOWED_SECURITY_MODES = {
    "LEGACY_MD5",
    "MIGRATION",
    "SECURE_SHA3"
}


# =========================================================
# COMMON RESPONSE HELPERS
# =========================================================

def success_response(data=None, message=None, status=200):
    response = {"success": True}

    if message:
        response["message"] = message

    if data is not None:
        response["data"] = data

    return jsonify(response), status


def error_response(message, status=400, extra=None):
    response = {
        "success": False,
        "error": message
    }

    if extra:
        response.update(extra)

    return jsonify(response), status


def get_json_body():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return None

    return data


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():
    return render_template("dashboard.html")


@app.route("/api/health", methods=["GET"])
def health():
    return success_response({
        "status": "online",
        "application": "EVSecure-Migrate"
    })


# =========================================================
# CHARGER REGISTRATION
# =========================================================

@app.route("/api/chargers/register", methods=["POST"])
def register():

    data = get_json_body()

    if data is None:
        return error_response("A JSON request body is required.")

    required_fields = [
        "charger_id",
        "location",
        "connector_count",
        "protocol"
    ]

    missing = [
        field for field in required_fields
        if field not in data or data[field] in (None, "")
    ]

    if missing:
        return error_response(
            "Missing required fields.",
            400,
            {"missing": missing}
        )

    charger_id = str(data["charger_id"]).strip()
    location = str(data["location"]).strip()
    protocol = str(data["protocol"]).strip()

    if not charger_id or not location or not protocol:
        return error_response("Charger ID, location and protocol cannot be empty.")

    security_mode = data.get("security_mode", "LEGACY_MD5")

    if security_mode not in ALLOWED_SECURITY_MODES:
        return error_response("Invalid security mode.")

    try:
        connector_count = int(data["connector_count"])

        if connector_count < 1:
            raise ValueError

    except (ValueError, TypeError):
        return error_response(
            "connector_count must be a positive integer."
        )

    try:
        # The database function generates and returns the credential.
        # Do not pass credential= here.
        credential = register_charger(
            charger_id=charger_id,
            location=location,
            connector_count=connector_count,
            protocol=protocol,
            security_mode=security_mode
        )

        save_security_event(
            "CHARGER_REGISTERED",
            "INFO",
            charger_id,
            "New charger registered successfully."
        )

        return success_response(
            {
                "charger_id": charger_id,
                "security_mode": security_mode,
                "credential": credential,
                "credential_note": (
                    "Store this credential securely. "
                    "It is required for charger communication."
                )
            },
            "Charger registered successfully.",
            201
        )

    except Exception:
        app.logger.exception("Charger registration failed")
        return error_response(
            "Charger registration failed. Check the server log.",
            500
        )


# =========================================================
# CHARGER MANAGEMENT
# =========================================================

@app.route("/api/chargers", methods=["GET"])
def chargers():

    try:
        return success_response(get_all_chargers())

    except Exception:
        app.logger.exception("Unable to load chargers")
        return error_response("Unable to load chargers.", 500)


@app.route("/api/chargers/<charger_id>", methods=["GET"])
def charger_details(charger_id):

    try:
        charger = get_charger(charger_id)

        if not charger:
            return error_response("Charger not found.", 404)

        return success_response(charger)

    except Exception:
        app.logger.exception("Unable to load charger details")
        return error_response("Unable to load charger details.", 500)


# =========================================================
# SECURITY MODE MANAGEMENT
# =========================================================

def apply_security_mode(charger_id, security_mode):

    if not charger_id:
        return error_response("Charger ID is required.")

    if security_mode not in ALLOWED_SECURITY_MODES:
        return error_response("Invalid security mode.")

    try:
        charger = get_charger(charger_id)

        if not charger:
            return error_response("Charger not found.", 404)

        updated = update_security_mode(
            charger_id,
            security_mode
        )

        if not updated:
            return error_response(
                "Unable to update security mode.",
                500
            )

        save_security_event(
            "SECURITY_MODE_CHANGED",
            "INFO",
            charger_id,
            f"Security mode changed to {security_mode}."
        )

        return success_response(
            {
                "charger_id": charger_id,
                "security_mode": security_mode
            },
            "Security mode updated successfully."
        )

    except Exception:
        app.logger.exception("Security mode update failed")
        return error_response(
            "Security mode update failed.",
            500
        )


# Frontend-compatible endpoint.
# Accepts POST and PUT requests.
@app.route("/api/security/mode", methods=["POST", "PUT"])
def update_security_mode_api():

    data = get_json_body()

    if data is None:
        return error_response("A JSON request body is required.")

    charger_id = data.get("charger_id")
    security_mode = data.get(
        "security_mode",
        data.get("mode")
    )

    return apply_security_mode(
        charger_id,
        security_mode
    )


# Charger-specific endpoint.
@app.route(
    "/api/chargers/<charger_id>/security",
    methods=["PUT", "POST"]
)
def change_security_mode(charger_id):

    data = get_json_body()

    if data is None:
        return error_response("A JSON request body is required.")

    security_mode = data.get(
        "security_mode",
        data.get("mode")
    )

    return apply_security_mode(
        charger_id,
        security_mode
    )


# =========================================================
# CHARGER AUTHENTICATION TEST
# =========================================================

@app.route(
    "/api/chargers/<charger_id>/authenticate",
    methods=["POST"]
)
def authenticate_charger_api(charger_id):

    data = get_json_body()

    if data is None:
        return error_response("A JSON request body is required.")

    credential = data.get("credential")

    if not credential:
        return error_response("Credential is required.", 401)

    try:
        charger = get_charger(charger_id)

        if not charger:
            save_security_event(
                "UNKNOWN_CHARGER",
                "HIGH",
                charger_id,
                "Authentication attempted for an unregistered charger."
            )

            return error_response("UNAUTHORIZED CHARGER.", 403)

        authenticated = authenticate_charger(
            charger_id,
            credential
        )

        if not authenticated:
            save_security_event(
                "AUTHENTICATION_FAILED",
                "CRITICAL",
                charger_id,
                "Invalid charger credential."
            )

            return error_response("AUTHENTICATION FAILED.", 401)

        return success_response(
            {"charger_id": charger_id},
            "Charger authenticated successfully."
        )

    except Exception:
        app.logger.exception("Charger authentication failed")
        return error_response("Authentication failed.", 500)


# =========================================================
# CHARGING MESSAGE PROCESSING
# =========================================================

@app.route("/api/messages", methods=["POST"])
def receive_message():

    data = get_json_body()

    if data is None:
        return error_response(
            "A JSON request body is required."
        )

    message_type = data.get("message_type")
    charger_id = data.get("charger_id")
    credential = data.get("credential")
    transaction_id = data.get("transaction_id")

    if not message_type or not charger_id:
        return error_response(
            "message_type and charger_id are required."
        )

    if message_type not in ALLOWED_MESSAGE_TYPES:

        save_security_event(
            "INVALID_MESSAGE_TYPE",
            "MEDIUM",
            str(charger_id),
            f"Rejected unsupported message type: {message_type}."
        )

        return error_response(
            "Unsupported message type."
        )

    # Validate transaction data before recording replay state.
    if message_type in {"StartTransaction", "StopTransaction"}:
        if transaction_id in (None, ""):
            return error_response(
                "transaction_id is required for this message type."
            )

    try:
        charger = get_charger(charger_id)

        # -------------------------------------------------
        # UNKNOWN CHARGER DETECTION
        # -------------------------------------------------

        if not charger:

            save_security_event(
                "UNKNOWN_CHARGER",
                "HIGH",
                charger_id,
                "Message received from an unregistered charger."
            )

            return error_response(
                "UNAUTHORIZED CHARGER.",
                403
            )

        # -------------------------------------------------
        # MISSING CREDENTIAL DETECTION
        # -------------------------------------------------

        if not credential:

            save_security_event(
                "MISSING_CREDENTIAL",
                "HIGH",
                charger_id,
                "Charger communication attempted without credentials."
            )

            return error_response(
                "AUTHENTICATION REQUIRED.",
                401
            )

        # -------------------------------------------------
        # INVALID CREDENTIAL DETECTION
        # -------------------------------------------------

        if not authenticate_charger(charger_id, credential):

            save_security_event(
                "AUTHENTICATION_FAILED",
                "CRITICAL",
                charger_id,
                "Invalid charger credential."
            )

            return error_response(
                "AUTHENTICATION FAILED.",
                401
            )

        # Remove the credential before hashing or storing.
        message_payload = {
            key: value
            for key, value in data.items()
            if key != "credential"
        }

        payload_string = json.dumps(
            message_payload,
            sort_keys=True,
            separators=(",", ":")
        )

        # -------------------------------------------------
        # PERSISTENT REPLAY DETECTION
        # -------------------------------------------------

        replay_detected = check_and_record_replay(
            charger_id,
            message_type,
            payload_string
        )

        if replay_detected:

            save_security_event(
                "REPLAY_ATTACK_DETECTED",
                "HIGH",
                charger_id,
                f"Previously received {message_type} message was rejected."
            )

            return error_response(
                "REPLAY ATTACK DETECTED: duplicate message rejected.",
                409
            )

        # -------------------------------------------------
        # HASH GENERATION
        # -------------------------------------------------

        all_hashes = calculate_all_hashes(payload_string)

        security_mode = charger["security_mode"]

        # -------------------------------------------------
        # LEGACY MD5 MODE
        # -------------------------------------------------

        if security_mode == "LEGACY_MD5":

            integrity_algorithm = "MD5"

            integrity_verified = verify_hash(
                payload_string,
                all_hashes["md5"],
                "md5"
            )

            integrity_status = (
                "LEGACY_VERIFIED"
                if integrity_verified
                else "LEGACY_VERIFICATION_FAILED"
            )

        # -------------------------------------------------
        # DUAL-HASH MIGRATION MODE
        # -------------------------------------------------

        elif security_mode == "MIGRATION":

            md5_verified = verify_hash(
                payload_string,
                all_hashes["md5"],
                "md5"
            )

            sha3_verified = verify_hash(
                payload_string,
                all_hashes["sha3_256"],
                "sha3_256"
            )

            integrity_verified = (
                md5_verified and sha3_verified
            )

            integrity_algorithm = "MD5 + SHA3-256"

            integrity_status = (
                "DUAL_VERIFIED"
                if integrity_verified
                else "DUAL_VERIFICATION_FAILED"
            )

        # -------------------------------------------------
        # SHA3-256 MODE
        # -------------------------------------------------

        elif security_mode == "SECURE_SHA3":

            integrity_algorithm = "SHA3-256"

            integrity_verified = verify_hash(
                payload_string,
                all_hashes["sha3_256"],
                "sha3_256"
            )

            integrity_status = (
                "SECURE_VERIFIED"
                if integrity_verified
                else "SECURE_VERIFICATION_FAILED"
            )

        else:
            return error_response(
                "Unknown charger security configuration.",
                500
            )

        # -------------------------------------------------
        # INTEGRITY FAILURE
        # -------------------------------------------------

        if not integrity_verified:

            save_security_event(
                "MESSAGE_INTEGRITY_FAILED",
                "CRITICAL",
                charger_id,
                f"Integrity verification failed in {security_mode} mode."
            )

            return error_response(
                "Message integrity verification failed.",
                400
            )

        # -------------------------------------------------
        # TRANSACTION PROCESSING
        # -------------------------------------------------

        if message_type == "StartTransaction":

            save_transaction(
                transaction_id=transaction_id,
                charger_id=charger_id,
                connector_id=data.get("connector_id"),
                id_tag=data.get("id_tag"),
                meter_start=data.get("meter_start"),
                started_at=data.get("timestamp")
            )

        elif message_type == "StopTransaction":

            save_transaction(
                transaction_id=transaction_id,
                charger_id=charger_id,
                meter_stop=data.get("meter_stop"),
                energy_kwh=data.get("energy_kwh"),
                stopped_at=data.get("timestamp")
            )

        # -------------------------------------------------
        # SAVE MESSAGE
        # -------------------------------------------------

        save_message(
            message_type=message_type,
            charger_id=charger_id,
            transaction_id=transaction_id,
            payload=payload_string,
            hashes=all_hashes,
            integrity_algorithm=integrity_algorithm,
            integrity_status=integrity_status
        )

        save_security_event(
            "MESSAGE_ACCEPTED",
            "INFO",
            charger_id,
            f"{message_type} accepted using {integrity_algorithm}."
        )

        return success_response({
            "message": "Charging message accepted.",
            "charger": charger_id,
            "message_type": message_type,
            "security_mode": security_mode,
            "integrity_algorithm": integrity_algorithm,
            "integrity_status": integrity_status,
            "hashes": all_hashes
        })

    except Exception:
        app.logger.exception("Charging message processing failed")
        return error_response(
            "Unable to process charging message.",
            500
        )


# =========================================================
# MESSAGE HISTORY
# =========================================================

@app.route("/api/messages", methods=["GET"])
def messages():

    try:
        return success_response(get_recent_messages())

    except Exception:
        app.logger.exception("Unable to load message history")
        return error_response(
            "Unable to load message history.",
            500
        )


# =========================================================
# SECURITY EVENTS
# =========================================================

@app.route("/api/security/events", methods=["GET"])
def security_events():

    try:
        return success_response(get_security_events())

    except Exception:
        app.logger.exception("Unable to load security events")
        return error_response(
            "Unable to load security events.",
            500
        )


# =========================================================
# CRYPTOGRAPHIC HASH ANALYZER
# =========================================================

@app.route("/api/crypto/analyze", methods=["POST"])
def analyze_crypto():

    data = get_json_body()

    if data is None:
        return error_response(
            "A JSON request body is required."
        )

    message = data.get("message")

    if not isinstance(message, str) or not message.strip():
        return error_response(
            "Please enter a valid message."
        )

    if len(message) > 100000:
        return error_response(
            "Message exceeds the 100,000 character limit.",
            413
        )

    try:
        hashes = calculate_all_hashes(message)

        digest_lengths = {
            "md5": 128,
            "sha1": 160,
            "sha256": 256,
            "sha3_256": 256
        }

        results = {}

        for algorithm, digest in hashes.items():

            results[algorithm] = {
                "hash": digest,
                "digest_bits": digest_lengths[algorithm],
                "digest_characters": len(digest)
            }

        return success_response({
            "original_message": message,
            "message_length": len(message),
            "algorithms": results
        })

    except Exception:
        app.logger.exception("Hash analysis failed")
        return error_response(
            "Unable to calculate message hashes.",
            500
        )


# =========================================================
# CONTROLLED MESSAGE TAMPERING SIMULATION
# =========================================================

@app.route("/api/attack/tampering", methods=["POST"])
def simulate_tampering():

    data = get_json_body()

    if data is None:
        return error_response(
            "A JSON request body is required."
        )

    original_message = data.get("original_message")
    modified_message = data.get("modified_message")

    if not isinstance(original_message, str):
        return error_response(
            "original_message must be a string."
        )

    if not isinstance(modified_message, str):
        return error_response(
            "modified_message must be a string."
        )

    if not original_message.strip() or not modified_message.strip():
        return error_response(
            "Both messages must contain text."
        )

    if len(original_message) > 100000 or len(modified_message) > 100000:
        return error_response(
            "Messages cannot exceed 100,000 characters.",
            413
        )

    try:
        original_hashes = calculate_all_hashes(
            original_message
        )

        modified_hashes = calculate_all_hashes(
            modified_message
        )

        algorithm_results = {}

        for algorithm, original_digest in original_hashes.items():

            verified = verify_hash(
                modified_message,
                original_digest,
                algorithm
            )

            algorithm_results[algorithm] = {
                "original_hash": original_digest,
                "modified_hash": modified_hashes[algorithm],
                "integrity_verified": verified,
                "tampering_detected": not verified
            }

        tampering_detected = any(
            result["tampering_detected"]
            for result in algorithm_results.values()
        )

        detected_algorithms = [
            algorithm.upper()
            for algorithm, result in algorithm_results.items()
            if result["tampering_detected"]
        ]

        unchanged_algorithms = [
            algorithm.upper()
            for algorithm, result in algorithm_results.items()
            if result["integrity_verified"]
        ]

        save_security_event(
            "MESSAGE_TAMPERING_DETECTED"
            if tampering_detected
            else "MESSAGE_INTEGRITY_VERIFIED",
            "HIGH" if tampering_detected else "INFO",
            "SIMULATION",
            (
                "Controlled modification detected by: "
                + ", ".join(detected_algorithms)
                if tampering_detected
                else "No message modification detected."
            )
        )

        return success_response({
            "simulation": "CONTROLLED_MESSAGE_TAMPERING",
            "original_message": original_message,
            "modified_message": modified_message,
            "messages_identical": (
                original_message == modified_message
            ),
            "tampering_detected": tampering_detected,
            "overall_status": (
                "TAMPERING_DETECTED"
                if tampering_detected
                else "INTEGRITY_VERIFIED"
            ),
            "detected_algorithms": detected_algorithms,
            "unchanged_algorithms": unchanged_algorithms,
            "algorithms": algorithm_results,
            "methodology": (
                "This is a controlled message modification test, "
                "not an MD5 collision attack."
            )
        })

    except Exception:
        app.logger.exception("Tampering simulation failed")
        return error_response(
            "Unable to complete tampering simulation.",
            500
        )


# =========================================================
# MIGRATION ANALYSIS
# =========================================================

@app.route("/api/migration/analyze", methods=["POST"])
def migration_analysis():

    data = get_json_body()

    if data is None:
        return error_response(
            "A JSON request body is required."
        )

    message = data.get("message")
    mode = data.get("security_mode", "MIGRATION")
    trusted_hashes = data.get("trusted_hashes")

    if not isinstance(message, str) or not message.strip():
        return error_response(
            "A non-empty message is required."
        )

    if len(message) > 100000:
        return error_response(
            "Message exceeds 100,000 characters.",
            413
        )

    if mode not in ALLOWED_SECURITY_MODES:
        return error_response(
            "Invalid security mode."
        )

    try:
        comparison = compare_migration_results(message)

        response_data = {
            "comparison": comparison,
            "security_mode": mode
        }

        if trusted_hashes is None:

            response_data["reference_hashes"] = (
                generate_integrity_hashes(message)
            )

            response_data["verification"] = (
                "Reference hashes generated. Store them securely "
                "for future independent verification."
            )

        else:

            verification = verify_message_integrity(
                message,
                trusted_hashes,
                mode
            )

            response_data["verification"] = verification

        return success_response(response_data)

    except ValueError as error:
        return error_response(str(error), 400)

    except Exception:
        app.logger.exception("Migration analysis failed")
        return error_response(
            "Migration analysis failed.",
            500
        )


# =========================================================
# MD5 COLLISION RISK ANALYSIS
# =========================================================

@app.route("/api/collision/analysis", methods=["GET"])
def collision_analysis():

    try:
        return success_response({
            "algorithms": analyze_algorithms(),
            "conclusion": (
                "MD5 is unsuitable for collision-resistant "
                "security applications. SHA3-256 provides a "
                "256-bit digest and approximately 128-bit "
                "generic collision resistance."
            ),
            "warning": (
                "This endpoint provides a theoretical risk "
                "analysis. It does not claim to generate an "
                "MD5 collision."
            )
        })

    except Exception:
        app.logger.exception("Collision analysis failed")
        return error_response(
            "Collision analysis failed.",
            500
        )


# =========================================================
# COMPARE TWO FILES
# =========================================================

@app.route("/api/collision/compare", methods=["POST"])
def collision_file_comparison():

    data = get_json_body()

    if data is None:
        return error_response(
            "A JSON request body is required."
        )

    file1 = data.get("file1")
    file2 = data.get("file2")

    if not isinstance(file1, str) or not isinstance(file2, str):
        return error_response(
            "Provide file1 and file2 paths."
        )

    try:
        base = BASE_DIR.resolve()

        path1 = (base / file1).resolve()
        path2 = (base / file2).resolve()

        if (
            not path1.is_relative_to(base)
            or not path2.is_relative_to(base)
        ):
            return error_response(
                "File paths must remain inside the project."
            )

        if not path1.is_file() or not path2.is_file():
            return error_response(
                "One or both files do not exist.",
                404
            )

        results = compare_files(path1, path2)

        return success_response(results)

    except Exception:
        app.logger.exception("File comparison failed")
        return error_response(
            "File comparison failed.",
            500
        )


# =========================================================
# DATASET EVALUATION
# =========================================================

@app.route("/api/dataset/evaluation", methods=["GET"])
def dataset_evaluation():

    evaluation_file = (
        PROCESSED_DIR / "crypto_evaluation.json"
    )

    labels_file = (
        PROCESSED_DIR / "label_distribution.csv"
    )

    if not evaluation_file.exists():
        return error_response(
            "Dataset evaluation not found. Run the dataset pipeline first.",
            404
        )

    try:
        with evaluation_file.open(
            "r",
            encoding="utf-8"
        ) as file:
            evaluation = json.load(file)

        label_distribution = {}

        if labels_file.exists():

            with labels_file.open(
                "r",
                encoding="utf-8"
            ) as file:

                reader = csv.reader(file)
                next(reader, None)

                for row in reader:

                    if len(row) >= 2:

                        try:
                            label_distribution[row[0]] = int(
                                float(row[1])
                            )

                        except (ValueError, TypeError):
                            continue

        return success_response({
            "evaluation": evaluation,
            "label_distribution": label_distribution
        })

    except Exception:
        app.logger.exception(
            "Unable to load dataset evaluation"
        )

        return error_response(
            "Unable to load dataset evaluation.",
            500
        )


# =========================================================
# RUN DATASET PIPELINE FROM THE WEBSITE
# =========================================================

@app.route("/api/dataset/run", methods=["POST"])
def run_dataset_pipeline():

    modules = [
        "dataset.dataset_loader",
        "dataset.dataset_analyzer",
        "dataset.dataset_to_messages",
        "dataset.dataset_crypto_evaluation"
    ]

    results = []

    try:
        for module in modules:

            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    module
                ],
                cwd=str(BASE_DIR),
                capture_output=True,
                text=True,
                timeout=300
            )

            result = {
                "module": module,
                "return_code": process.returncode,
                "success": process.returncode == 0,
                "output": process.stdout[-5000:],
                "error": process.stderr[-5000:]
            }

            results.append(result)

            if process.returncode != 0:

                return jsonify({
                    "success": False,
                    "error": f"Dataset pipeline failed at {module}.",
                    "results": results
                }), 500

        return success_response({
            "message": "Dataset pipeline completed.",
            "results": results
        })

    except subprocess.TimeoutExpired:
        app.logger.exception("Dataset pipeline timed out")

        return error_response(
            "Dataset pipeline timed out.",
            500
        )

    except Exception:
        app.logger.exception("Dataset pipeline failed")

        return error_response(
            "Unable to run dataset pipeline.",
            500
        )


# =========================================================
# APPLICATION STARTUP
# =========================================================

if __name__ == "__main__":

    initialize_database()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
