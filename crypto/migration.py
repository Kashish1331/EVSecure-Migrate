from crypto.hash_engine import (
    calculate_hash,
    calculate_all_hashes,
    verify_hash
)


# --------------------------------------------------
# SUPPORTED SECURITY MODES
# --------------------------------------------------

SUPPORTED_MODES = {
    "LEGACY_MD5",
    "MIGRATION",
    "SECURE_SHA3"
}


# --------------------------------------------------
# GENERATE INTEGRITY HASHES
# --------------------------------------------------

def generate_integrity_hashes(message):
    """
    Generates MD5, SHA-1, SHA-256 and SHA3-256
    hashes for a message.
    """

    return calculate_all_hashes(message)


# --------------------------------------------------
# VERIFY MESSAGE INTEGRITY
# --------------------------------------------------

def verify_message_integrity(
    message,
    expected_hashes,
    security_mode="LEGACY_MD5"
):
    """
    Verifies message integrity according to the
    selected security mode.

    LEGACY_MD5:
        Verifies MD5.

    MIGRATION:
        Verifies both MD5 and SHA3-256.

    SECURE_SHA3:
        Verifies SHA3-256.
    """

    security_mode = security_mode.upper()

    if security_mode not in SUPPORTED_MODES:
        raise ValueError(
            f"Unsupported security mode: {security_mode}"
        )

    if not isinstance(expected_hashes, dict):
        expected_hashes = {}

    algorithm_results = {}

    if security_mode == "LEGACY_MD5":

        algorithm_results["md5"] = verify_hash(
            message,
            expected_hashes.get("md5"),
            "md5"
        )

        verified = algorithm_results["md5"]

    elif security_mode == "MIGRATION":

        algorithm_results["md5"] = verify_hash(
            message,
            expected_hashes.get("md5"),
            "md5"
        )

        algorithm_results["sha3_256"] = verify_hash(
            message,
            expected_hashes.get("sha3_256"),
            "sha3_256"
        )

        verified = (
            algorithm_results["md5"]
            and algorithm_results["sha3_256"]
        )

    else:

        algorithm_results["sha3_256"] = verify_hash(
            message,
            expected_hashes.get("sha3_256"),
            "sha3_256"
        )

        verified = algorithm_results["sha3_256"]

    if verified:
        status = "VERIFIED"
    else:
        status = "INTEGRITY_FAILED"

    return {
        "security_mode": security_mode,
        "status": status,
        "verified": verified,
        "algorithm_results": algorithm_results
    }


# --------------------------------------------------
# MIGRATE MESSAGE FROM MD5 TO SHA3-256
# --------------------------------------------------

def migrate_message(message):
    """
    Generates both legacy MD5 and modern SHA3-256
    hashes for a message during migration.

    This supports dual-hash verification.
    """

    hashes = {
        "md5": calculate_hash(message, "md5"),
        "sha3_256": calculate_hash(message, "sha3_256")
    }

    return {
        "status": "DUAL_HASH_GENERATED",
        "hashes": hashes,
        "migration_mode": "MIGRATION"
    }


# --------------------------------------------------
# COMPARE MIGRATION RESULTS
# --------------------------------------------------

def compare_migration_results(message):
    """
    Compares MD5 and SHA3-256 digest properties.
    """

    md5_hash = calculate_hash(message, "md5")
    sha3_hash = calculate_hash(message, "sha3_256")

    return {
        "message_length": len(str(message)),
        "algorithms": {
            "MD5": {
                "digest": md5_hash,
                "digest_bits": 128,
                "digest_characters": 32,
                "security_status": "DEPRECATED"
            },
            "SHA3-256": {
                "digest": sha3_hash,
                "digest_bits": 256,
                "digest_characters": 64,
                "security_status": "RECOMMENDED"
            }
        },
        "recommendation": (
            "Migrate from MD5 to SHA3-256 "
            "for improved collision resistance."
        )
    }


# --------------------------------------------------
# VERIFY MIGRATION
# --------------------------------------------------

def verify_migration(message, migration_result):
    """
    Verifies both hashes generated during migration.
    """

    if not isinstance(migration_result, dict):
        return {
            "verified": False,
            "status": "INVALID_MIGRATION_DATA"
        }

    expected_hashes = migration_result.get("hashes", {})

    return verify_message_integrity(
        message,
        expected_hashes,
        "MIGRATION"
    )


# --------------------------------------------------
# MIGRATION SUMMARY
# --------------------------------------------------

def get_migration_summary():
    return {
        "legacy_algorithm": "MD5",
        "target_algorithm": "SHA3-256",
        "legacy_digest_size": "128 bits",
        "target_digest_size": "256 bits",
        "migration_strategy": "Dual Hash Verification",
        "supported_modes": list(SUPPORTED_MODES)
    }


# --------------------------------------------------
# MODULE TEST
# --------------------------------------------------

if __name__ == "__main__":

    sample_message = {
        "charger_id": "EV-001",
        "message_type": "StartTransaction",
        "transaction_id": 101,
        "energy_kwh": 20.5
    }

    print("\nEVSECURE-MIGRATE")
    print("MD5 TO SHA3-256 MIGRATION")
    print("-" * 45)

    print("\n1. Generating dual hashes")

    migration_result = migrate_message(sample_message)

    for algorithm, digest in migration_result["hashes"].items():
        print(f"{algorithm.upper()}: {digest}")

    print("\n2. Verifying original message")

    verification = verify_migration(
        sample_message,
        migration_result
    )

    print(verification)

    print("\n3. Testing modified message")

    modified_message = sample_message.copy()
    modified_message["energy_kwh"] = 120.5

    modified_verification = verify_migration(
        modified_message,
        migration_result
    )

    print(modified_verification)

    print("\n4. Migration comparison")

    comparison = compare_migration_results(sample_message)

    for algorithm, details in comparison["algorithms"].items():
        print(
            f"{algorithm}: "
            f"{details['digest_bits']} bits | "
            f"{details['security_status']}"
        )

    print("\nMigration test completed.")