import hashlib
import math
import os


# --------------------------------------------------
# ALGORITHM INFORMATION
# --------------------------------------------------

ALGORITHMS = {
    "md5": {
        "digest_bits": 128,
        "digest_characters": 32,
        "status": "BROKEN",
        "description": "MD5 is vulnerable to practical collision attacks."
    },
    "sha1": {
        "digest_bits": 160,
        "digest_characters": 40,
        "status": "DEPRECATED",
        "description": "SHA-1 has known practical collision attacks."
    },
    "sha256": {
        "digest_bits": 256,
        "digest_characters": 64,
        "status": "SECURE",
        "description": "SHA-256 is a widely used secure hash function."
    },
    "sha3_256": {
        "digest_bits": 256,
        "digest_characters": 64,
        "status": "RECOMMENDED",
        "description": "SHA3-256 provides a modern hash standard."
    }
}


# --------------------------------------------------
# FILE HASH GENERATION
# --------------------------------------------------

def calculate_file_hash(file_path, algorithm="sha3_256"):
    """
    Calculates a hash of a file using the selected
    hashing algorithm.

    Reads the file in chunks to support large files.
    """

    algorithm = algorithm.lower()

    if algorithm not in ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {algorithm}"
        )

    hash_object = hashlib.new(algorithm)

    with open(file_path, "rb") as file:

        while True:
            chunk = file.read(8192)

            if not chunk:
                break

            hash_object.update(chunk)

    return hash_object.hexdigest()


# --------------------------------------------------
# MESSAGE HASH GENERATION
# --------------------------------------------------

def calculate_message_hash(message, algorithm="sha3_256"):
    """
    Calculates the hash of a text message.
    """

    algorithm = algorithm.lower()

    if algorithm not in ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {algorithm}"
        )

    message_bytes = str(message).encode("utf-8")

    return hashlib.new(
        algorithm,
        message_bytes
    ).hexdigest()


# --------------------------------------------------
# BIRTHDAY COLLISION ESTIMATION
# --------------------------------------------------

def calculate_collision_estimate(digest_bits):
    """
    Estimates the number of random inputs required
    for approximately 50% collision probability.

    Uses the birthday-bound approximation:

        n ≈ sqrt(2 * ln(2)) * 2^(b/2)

    where b is the digest size in bits.
    """

    if digest_bits <= 0:
        raise ValueError(
            "Digest size must be positive."
        )

    return math.sqrt(
        2 * math.log(2)
    ) * (2 ** (digest_bits / 2))


# --------------------------------------------------
# ALGORITHM SECURITY ANALYSIS
# --------------------------------------------------

def analyze_algorithms():
    """
    Provides a theoretical comparison of supported
    hashing algorithms.
    """

    results = {}

    for algorithm, details in ALGORITHMS.items():

        digest_bits = details["digest_bits"]

        estimated_inputs = calculate_collision_estimate(
            digest_bits
        )

        results[algorithm] = {
            "algorithm": algorithm.upper(),
            "digest_bits": digest_bits,
            "digest_characters": details["digest_characters"],
            "collision_strength_bits": digest_bits // 2,
            "approx_inputs_for_50_percent_collision": (
                f"{estimated_inputs:.3e}"
            ),
            "status": details["status"],
            "description": details["description"]
        }

    return results


# --------------------------------------------------
# FILE COMPARISON
# --------------------------------------------------

def compare_files(file1_path, file2_path):
    """
    Compares two files using MD5, SHA-1,
    SHA-256 and SHA3-256.

    A collision is reported only if:
        1. The files have different contents.
        2. Their hashes are identical.

    This function does not generate collisions.
    """

    if not os.path.isfile(file1_path):
        raise FileNotFoundError(
            f"File not found: {file1_path}"
        )

    if not os.path.isfile(file2_path):
        raise FileNotFoundError(
            f"File not found: {file2_path}"
        )

    files_are_identical = (
        open(file1_path, "rb").read()
        == open(file2_path, "rb").read()
    )

    results = {}

    for algorithm in ALGORITHMS:

        hash1 = calculate_file_hash(
            file1_path,
            algorithm
        )

        hash2 = calculate_file_hash(
            file2_path,
            algorithm
        )

        collision_observed = (
            not files_are_identical
            and hash1 == hash2
        )

        results[algorithm] = {
            "hash_file_1": hash1,
            "hash_file_2": hash2,
            "hashes_match": hash1 == hash2,
            "files_identical": files_are_identical,
            "collision_observed": collision_observed
        }

    return results


# --------------------------------------------------
# MESSAGE COMPARISON
# --------------------------------------------------

def compare_messages(message1, message2):
    """
    Compares two messages using all supported
    algorithms and checks whether a collision
    is observed.
    """

    messages_are_identical = (
        str(message1) == str(message2)
    )

    results = {}

    for algorithm in ALGORITHMS:

        hash1 = calculate_message_hash(
            message1,
            algorithm
        )

        hash2 = calculate_message_hash(
            message2,
            algorithm
        )

        collision_observed = (
            not messages_are_identical
            and hash1 == hash2
        )

        results[algorithm] = {
            "hash1": hash1,
            "hash2": hash2,
            "hashes_match": hash1 == hash2,
            "messages_identical": messages_are_identical,
            "collision_observed": collision_observed
        }

    return results


# --------------------------------------------------
# COLLISION ANALYSIS SUMMARY
# --------------------------------------------------

def get_collision_summary():
    """
    Returns a concise summary for the dashboard.
    """

    analysis = analyze_algorithms()

    return {
        "algorithms_analyzed": len(analysis),
        "algorithms": analysis,
        "conclusion": (
            "MD5 should not be used for security-sensitive "
            "integrity applications. SHA3-256 provides "
            "stronger collision resistance."
        )
    }


# --------------------------------------------------
# MODULE TEST
# --------------------------------------------------

if __name__ == "__main__":

    print("\nEVSECURE-MIGRATE")
    print("HASH COLLISION RISK ANALYSIS")
    print("=" * 55)

    # 1. Algorithm analysis
    print("\n1. ALGORITHM COMPARISON")

    analysis = analyze_algorithms()

    for algorithm, details in analysis.items():

        print(f"\n{algorithm.upper()}")

        print(
            "Digest size:",
            details["digest_bits"],
            "bits"
        )

        print(
            "Collision strength:",
            details["collision_strength_bits"],
            "bits"
        )

        print(
            "Estimated inputs:",
            details["approx_inputs_for_50_percent_collision"]
        )

        print(
            "Security status:",
            details["status"]
        )

    # 2. Compare two sample messages
    print("\n2. MESSAGE COMPARISON")

    message1 = "EV Charger Transaction 100"
    message2 = "EV Charger Transaction 101"

    comparison = compare_messages(
        message1,
        message2
    )

    for algorithm, result in comparison.items():

        print(
            f"{algorithm.upper()}: "
            f"Hashes match = {result['hashes_match']}, "
            f"Collision observed = {result['collision_observed']}"
        )

    print("\n3. ANALYSIS COMPLETED")