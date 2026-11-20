import hashlib
import json
import time
import hmac


# --------------------------------------------------
# SUPPORTED HASHING ALGORITHMS
# --------------------------------------------------

SUPPORTED_ALGORITHMS = [
    "md5",
    "sha1",
    "sha256",
    "sha3_256"
]


# --------------------------------------------------
# MESSAGE NORMALIZATION
# --------------------------------------------------

def normalize_message(message):
    """
    Converts messages into a consistent string format.

    Dictionaries and lists are serialized into
    deterministic JSON so the same data produces
    the same hash.
    """

    if isinstance(message, (dict, list)):
        return json.dumps(
            message,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False
        )

    if isinstance(message, bytes):
        return message.decode("utf-8", errors="replace")

    return str(message)


# --------------------------------------------------
# HASH GENERATION
# --------------------------------------------------

def calculate_hash(message, algorithm="sha3_256"):
    """
    Generates a cryptographic hash for a message.

    Supported:
        MD5
        SHA-1
        SHA-256
        SHA3-256
    """

    algorithm = algorithm.lower()

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {algorithm}"
        )

    normalized_message = normalize_message(message)

    message_bytes = normalized_message.encode("utf-8")

    hash_object = hashlib.new(
        algorithm,
        message_bytes
    )

    return hash_object.hexdigest()


# --------------------------------------------------
# GENERATE ALL HASHES
# --------------------------------------------------

def calculate_all_hashes(message):
    """
    Generates hashes using all supported algorithms.
    """

    return {
        algorithm: calculate_hash(message, algorithm)
        for algorithm in SUPPORTED_ALGORITHMS
    }


# --------------------------------------------------
# HASH VERIFICATION
# --------------------------------------------------

def verify_hash(
    message,
    expected_hash,
    algorithm="sha3_256"
):
    """
    Verifies whether a message matches its expected hash.

    Returns True if the calculated hash matches
    the supplied expected hash.
    """

    if not expected_hash:
        return False

    calculated_hash = calculate_hash(
        message,
        algorithm
    )

    return hmac.compare_digest(
        calculated_hash.lower(),
        str(expected_hash).lower()
    )


# --------------------------------------------------
# VERIFY ALL HASHES
# --------------------------------------------------

def verify_all_hashes(message, expected_hashes):
    """
    Verifies a message against multiple stored hashes.
    """

    results = {}

    for algorithm in SUPPORTED_ALGORITHMS:

        expected_hash = expected_hashes.get(algorithm)

        if expected_hash:
            results[algorithm] = verify_hash(
                message,
                expected_hash,
                algorithm
            )
        else:
            results[algorithm] = False

    return results


# --------------------------------------------------
# HASH BENCHMARKING
# --------------------------------------------------

def benchmark_hashing(
    message,
    iterations=1000,
    algorithm="sha3_256"
):
    """
    Measures the time required to hash a message
    repeatedly using a selected algorithm.

    Results depend on the computer and environment.
    """

    if iterations <= 0:
        raise ValueError(
            "Iterations must be greater than zero."
        )

    algorithm = algorithm.lower()

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {algorithm}"
        )

    normalized_message = normalize_message(message)
    message_bytes = normalized_message.encode("utf-8")

    start_time = time.perf_counter()

    for _ in range(iterations):
        hashlib.new(algorithm, message_bytes).hexdigest()

    end_time = time.perf_counter()

    total_time = end_time - start_time

    average_time = total_time / iterations

    return {
        "algorithm": algorithm,
        "iterations": iterations,
        "total_time_seconds": round(total_time, 6),
        "average_time_seconds": round(average_time, 9),
        "average_time_ms": round(
            average_time * 1000,
            6
        ),
        "operations_per_second": round(
            iterations / total_time,
            2
        ) if total_time > 0 else 0
    }


# --------------------------------------------------
# COMPARE ALGORITHM PERFORMANCE
# --------------------------------------------------

def compare_hash_performance(
    message,
    iterations=1000
):
    """
    Benchmarks all supported algorithms
    using the same message and iteration count.
    """

    results = {}

    for algorithm in SUPPORTED_ALGORITHMS:
        results[algorithm] = benchmark_hashing(
            message,
            iterations,
            algorithm
        )

    return results


# --------------------------------------------------
# MESSAGE ANALYSIS
# --------------------------------------------------

def analyze_message(message):
    """
    Provides hash information for a message.
    """

    normalized_message = normalize_message(message)

    hashes = calculate_all_hashes(normalized_message)

    digest_lengths = {
        algorithm: len(digest) * 4
        for algorithm, digest in hashes.items()
    }

    return {
        "message": normalized_message,
        "message_length": len(normalized_message),
        "message_size_bytes": len(
            normalized_message.encode("utf-8")
        ),
        "hashes": hashes,
        "digest_lengths_bits": digest_lengths
    }


# --------------------------------------------------
# HASH COMPARISON
# --------------------------------------------------

def compare_hashes(message1, message2):
    """
    Compares the hashes of two messages.

    This detects whether their calculated digests
    are equal. It does not generate a collision.
    """

    hashes1 = calculate_all_hashes(message1)
    hashes2 = calculate_all_hashes(message2)

    comparison = {}

    for algorithm in SUPPORTED_ALGORITHMS:

        comparison[algorithm] = {
            "hash1": hashes1[algorithm],
            "hash2": hashes2[algorithm],
            "match": (
                hashes1[algorithm] == hashes2[algorithm]
            )
        }

    return comparison


# --------------------------------------------------
# QUICK MODULE TEST
# --------------------------------------------------

if __name__ == "__main__":

    sample_message = {
        "charger_id": "EV-001",
        "message_type": "Heartbeat",
        "status": "Available",
        "energy_kwh": 120.5
    }

    print("\nEVSECURE-MIGRATE HASH ENGINE")
    print("-" * 45)

    print("\nSample Message:")
    print(json.dumps(sample_message, indent=4))

    print("\nGenerated Hashes:")

    hashes = calculate_all_hashes(sample_message)

    for algorithm, digest in hashes.items():
        print(f"{algorithm.upper():10}: {digest}")

    print("\nVerification:")

    for algorithm, digest in hashes.items():

        result = verify_hash(
            sample_message,
            digest,
            algorithm
        )

        print(f"{algorithm.upper():10}: {result}")

    print("\nPerformance Benchmark:")

    benchmark_results = compare_hash_performance(
        sample_message,
        iterations=1000
    )

    for algorithm, result in benchmark_results.items():

        print(
            f"{algorithm.upper():10}: "
            f"{result['average_time_ms']} ms per operation"
        )

    print("\nHash Engine Test Completed.")