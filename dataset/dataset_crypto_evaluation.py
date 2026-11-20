import json
import time
import pandas as pd

from pathlib import Path

from crypto.hash_engine import (
    calculate_hash,
    verify_hash,
    SUPPORTED_ALGORITHMS
)

from dataset.dataset_loader import PROCESSED_DIR


# --------------------------------------------------
# PATH CONFIGURATION
# --------------------------------------------------

MESSAGES_FILE = (
    PROCESSED_DIR / "cryptographic_test_messages.jsonl"
)

EVALUATION_JSON = (
    PROCESSED_DIR / "crypto_evaluation.json"
)

EVALUATION_CSV = (
    PROCESSED_DIR / "crypto_evaluation.csv"
)

BENCHMARK_CSV = (
    PROCESSED_DIR / "crypto_benchmarks.csv"
)


# --------------------------------------------------
# LOAD SYNTHETIC MESSAGES
# --------------------------------------------------

def load_messages():
    """
    Loads previously generated synthetic messages
    from the JSONL file.
    """

    if not MESSAGES_FILE.exists():
        raise FileNotFoundError(
            "Cryptographic test messages not found. "
            "Run dataset_to_messages.py first."
        )

    messages = []

    with open(
        MESSAGES_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            if line.strip():
                messages.append(
                    json.loads(line)
                )

    return messages


# --------------------------------------------------
# GET MESSAGE CONTENT WITHOUT HASHES
# --------------------------------------------------

def get_message_content(message):
    """
    Removes the stored hashes before recalculating
    the message digest.
    """

    return {
        key: value
        for key, value in message.items()
        if key != "hashes"
    }


# --------------------------------------------------
# HASH CONSISTENCY EVALUATION
# --------------------------------------------------

def evaluate_hash_consistency(messages):
    """
    Recalculates every stored hash and checks whether
    the result matches the original digest.
    """

    results = {}

    for algorithm in SUPPORTED_ALGORITHMS:

        passed = 0
        failed = 0

        for message in messages:

            content = get_message_content(message)

            expected_hash = message.get(
                "hashes", {}
            ).get(algorithm)

            if verify_hash(
                content,
                expected_hash,
                algorithm
            ):
                passed += 1
            else:
                failed += 1

        total = passed + failed

        results[algorithm] = {
            "total_messages": total,
            "passed": passed,
            "failed": failed,
            "success_rate": round(
                (passed / total) * 100,
                2
            ) if total else 0
        }

    return results


# --------------------------------------------------
# CONTROLLED TAMPERING EVALUATION
# --------------------------------------------------

def evaluate_tampering(messages):
    """
    Changes one selected field in each message
    and checks whether verification against the
    original digest detects the modification.

    This is a controlled message modification test,
    not an actual hash collision attack.
    """

    results = {}

    for algorithm in SUPPORTED_ALGORITHMS:

        detected = 0
        undetected = 0
        skipped = 0

        for message in messages:

            original_content = get_message_content(
                message
            )

            original_hash = message.get(
                "hashes", {}
            ).get(algorithm)

            if not original_hash:
                skipped += 1
                continue

            modified_content = json.loads(
                json.dumps(original_content)
            )

            payload = modified_content.get(
                "payload", {}
            )

            if not isinstance(payload, dict):
                skipped += 1
                continue

            # Modify an existing numeric field.
            numeric_field = None

            for field, value in payload.items():

                if (
                    isinstance(value, (int, float))
                    and not isinstance(value, bool)
                ):
                    numeric_field = field
                    break

            if numeric_field is not None:

                payload[numeric_field] = (
                    payload[numeric_field] + 1
                )

            else:
                # If no numeric field exists, add a
                # controlled modification marker.
                payload["tampering_test_marker"] = (
                    "MODIFIED"
                )

            # Verify modified content against original hash.
            is_valid = verify_hash(
                modified_content,
                original_hash,
                algorithm
            )

            if is_valid:
                undetected += 1
            else:
                detected += 1

        tested = detected + undetected

        results[algorithm] = {
            "tested": tested,
            "detected": detected,
            "undetected": undetected,
            "skipped": skipped,
            "detection_rate": round(
                (detected / tested) * 100,
                2
            ) if tested else 0
        }

    return results


# --------------------------------------------------
# HASH PERFORMANCE BENCHMARK
# --------------------------------------------------

def benchmark_algorithms(
    messages,
    sample_size=100,
    iterations=100
):
    """
    Measures hashing time for each algorithm.

    Uses the same sample messages and iteration
    count for each algorithm.

    Results are machine-dependent.
    """

    sample_messages = messages[:sample_size]

    results = []

    if not sample_messages:
        return results

    for algorithm in SUPPORTED_ALGORITHMS:

        total_operations = 0

        start_time = time.perf_counter()

        for message in sample_messages:

            content = get_message_content(
                message
            )

            for _ in range(iterations):

                calculate_hash(
                    content,
                    algorithm
                )

                total_operations += 1

        end_time = time.perf_counter()

        total_time = end_time - start_time

        average_time = (
            total_time / total_operations
            if total_operations
            else 0
        )

        results.append({
            "algorithm": algorithm,
            "messages_tested": len(sample_messages),
            "iterations_per_message": iterations,
            "total_operations": total_operations,
            "total_time_seconds": round(
                total_time,
                6
            ),
            "average_time_ms": round(
                average_time * 1000,
                6
            ),
            "operations_per_second": round(
                total_operations / total_time,
                2
            ) if total_time > 0 else 0
        })

    return results


# --------------------------------------------------
# SAVE EVALUATION RESULTS
# --------------------------------------------------

def save_evaluation_results(evaluation):
    """
    Saves the complete evaluation in JSON format.
    """

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        EVALUATION_JSON,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            evaluation,
            file,
            indent=4
        )


# --------------------------------------------------
# SAVE RESULTS AS CSV
# --------------------------------------------------

def save_evaluation_csv(evaluation):
    """
    Saves hash consistency and tampering results
    in a tabular CSV format.
    """

    rows = []

    for algorithm in SUPPORTED_ALGORITHMS:

        consistency = evaluation[
            "hash_consistency"
        ][algorithm]

        tampering = evaluation[
            "tampering"
        ][algorithm]

        rows.append({
            "algorithm": algorithm,
            "total_messages": consistency[
                "total_messages"
            ],
            "hash_passed": consistency["passed"],
            "hash_failed": consistency["failed"],
            "hash_success_rate": consistency[
                "success_rate"
            ],
            "tampering_tested": tampering["tested"],
            "tampering_detected": tampering["detected"],
            "tampering_undetected": tampering[
                "undetected"
            ],
            "tampering_detection_rate": tampering[
                "detection_rate"
            ]
        })

    dataframe = pd.DataFrame(rows)

    dataframe.to_csv(
        EVALUATION_CSV,
        index=False
    )


# --------------------------------------------------
# SAVE BENCHMARK RESULTS
# --------------------------------------------------

def save_benchmark_csv(benchmarks):
    """
    Saves algorithm performance measurements.
    """

    dataframe = pd.DataFrame(benchmarks)

    dataframe.to_csv(
        BENCHMARK_CSV,
        index=False
    )


# --------------------------------------------------
# COMPLETE CRYPTOGRAPHIC EVALUATION
# --------------------------------------------------

def run_crypto_evaluation():
    """
    Runs:
    1. Hash consistency testing.
    2. Controlled tampering detection.
    3. Hash performance benchmarking.
    4. Saves JSON and CSV evaluation reports.
    """

    print("\nEVSECURE-MIGRATE")
    print("CRYPTOGRAPHIC DATASET EVALUATION")
    print("-" * 60)

    # Load messages.
    messages = load_messages()

    print(
        "\nTotal synthetic messages:",
        len(messages)
    )

    # 1. Hash consistency.
    print("\n1. HASH CONSISTENCY TEST")

    consistency_results = (
        evaluate_hash_consistency(messages)
    )

    for algorithm, result in consistency_results.items():

        print(
            f"{algorithm.upper()}: "
            f"{result['passed']} passed, "
            f"{result['failed']} failed, "
            f"{result['success_rate']}%"
        )

    # 2. Tampering detection.
    print("\n2. CONTROLLED TAMPERING TEST")

    tampering_results = evaluate_tampering(
        messages
    )

    for algorithm, result in tampering_results.items():

        print(
            f"{algorithm.upper()}: "
            f"{result['detected']} detected, "
            f"{result['undetected']} undetected, "
            f"{result['detection_rate']}%"
        )

    # 3. Performance benchmarking.
    print("\n3. PERFORMANCE BENCHMARK")

    benchmark_results = benchmark_algorithms(
        messages,
        sample_size=100,
        iterations=100
    )

    for result in benchmark_results:

        print(
            f"{result['algorithm'].upper()}: "
            f"{result['average_time_ms']} ms average"
        )

    # 4. Create evaluation object.
    evaluation = {
        "total_messages": len(messages),
        "algorithms": SUPPORTED_ALGORITHMS,
        "methodology": {
            "hash_consistency": (
                "Recalculate each stored digest and "
                "compare it with the original digest."
            ),
            "tampering": (
                "Modify a message field and verify it "
                "against the original stored digest."
            ),
            "benchmark": (
                "Measure repeated hash calculations "
                "on a fixed sample of messages."
            ),
            "limitations": [
                "Synthetic messages are derived from dataset flow features.",
                "Tampering tests are not actual collision attacks.",
                "Benchmark results depend on the machine and environment.",
                "Hashing does not classify dataset attack labels."
            ]
        },
        "hash_consistency": consistency_results,
        "tampering": tampering_results,
        "benchmarks": benchmark_results
    }

    # 5. Save reports.
    save_evaluation_results(evaluation)

    save_evaluation_csv(evaluation)

    save_benchmark_csv(benchmark_results)

    print("\nOUTPUT FILES")

    print(EVALUATION_JSON)
    print(EVALUATION_CSV)
    print(BENCHMARK_CSV)

    print("\nCryptographic evaluation completed.")

    return evaluation


# --------------------------------------------------
# EXECUTION
# --------------------------------------------------

if __name__ == "__main__":
    run_crypto_evaluation()