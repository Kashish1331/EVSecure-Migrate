import json
import pandas as pd

from pathlib import Path
from datetime import datetime, timezone

from crypto.hash_engine import calculate_all_hashes
from dataset.dataset_loader import (
    load_training_data,
    load_testing_data,
    PROCESSED_DIR
)


# --------------------------------------------------
# PATH CONFIGURATION
# --------------------------------------------------

OUTPUT_FILE = (
    PROCESSED_DIR / "cryptographic_test_messages.jsonl"
)


# --------------------------------------------------
# DATASET FEATURE MAPPING
# --------------------------------------------------

def get_feature_value(row, possible_names, default=0):
    """
    Finds a feature using possible column names.
    """

    for column in possible_names:

        if column in row.index:
            value = row[column]

            if pd.notna(value):
                return value

    return default


# --------------------------------------------------
# CONVERT DATASET ROW INTO MESSAGE
# --------------------------------------------------

def convert_row_to_message(row, index, label):
    """
    Converts one dataset record into a synthetic
    OCPP-style message for cryptographic evaluation.

    The original dataset label is retained as metadata.
    It is not predicted by the hashing algorithms.
    """

    message = {
        "message_id": f"DATASET-MSG-{index + 1}",
        "charger_id": f"DATASET-CHARGER-{(index % 10) + 1}",
        "message_type": "DatasetFlowRecord",
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "payload": {
            "total_packets": get_feature_value(
                row,
                ["total_packets", "Total_Packets", "packet_count"]
            ),
            "total_bytes": get_feature_value(
                row,
                ["total_bytes", "Total_Bytes", "byte_count"]
            ),
            "flow_duration": get_feature_value(
                row,
                ["flow_duration", "Flow_Duration", "duration"]
            ),
            "flow_bytes_per_second": get_feature_value(
                row,
                ["flow_bytes_per_second", "Flow_Bytes/s"]
            ),
            "flow_packets_per_second": get_feature_value(
                row,
                ["flow_packets_per_second", "Flow_Packets/s"]
            )
        },
        "dataset_metadata": {
            "source": "Federated OCPP 1.6 Intrusion Detection Dataset",
            "original_class": str(label)
        }
    }

    return message


# --------------------------------------------------
# GENERATE SYNTHETIC MESSAGES
# --------------------------------------------------

def generate_messages():
    """
    Converts dataset rows into synthetic message records.
    """

    train_dataframe, label_column = load_training_data()

    test_dataframe = load_testing_data(
        label_column
    )

    combined_dataframe = pd.concat(
        [train_dataframe, test_dataframe],
        ignore_index=True
    )

    messages = []

    for index, row in combined_dataframe.iterrows():

        label = row[label_column]

        message = convert_row_to_message(
            row,
            index,
            label
        )

        messages.append(message)

    return messages


# --------------------------------------------------
# GENERATE CRYPTOGRAPHIC HASHES
# --------------------------------------------------

def add_hashes_to_messages(messages):
    """
    Generates MD5, SHA-1, SHA-256 and SHA3-256
    hashes for each synthetic message.

    Hashes are calculated over the message content
    excluding the hashes field itself.
    """

    processed_messages = []

    for message in messages:

        message_content = {
            key: value
            for key, value in message.items()
            if key != "hashes"
        }

        hashes = calculate_all_hashes(
            message_content
        )

        processed_message = {
            **message_content,
            "hashes": hashes
        }

        processed_messages.append(
            processed_message
        )

    return processed_messages


# --------------------------------------------------
# SAVE MESSAGES AS JSONL
# --------------------------------------------------

def save_messages(messages):
    """
    Saves each message as one JSON line.
    """

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        for message in messages:

            file.write(
                json.dumps(
                    message,
                    ensure_ascii=False
                ) + "\n"
            )

    return OUTPUT_FILE


# --------------------------------------------------
# COMPLETE DATASET CONVERSION PIPELINE
# --------------------------------------------------

def run_message_conversion():
    """
    Loads dataset records, converts them into
    synthetic messages, generates hashes and saves
    the resulting JSONL file.
    """

    print("\nEVSECURE-MIGRATE")
    print("DATASET TO MESSAGE CONVERSION")
    print("-" * 55)

    # Step 1: Generate messages.
    messages = generate_messages()

    print(
        "\nGenerated synthetic messages:",
        len(messages)
    )

    # Step 2: Generate cryptographic hashes.
    processed_messages = add_hashes_to_messages(
        messages
    )

    print("Generated hashes for all messages.")

    # Step 3: Save JSONL file.
    output_path = save_messages(
        processed_messages
    )

    print("\nOUTPUT FILE")
    print(output_path)

    # Step 4: Display sample.
    if processed_messages:

        print("\nSAMPLE MESSAGE")

        print(
            json.dumps(
                processed_messages[0],
                indent=4,
                ensure_ascii=False
            )
        )

    print("\nMessage conversion completed.")

    return {
        "total_messages": len(processed_messages),
        "output_file": str(output_path)
    }


# --------------------------------------------------
# EXECUTION
# --------------------------------------------------

if __name__ == "__main__":
    run_message_conversion()