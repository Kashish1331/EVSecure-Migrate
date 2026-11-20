import json
import pandas as pd
import matplotlib.pyplot as plt

from pathlib import Path

from dataset.dataset_loader import (
    load_training_data,
    load_testing_data,
    PROCESSED_DIR
)


# --------------------------------------------------
# OUTPUT PATHS
# --------------------------------------------------

LABEL_DISTRIBUTION_FILE = (
    PROCESSED_DIR / "label_distribution.csv"
)

DATASET_SUMMARY_FILE = (
    PROCESSED_DIR / "dataset_summary.json"
)

ATTACK_DISTRIBUTION_IMAGE = (
    PROCESSED_DIR / "attack_distribution.png"
)


# --------------------------------------------------
# COMBINE TRAINING AND TESTING DATA
# --------------------------------------------------

def combine_datasets():
    """
    Loads cleaned training and testing datasets
    and combines them for analysis.
    """

    train_dataframe, label_column = load_training_data()

    test_dataframe = load_testing_data(label_column)

    combined_dataframe = pd.concat(
        [train_dataframe, test_dataframe],
        ignore_index=True
    )

    return combined_dataframe, label_column


# --------------------------------------------------
# LABEL DISTRIBUTION
# --------------------------------------------------

def analyze_label_distribution(
    dataframe,
    label_column
):
    """
    Counts the number of records in each dataset class.
    """

    distribution = (
        dataframe[label_column]
        .value_counts()
        .rename_axis("class")
        .reset_index(name="count")
    )

    distribution["percentage"] = (
        distribution["count"]
        / distribution["count"].sum()
        * 100
    ).round(2)

    return distribution


# --------------------------------------------------
# DATASET STATISTICS
# --------------------------------------------------

def analyze_dataset_statistics(
    dataframe,
    label_column
):
    """
    Calculates general dataset statistics.
    """

    numeric_dataframe = dataframe.select_dtypes(
        include=["number"]
    )

    statistics = {
        "total_records": int(len(dataframe)),
        "total_columns": int(len(dataframe.columns)),
        "total_features": int(
            len(dataframe.columns) - 1
        ),
        "label_column": label_column,
        "number_of_classes": int(
            dataframe[label_column].nunique()
        ),
        "class_names": [
            str(value)
            for value in sorted(
                dataframe[label_column].dropna().unique()
            )
        ],
        "missing_values": int(
            dataframe.isnull().sum().sum()
        ),
        "duplicate_records": int(
            dataframe.duplicated().sum()
        ),
        "numeric_features": int(
            len(numeric_dataframe.columns)
        ),
        "categorical_features": int(
            len(dataframe.select_dtypes(
                include=["object", "category"]
            ).columns)
        )
    }

    return statistics


# --------------------------------------------------
# NUMERIC FEATURE SUMMARY
# --------------------------------------------------

def generate_feature_summary(dataframe):
    """
    Generates descriptive statistics for numeric features.
    """

    numeric_dataframe = dataframe.select_dtypes(
        include=["number"]
    )

    if numeric_dataframe.empty:
        return {}

    summary = numeric_dataframe.describe().round(3)

    return {
        column: {
            statistic: float(value)
            for statistic, value in summary[column].items()
            if pd.notna(value)
        }
        for column in summary.columns
    }


# --------------------------------------------------
# SAVE LABEL DISTRIBUTION
# --------------------------------------------------

def save_label_distribution(distribution):
    """
    Saves class counts and percentages to CSV.
    """

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    distribution.to_csv(
        LABEL_DISTRIBUTION_FILE,
        index=False
    )


# --------------------------------------------------
# SAVE DATASET SUMMARY
# --------------------------------------------------

def save_dataset_summary(summary):
    """
    Saves dataset statistics in JSON format.
    """

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        DATASET_SUMMARY_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            summary,
            file,
            indent=4
        )


# --------------------------------------------------
# CREATE CLASS DISTRIBUTION GRAPH
# --------------------------------------------------

def create_distribution_graph(distribution):
    """
    Creates a bar chart showing the number of
    records belonging to each dataset class.
    """

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    plt.figure(figsize=(12, 6))

    plt.bar(
        distribution["class"],
        distribution["count"]
    )

    plt.title(
        "OCPP 1.6 Dataset Class Distribution"
    )

    plt.xlabel("Dataset Class")
    plt.ylabel("Number of Records")

    plt.xticks(
        rotation=25,
        ha="right"
    )

    plt.tight_layout()

    plt.savefig(
        ATTACK_DISTRIBUTION_IMAGE,
        dpi=300
    )

    plt.close()


# --------------------------------------------------
# COMPLETE DATASET ANALYSIS
# --------------------------------------------------

def run_dataset_analysis():
    """
    Runs the complete dataset analysis pipeline.
    """

    print("\nEVSECURE-MIGRATE")
    print("DATASET ANALYSIS")
    print("-" * 55)

    # Load and combine datasets.
    dataframe, label_column = combine_datasets()

    # Analyze class distribution.
    distribution = analyze_label_distribution(
        dataframe,
        label_column
    )

    # Analyze general statistics.
    statistics = analyze_dataset_statistics(
        dataframe,
        label_column
    )

    # Analyze numerical features.
    feature_summary = generate_feature_summary(
        dataframe
    )

    # Save outputs.
    save_label_distribution(distribution)

    complete_summary = {
        "dataset_statistics": statistics,
        "label_distribution": distribution.to_dict(
            orient="records"
        ),
        "feature_summary": feature_summary
    }

    save_dataset_summary(complete_summary)

    create_distribution_graph(distribution)

    # Display results.
    print("\nDATASET STATISTICS")

    for key, value in statistics.items():
        print(f"{key}: {value}")

    print("\nCLASS DISTRIBUTION")

    print(
        distribution.to_string(index=False)
    )

    print("\nOUTPUT FILES")

    print(
        "Label distribution:",
        LABEL_DISTRIBUTION_FILE
    )

    print(
        "Dataset summary:",
        DATASET_SUMMARY_FILE
    )

    print(
        "Distribution graph:",
        ATTACK_DISTRIBUTION_IMAGE
    )

    print("\nDataset analysis completed.")

    return complete_summary


# --------------------------------------------------
# EXECUTION
# --------------------------------------------------

if __name__ == "__main__":
    run_dataset_analysis()