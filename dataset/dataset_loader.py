import pandas as pd

from pathlib import Path


# --------------------------------------------------
# PATH CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

RAW_DIR = (
    BASE_DIR
    / "raw"
    / "Balanced_OCPP16_APP_Layer"
    / "Combined"
)

PROCESSED_DIR = BASE_DIR / "processed"

TRAIN_FILE = RAW_DIR / "Train.csv"
TEST_FILE = RAW_DIR / "Test.csv"

CLEAN_TRAIN_FILE = PROCESSED_DIR / "cleaned_train.csv"
CLEAN_TEST_FILE = PROCESSED_DIR / "cleaned_test.csv"


# --------------------------------------------------
# DATASET LABEL CONFIGURATION
# --------------------------------------------------

EXPECTED_CLASSES = [
    "cyberattack_ocpp16_doc_idtag",
    "cyberattack_ocpp16_unauthorized_access",
    "cyberattack_ocpp16_dos_flooding_heartbeat",
    "cyberattack_ocpp16_fdi_chargingprofile",
    "normal"
]


# --------------------------------------------------
# LOAD CSV FILE
# --------------------------------------------------

def load_csv(file_path):
    """
    Loads a CSV dataset and removes unnecessary
    whitespace from column names.
    """

    if not file_path.exists():
        raise FileNotFoundError(
            f"Dataset file not found: {file_path}"
        )

    dataframe = pd.read_csv(file_path)

    dataframe.columns = (
        dataframe.columns
        .astype(str)
        .str.strip()
    )

    return dataframe


# --------------------------------------------------
# IDENTIFY LABEL COLUMN
# --------------------------------------------------

def identify_label_column(dataframe):
    """
    Identifies the target label column.

    First checks common column names, then checks
    which object column contains the expected labels.
    """

    common_names = [
        "label",
        "Label",
        "class",
        "Class",
        "attack",
        "Attack",
        "category",
        "Category",
        "attack_type",
        "Attack_Type"
    ]

    for column in common_names:
        if column in dataframe.columns:
            return column

    expected = set(EXPECTED_CLASSES)

    for column in dataframe.select_dtypes(
        include=["object", "string"]
    ).columns:

        values = set(
            dataframe[column]
            .dropna()
            .astype(str)
            .str.strip()
            .unique()
        )

        if values.intersection(expected):
            return column

    raise ValueError(
        "Could not identify the dataset label column. "
        "Please check the CSV column names."
    )


# --------------------------------------------------
# CLEAN DATAFRAME
# --------------------------------------------------

def clean_dataframe(dataframe, label_column):
    """
    Cleans the dataset by:
    - Removing duplicate rows.
    - Removing rows without labels.
    - Cleaning column names.
    - Converting numeric columns.
    - Filling missing numeric values.
    """

    dataframe = dataframe.copy()

    # Remove whitespace around column names.
    dataframe.columns = (
        dataframe.columns
        .astype(str)
        .str.strip()
    )

    # Remove duplicate rows.
    dataframe = dataframe.drop_duplicates()

    # Remove rows where target label is missing.
    dataframe = dataframe.dropna(
        subset=[label_column]
    )

    # Remove whitespace around labels.
    dataframe[label_column] = (
        dataframe[label_column]
        .astype(str)
        .str.strip()
    )

    # Convert numeric columns where possible.
    for column in dataframe.columns:

        if column == label_column:
            continue

        if dataframe[column].dtype == "object":

            converted = pd.to_numeric(
                dataframe[column],
                errors="coerce"
            )

            non_missing_original = (
                dataframe[column].notna().sum()
            )

            non_missing_converted = (
                converted.notna().sum()
            )

            if (
                non_missing_original > 0
                and non_missing_converted / non_missing_original >= 0.9
            ):
                dataframe[column] = converted

    # Fill missing numeric values with column median.
    numeric_columns = dataframe.select_dtypes(
        include=["number"]
    ).columns

    for column in numeric_columns:

        median_value = dataframe[column].median()

        if pd.notna(median_value):
            dataframe[column] = (
                dataframe[column].fillna(median_value)
            )
        else:
            dataframe[column] = (
                dataframe[column].fillna(0)
            )

    return dataframe


# --------------------------------------------------
# LOAD AND CLEAN TRAINING DATA
# --------------------------------------------------

def load_training_data():
    """
    Loads and cleans the training dataset.
    """

    dataframe = load_csv(TRAIN_FILE)

    label_column = identify_label_column(dataframe)

    cleaned_dataframe = clean_dataframe(
        dataframe,
        label_column
    )

    return cleaned_dataframe, label_column


# --------------------------------------------------
# LOAD AND CLEAN TEST DATA
# --------------------------------------------------

def load_testing_data(label_column=None):
    """
    Loads and cleans the testing dataset.
    """

    dataframe = load_csv(TEST_FILE)

    if label_column is None:
        label_column = identify_label_column(dataframe)

    if label_column not in dataframe.columns:
        raise ValueError(
            f"Label column '{label_column}' "
            "does not exist in the test dataset."
        )

    cleaned_dataframe = clean_dataframe(
        dataframe,
        label_column
    )

    return cleaned_dataframe


# --------------------------------------------------
# SAVE CLEANED DATASETS
# --------------------------------------------------

def save_cleaned_data(
    train_dataframe,
    test_dataframe
):
    """
    Saves cleaned training and testing CSV files.
    """

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    train_dataframe.to_csv(
        CLEAN_TRAIN_FILE,
        index=False
    )

    test_dataframe.to_csv(
        CLEAN_TEST_FILE,
        index=False
    )

    return {
        "training_file": str(CLEAN_TRAIN_FILE),
        "testing_file": str(CLEAN_TEST_FILE)
    }


# --------------------------------------------------
# DATASET SUMMARY
# --------------------------------------------------

def get_dataset_summary(
    train_dataframe,
    test_dataframe,
    label_column
):
    """
    Generates basic dataset statistics.
    """

    combined_dataframe = pd.concat(
        [train_dataframe, test_dataframe],
        ignore_index=True
    )

    return {
        "training_rows": len(train_dataframe),
        "testing_rows": len(test_dataframe),
        "total_rows": len(combined_dataframe),
        "total_features": len(combined_dataframe.columns) - 1,
        "label_column": label_column,
        "classes": sorted(
            combined_dataframe[label_column]
            .dropna()
            .unique()
            .tolist()
        ),
        "missing_values": int(
            combined_dataframe.isnull().sum().sum()
        ),
        "duplicate_rows": int(
            combined_dataframe.duplicated().sum()
        )
    }


# --------------------------------------------------
# MAIN DATASET LOADING PIPELINE
# --------------------------------------------------

def run_dataset_loader():
    """
    Loads, cleans, summarizes and saves the
    training and testing datasets.
    """

    print("\nEVSECURE-MIGRATE")
    print("DATASET LOADING AND CLEANING")
    print("-" * 55)

    # Load training data.
    train_dataframe, label_column = (
        load_training_data()
    )

    # Load testing data.
    test_dataframe = load_testing_data(
        label_column
    )

    # Save cleaned datasets.
    saved_files = save_cleaned_data(
        train_dataframe,
        test_dataframe
    )

    # Generate summary.
    summary = get_dataset_summary(
        train_dataframe,
        test_dataframe,
        label_column
    )

    print("\nDATASET SUMMARY")

    for key, value in summary.items():
        print(f"{key}: {value}")

    print("\nSAVED FILES")

    for key, value in saved_files.items():
        print(f"{key}: {value}")

    print("\nDataset loading completed successfully.")

    return {
        "summary": summary,
        "files": saved_files
    }


# --------------------------------------------------
# EXECUTION
# --------------------------------------------------

if __name__ == "__main__":
    run_dataset_loader()