
# EVSecure-Migrate
## MD5-to-SHA-3 Migration and Collision Risk Analysis in Legacy EV Firmware

EVSecure-Migrate is a cybersecurity project that demonstrates the migration of legacy MD5-based message integrity checking to SHA3-256 in a simulated EV charging station communication environment.

The project focuses on cryptographic hash comparison, message integrity verification, controlled tampering detection, replay detection, and cryptographic performance analysis.

---

## 1. Project Objectives

- Demonstrate the weaknesses of legacy MD5 hashing.
- Implement SHA3-256 for stronger message integrity protection.
- Demonstrate dual-hash verification during migration.
- Simulate EV charging station communication using OCPP-style messages.
- Detect repeated messages using replay detection.
- Analyze theoretical collision risks of different hash algorithms.
- Evaluate cryptographic performance using a real-world OCPP 1.6 intrusion detection dataset.

## 2. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend development |
| Flask | Web application |
| SQLite | Database management |
| HTML | Dashboard structure |
| CSS | Dashboard styling |
| JavaScript | Frontend interaction |
| hashlib | Cryptographic hashing |
| Pandas | Dataset processing |
| Matplotlib | Dataset visualization |
| OCPP-style simulation | EV charger communication model |

## 3. Cryptographic Algorithms

The project compares four hashing algorithms:

- MD5 – 128-bit digest; vulnerable to practical collision attacks.
- SHA-1 – 160-bit digest; deprecated for security-sensitive use.
- SHA-256 – 256-bit digest.
- SHA3-256 – 256-bit digest based on the SHA-3 standard.

The project focuses on migrating from MD5 to SHA3-256.

**Note:** Hashing is used for integrity checking, not encryption.

## 4. Security Modes

### LEGACY_MD5
Uses MD5 to verify message integrity.

### MIGRATION
Uses both MD5 and SHA3-256. Both stored digests must verify successfully.

### SECURE_SHA3
Uses SHA3-256 for message integrity verification.

## 5. Project Structure

```text
EVSecure-Migrate/
│
├── app.py
├── requirements.txt
├── README.md
│
├── crypto/
│   ├── __init__.py
│   ├── hash_engine.py
│   ├── migration.py
│   └── collision_demo.py
│
├── simulator/
│   ├── __init__.py
│   └── ev_charger.py
│
├── database/
│   ├── __init__.py
│   └── db.py
│
├── dataset/
│   ├── __init__.py
│   ├── dataset_loader.py
│   ├── dataset_analyzer.py
│   ├── dataset_to_messages.py
│   ├── dataset_crypto_evaluation.py
│   │
│   ├── raw/
│   │   └── Balanced_OCPP16_APP_Layer/
│   │       └── Combined/
│   │           ├── Train.csv
│   │           └── Test.csv
│   │
│   └── processed/
│
├── templates/
│   └── dashboard.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── dashboard.js
│
├── logs/
└── tests/
```

## 6. Dataset

The project uses the Federated OCPP 1.6 Intrusion Detection Dataset.

Source:
https://zenodo.org/records/14887131

The dataset contains five classes:

1. Normal
2. Unauthorized access
3. Document ID tag attack
4. Heartbeat DoS flooding
5. False data injection through charging profiles

The dataset contains application-layer flow statistics.

The dataset is used to generate synthetic message records for cryptographic evaluation. Its original labels are retained as metadata and are not predicted by the hashing algorithms.

## 7. Main Modules

### Cryptographic Hash Engine
- Generates MD5, SHA-1, SHA-256 and SHA3-256 hashes.
- Verifies message integrity.
- Compares hash outputs.
- Measures hashing performance.

### Migration Module
- Implements legacy MD5 verification.
- Implements dual-hash migration.
- Implements SHA3-256 verification.
- Compares digest properties.

### Collision Analysis
- Compares digest sizes.
- Calculates theoretical birthday-bound collision estimates.
- Compares files and messages.
- Identifies whether a collision is observed.

### EV Charger Simulator
- Simulates charger registration and communication messages.
- Generates BootNotification and Heartbeat messages.
- Simulates StartTransaction and StopTransaction.
- Tracks energy consumption.

### Database Module
- Stores charger information.
- Stores transactions and messages.
- Stores security events.
- Maintains persistent replay fingerprints.

### Dataset Evaluation
- Loads and cleans the dataset.
- Analyzes class distribution.
- Generates synthetic messages.
- Tests hash consistency.
- Tests controlled tampering detection.
- Benchmarks cryptographic algorithms.

## 8. Installation

Clone the repository:

```bash
git clone https://github.com/your-username/EVSecure-Migrate.git
```

Navigate to the project:

```bash
cd EVSecure-Migrate
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## 9. Dataset Setup

Place the original dataset files in:

```text
dataset/raw/Balanced_OCPP16_APP_Layer/Combined/
```

Required files:

- Train.csv
- Test.csv

## 10. Running the Project

Start the Flask application:

```bash
python3 app.py
```

Open the dashboard:

```text
http://127.0.0.1:5000
```

## 11. Dataset Evaluation Pipeline

The dataset evaluation modules can be executed in this order:

```bash
python3 -m dataset.dataset_loader
```

```bash
python3 -m dataset.dataset_analyzer
```

```bash
python3 -m dataset.dataset_to_messages
```

```bash
python3 -m dataset.dataset_crypto_evaluation
```

The generated reports are stored in:

```text
dataset/processed/
```

## 12. Expected Evaluation Outputs

The project produces:

- Cleaned training and testing datasets.
- Dataset class distribution.
- Dataset summary in JSON format.
- Class distribution graph.
- Synthetic cryptographic test messages.
- Hash consistency evaluation.
- Controlled tampering detection results.
- Hashing performance benchmarks.

Actual benchmark values depend on the system and execution environment.

## 13. Security Considerations

- MD5 is not suitable for security-sensitive collision resistance.
- SHA3-256 offers stronger collision resistance.
- A plain hash does not authenticate the sender.
- Authentication requires mechanisms such as HMACs, digital signatures or certificates.
- Replay detection based on identical payloads can flag legitimate repeated messages.
- The application is a simulation and educational demonstration, not a production EV charging security system.

## 14. Conclusion

EVSecure-Migrate demonstrates the importance of modernizing cryptographic integrity mechanisms in legacy EV charging communication environments.

By comparing MD5, SHA-1, SHA-256 and SHA3-256, implementing dual-hash migration, simulating charging station messages and evaluating controlled tampering, the project provides an experimental demonstration of cryptographic migration and collision risk analysis.

---

**Project:** EVSecure-Migrate  
**Domain:** Cybersecurity and Cryptography  
**Application:** Simulated EV Charging Station Communication Security
