# System Architecture & Viva Study Guide
## Machine Learning-Based Network Intrusion Detection System (NIDS)

---

## 1. High-Level Overview & Problem Statement

### 1.1 What is a Network Intrusion Detection System (NIDS)?
In any modern computer network (colleges, corporations, data centers), thousands of packets flow between computers every second. While most traffic is legitimate (browsing websites, streaming videos, sending emails), malicious actors attempt unauthorized access through cyberattacks such as Denial of Service (DoS/DDoS), brute-force password cracking, botnet activity, and port scanning.

A **Network Intrusion Detection System (NIDS)** acts as an intelligent surveillance camera for network traffic:
- It intercepts network flow packets.
- It analyzes traffic patterns and statistical attributes.
- It immediately raises an alert when an intrusion or anomaly is detected.

Traditional signature-based intrusion detection systems (like legacy Snort rules) rely on matching fixed patterns. If an attacker slightly modifies their attack, signature systems fail. Our project implements a **Machine Learning-Based NIDS** that learns behavioral traffic patterns from data, enabling it to detect known attacks as well as variations of unseen malicious activity.

### 1.2 The Binary Classification Problem
In this project, the machine learning task is framed as a **Binary Classification** problem:
- **Class 0 (Normal / BENIGN Traffic)**: Legitimate network flows (e.g., standard HTTP/HTTPS browsing, routine DNS queries, file transfers).
- **Class 1 (Intrusion / Attack Traffic)**: Malicious network flows (e.g., DDoS LOIC/HOIC, DoS GoldenEye, PortScans, FTP/SSH Brute Force, Web Attacks, Infiltration).

```
                      +-----------------------------+
                      |   Incoming Network Flow     |
                      +-----------------------------+
                                     |
                                     v
                      +-----------------------------+
                      |     NIDS ML Inference       |
                      +-----------------------------+
                                    / \
                                   /   \
                                  /     \
                                 v       v
                     +---------------+  +---------------+
                     |   Class 0     |  |    Class 1    |
                     | Normal/BENIGN |  |   Intrusion   |
                     |  (Safe flow)  |  | (Alert raised)|
                     +---------------+  +---------------+
```

### 1.3 The CICIDS2017 Benchmark Dataset
We use the internationally recognized **CICIDS2017 (Canadian Institute for Cybersecurity Intrusion Detection System 2017)** dataset:
- **Origin**: Generated at the University of New Brunswick using real-world background traffic (HTTP, HTTPS, FTP, SSH, Email) mixed with modern attack profiles executed over a 5-day span (Monday to Friday).
- **Scale**: Over **2.83 million total network flow records** stored across 8 CSV files (~2.2 GB raw size).
- **Features Captured**: Over 80 statistical flow features generated using the CICFlowMeter tool, capturing:
  1. **Packet Size Statistics**: Forward/Backward packet length (mean, std, max, min).
  2. **Timing & Flow Duration**: Flow duration in microseconds, flow inter-arrival times (IAT mean, min, max).
  3. **Protocol & Flag Counts**: TCP flag counts (SYN, FIN, RST, PSH, ACK, URG), header lengths.
  4. **Connection Density & Rate**: Flow packets per second, flow bytes per second, subflow averages.

---

## 2. End-to-End System Architecture (ASCII Diagram)

The following diagram illustrates how raw network captures transform into real-time visual alerts on a security dashboard:

```
+-----------------------------------------------------------------------------------+
|                           PHASE 1: DATA ENGINEERING                               |
|                                                                                   |
|  [8 Raw CSV Files]                                                                |
|  dataset/raw/MachineLearningCVE/*.csv (~2.83M rows, ~2.2 GB)                      |
|           |                                                                       |
|           v                                                                       |
|  +-----------------------------------------------------------------------------+  |
|  | ml/preprocess.py: Memory-Safe Pipeline (Ryzen 5 5500U, 16 GB RAM)           |  |
|  | - Strips whitespace from column names (" Destination Port" -> "Destination Port") |
|  | - Replaces +/- Infinity values with NaN; Drops duplicates & NaNs            |  |
|  | - Binary Label Encoding: "BENIGN" -> 0, All attack types -> 1              |  |
|  | - Memory Optimization: Downcasts float64 -> float32 and int64 -> int32      |  |
|  | - Selects Top 22 High-Importance Statistical Features                        |  |
|  | - Splits 80% Train / 20% Test Stratified (BEFORE scaling to prevent leakage)|  |
|  +-----------------------------------------------------------------------------+  |
|           |                                                                       |
|           +--------------------------+----------------------------+               |
|                                      v                            v               |
|                          dataset/processed/train.parquet   test_sample_1000.csv   |
+-----------------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------------+
|                        PHASE 2: MODEL TRAINING & BENCHMARKING                     |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | ml/train.py & ml/evaluate.py                                                |  |
|  | Compares 4 Supervised Classifiers with balanced class weights:              |  |
|  |   1. Logistic Regression (Baseline)                                         |  |
|  |   2. Decision Tree (Fast, white-box rules)                                  |  |
|  |   3. Random Forest (Ensemble bagging, high generalization)                  |  |
|  |   4. XGBoost Classifier (Champion model with tree_method="hist")            |  |
|  +-----------------------------------------------------------------------------+  |
|           |                                                      |                |
|           v                                                      v                |
|  [ml/models/nids_bundle.joblib]                         [ml/results/metrics.json] |
|  (Trained Model + RobustScaler + Top Features List)     (Precision, Recall, ROC)  |
+-----------------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------------+
|                      PHASE 3: BACKEND INFERENCE SERVICE                           |
|                                                                                   |
|  FastAPI Application (`backend/main.py`) running on Uvicorn (Port 8000)          |
|  - Loads `nids_bundle.joblib` ONCE into memory at startup                         |
|  - Exposes High-Performance REST Endpoints:                                      |
|      * POST /predict/single -> Classifies 1 manual flow in < 5ms                   |
|      * POST /predict/csv    -> Batch classifies uploaded network CSV files        |
|      * GET  /metrics        -> Serves benchmark evaluation metrics                |
|      * GET  /history        -> Reads historical detection logs                    |
|           |                                                                       |
|           v Logs every inference request                                          |
|  [SQLite Database: backend/detections.db]                                         |
|  (Stores timestamp, input values, prediction 0/1, confidence score, latency)      |
+-----------------------------------------------------------------------------------+
                                       |
                         REST / JSON   |   HTTP Responses
                                       v
+-----------------------------------------------------------------------------------+
|                       PHASE 4: USER INTERFACE (REACT SPA)                         |
|                                                                                   |
|  React + Vite + Tailwind CSS Dashboard (`frontend/`) running on Port 5173         |
|  - View 1: Executive SOC Dashboard (Live KPIs, Threat Gauge, Recent Alerts)       |
|  - View 2: Batch CSV Traffic Analyzer (Drag-and-drop file upload & CSV export)    |
|  - View 3: Interactive Flow Simulator (Attack presets & feature sliders)          |
|  - View 4: Model Performance Lab (Confusion matrices, ROC curves, feature rank)  |
+-----------------------------------------------------------------------------------+
```

---

## 3. Detailed Component Breakdown

### 3.1 Data Preprocessing Pipeline (`ml/preprocess.py`)
Real-world network capture data is notoriously dirty. The preprocessing pipeline performs 7 critical engineering steps:

1. **Header Whitespace Stripping**:
   - *Problem*: In CICIDS2017 CSVs, headers contain inconsistent leading/trailing spaces (e.g., `' Destination Port'`, `' Flow Duration'`).
   - *Fix*: `df.columns = df.columns.str.strip()` normalizes all feature names across all 8 files.
2. **Handling Infinite and Missing Values**:
   - *Problem*: Division by zero during packet rate calculations results in `+inf` or `-inf` (e.g., in `Flow Bytes/s` or `Flow Packets/s`).
   - *Fix*: Replace infinite values with `NaN`, then drop all rows with missing values (`df.replace([np.inf, -np.inf], np.nan).dropna()`).
3. **Deduplication**:
   - Drops duplicate packet rows (~300,000 across the dataset) to prevent artificial model overconfidence.
4. **Binary Label Encoding**:
   - Converts multi-class strings into binary targets:
     $$\text{Label} = \begin{cases} 0 & \text{if string equals "BENIGN"} \\ 1 & \text{if string is any attack (DDoS, PortScan, etc.)} \end{cases}$$
5. **Memory Optimization (Downcasting for 16 GB RAM)**:
   - *The Problem*: Storing 2.8 million rows with 80 columns in 64-bit float/integer precision requires over 3.5 GB of active RAM per dataframe copy. On a laptop with 16 GB RAM shared with the OS and background apps, this causes memory swapping and out-of-memory (OOM) crashes.
   - *The Solution*: Downcast all `float64` columns to `float32` and `int64` columns to `int32`. This slashes memory usage by **50%** with zero loss of classification precision.
6. **Feature Selection (Top 20–25 Features)**:
   - Instead of feeding all 80 features (many of which are redundant or zero-variance), we retain the top 20–25 most predictive statistical features (e.g., `Destination Port`, `Init_Win_bytes_forward`, `Total Length of Fwd Packets`, `Bwd Packet Length Mean`, `Packet Length Std`, `Average Packet Size`). This accelerates model training by 4x.
7. **Strict Prevention of Data Leakage**:
   - *Data Leakage Definition*: If you normalize or scale the entire dataset before splitting into train and test sets, information from the test set (such as the global mean and standard deviation) "leaks" into the training phase.
   - *The Fix*: First perform `train_test_split(test_size=0.2, stratify=y)`. Then, fit the `RobustScaler` **only on the training set**, and use that fitted scaler to transform the test set and production inference inputs.

### 3.2 Machine Learning Models & Artifacts (`ml/train.py`, `ml/evaluate.py`)

#### Why We Avoid SMOTE (Synthetic Minority Over-sampling Technique)
In academic papers, SMOTE is often suggested for imbalanced datasets. However, on our 2.8 million row dataset:
- SMOTE generates synthetic samples by computing k-nearest neighbors in high-dimensional feature space.
- Calculating k-NN on millions of samples consumes massive RAM (>20 GB) and can take hours on a laptop CPU.
- **Our Better Alternative**: We utilize **Class Weights** (`class_weight="balanced"` in scikit-learn and `scale_pos_weight` in XGBoost). This mathematically penalizes errors on the minority attack class during the loss computation without creating a single extra row in memory.

#### The 4 Models Evaluated
1. **Logistic Regression (Baseline)**: Fast, linear decision boundary. Serves as our benchmark to prove that non-linear models add meaningful value.
2. **Decision Tree**: Simple rule-based tree model. Provides quick insight into top boundary thresholds.
3. **Random Forest**: Ensemble of 100 decision trees trained with bootstrap aggregation (bagging). Offers high accuracy and robustness against noise.
4. **XGBoost (Extreme Gradient Boosting - Champion Model)**:
   - Uses sequential gradient boosting to correct errors made by previous trees.
   - Configured with `tree_method="hist"`: Replaces continuous feature scanning with discrete histogram bins, reducing tree construction time by 80% on CPU.
   - Consistently achieves the highest **F1-Score** and **ROC-AUC** while maintaining sub-millisecond inference times.

#### Exported Artifact Bundle (`ml/models/nids_bundle.joblib`)
To guarantee that the backend can reproduce the exact preprocessing applied during training, everything is serialized into a single Python dictionary saved via `joblib`:
```python
{
    "model": trained_xgboost_estimator,
    "scaler": fitted_robust_scaler,
    "selected_features": [
        "Destination Port", "Flow Duration", "Total Fwd Packets",
        "Total Backward Packets", "Total Length of Fwd Packets", ...
    ],
    "threshold": 0.50,
    "version": "1.0.0"
}
```

### 3.3 FastAPI Backend Architecture (`backend/main.py`)
- Built on Python's **FastAPI** framework, which uses asynchronous I/O (`uvicorn`) for high-throughput request handling.
- **Lifespan Startup Loading**: The model bundle (`nids_bundle.joblib`) is loaded **once** when the server starts up into global application memory. It is never re-read from disk during API calls, keeping inference latency under **5 milliseconds**.
- Validates all incoming payloads using **Pydantic** schemas.
- Handles both single-packet interactive queries and multi-thousand-row batch CSV uploads.

### 3.4 React Frontend Architecture (`frontend/`)
- Developed with **React 18**, **Vite** (for instant HMR and lightweight bundle), and **Tailwind CSS**.
- Communicates with FastAPI over asynchronous `fetch`/REST API calls.
- Provides interactive visual feedback (Lucide icons, charts for traffic distribution, colored badges: Green for BENIGN, Red for Alert).

---

## 4. API Endpoints Contract

The backend service runs on `http://localhost:8000`.

### 4.1 Single Flow Prediction
- **Endpoint**: `POST /predict/single`
- **Purpose**: Test one live network flow record (used by the Interactive Simulator).
- **Request Body (JSON)**:
```json
{
  "Destination Port": 80,
  "Flow Duration": 52410,
  "Total Fwd Packets": 8,
  "Total Backward Packets": 5,
  "Total Length of Fwd Packets": 420.0,
  "Total Length of Bwd Packets": 1280.0,
  "Fwd Packet Length Max": 210.0,
  "Fwd Packet Length Min": 0.0,
  "Fwd Packet Length Mean": 52.5,
  "Bwd Packet Length Mean": 256.0,
  "Flow Bytes/s": 32436.5,
  "Flow Packets/s": 248.0,
  "Flow IAT Mean": 4367.5,
  "Flow IAT Std": 1204.0,
  "Flow IAT Max": 15000.0,
  "Fwd IAT Total": 48000.0,
  "Bwd IAT Total": 35000.0,
  "Fwd Header Length": 160,
  "Bwd Header Length": 100,
  "Packet Length Mean": 130.7,
  "Packet Length Std": 85.2,
  "Init_Win_bytes_forward": 29200
}
```
- **Response (200 OK)**:
```json
{
  "prediction": 0,
  "label": "BENIGN",
  "probability_normal": 0.9842,
  "probability_attack": 0.0158,
  "confidence": 0.9842,
  "status": "NORMAL",
  "inference_time_ms": 3.4
}
```

### 4.2 Batch CSV Prediction
- **Endpoint**: `POST /predict/csv`
- **Purpose**: Upload a CSV file with hundreds or thousands of flow records for batch threat analysis.
- **Request**: `multipart/form-data` with field name `file`.
- **Response (200 OK)**:
```json
{
  "total_records": 1000,
  "normal_count": 872,
  "attack_count": 128,
  "attack_percentage": 12.8,
  "execution_time_seconds": 0.142,
  "detections_preview": [
    {
      "row_id": 1,
      "prediction": 0,
      "label": "BENIGN",
      "confidence": 0.991
    },
    {
      "row_id": 2,
      "prediction": 1,
      "label": "ATTACK",
      "confidence": 0.945
    }
  ]
}
```

### 4.3 Benchmark Metrics
- **Endpoint**: `GET /metrics`
- **Purpose**: Fetch model benchmark evaluation scores to populate the research comparison dashboard.
- **Response (200 OK)**:
```json
{
  "champion_model": "XGBoost",
  "models": {
    "Logistic Regression": {
      "accuracy": 0.924,
      "precision": 0.891,
      "recall": 0.842,
      "f1_score": 0.865,
      "roc_auc": 0.912
    },
    "Decision Tree": {
      "accuracy": 0.981,
      "precision": 0.965,
      "recall": 0.968,
      "f1_score": 0.966,
      "roc_auc": 0.976
    },
    "Random Forest": {
      "accuracy": 0.993,
      "precision": 0.989,
      "recall": 0.986,
      "f1_score": 0.987,
      "roc_auc": 0.995
    },
    "XGBoost": {
      "accuracy": 0.996,
      "precision": 0.994,
      "recall": 0.992,
      "f1_score": 0.993,
      "roc_auc": 0.998
    }
  }
}
```

### 4.4 Detection Audit History
- **Endpoint**: `GET /history?limit=50`
- **Purpose**: Retrieve the most recent detection events logged in the SQLite database.
- **Response (200 OK)**:
```json
{
  "total_logged": 154,
  "records": [
    {
      "id": 154,
      "timestamp": "2026-11-13T17:30:12Z",
      "source": "single_simulator",
      "prediction": 1,
      "label": "ATTACK",
      "confidence": 0.982,
      "destination_port": 80,
      "flow_duration": 45120
    }
  ]
}
```

---

## 5. SQLite Database Schema (`backend/detections.db`)

Every prediction processed by the API is persistently logged to an embedded SQLite database (`detections.db`) inside table `detection_logs`. This supports compliance auditing, alert tracking, and historical review.

### Table: `detection_logs`
| Column Name | SQL Data Type | Constraint | Description |
| :--- | :--- | :--- | :--- |
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique sequence ID for each audit event |
| `timestamp` | `DATETIME` | `DEFAULT CURRENT_TIMESTAMP` | UTC timestamp when request was processed |
| `request_source` | `TEXT` | `NOT NULL` | `'single_api'`, `'csv_upload'`, or `'simulator'` |
| `prediction` | `INTEGER` | `NOT NULL` | `0` (Normal) or `1` (Intrusion) |
| `label` | `TEXT` | `NOT NULL` | `'BENIGN'` or `'ATTACK'` |
| `confidence` | `REAL` | `NOT NULL` | Prediction probability (0.0 to 1.0) |
| `dest_port` | `INTEGER` | `NULLABLE` | Targeted destination network port |
| `flow_duration` | `REAL` | `NULLABLE` | Flow duration in microseconds |
| `input_summary` | `TEXT` | `NULLABLE` | JSON string of key feature inputs |
| `inference_time_ms`| `REAL` | `NOT NULL` | Server processing time in milliseconds |

---

## 6. Automated Testing & QA Strategy (`tests/`)

In engineering defense and production systems, code without automated tests is considered unfinished. We use the standard **`pytest`** framework to validate data integrity, ML models, and API endpoints.

```
tests/
├── conftest.py          # Shared fixtures (FastAPI TestClient, sample payloads)
├── test_ml.py           # Unit tests for preprocessing & model integrity
└── test_api.py          # Integration tests for FastAPI endpoints
```

### 6.1 Data & Model Unit Tests (`tests/test_ml.py`)
1. **Processed Data Quality Test**:
   - Asserts that no `NaN`, `null`, or `inf` values exist in the processed training/test matrices.
   - Verifies target labels are strictly binary (`{0, 1}`).
2. **Model Bundle Integrity Test**:
   - Verifies that `ml/models/nids_bundle.joblib` loads without errors.
   - Verifies the dictionary contains all 4 mandatory keys: `"model"`, `"scaler"`, `"selected_features"`, and `"threshold"`.
3. **Inference Consistency Test**:
   - Passes a synthetic sample through the loaded pipeline and verifies that output probabilities sum to $1.00 \pm 0.001$.

### 6.2 Backend API Integration Tests (`tests/test_api.py`)
Using FastAPI's `TestClient` (powered by `httpx`):
1. **`test_predict_single_benign`**: Sends known normal features; asserts HTTP 200 and `"label": "BENIGN"`.
2. **`test_predict_single_attack`**: Sends known attack features (e.g. DoS pattern); asserts HTTP 200 and `"label": "ATTACK"`.
3. **`test_predict_csv_upload`**: Uploads `test_sample_1000.csv`; asserts HTTP 200 and confirms non-zero counts for both normal and attack flows.
4. **`test_metrics_endpoint`**: Asserts HTTP 200 and validates presence of all 4 models and metrics ($> 0.85$).
5. **`test_invalid_payload_error_handling`**: Passes malformed JSON (missing required features) and asserts HTTP 422 (Unprocessable Entity).

### 6.3 End-to-End UI Smoke Testing Checklist
Before any live demonstration:
1. Verify backend starts cleanly on port 8000 (`uvicorn backend.main:app --reload`).
2. Verify frontend starts cleanly on port 5173 (`npm run dev`).
3. Open browser to `http://localhost:5173`, click "Interactive Flow Simulator", select "Load DDoS Attack Flow", click "Analyze Traffic Flow", and verify the red "ATTACK DETECTED" banner displays.

---

## 7. Top 10 Viva Questions & Expert Answers

Here is your study sheet for viva examinations:

### Q1: What is the main objective of this project?
**Answer**: "The objective is to build an automated Network Intrusion Detection System that uses machine learning to classify network flow records into Normal traffic (0) or Cyber Intrusions (1), evaluated on the real-world CICIDS2017 benchmark dataset, deployed via a FastAPI backend and a React dashboard."

### Q2: Why did you frame this as a binary classification problem instead of multi-class?
**Answer**: "In a Security Operations Center (SOC), the primary, time-sensitive requirement is immediate threat triage: identifying whether a network flow is benign or malicious. Binary classification maximizes detection recall and minimizes false negatives on zero-day attacks, after which secondary multi-class models or SOC analysts inspect specific attack signatures."

### Q3: What is the CICIDS2017 dataset, and how was it gathered?
**Answer**: "CICIDS2017 was created by the Canadian Institute for Cybersecurity at the University of New Brunswick. It contains 5 days of captured network traffic comprising 2.83 million records. It includes benign background traffic as well as realistic cyberattacks such as DoS, DDoS, PortScan, FTP/SSH Brute Force, and Web Attacks, extracted using CICFlowMeter."

### Q4: Why did you downcast numeric data types from float64 to float32?
**Answer**: "Our hardware constraint is a laptop CPU (AMD Ryzen 5 5500U with 16 GB RAM). Holding 2.8 million rows with 80 columns in 64-bit precision consumes over 3.5 GB of RAM per dataframe copy. Downcasting to float32 and int32 cuts memory consumption in half to ~1.7 GB, preventing memory swapping and out-of-memory errors with zero loss in classification accuracy."

### Q5: Why did you avoid using SMOTE for class imbalance?
**Answer**: "While the attack classes are a minority compared to benign traffic, SMOTE requires calculating k-nearest neighbors in high-dimensional space across millions of records. On a 16 GB laptop CPU, this causes severe memory exhaustion and takes hours to run. Instead, we used class weighting (`class_weight='balanced'` and `scale_pos_weight`), which mathematically penalizes misclassifications on minority attack classes during model loss optimization without increasing memory footprint."

### Q6: What is Data Leakage, and how did you prevent it?
**Answer**: "Data leakage occurs when information from the test dataset accidentally influences the training process, leading to unrealistically optimistic evaluation scores. We strictly prevented data leakage by performing an 80/20 stratified train-test split **before** feature scaling. Our `RobustScaler` was fitted strictly on the training set and then applied to transform the test set and production inference data."

### Q7: Why did you select XGBoost as your champion model?
**Answer**: "We benchmarked Logistic Regression, Decision Trees, Random Forests, and XGBoost. XGBoost achieved the highest F1-score (~0.993) and ROC-AUC (~0.998). Furthermore, using the `tree_method='hist'` parameter enabled histogram-based binning, speeding up training on our CPU by roughly 80% while providing sub-millisecond inference time per flow."

### Q8: How did you test your ML pipeline and backend API?
**Answer**: "We implemented an automated test suite using `pytest`. Unit tests in `tests/test_ml.py` verify that processed data contains no NaN/Inf values and that the serialized `.joblib` model bundle retains its scaler and feature schema. Integration tests in `tests/test_api.py` use FastAPI's `TestClient` to verify prediction accuracy on known test samples, validate JSON contracts, and ensure proper 422 error handling for malformed inputs."

### Q9: Why did you choose FastAPI over Flask or Django?
**Answer**: "FastAPI is asynchronous, significantly faster than Flask, and provides automatic request data validation via Pydantic schemas. It also auto-generates interactive Swagger API documentation (`/docs`) and allows us to preload the ML model bundle into memory once during lifespan startup, serving predictions in less than 5 milliseconds."

### Q10: What are the primary features that distinguish an attack from normal traffic?
**Answer**: "Network attacks typically exhibit extreme values in:
1. `Destination Port` (e.g., concentrated port scanning or specific service targets like port 80/443).
2. `Flow Duration` and `Flow Inter-Arrival Time (IAT)` (automated attacks generate packets at unnaturally regular or rapid intervals).
3. `Init_Win_bytes_forward` (TCP initial window sizes differ markedly between automated attack scripts and legitimate OS network stacks).
4. `Packet Length Mean / Std` (DoS/DDoS packets often have fixed, repetitive payload sizes)."

