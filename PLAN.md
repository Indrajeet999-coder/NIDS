# Step-by-Step Development & Testing Roadmap
## Machine Learning-Based Network Intrusion Detection System (NIDS)

---

## Roadmap Overview

This engineering roadmap outlines the 7 phases required to build, test, and deploy the complete NIDS system. Each phase contains clear checklist tasks (`[ ]`), target files, and terminal verification commands so progress can be monitored and validated step by step.

```
 Phase 1: Setup & Docs
         │
         ▼
 Phase 2: Memory-Safe Preprocessing (ml/preprocess.py)
         │
         ▼
 Phase 3: Multi-Model Training & Benchmarking (ml/train.py, ml/evaluate.py)
         │
         ▼
 Phase 4: FastAPI Backend & SQLite Audit (backend/)
         │
         ▼
 Phase 5: Automated Testing Suite (tests/test_ml.py, tests/test_api.py)
         │
         ▼
 Phase 6: React SOC Dashboard (frontend/)
         │
         ▼
 Phase 7: End-to-End Verification & Viva Preparation
```

---

## Phase 1: Workspace, Gitignore & Documentation Setup

**Goal**: Establish project guardrails, configure version control exclusions, and prepare documentation standards.

- [x] **Task 1.1**: Initialize project folder hierarchy (`dataset/raw/`, `dataset/processed/`, `ml/models/`, `ml/results/`, `backend/`, `frontend/`, `tests/`).
- [x] **Task 1.2**: Configure `.gitignore` to exclude raw datasets, virtual environments, bytecode, SQLite databases, and large `.joblib` model binaries.
- [x] **Task 1.3**: Author the project rulebook in `AGENTS.md` covering hardware constraints (Ryzen 5 5500U, 16 GB RAM), downcasting rules, and raw data protection.
- [x] **Task 1.4**: Author comprehensive system architecture and viva study guide in `ARCHITECTURE.md`.
- [x] **Task 1.5**: Author frontend visual and UI/UX design specifications in `DESIGN.md`.
- [x] **Task 1.6**: Author execution roadmap in `PLAN.md`.

### Verification Command (Terminal)
```powershell
Get-ChildItem -Path . -Force | Select-Object Name, Length
```
*Expected Output*: Verified presence of `.gitignore`, `AGENTS.md`, `ARCHITECTURE.md`, `DESIGN.md`, and `PLAN.md`.

---

## Phase 2: Memory-Safe Data Preprocessing (`ml/preprocess.py`)

**Goal**: Transform 8 dirty raw CSV files (~2.83M rows) into clean, memory-optimized train/test datasets and generate small sample CSVs for testing.

- [ ] **Task 2.1**: Author `ml/preprocess.py`:
  - Read all 8 CSV files from `dataset/raw/MachineLearningCVE/` iteratively.
  - Strip whitespace from all column names (`df.columns.str.strip()`).
  - Replace `+inf` and `-inf` with `np.nan` and drop nulls.
  - Drop duplicate rows.
  - Map target column: `"BENIGN"` $\rightarrow 0$, all attack names $\rightarrow 1$.
  - Downcast numeric columns (`float64` $\rightarrow$ `float32`, `int64` $\rightarrow$ `int32`) to fit in 16 GB RAM.
  - Select the top 20–25 highest-variance predictive features.
- [ ] **Task 2.2**: Implement stratified 80/20 train-test split (`train_test_split(stratify=y, test_size=0.20, random_state=42)`).
- [ ] **Task 2.3**: Fit `RobustScaler` **only on the training split** to prevent data leakage and save it.
- [ ] **Task 2.4**: Export processed training and test splits to `dataset/processed/` (e.g. Parquet or compressed CSV).
- [ ] **Task 2.5**: Generate `test_sample_1000.csv` containing a realistic 1,000-row mixture (85% Benign, 15% Attacks) for UI drag-and-drop demonstrations.

### Verification Command (Terminal)
```powershell
python ml/preprocess.py
```
*Expected Output*: Summary log displaying cleaned row count, memory reduction percentage (>50%), confirmed 0 NaN/Inf values, and creation of `test_sample_1000.csv`.

---

## Phase 3: Multi-Model Training, Evaluation & Artifact Export (`ml/train.py`, `ml/evaluate.py`)

**Goal**: Train, evaluate, and compare 4 algorithms, then serialize the champion model into an inference bundle.

- [ ] **Task 3.1**: Author `ml/train.py`:
  - Load preprocessed training split.
  - Train Model 1: **Logistic Regression** (Linear baseline, `class_weight="balanced"`).
  - Train Model 2: **Decision Tree Classifier** (`max_depth=12`, `class_weight="balanced"`).
  - Train Model 3: **Random Forest Classifier** (`n_estimators=100`, `max_depth=15`, `n_jobs=-1`).
  - Train Model 4: **XGBoost Classifier** (Champion model with `tree_method="hist"`, `n_estimators=150`, `learning_rate=0.1`).
- [ ] **Task 3.2**: Author `ml/evaluate.py`:
  - Evaluate all 4 models on the untouched 20% test set.
  - Calculate Accuracy, Precision, Recall, F1-Score, and ROC-AUC.
  - Generate Confusion Matrices and Top Feature Importance scores.
  - Export structured benchmark results to `ml/results/metrics.json`.
- [ ] **Task 3.3**: Export production bundle to `ml/models/nids_bundle.joblib`:
  - Must include: `{"model": xgb_model, "scaler": fitted_scaler, "selected_features": feature_list, "threshold": 0.50}`.

### Verification Command (Terminal)
```powershell
python ml/train.py
python ml/evaluate.py
```
*Expected Output*: Formatted evaluation comparison table in console and verified creation of `ml/models/nids_bundle.joblib` and `ml/results/metrics.json`.

---

## Phase 4: FastAPI Backend & SQLite Logging (`backend/`)

**Goal**: Build a high-performance REST API with persistent audit logging and model pre-loading.

- [ ] **Task 4.1**: Set up backend directory structure:
  ```
  backend/
  ├── __init__.py
  ├── main.py
  ├── database.py
  └── schemas.py
  ```
- [ ] **Task 4.2**: Implement `backend/database.py`:
  - Initialize SQLite database `backend/detections.db`.
  - Create table `detection_logs` with columns: `id`, `timestamp`, `request_source`, `prediction`, `label`, `confidence`, `dest_port`, `flow_duration`, `inference_time_ms`.
  - Provide asynchronous helper functions `log_detection()` and `get_recent_logs()`.
- [ ] **Task 4.3**: Implement `backend/schemas.py`:
  - Define Pydantic request models for single flow input validation.
  - Define response schemas for predictions, batch summary, and metrics.
- [ ] **Task 4.4**: Implement `backend/main.py`:
  - Use FastAPI Lifespan context to load `nids_bundle.joblib` once at startup.
  - Implement `POST /predict/single`: Returns classification verdict in < 5ms.
  - Implement `POST /predict/csv`: Batch parses multipart CSV and returns threat breakdown.
  - Implement `GET /metrics`: Serves JSON metrics from `ml/results/metrics.json`.
  - Implement `GET /history`: Returns latest logged rows from SQLite.
  - Enable CORS middleware for frontend communication (`http://localhost:5173`).

### Verification Command (Terminal)
```powershell
uvicorn backend.main:app --port 8000
# In a separate terminal:
curl -X GET http://localhost:8000/metrics
```
*Expected Output*: FastAPI starts on port 8000 and responds with HTTP 200 containing model metrics JSON.

---

## Phase 5: Automated Pytest Suite (`tests/test_ml.py`, `tests/test_api.py`)

**Goal**: Build a comprehensive automated QA test suite verifying data integrity, model artifacts, and API endpoints.

- [ ] **Task 5.1**: Create `tests/conftest.py` with shared fixtures (FastAPI `TestClient`, valid benign flow payload, valid attack flow payload, sample CSV file buffer).
- [ ] **Task 5.2**: Author `tests/test_ml.py`:
  - Test that processed datasets contain zero `NaN` or `Inf` values.
  - Test that target labels are strictly `{0, 1}`.
  - Test that `nids_bundle.joblib` exists, loads, and contains all expected dictionary keys (`model`, `scaler`, `selected_features`).
  - Test that model output probabilities sum to 1.0.
- [ ] **Task 5.3**: Author `tests/test_api.py`:
  - Test `GET /metrics` returns HTTP 200 and valid schema.
  - Test `POST /predict/single` with known benign sample yields `label: "BENIGN"`.
  - Test `POST /predict/single` with known attack sample yields `label: "ATTACK"`.
  - Test `POST /predict/csv` with `test_sample_1000.csv` yields HTTP 200 with normal and attack counts.
  - Test input validation error handling (missing required features returns HTTP 422).
  - Test `GET /history` returns persistent detection records.

### Verification Command (Terminal)
```powershell
pytest tests/ -v
```
*Expected Output*: All test cases pass with green checkmarks (100% pass rate).

---

## Phase 6: React SOC Dashboard Frontend (`frontend/`)

**Goal**: Build a responsive React single-page application with an industrial cybersecurity SOC design.

- [ ] **Task 6.1**: Initialize Vite React project with Tailwind CSS and Lucide React icons.
- [ ] **Task 6.2**: Configure color palette in `tailwind.config.js` (`#0B0F19` canvas, `#111827` cards, `#10B981` green, `#EF4444` red, `#3B82F6` blue).
- [ ] **Task 6.3**: Implement Navigation Shell and Tab switching (`Dashboard`, `Batch Analyzer`, `Simulator`, `Research Lab`).
- [ ] **Task 6.4**: Implement **View 1: Executive SOC Dashboard**:
  - Live KPI metric cards (Total Flows, Normal Traffic %, Intrusions Blocked, Latency).
  - Visual charts for traffic distribution and attack categories.
  - Recent alerts table connected to `GET /history`.
- [ ] **Task 6.5**: Implement **View 2: Batch CSV Traffic Analyzer**:
  - Drag-and-drop CSV uploader for `test_sample_1000.csv`.
  - Summary metrics and filterable predictions table (`All`, `Attacks Only`, `Benign Only`).
- [ ] **Task 6.6**: Implement **View 3: Interactive Flow Simulator**:
  - Preset attack buttons ("Normal Web Flow", "DDoS Flood", "PortScan").
  - Feature sliders for live parameter tuning.
  - Immediate visual verdict card with threat indicator and confidence breakdown.
- [ ] **Task 6.7**: Implement **View 4: Model Performance & Research Lab**:
  - Side-by-side comparison table of all 4 models.
  - Confusion matrix heatmap and top feature importance graph.

### Verification Command (Terminal)
```powershell
cd frontend
npm run build
npm run dev
```
*Expected Output*: Clean Vite build and local development server running on `http://localhost:5173`.

---

## Phase 7: End-to-End Demo Verification & Viva Preparation

**Goal**: Conduct full system rehearsals to ensure flawless live execution during project presentations.

- [ ] **Task 7.1**: Run complete automated test suite (`pytest tests/ -v`).
- [ ] **Task 7.2**: Execute pre-demo dry run:
  1. Launch backend (`uvicorn backend.main:app --port 8000`).
  2. Launch frontend (`npm run dev`).
  3. Upload `test_sample_1000.csv` in the Batch Analyzer and verify real-time classification.
  4. Trigger preset attacks in the Simulator and verify instant alerts.
  5. Check that the Executive Dashboard reflects newly logged events from SQLite.
- [ ] **Task 7.3**: Review viva defense questions in `ARCHITECTURE.md` Section 7 to ensure fluent verbal mastery of architecture decisions (memory downcasting, avoiding SMOTE, preventing data leakage, and automated testing).

