# NIDS SOC Frontend Dashboard (React + Vite + Tailwind CSS)
## Real-Time Network Intrusion Detection System — CICIDS2017 Classifier

An industrial-grade Security Operations Center (SOC) dashboard built with React 18, Vite, and Tailwind CSS. Provides real-time inference visualization, batch CSV packet inspection, single-flow tuning simulator, and SQLite detection audit streams.

---

## 1. Quick Start

### Prerequisites
- Node.js (v18 or higher)
- `pnpm` (or `npm` / `yarn`)
- FastAPI Backend running on `http://127.0.0.1:8000`

### Installation & Launch
```bash
# 1. Navigate to the frontend directory
cd frontend

# 2. Install dependencies (run in your terminal)
pnpm install

# 3. Start the Vite development server on port 5173
pnpm dev
```

Open your browser to: **[http://localhost:5173](http://localhost:5173)**

---

## 2. Views & Features Overview

### 1. Overview & Benchmarks
- **Live SOC KPIs**: Test Accuracy (`99.38%`), Champion F1-Score (`0.9821`), ROC-AUC (`0.9998`), and Inference Latency (`6.91 ms` per 1k flows).
- **Interactive 4-Model Comparison Bar Chart**: Toggle metrics (F1-score, Accuracy, Precision, Recall, ROC-AUC, Latency) across Logistic Regression, Decision Tree, Random Forest, and XGBoost.
- **Confusion Matrix Heatmap**: Visualizes True Negatives (98,942), False Positives (608), False Negatives (131), and True Positives (20,319) with calculated False Alarm Rate (0.61%) and Attack Recall (99.36%).
- **Top 15 Feature Importances**: Relative gain weight rankings from CICFlowMeter features.

### 2. CSV Traffic Analyzer
- **Drag-and-Drop Dropzone**: Upload `.csv` network flow captures (e.g., `dataset/processed/demo_test_flows.csv`).
- **Batch Evaluation Metrics**: Total flows, normal traffic count, intrusion count, threat rate percentage, and latency in milliseconds.
- **Filterable Results Table**: Filter by All, Threats Only, or Normal Only, with search by port or index and confidence progress bars.
- **CSV Export**: One-click download of batch prediction verdicts.

### 3. Live Flow Simulator
- **Preset Telemetry**: One-click **"Load Sample Normal Flow"** (HTTPS Web traffic) and **"Load Sample Attack Flow"** (DDoS/PortScan pattern).
- **Parameter Tuner**: Range sliders and two-way numeric inputs for key features (`Destination Port`, `Bwd Packet Length Std`, `Average Packet Size`, `Max Packet Length`, `PSH/ACK Flag Counts`, etc.), plus collapsible panel for all 25 features.
- **Real-Time AI Verdict Card**: Glowing status banner (Emerald for Authorized Normal vs Crimson for Malicious Intrusion), confidence gauge, assessed risk level, and destination port telemetry.

### 4. Audit Logs & Compliance Stream
- **Persistent SQLite Audit**: Streams logs stored in `backend/detections.db`.
- **Forensic Details**: Channel source (`csv_upload` vs `single_flow`), flow count, threat triage, peak confidence, and metadata context.
- **Management Controls**: Refresh and **Clear History** (`DELETE /history`) with confirmation modal.

---

## 3. Configuration & Environment Variables

Create a `.env` file in `frontend/` if you need to point to a custom backend host or port:

```bash
VITE_API_URL=http://127.0.0.1:8000
```

---

## 4. Architecture Contract

- **Frontend Port**: `http://localhost:5173` (Allowed in `backend/config.py` CORS origins).
- **Backend API**: `http://127.0.0.1:8000` (`GET /health`, `GET /metrics`, `GET /features`, `POST /predict/single`, `POST /predict/csv`, `GET /history`, `DELETE /history`).
- **Styling**: Tailwind CSS with custom SOC palette (`#0b1120` canvas, `#111827` cards, emerald `#10b981`, rose `#f43f5e`, sky `#38bdf8`).

