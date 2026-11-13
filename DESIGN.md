# Frontend UI/UX & Visual Specification (SOC Dashboard)
## Machine Learning-Based Network Intrusion Detection System (NIDS)

---

## 1. Design Philosophy & Aesthetic Identity

Modern Security Operations Centers (SOCs) operate 24/7 in low-light command rooms where security analysts must rapidly digest thousands of telemetry signals without visual fatigue. The user interface for our NIDS project is designed with an **Industrial Cybersecurity SOC Theme**:
- **High-Contrast Dark Mode**: Minimizes eye strain and makes high-priority cyber threats instantly noticeable.
- **Immediate Threat Triage**: Uses universally recognized security color semantics (Emerald Green for Safe/Normal traffic, Crimson Red for Intrusion Alerts).
- **Zero-Latency Visual Feedback**: Provides immediate confidence scores, latency badges, and micro-interactions.
- **Glassmorphic & Clean Accents**: Subtle borders and translucent cards with crisp typography for an enterprise-grade finish.

---

## 2. Color Palette & Typography Specification

### 2.1 Color Palette
| Color Role | Hex Code | Tailwind Class | Semantic Meaning & Usage |
| :--- | :--- | :--- | :--- |
| **Main Background** | `#0B0F19` | `bg-slate-950` / `#0B0F19` | Canvas background for the entire application |
| **Card / Panel Background** | `#111827` | `bg-gray-900` | Elevates cards, tables, charts, and input panels |
| **Surface Accent / Hover** | `#1F2937` | `bg-gray-800` | Input borders, table header rows, divider lines |
| **Normal Traffic (Safe)** | `#10B981` | `text-emerald-500` / `bg-emerald-500/10` | Benign network flows, healthy status badges, safe metrics |
| **Intrusion Alert (Threat)** | `#EF4444` | `text-red-500` / `bg-red-500/10` | Attack detections, high-risk warnings, critical alerts |
| **Cyber Accent / Info** | `#3B82F6` | `text-blue-500` / `bg-blue-500/10` | Primary buttons, active tabs, links, network metrics |
| **Secondary Accent / Warning** | `#F59E0B` | `text-amber-500` | Medium confidence warnings, pending file processing |
| **Primary Text** | `#F9FAFB` | `text-gray-50` | Headings, primary metrics, high-emphasis text |
| **Muted Text** | `#9CA3AF` | `text-gray-400` | Subtitles, table column headers, helper hints |

### 2.2 Typography
- **Primary Font**: `Inter`, system-ui, `-apple-system`, sans-serif (Clean, highly legible at small sizes).
- **Monospace Font**: `JetBrains Mono`, `Fira Code`, monospace (Used for IP addresses, port numbers, confidence percentages, latency values, and JSON data).

---

## 3. Global Navigation & Layout Shell

The application uses a persistent top navigation bar and a responsive container layout:

```
+-----------------------------------------------------------------------------------------------+
| [Shield Icon] NIDS SEC-OPS | (●) MODEL ONLINE (XGBoost 99.6%)  | [Dashboard] [Batch] [Sim] [Lab] |
+-----------------------------------------------------------------------------------------------+
|                                                                                               |
|                                    ACTIVE VIEW CONTAINER                                      |
|                                                                                               |
+-----------------------------------------------------------------------------------------------+
```

- **Top Navigation Bar**:
  - **Left**: Project Logo (`ShieldCheck` icon) with glowing cyan title `"NIDS SEC-OPS"` and subtitle `"CICIDS2017 Classifier"`.
  - **Center**: Engine Status Pill with a pulsing green dot: `"Model Engine: XGBoost v1.0 (99.6% F1)"`.
  - **Right**: Tab navigation pills with active blue state indicators:
    1. **SOC Dashboard** (`LayoutDashboard` icon)
    2. **Batch Traffic Analyzer** (`FileSpreadsheet` icon)
    3. **Interactive Simulator** (`Sliders` icon)
    4. **Model Performance Lab** (`Cpu` icon)

---

## 4. Screen-by-Screen Visual Breakdown

### 4.1 View 1: Executive SOC Dashboard (Overview & Monitoring)
The landing view for security managers and SOC tier-1 analysts. It gives an immediate summary of overall network safety.

```
+-----------------------------------------------------------------------------------------------+
| [ Total Flows: 128,490 ]  [ Benign: 114,200 (88.9%) ]  [ Intrusions: 14,290 ]  [ Mean Latency: 3.2ms ] |
+-----------------------------------------------------------------------------------------------+
| +-----------------------------------------------+ +-----------------------------------------+ |
| |  TRAFFIC CLASSIFICATION OVER TIME (Bar Chart) | | ATTACK DISTRIBUTION (Donut Chart)       | |
| |  [==== Benign (Green) ====]                   | |  (O) DoS/DDoS: 64%                      | |
| |  [== Attacks (Red) ==]                        | |      PortScan: 22%                      | |
| |                                               | |      Brute Force: 14%                   | |
| +-----------------------------------------------+ +-----------------------------------------+ |
| +-------------------------------------------------------------------------------------------+ |
| | RECENT INTRUSION ALERTS TABLE (Live SQLite Audit Stream)                                  | |
| | Timestamp         | Source   | Dest Port | Protocol | Confidence | Severity  | Action     | |
| | 17:42:01.210 UTC  | Single   | 80        | TCP      | 99.4%      | [CRITICAL]| [Inspect]  | |
| | 17:41:55.840 UTC  | Batch    | 443       | TCP      | 96.1%      | [WARNING] | [Inspect]  | |
| +-------------------------------------------------------------------------------------------+ |
```

#### Key Elements:
1. **Top KPI Metric Cards (4 Cards Grid)**:
   - **Total Processed Flows**: Displays total flows analyzed across all sessions with a blue trend badge.
   - **Normal Traffic**: Highlighted in Emerald Green (`#10B981`) with a checkmark badge.
   - **Threats Intercepted**: Highlighted in Crimson Red (`#EF4444`) with an alert triangle icon and percentage of total.
   - **Inference Latency**: Displays average response time (e.g., `3.2 ms`) indicating real-time performance.
2. **Visual Analytics Grid (2 Columns)**:
   - **Left Panel (Traffic Overview)**: Stacked bar chart showing benign vs. malicious traffic volume.
   - **Right Panel (Attack Distribution Donut)**: Visual breakdown of detected threat categories (DoS, PortScan, Web Attacks).
3. **Recent Intrusion Alerts Table**:
   - Queries `GET /history` from the SQLite database.
   - Displays real-time entries with color-coded severity badges (`CRITICAL`, `WARNING`, `SAFE`).

---

### 4.2 View 2: Batch CSV Traffic Analyzer (File Upload & Bulk Inspection)
Allows analysts to upload real network capture CSV files (e.g., `test_sample_1000.csv`) and run instant batch inference.

```
+-----------------------------------------------------------------------------------------------+
|  DRAG & DROP CSV NETWORK CAPTURE FILE                                                         |
|  [ Cloud Upload Icon ]                                                                        |
|  Drag and drop 'test_sample_1000.csv' here or Click to Browse                                |
|  Supports CICIDS2017 formatted CSV captures (up to 50,000 rows)                               |
+-----------------------------------------------------------------------------------------------+
|  BATCH ANALYSIS SUMMARY (Processed 1,000 Flows in 0.14 seconds)                              |
|  [ Safe: 872 (87.2%) ]             [ Threats Detected: 128 (12.8%) ]      [ Export CSV ]      |
+-----------------------------------------------------------------------------------------------+
|  PREDICTION TABLE (Filter: [All] [Threats Only] [Benign Only])                                |
|  #   | Dest Port | Flow Duration | Fwd Packets | Total Bwd Len | Confidence | Classification  |
|  001 | 80        | 52,410 us     | 8           | 1,280 bytes   | 98.4%      | [BENIGN (Safe)] |
|  002 | 8080      | 120 us        | 1           | 0 bytes       | 99.8%      | [ATTACK (DDoS)] |
|  ... | ...       | ...           | ...         | ...           | ...        | ...             |
+-----------------------------------------------------------------------------------------------+
```

#### Key Elements:
1. **Interactive Drag-and-Drop Dropzone**:
   - Dashed cyber-blue border (`#3B82F6`) that lights up green on hover/drag-over.
   - Shows file name, file size, and a one-click **"Run AI Batch Inspection"** button.
2. **Batch Result KPI Summary**:
   - Appears immediately upon receiving HTTP 200 from `POST /predict/csv`.
   - Displays total rows, benign count, attack count, and inference throughput (flows/sec).
   - Includes an **"Export Inspection Report (CSV)"** button.
3. **Interactive Filterable Results Table**:
   - Tabs to filter rows by `All`, `Attacks Only (128)`, or `Benign Only (872)`.
   - Shows confidence score progress bars (red for attack, green for benign).

---

### 4.3 View 3: Interactive Flow Simulator (Single-Flow Tester & Demo Center)
The premier tool for college viva and project demonstrations. Enables testing individual network packet flows with preset buttons or custom sliders.

```
+-----------------------------------------------------------------------------------------------+
|  QUICK SCENARIO PRESETS:                                                                      |
|  [ [O] Normal HTTPS Web Browsing ]  [ [!] High-Rate DDoS Flood ]  [ [?] Stealth PortScan ]     |
+-----------------------------------------------------------------------------------------------+
|  NETWORK FEATURE PARAMETER TUNER:                                                             |
|                                                                                               |
|  Destination Port: [ 80 ] (Slider: 0 - 65535)                                                 |
|  Flow Duration:    [ 52,410 ] us                                                              |
|  Total Fwd Packets:[ 8 ] packets                                                              |
|  Total Bwd Packets:[ 5 ] packets                                                              |
|  Flow Packets/s:   [ 248.0 ] pkts/s                                                           |
|  Init Win Bytes:   [ 29,200 ] bytes                                                           |
|                                                                                               |
|  [ Analyze Traffic Flow (POST /predict/single) ]                                              |
+-----------------------------------------------------------------------------------------------+
|  ANALYSIS RESULT CARD:                                                                        |
|  +-----------------------------------------------------------------------------------------+  |
|  |  ( ! ) ATTACK DETECTED - MALICIOUS NETWORK FLOW                                         |  |
|  |  Predicted Class: 1 (Intrusion)    | Confidence: 99.4%    | Latency: 2.8 ms             |  |
|  |  Probability Breakdown: [ Normal: 0.6% ] [ Attack: 99.4% ]                             |  |
|  +-----------------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------------+
```

#### Key Elements:
1. **Scenario Preset Buttons**:
   - **"Load Normal Web Flow"**: Populates fields with typical HTTPS traffic (Port 443, moderate duration, balanced packet lengths).
   - **"Load DDoS Attack Flow"**: Populates fields with high packet count, extreme packet rate, and tiny payload sizes.
   - **"Load PortScan Flow"**: Populates fields with short duration, single forward packet, and zero backward response.
2. **Feature Control Sliders & Number Inputs**:
   - Instant two-way binding between range sliders and numerical inputs for the top 10 most impactful features.
3. **Live Result Banner**:
   - Massive glowing verdict banner:
     - **Safe Traffic**: Green background glow with checkmark icon and `"BENIGN - TRAFFIC AUTHORIZED"`.
     - **Intrusion Traffic**: Red background glow with pulsing alert icon and `"ALERT: MALICIOUS FLOW DETECTED"`.
   - Displays exact confidence percentage and backend roundtrip latency.

---

### 4.4 View 4: Model Performance & Research Lab (Viva Defense View)
Designed to provide faculty examiners with full academic and mathematical transparency into the ML benchmarking process.

```
+-----------------------------------------------------------------------------------------------+
|  ACADEMIC MODEL BENCHMARKING COMPARISON (Test Set: 565,000 Records)                           |
|  Model Name          | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Inference Time|
|  Logistic Regression | 92.4%    | 89.1%     | 84.2%  | 86.5%    | 0.912   | 0.8 ms / flow |
|  Decision Tree       | 98.1%    | 96.5%     | 96.8%  | 96.6%    | 0.976   | 0.4 ms / flow |
|  Random Forest       | 99.3%    | 98.9%     | 98.6%  | 98.7%    | 0.995   | 2.1 ms / flow |
|  XGBoost (Champion)  | 99.6%    | 99.4%     | 99.2%  | 99.3%    | 0.998   | 0.6 ms / flow |
+-----------------------------------------------------------------------------------------------+
| +-----------------------------------------------+ +-----------------------------------------+ |
| | CONFUSION MATRIX (XGBoost)                    | | TOP 10 FEATURE IMPORTANCE (Gini Weight) | |
| |                Predicted 0    Predicted 1     | | Destination Port          [===========] | |
| | Actual 0 (Benign)  452,100        1,120       | | Init_Win_bytes_forward    [=========  ] | |
| | Actual 1 (Attack)      980      110,800       | | Packet Length Std         [========   ] | |
| |                                               | | Bwd Packet Length Mean    [======     ] | |
| +-----------------------------------------------+ +-----------------------------------------+ |
```

#### Key Elements:
1. **Benchmark Comparison Table**:
   - Direct side-by-side comparison of all 4 tested algorithms.
   - Highlights why XGBoost was chosen as the production champion (best F1-score and optimal balance of speed vs. memory).
2. **Interactive Confusion Matrix Heatmap**:
   - Displays True Negatives (TN), False Positives (FP), False Negatives (FN), and True Positives (TP).
   - Highlighting the extremely low False Negative rate (<0.8%), critical for network security.
3. **Feature Importance Horizontal Bar Chart**:
   - Illustrates which statistical features had the greatest predictive weight in the ensemble trees.

---

## 5. UI State Management & Error Handling

1. **Loading States**:
   - While uploading a CSV or analyzing a flow, buttons display a spinning cyber ring and label `"Analyzing packet telemetry..."`.
2. **Error Alerts (Toast Notifications)**:
   - If the FastAPI backend is offline or returns HTTP 500/422, a crimson toast notification slides in from the top-right: `"Backend Unreachable: Ensure uvicorn backend.main:app is running on port 8000"`.
3. **Empty States**:
   - Tables with no data display a clean placeholder with an illustration and instructions: `"No network captures loaded yet. Upload a CSV or run the Simulator to see live detections"`.

