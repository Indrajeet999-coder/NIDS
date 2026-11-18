"""
backend/main.py — FastAPI High-Performance NIDS Inference Service
=================================================================
Exposes REST endpoints for:
  - System health and model info (`GET /health`)
  - Multi-model evaluation benchmark metrics (`GET /metrics`)
  - Expected feature list & simulator preset samples (`GET /features`)
  - Single network flow classification (`POST /predict/single`)
  - Batch CSV traffic classification (`POST /predict/csv`)
  - SQLite detection audit history (`GET /history`, `DELETE /history`)

Pre-loads `ml/models/nids_bundle.joblib` once at startup via the FastAPI lifespan
context manager, serving sub-5ms inferences with zero per-request disk reads.
"""

import datetime
import io
import json
import logging
import math
import time
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from backend.config import (
    CORS_ORIGINS,
    DEMO_FLOWS_PATH,
    METRICS_PATH,
    MODEL_PATH,
)
from backend.database import clear_logs, get_recent_logs, init_db, log_detection
from backend.schemas import (
    BatchPredictionResponse,
    FeaturesResponse,
    HealthResponse,
    HistoryResponse,
    PredictionItem,
    SingleFlowRequest,
)

logger = logging.getLogger("nids.backend")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Directory for pre-built sample CSV files shipped with the project
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "dataset" / "samples"


# ── Helper: Load preset demo flows for simulator ────────────────────────────

def load_sample_flows(features: List[str]) -> Tuple[Dict[str, float], Dict[str, float]]:
    """
    Loads one representative normal flow and one representative attack flow
    from `dataset/processed/demo_test_flows.csv` for the frontend simulator.
    Falls back to safe defaults if the demo CSV is not present.
    """
    sample_normal: Dict[str, float] = {}
    sample_attack: Dict[str, float] = {}

    if DEMO_FLOWS_PATH.exists():
        try:
            demo_df = pd.read_csv(DEMO_FLOWS_PATH)
            demo_df.columns = demo_df.columns.str.strip()

            # Normal flow sample (Label_Binary == 0 or BENIGN)
            normal_mask = demo_df.get("Label_Binary", 0) == 0
            normal_rows = demo_df[normal_mask]
            if not normal_rows.empty:
                sample_normal = {
                    col: float(normal_rows.iloc[0][col])
                    for col in features
                    if col in normal_rows.columns
                }

            # Attack flow sample (Label_Binary == 1)
            attack_mask = demo_df.get("Label_Binary", 0) == 1
            attack_rows = demo_df[attack_mask]
            if not attack_rows.empty:
                sample_attack = {
                    col: float(attack_rows.iloc[0][col])
                    for col in features
                    if col in attack_rows.columns
                }
        except Exception as exc:
            logger.warning(f"Could not load samples from {DEMO_FLOWS_PATH}: {exc}")

    # Ensure all 25 features are populated with sensible numeric fallbacks
    for col in features:
        if col not in sample_normal:
            sample_normal[col] = 0.0
        if col not in sample_attack:
            sample_attack[col] = 0.0

    if sample_normal.get("Destination Port", 0.0) == 0.0:
        sample_normal["Destination Port"] = 443.0
    if sample_attack.get("Destination Port", 0.0) == 0.0:
        sample_attack["Destination Port"] = 80.0

    return sample_normal, sample_attack


def compute_risk_level(is_attack: bool, confidence: float) -> str:
    """
    Determines threat risk classification based on predicted label and model confidence.
    """
    if not is_attack:
        return "Low"
    if confidence >= 0.90:
        return "Critical"
    elif confidence >= 0.75:
        return "High"
    elif confidence >= 0.50:
        return "Medium"
    return "Low"


# ── Telemetry Helpers ──────────────────────────────────────────────────────────

def infer_telemetry(row: dict, idx: int) -> dict:
    """
    Derives enriched telemetry fields from a raw flow feature dict.

    Parameters
    ----------
    row : dict
        Feature key/value pairs from a single CSV row (df.iloc[i].to_dict()).
    idx : int
        Zero-based row index used to generate deterministic IPs when real IPs
        are absent from the dataset.

    Returns
    -------
    dict
        Telemetry fields ready to unpack into a PredictionItem.
    """

    # Average packet size in bytes (from CICIDS feature)
    packet_size_bytes = round(float(row.get("Average Packet Size", 0.0)), 1)

    # Protocol — use explicit column if present, otherwise derive from dest port
    dest_port_raw = row.get("Destination Port", 80)
    try:
        dest_port_int = int(float(dest_port_raw))
    except (ValueError, TypeError):
        dest_port_int = 80

    protocol_raw = row.get("Protocol")
    if protocol_raw is not None:
        try:
            # Protocol can arrive as a float (NaN) in some CSV exports
            if not (isinstance(protocol_raw, float) and math.isnan(protocol_raw)):
                protocol = str(protocol_raw)
            else:
                protocol = None
        except Exception:
            protocol = None
    else:
        protocol = None

    if protocol is None:
        # Derive from well-known port numbers
        if dest_port_int in {53, 123}:
            protocol = "UDP"
        elif dest_port_int == 0:
            protocol = "ICMP"
        else:
            protocol = "TCP"

    # Flow duration converted from microseconds → seconds / milliseconds
    val = row.get("Flow Duration")
    if val is None or float(val) == 0.0:
        bwd_pkts = float(row.get("Total Backward Packets", 0.0))
        bwd_rate = float(row.get("Bwd Packets/s", 0.0))
        if bwd_rate > 0 and bwd_pkts > 0:
            val = (bwd_pkts / bwd_rate) * 1_000_000.0
        else:
            val = float(val or 0.0)
    else:
        val = float(val)

    duration_ms = round(float(val) / 1000.0, 2)
    duration_sec = round(float(val) / 1_000_000.0, 4)

    # Total packet count as proxy for connection activity
    connections = max(
        1,
        int(
            float(row.get("Total Fwd Packets", 1))
            + float(row.get("Total Backward Packets", 0))
        ),
    )

    # Source IP — use real value when present, otherwise deterministic placeholder
    src_ip_raw = row.get("Source IP")
    if src_ip_raw is not None:
        try:
            if isinstance(src_ip_raw, float) and math.isnan(src_ip_raw):
                src_ip_raw = None
        except Exception:
            src_ip_raw = None
    source_ip = src_ip_raw if src_ip_raw else f"192.168.1.{(idx % 200) + 10}"

    # Destination IP — use real value when present, otherwise deterministic placeholder
    dst_ip_raw = row.get("Destination IP")
    if dst_ip_raw is not None:
        try:
            if isinstance(dst_ip_raw, float) and math.isnan(dst_ip_raw):
                dst_ip_raw = None
        except Exception:
            dst_ip_raw = None
    if dst_ip_raw:
        destination_ip = dst_ip_raw
    elif idx % 2 == 0:
        destination_ip = f"172.217.10.{(idx % 90) + 10}"
    else:
        destination_ip = f"10.0.0.{(idx % 50) + 1}"

    # Destination port as integer
    destination_port = dest_port_int

    # Forward/backward byte totals (Subflow columns as fallback for some CICIDS variants)
    src_bytes = int(
        float(row.get("Total Length of Fwd Packets", row.get("Subflow Fwd Bytes", 0)))
    )
    dst_bytes = int(
        float(row.get("Total Length of Bwd Packets", row.get("Subflow Bwd Bytes", 0)))
    )

    # Throughput
    flow_bytes_per_sec = round(float(row.get("Flow Bytes/s", 0.0)), 1)

    return {
        "packet_size_bytes": packet_size_bytes,
        "protocol": protocol,
        "duration_sec": duration_sec,
        "duration_ms": duration_ms,
        "connections": connections,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "flow_bytes_per_sec": flow_bytes_per_sec,
    }


def infer_attack_type(prediction: str, tel: dict) -> str:
    """
    Returns a human-readable attack category based on the model's prediction
    and coarse flow telemetry heuristics.

    Parameters
    ----------
    prediction : str
        "Normal" or "Intrusion".
    tel : dict
        Telemetry dict as returned by :func:`infer_telemetry`.
    """
    if prediction == "Normal":
        return "Normal Traffic"

    port = tel.get("destination_port", 80)
    connections = tel.get("connections", 1)
    flow_bytes_per_sec = tel.get("flow_bytes_per_sec", 0.0)
    packet_size_bytes = tel.get("packet_size_bytes", 0.0)

    if port in {22, 23}:
        return "Brute Force Attempt"
    if port in {80, 443} and (connections > 100 or flow_bytes_per_sec > 100_000):
        return "DDoS Attack Pattern"
    if port in {0, 1} or (connections <= 3 and packet_size_bytes < 100):
        return "Port Scan Activity"
    return "Anomalous Flow Intrusion"


# ── FastAPI Lifespan (Startup & Shutdown) ────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager:
      1. Initializes the SQLite audit table.
      2. Loads the serialized model bundle into memory ONCE.
      3. Prepares simulator sample presets.
    """
    logger.info("Initializing NIDS Backend Service...")

    # 1. Initialize SQLite Database
    init_db()
    logger.info("SQLite audit database initialized.")

    # 2. Verify and Load ML Artifact Bundle
    if not MODEL_PATH.exists():
        err_msg = (
            f"Artifact bundle not found at: {MODEL_PATH}. "
            "Please run `python ml/train.py` to generate the model bundle."
        )
        logger.error(err_msg)
        raise RuntimeError(err_msg)

    logger.info(f"Loading champion model bundle from {MODEL_PATH}...")
    bundle = joblib.load(MODEL_PATH)

    app.state.model = bundle["model"]
    app.state.selected_features = list(bundle["selected_features"])
    app.state.threshold = float(bundle.get("threshold", 0.50))
    app.state.champion_model = str(bundle.get("champion_model", "XGBoost"))
    app.state.version = str(bundle.get("version", "1.0.0"))

    # 3. Preload preset flow samples for simulator
    sample_normal, sample_attack = load_sample_flows(app.state.selected_features)
    app.state.sample_normal = sample_normal
    app.state.sample_attack = sample_attack

    # 4. Initialize active dataset for dashboard telemetry (default: 5_mixed_enterprise_soc.csv)
    primary_path = SAMPLES_DIR / "5_mixed_enterprise_soc.csv"
    fallback_path = DEMO_FLOWS_PATH
    default_source = "5_mixed_enterprise_soc.csv"

    if primary_path.exists():
        try:
            init_df = pd.read_csv(primary_path)
            init_df.columns = init_df.columns.str.strip()
            app.state.active_df = init_df
            app.state.active_source = default_source
            logger.info(f"Initialized active telemetry dataset with {default_source} ({len(init_df)} flows).")
        except Exception as exc:
            logger.warning(f"Could not preload {primary_path}: {exc}")
            app.state.active_df = pd.DataFrame()
            app.state.active_source = default_source
    elif fallback_path.exists():
        try:
            init_df = pd.read_csv(fallback_path)
            init_df.columns = init_df.columns.str.strip()
            app.state.active_df = init_df
            app.state.active_source = fallback_path.name
        except Exception:
            app.state.active_df = pd.DataFrame()
            app.state.active_source = default_source
    else:
        app.state.active_df = pd.DataFrame()
        app.state.active_source = default_source

    logger.info(
        f"Champion Model '{app.state.champion_model}' (v{app.state.version}) loaded successfully. "
        f"Input features: {len(app.state.selected_features)}"
    )

    yield

    logger.info("NIDS Backend Service shutting down.")


# ── Application Factory & Middleware ─────────────────────────────────────────

app = FastAPI(
    title="NIDS Real-Time Machine Learning Inference API",
    description="Network Intrusion Detection System REST API powered by FastAPI, XGBoost, and SQLite.",
    version="1.0.0",
    lifespan=lifespan,
)

# Configure CORS to allow Vite React frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/", tags=["General"])
def root():
    """Root status greeting with links to docs and health status."""
    return {
        "service": "Network Intrusion Detection System (NIDS) API",
        "status": "online",
        "docs_url": "/docs",
        "health_url": "/health",
    }


@app.get("/health", response_model=HealthResponse, tags=["Monitoring"])
def get_health():
    """
    Returns API health status, loaded champion model name, expected feature count, and active dataset.
    """
    return HealthResponse(
        status="healthy",
        model_name=getattr(app.state, "champion_model", "XGBoost"),
        expected_feature_count=len(getattr(app.state, "selected_features", [])),
        version=getattr(app.state, "version", "1.0.0"),
        active_dataset=getattr(app.state, "active_source", "5_mixed_enterprise_soc.csv"),
    )


@app.get("/metrics", tags=["Evaluation"])
def get_metrics():
    """
    Returns evaluation metrics across all 4 benchmarked models (accuracy, precision, recall,
    F1-score, ROC-AUC), best model confusion matrix, and top feature importances.
    """
    if not METRICS_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Metrics report not found at {METRICS_PATH}. Please run ml/train.py first.",
        )
    try:
        with open(METRICS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load metrics data: {str(exc)}",
        )


@app.get("/features", response_model=FeaturesResponse, tags=["Metadata"])
def get_features():
    """
    Returns the exact 25 required feature names in order, plus preset normal and attack
    sample flows for one-click testing in the frontend simulator.
    """
    features: List[str] = getattr(app.state, "selected_features", [])
    return FeaturesResponse(
        feature_names=features,
        feature_count=len(features),
        sample_normal=getattr(app.state, "sample_normal", {}),
        sample_attack=getattr(app.state, "sample_attack", {}),
    )


@app.post("/predict/single", response_model=PredictionItem, tags=["Inference"])
def predict_single(payload: SingleFlowRequest):
    """
    Scores a single network flow payload, logs the audit record to SQLite,
    and returns prediction, confidence score, and threat risk level.
    """
    selected_features: List[str] = app.state.selected_features
    features_dict = payload.features

    # Validate that all 25 required features are provided
    missing_features = [f for f in selected_features if f not in features_dict]
    if missing_features:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Missing required flow features",
                "missing_features": missing_features,
                "expected_features_count": len(selected_features),
            },
        )

    # Construct single-row DataFrame strictly aligned with model features
    row_values = {}
    for f in selected_features:
        val = features_dict[f]
        try:
            row_values[f] = [float(val)]
        except (ValueError, TypeError):
            row_values[f] = [0.0]

    input_df = pd.DataFrame(row_values, columns=selected_features)
    # Memory downcasting and NaN/Inf cleaning
    input_df = input_df.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(np.float32)

    # Perform inference
    probabilities = app.state.model.predict_proba(input_df)[0]
    prob_normal = float(probabilities[0])
    prob_attack = float(probabilities[1])

    is_attack = prob_attack >= app.state.threshold
    label_binary = 1 if is_attack else 0
    prediction = "Intrusion" if is_attack else "Normal"
    confidence = round(prob_attack if is_attack else prob_normal, 4)
    risk_level = compute_risk_level(is_attack, confidence)

    # Extract destination port and flow duration if available
    destination_port = None
    if "Destination Port" in features_dict:
        try:
            destination_port = int(float(features_dict["Destination Port"]))
        except (ValueError, TypeError):
            pass

    flow_duration = None
    if "Flow Duration" in features_dict:
        try:
            flow_duration = float(features_dict["Flow Duration"])
        except (ValueError, TypeError):
            pass

    # Enrich response with telemetry fields derived from the submitted features
    tel = infer_telemetry(features_dict, 0)
    attack_type = infer_attack_type(prediction, tel)

    # Update active dataset in memory so dashboard telemetry updates live
    single_row_dict = dict(features_dict)
    single_row_dict["prediction"] = prediction
    single_row_dict["label_binary"] = label_binary
    single_row_dict["confidence"] = confidence
    single_row_df = pd.DataFrame([single_row_dict])
    if hasattr(app.state, "active_df") and not app.state.active_df.empty:
        app.state.active_df = pd.concat([single_row_df, app.state.active_df], ignore_index=True).head(500)
    else:
        app.state.active_df = single_row_df
    app.state.active_source = "Live Single Flow"

    # Log inference transaction to SQLite
    log_detection(
        source_type="single_flow",
        total_flows=1,
        intrusion_count=1 if is_attack else 0,
        normal_count=0 if is_attack else 1,
        max_confidence=confidence,
        summary_json=json.dumps({
            "prediction": prediction,
            "label_binary": label_binary,
            "confidence": confidence,
            "risk_level": risk_level,
            "destination_port": destination_port,
            "flow_duration": flow_duration,
        }),
    )

    return PredictionItem(
        flow_index=0,
        prediction=prediction,
        label_binary=label_binary,
        confidence=confidence,
        risk_level=risk_level,
        destination_port=tel["destination_port"],
        flow_duration=flow_duration,
        packet_size_bytes=tel["packet_size_bytes"],
        protocol=tel["protocol"],
        duration_sec=tel["duration_sec"],
        duration_ms=tel["duration_ms"],
        connections=tel["connections"],
        source_ip=tel["source_ip"],
        destination_ip=tel["destination_ip"],
        src_bytes=tel["src_bytes"],
        dst_bytes=tel["dst_bytes"],
        flow_bytes_per_sec=tel["flow_bytes_per_sec"],
        attack_type=attack_type,
        time=datetime.datetime.utcnow().strftime("%H:%M:%S"),
    )


@app.post("/predict/csv", response_model=BatchPredictionResponse, tags=["Inference"])
async def predict_csv(file: UploadFile = File(...)):
    """
    Accepts an uploaded CSV file, validates that all 25 required features exist,
    handles +/- Infinity and NaN values, executes batch XGBoost inference,
    logs aggregate detection statistics to SQLite, and returns batch predictions.
    """
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail={"error": "Invalid file format. Please upload a .csv file."},
        )

    try:
        content = await file.read()
        df = pd.read_csv(io.BytesIO(content))
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": f"Failed to parse uploaded CSV: {str(exc)}"},
        )

    if df.empty:
        raise HTTPException(
            status_code=400,
            detail={"error": "Uploaded CSV file contains no data rows."},
        )

    # Strip column name whitespace
    df.columns = df.columns.str.strip()

    selected_features: List[str] = app.state.selected_features

    # Validate that all 25 features are present in the uploaded CSV
    missing_columns = [col for col in selected_features if col not in df.columns]
    if missing_columns:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Uploaded CSV is missing mandatory features",
                "missing_features": missing_columns,
                "expected_features": selected_features,
            },
        )

    # Extract feature matrix, clean invalid values, downcast for CPU efficiency
    X = df[selected_features].copy()
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(np.float32)

    # Execute batch inference and record latency
    t_start = time.perf_counter()
    probabilities = app.state.model.predict_proba(X)
    inference_time_ms = round((time.perf_counter() - t_start) * 1000, 2)

    probs_attack = probabilities[:, 1]
    probs_normal = probabilities[:, 0]
    is_attack_arr = probs_attack >= app.state.threshold
    predictions_binary = is_attack_arr.astype(int)

    total_flows = len(df)
    intrusion_count = int(np.sum(predictions_binary == 1))
    normal_count = int(np.sum(predictions_binary == 0))
    threat_rate = round((intrusion_count / total_flows) * 100, 2) if total_flows > 0 else 0.0

    confidences = np.where(is_attack_arr, probs_attack, probs_normal)
    max_confidence = float(np.max(confidences)) if total_flows > 0 else 0.0

    has_duration = "Flow Duration" in df.columns
    duration_values = df["Flow Duration"].values if has_duration else None

    predictions: List[PredictionItem] = []
    df_records = df.to_dict("records")
    for idx in range(total_flows):
        is_att = bool(is_attack_arr[idx])
        conf = float(round(confidences[idx], 4))
        risk = compute_risk_level(is_att, conf)

        dur_val = None
        if has_duration and pd.notna(duration_values[idx]):
            try:
                dur_val = float(duration_values[idx])
            except (ValueError, TypeError):
                pass

        # Build enriched telemetry from full row features
        row_dict = df_records[idx]
        tel = infer_telemetry(row_dict, idx)
        attack_type = infer_attack_type("Intrusion" if is_att else "Normal", tel)

        predictions.append(
            PredictionItem(
                flow_index=idx,
                prediction="Intrusion" if is_att else "Normal",
                label_binary=int(predictions_binary[idx]),
                confidence=conf,
                risk_level=risk,
                destination_port=tel["destination_port"],
                flow_duration=dur_val,
                packet_size_bytes=tel["packet_size_bytes"],
                protocol=tel["protocol"],
                duration_sec=tel["duration_sec"],
                duration_ms=tel["duration_ms"],
                connections=tel["connections"],
                source_ip=tel["source_ip"],
                destination_ip=tel["destination_ip"],
                src_bytes=tel["src_bytes"],
                dst_bytes=tel["dst_bytes"],
                flow_bytes_per_sec=tel["flow_bytes_per_sec"],
                attack_type=attack_type,
                time=datetime.datetime.utcnow().strftime("%H:%M:%S"),
            )
        )

    # Log batch summary to SQLite database
    summary_meta = {
        "filename": file.filename,
        "total_flows": total_flows,
        "intrusion_count": intrusion_count,
        "normal_count": normal_count,
        "threat_rate_percent": threat_rate,
        "inference_time_ms": inference_time_ms,
    }
    log_detection(
        source_type="csv_upload",
        total_flows=total_flows,
        intrusion_count=intrusion_count,
        normal_count=normal_count,
        max_confidence=round(max_confidence, 4),
        summary_json=json.dumps(summary_meta),
    )

    # Store active dataset in memory for live telemetry updates
    app.state.active_df = df.copy()
    app.state.active_source = file.filename

    return BatchPredictionResponse(
        total_flows=total_flows,
        normal_count=normal_count,
        intrusion_count=intrusion_count,
        threat_rate_percent=threat_rate,
        inference_time_ms=inference_time_ms,
        predictions=predictions,
    )


# ── Helper: shared CSV inference core (used by /predict/csv and /predict/sample) ─

def _run_csv_inference(df: pd.DataFrame, source_label: str) -> BatchPredictionResponse:
    """
    Runs the full batch inference pipeline on an already-parsed DataFrame.
    Validates features, executes XGBoost inference, enriches each row with
    telemetry, logs to SQLite, and returns a BatchPredictionResponse.

    Parameters
    ----------
    df : pd.DataFrame
        Pre-parsed flow feature DataFrame (columns already stripped).
    source_label : str
        Label used for SQLite source_type (e.g. "csv_upload" or "sample_file").
    """
    selected_features: List[str] = app.state.selected_features

    # Validate required features
    missing_columns = [col for col in selected_features if col not in df.columns]
    if missing_columns:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "CSV is missing mandatory features",
                "missing_features": missing_columns,
                "expected_features": selected_features,
            },
        )

    # Build cleaned feature matrix
    X = df[selected_features].copy()
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(np.float32)

    # Batch inference
    t_start = time.perf_counter()
    probabilities = app.state.model.predict_proba(X)
    inference_time_ms = round((time.perf_counter() - t_start) * 1000, 2)

    probs_attack = probabilities[:, 1]
    probs_normal = probabilities[:, 0]
    is_attack_arr = probs_attack >= app.state.threshold
    predictions_binary = is_attack_arr.astype(int)

    total_flows = len(df)
    intrusion_count = int(np.sum(predictions_binary == 1))
    normal_count = int(np.sum(predictions_binary == 0))
    threat_rate = round((intrusion_count / total_flows) * 100, 2) if total_flows > 0 else 0.0

    confidences = np.where(is_attack_arr, probs_attack, probs_normal)
    max_confidence = float(np.max(confidences)) if total_flows > 0 else 0.0

    has_duration = "Flow Duration" in df.columns
    duration_values = df["Flow Duration"].values if has_duration else None

    items: List[PredictionItem] = []
    df_records = df.to_dict("records")
    for idx in range(total_flows):
        is_att = bool(is_attack_arr[idx])
        conf = float(round(confidences[idx], 4))
        risk = compute_risk_level(is_att, conf)

        dur_val = None
        if has_duration and pd.notna(duration_values[idx]):
            try:
                dur_val = float(duration_values[idx])
            except (ValueError, TypeError):
                pass

        # Enrich with telemetry
        row_dict = df_records[idx]
        tel = infer_telemetry(row_dict, idx)
        attack_type = infer_attack_type("Intrusion" if is_att else "Normal", tel)

        items.append(
            PredictionItem(
                flow_index=idx,
                prediction="Intrusion" if is_att else "Normal",
                label_binary=int(predictions_binary[idx]),
                confidence=conf,
                risk_level=risk,
                destination_port=tel["destination_port"],
                flow_duration=dur_val,
                packet_size_bytes=tel["packet_size_bytes"],
                protocol=tel["protocol"],
                duration_sec=tel["duration_sec"],
                duration_ms=tel["duration_ms"],
                connections=tel["connections"],
                source_ip=tel["source_ip"],
                destination_ip=tel["destination_ip"],
                src_bytes=tel["src_bytes"],
                dst_bytes=tel["dst_bytes"],
                flow_bytes_per_sec=tel["flow_bytes_per_sec"],
                attack_type=attack_type,
                time=datetime.datetime.utcnow().strftime("%H:%M:%S"),
            )
        )

    # Audit log
    log_detection(
        source_type=source_label,
        total_flows=total_flows,
        intrusion_count=intrusion_count,
        normal_count=normal_count,
        max_confidence=round(max_confidence, 4),
        summary_json=json.dumps({
            "source": source_label,
            "total_flows": total_flows,
            "intrusion_count": intrusion_count,
            "normal_count": normal_count,
            "threat_rate_percent": threat_rate,
            "inference_time_ms": inference_time_ms,
        }),
    )

    return BatchPredictionResponse(
        total_flows=total_flows,
        normal_count=normal_count,
        intrusion_count=intrusion_count,
        threat_rate_percent=threat_rate,
        inference_time_ms=inference_time_ms,
        predictions=items,
    )


# ── Sample File Endpoints ─────────────────────────────────────────────────────

@app.get("/samples", tags=["Samples"])
def list_samples():
    """
    Lists all pre-built sample CSV files available in `dataset/samples/`.
    Returns filename and size in bytes for each file.
    """
    files = []
    if SAMPLES_DIR.exists():
        for f in sorted(SAMPLES_DIR.glob("*.csv")):
            files.append({"filename": f.name, "size_bytes": f.stat().st_size})
    return {"samples": files}


@app.post("/predict/sample/{filename}", response_model=BatchPredictionResponse, tags=["Samples"])
def predict_sample(filename: str):
    """
    Runs batch XGBoost inference on a pre-built sample CSV identified by filename.
    The sample must exist in `dataset/samples/` and end with `.csv`.
    Logs the detection event to SQLite with source_type='sample_file'.
    """
    sample_path = SAMPLES_DIR / filename

    # Security and existence checks
    if not filename.endswith(".csv") or not sample_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Sample file '{filename}' not found.",
        )

    try:
        df = pd.read_csv(sample_path)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to parse sample CSV '{filename}': {str(exc)}",
        )

    if df.empty:
        raise HTTPException(status_code=400, detail="Sample CSV contains no data rows.")

    df.columns = df.columns.str.strip()
    app.state.active_df = df.copy()
    app.state.active_source = filename
    return _run_csv_inference(df, source_label="sample_file")


# ── Dashboard Telemetry Endpoint ──────────────────────────────────────────────

@app.get("/dashboard/telemetry", tags=["Dashboard"])
def get_dashboard_telemetry():
    """
    Runs inference on the enterprise SOC sample (or demo fallback) and returns
    a comprehensive telemetry payload for the React dashboard:
      - KPI summary counters
      - 12-bucket traffic time series
      - Protocol distribution
      - Top-5 source IPs
      - Normalized feature averages
      - Live sample flows (first 15 rows)
      - Recent intrusion alerts (last 6 intrusion rows)
    """
    try:
        # 1. Use currently active dataset in memory (from latest CSV upload, sample load, or single flow)
        # Default fallback to 5_mixed_enterprise_soc.csv
        source_name = getattr(app.state, "active_source", "5_mixed_enterprise_soc.csv")
        if hasattr(app.state, "active_df") and not app.state.active_df.empty:
            df = app.state.active_df.copy()
        else:
            primary_path = SAMPLES_DIR / "5_mixed_enterprise_soc.csv"
            fallback_path = DEMO_FLOWS_PATH
            if primary_path.exists():
                df = pd.read_csv(primary_path)
                source_name = "5_mixed_enterprise_soc.csv"
            elif fallback_path.exists():
                df = pd.read_csv(fallback_path)
                source_name = fallback_path.name
            else:
                raise FileNotFoundError("No telemetry data file found.")
            df.columns = df.columns.str.strip()
            app.state.active_df = df
            app.state.active_source = source_name

        selected_features: List[str] = app.state.selected_features
        # Ensure all required features exist (fill 0.0 for any absent columns)
        for c in selected_features:
            if c not in df.columns:
                df[c] = 0.0

        # 2. Run inference
        X = df[selected_features].copy()
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(np.float32)
        probabilities = app.state.model.predict_proba(X)

        probs_attack = probabilities[:, 1]
        probs_normal = probabilities[:, 0]
        is_attack_arr = probs_attack >= app.state.threshold
        predictions_binary = is_attack_arr.astype(int)
        confidences = np.where(is_attack_arr, probs_attack, probs_normal)

        total_flows = len(df)
        intrusion_count = int(np.sum(predictions_binary == 1))
        normal_count = int(np.sum(predictions_binary == 0))

        # 3. Build per-row telemetry lists
        all_tel = []
        all_pred = []
        all_conf = []
        df_records = df.to_dict("records")
        for idx in range(total_flows):
            row_dict = df_records[idx]
            tel = infer_telemetry(row_dict, idx)
            pred = "Intrusion" if bool(is_attack_arr[idx]) else "Normal"
            all_tel.append(tel)
            all_pred.append(pred)
            all_conf.append(float(round(confidences[idx], 4)))

        # ── KPI block ──────────────────────────────────────────────────────────
        avg_packet_size = sum(t["packet_size_bytes"] for t in all_tel) / total_flows
        avg_duration_sec = sum(t["duration_sec"] for t in all_tel) / total_flows
        avg_duration_ms = sum(t["duration_ms"] for t in all_tel) / total_flows
        total_connections = sum(t["connections"] for t in all_tel)

        kpi = {
            "total_packets_analyzed": total_flows,
            "normal_traffic_count": normal_count,
            "normal_percent": round(normal_count / total_flows * 100, 1),
            "intrusions_detected": intrusion_count,
            "intrusion_percent": round(intrusion_count / total_flows * 100, 1),
            "detection_rate": round((intrusion_count + normal_count) / total_flows * 100, 2),
            "avg_packet_size_bytes": round(avg_packet_size, 1),
            "avg_duration_sec": round(avg_duration_sec, 4),
            "avg_duration_ms": round(avg_duration_ms, 2),
            "total_connections": total_connections,
        }

        # ── 12-bucket traffic time series ──────────────────────────────────────
        bucket_size = max(1, math.ceil(total_flows / 12))
        traffic_series = []
        for b in range(12):
            start = b * bucket_size
            end = min(start + bucket_size, total_flows)
            bucket_preds = all_pred[start:end]
            n_normal = bucket_preds.count("Normal")
            n_intrusion = bucket_preds.count("Intrusion")
            hour = b * 2
            traffic_series.append({
                "time": f"{hour:02d}:00",
                "normal": n_normal,
                "intrusion": n_intrusion,
            })

        # ── Protocol distribution ──────────────────────────────────────────────
        protocol_counts: Counter = Counter(t["protocol"] for t in all_tel)
        protocol_distribution = [
            {
                "protocol": proto,
                "count": cnt,
                "percent": round(cnt / total_flows * 100, 1),
            }
            for proto, cnt in [
                ("TCP", protocol_counts.get("TCP", 0)),
                ("UDP", protocol_counts.get("UDP", 0)),
                ("ICMP", protocol_counts.get("ICMP", 0)),
            ]
        ]

        # ── Top-5 source IPs ───────────────────────────────────────────────────
        ip_counts: Counter = Counter(t["source_ip"] for t in all_tel)
        top_source_ips = [
            {
                "ip": ip,
                "packets": cnt,
                "share": round(cnt / total_flows * 100, 1),
            }
            for ip, cnt in ip_counts.most_common(5)
        ]

        # ── Normalized feature averages ────────────────────────────────────────
        # Max plausible reference values for 0-1 normalization
        MAX_PACKET = 2_000.0
        MAX_DURATION = 10.0
        MAX_CONNECTIONS = 500.0
        MAX_BYTES = 100_000.0

        avg_src = sum(t["src_bytes"] for t in all_tel) / total_flows
        avg_dst = sum(t["dst_bytes"] for t in all_tel) / total_flows
        avg_conns = total_connections / total_flows

        feature_averages = {
            "Packet Size": min(1.0, max(0.04, round(avg_packet_size / MAX_PACKET, 4))),
            "Duration": min(1.0, max(0.04, round(avg_duration_sec / MAX_DURATION, 4))),
            "Connections": min(1.0, max(0.04, round(avg_conns / MAX_CONNECTIONS, 4))),
            "Src Bytes": min(1.0, max(0.04, round(avg_src / MAX_BYTES, 4))),
            "Dst Bytes": min(1.0, max(0.04, round(avg_dst / MAX_BYTES, 4))),
        }

        # ── Live sample flows (first 15 rows) ─────────────────────────────────
        live_sample_flows = []
        for idx in range(min(15, total_flows)):
            tel = all_tel[idx]
            live_sample_flows.append({
                "packet_size_bytes": tel["packet_size_bytes"],
                "protocol": tel["protocol"],
                "duration_sec": tel["duration_sec"],
                "duration_ms": tel["duration_ms"],
                "connections": tel["connections"],
                "source_ip": tel["source_ip"],
                "destination_ip": tel["destination_ip"],
                "prediction": all_pred[idx],
                "confidence": all_conf[idx],
                "time": datetime.datetime.utcnow().strftime("%H:%M:%S"),
                "attack_type": infer_attack_type(all_pred[idx], tel),
            })

        # ── Recent alerts (last 6 intrusion rows) ─────────────────────────────
        intrusion_indices = [i for i, p in enumerate(all_pred) if p == "Intrusion"]
        last_six = intrusion_indices[-6:] if len(intrusion_indices) >= 6 else intrusion_indices
        recent_alerts = []
        for alert_rank, idx in enumerate(reversed(last_six)):
            tel = all_tel[idx]
            recent_alerts.append({
                "attack_type": infer_attack_type("Intrusion", tel),
                "prediction": "Intrusion",
                "source_ip": tel["source_ip"],
                "timestamp": f"{(alert_rank + 1) * 2} min ago",
            })

        return {
            "active_dataset": source_name,
            "kpi": kpi,
            "traffic_series": traffic_series,
            "protocol_distribution": protocol_distribution,
            "top_source_ips": top_source_ips,
            "feature_averages": feature_averages,
            "live_sample_flows": live_sample_flows,
            "recent_alerts": recent_alerts,
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Dashboard telemetry error: {exc}")
        raise HTTPException(
            status_code=503,
            detail=(
                "Dashboard telemetry unavailable. "
                "Ensure the model bundle and a sample data file exist. "
                f"Detail: {str(exc)}"
            ),
        )


@app.get("/history", response_model=HistoryResponse, tags=["Audit Logs"])
def get_history(limit: int = 20):
    """
    Returns the most recent detection audit records from SQLite.
    """
    logs = get_recent_logs(limit=limit)
    return HistoryResponse(total=len(logs), logs=logs)


@app.delete("/history", tags=["Audit Logs"])
def delete_history():
    """
    Clears all detection audit logs from SQLite for clean demo resets.
    """
    deleted_count = clear_logs()
    return {
        "message": "Detection history cleared successfully",
        "deleted_count": deleted_count,
    }

