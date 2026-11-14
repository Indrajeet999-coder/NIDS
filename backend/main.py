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

import io
import json
import logging
import time
from contextlib import asynccontextmanager
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
    Returns API health status, loaded champion model name, and expected feature count.
    """
    return HealthResponse(
        status="healthy",
        model_name=getattr(app.state, "champion_model", "XGBoost"),
        expected_feature_count=len(getattr(app.state, "selected_features", [])),
        version=getattr(app.state, "version", "1.0.0"),
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
        destination_port=destination_port,
        flow_duration=flow_duration,
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

    has_port = "Destination Port" in df.columns
    has_duration = "Flow Duration" in df.columns
    port_values = df["Destination Port"].values if has_port else None
    duration_values = df["Flow Duration"].values if has_duration else None

    predictions: List[PredictionItem] = []
    for idx in range(total_flows):
        is_att = bool(is_attack_arr[idx])
        conf = float(round(confidences[idx], 4))
        risk = compute_risk_level(is_att, conf)

        port_val = None
        if has_port and pd.notna(port_values[idx]):
            try:
                port_val = int(float(port_values[idx]))
            except (ValueError, TypeError):
                pass

        dur_val = None
        if has_duration and pd.notna(duration_values[idx]):
            try:
                dur_val = float(duration_values[idx])
            except (ValueError, TypeError):
                pass

        predictions.append(
            PredictionItem(
                flow_index=idx,
                prediction="Intrusion" if is_att else "Normal",
                label_binary=int(predictions_binary[idx]),
                confidence=conf,
                risk_level=risk,
                destination_port=port_val,
                flow_duration=dur_val,
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

    return BatchPredictionResponse(
        total_flows=total_flows,
        normal_count=normal_count,
        intrusion_count=intrusion_count,
        threat_rate_percent=threat_rate,
        inference_time_ms=inference_time_ms,
        predictions=predictions,
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

