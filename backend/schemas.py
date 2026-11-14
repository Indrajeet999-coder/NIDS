"""
backend/schemas.py — Pydantic v2 Data Validation Schemas
========================================================
Defines input request and output response models for:
  - Single flow inference
  - Batch CSV inference
  - Health & metrics reporting
  - SQLite detection audit history
"""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, model_validator


# ── Single Flow Inference Schemas ───────────────────────────────────────────

class SingleFlowRequest(BaseModel):
    """
    Accepts 25 network flow features either wrapped in a `features` dictionary
    or directly passed as top-level key-value pairs in the JSON body.
    """
    features: Dict[str, Any] = Field(
        ...,
        description="Dictionary mapping flow feature names to their numeric values"
    )

    @model_validator(mode="before")
    @classmethod
    def allow_flexible_payload(cls, data: Any) -> Any:
        """
        Supports both `{"features": {"Destination Port": 80, ...}}`
        and direct flow dictionaries `{"Destination Port": 80, ...}`.
        """
        if isinstance(data, dict):
            if "features" in data and isinstance(data["features"], dict):
                return data
            # Wrap raw top-level dictionary into the expected "features" key
            return {"features": data}
        return data


class PredictionItem(BaseModel):
    """
    Standardized inference verdict for an individual network flow.
    """
    flow_index: int = Field(
        default=0,
        description="Zero-based sequence index of the flow in batch or request"
    )
    prediction: str = Field(
        ...,
        description="Human-readable classification: 'Normal' or 'Intrusion'"
    )
    label_binary: int = Field(
        ...,
        description="Binary label: 0 for Normal traffic, 1 for Intrusion / Attack"
    )
    confidence: float = Field(
        ...,
        description="Confidence probability for the assigned prediction (0.0 to 1.0)"
    )
    risk_level: str = Field(
        ...,
        description="Threat severity assessment: 'Low', 'Medium', 'High', or 'Critical'"
    )
    destination_port: Optional[Union[int, float]] = Field(
        default=None,
        description="Target destination port if present in flow features"
    )
    flow_duration: Optional[Union[int, float]] = Field(
        default=None,
        description="Flow duration in microseconds if present in flow features"
    )


# ── Batch Prediction Response Schema ─────────────────────────────────────────

class BatchPredictionResponse(BaseModel):
    """
    Aggregated response returned when evaluating multi-row CSV files.
    """
    total_flows: int = Field(..., description="Total number of network flows evaluated")
    normal_count: int = Field(..., description="Count of benign / normal network flows")
    intrusion_count: int = Field(..., description="Count of malicious / attack flows")
    threat_rate_percent: float = Field(..., description="Percentage of traffic flagged as intrusions")
    inference_time_ms: float = Field(..., description="Total ML inference execution time in milliseconds")
    predictions: List[PredictionItem] = Field(..., description="List of per-flow classification results")


# ── System Health & Features Schemas ─────────────────────────────────────────

class HealthResponse(BaseModel):
    """
    System status and model metadata.
    """
    status: str = Field(default="healthy", description="API operational status")
    model_name: str = Field(..., description="Name of the active champion ML classifier")
    expected_feature_count: int = Field(..., description="Number of expected flow input features")
    version: Optional[str] = Field(default="1.0.0", description="Artifact bundle version")


class FeaturesResponse(BaseModel):
    """
    Required feature names and preset simulator flow samples.
    """
    feature_names: List[str] = Field(..., description="Exact 25 required feature names in correct order")
    feature_count: int = Field(..., description="Total feature count (25)")
    sample_normal: Dict[str, float] = Field(..., description="Preset sample values for benign flow")
    sample_attack: Dict[str, float] = Field(..., description="Preset sample values for attack flow")


# ── SQLite Audit History Schemas ─────────────────────────────────────────────

class DetectionLogItem(BaseModel):
    """
    Record of a logged inference event in SQLite.
    """
    id: int = Field(..., description="Unique database audit sequence ID")
    timestamp: str = Field(..., description="UTC ISO-8601 timestamp of inference")
    source_type: str = Field(..., description="'single_flow' or 'csv_upload'")
    total_flows: int = Field(..., description="Flows evaluated in this request")
    intrusion_count: int = Field(..., description="Number of intrusions detected")
    normal_count: int = Field(..., description="Number of normal flows detected")
    max_confidence: float = Field(..., description="Highest confidence observed in the batch")
    summary_json: Optional[str] = Field(default=None, description="JSON string with additional contextual metadata")


class HistoryResponse(BaseModel):
    """
    List of recent detection audit logs.
    """
    total: int = Field(..., description="Number of log records returned")
    logs: List[DetectionLogItem] = Field(..., description="Recent detection log records")

