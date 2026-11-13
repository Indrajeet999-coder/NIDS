"""
ml/train.py — Phase 3: Multi-Model Training, Evaluation & Artifact Export
==========================================================================
Trains and benchmarks 4 classifiers on the CICIDS2017 dataset:
  1. Logistic Regression  (baseline, linear)
  2. Decision Tree        (white-box, fast)
  3. Random Forest        (ensemble bagging)
  4. XGBoost              (champion, gradient boosting)

Outputs:
  - ml/models/nids_bundle.joblib      ← best model + metadata for FastAPI
  - ml/results/metrics.json           ← all evaluation metrics for dashboard
  - ml/results/model_comparison.png   ← grouped bar chart (4 models × 4 metrics)
  - ml/results/confusion_matrix.png   ← annotated heatmap of best model
"""

import json
import time
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

# ── Matplotlib dark theme (publication-quality charts) ─────────────────────
plt.style.use("dark_background")
ACCENT_COLORS = ["#4FC3F7", "#81C784", "#FFB74D", "#F06292"]  # LR, DT, RF, XGB

# ── Path setup (all relative — works on Windows & macOS) ───────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "dataset" / "processed"
MODELS_DIR    = PROJECT_ROOT / "ml" / "models"
RESULTS_DIR   = PROJECT_ROOT / "ml" / "results"

# Create output directories if they don't exist
MODELS_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Load preprocessed data
# ══════════════════════════════════════════════════════════════════════════════

def load_data():
    """
    Load train/test parquets and selected feature list.
    Returns X_train, X_test, y_train, y_test as float32 arrays.
    """
    print("\n" + "═" * 60)
    print("  STEP 1 — Loading processed data")
    print("═" * 60)

    # Load selected feature names
    features_path = PROCESSED_DIR / "selected_features.json"
    with open(features_path, "r") as f:
        selected_features = json.load(f)
    print(f"  ✔  Selected features : {len(selected_features)} columns")

    # Load train & test parquet files
    train_df = pd.read_parquet(PROCESSED_DIR / "train.parquet")
    test_df  = pd.read_parquet(PROCESSED_DIR / "test.parquet")

    print(f"  ✔  Train set shape   : {train_df.shape}")
    print(f"  ✔  Test  set shape   : {test_df.shape}")

    # Separate features (X) and binary label (y)
    # The label column saved by preprocess.py is 'Label_Binary'
    LABEL_COL = "Label_Binary"

    X_train = train_df[selected_features].astype("float32").values
    y_train = train_df[LABEL_COL].values

    X_test  = test_df[selected_features].astype("float32").values
    y_test  = test_df[LABEL_COL].values

    print(f"  ✔  Train label dist  : Normal={int((y_train == 0).sum()):,}  "
          f"Attack={int((y_train == 1).sum()):,}")
    print(f"  ✔  Test  label dist  : Normal={int((y_test  == 0).sum()):,}  "
          f"Attack={int((y_test  == 1).sum()):,}")

    return X_train, X_test, y_train, y_test, selected_features


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Compute class imbalance ratio for XGBoost scale_pos_weight
# ══════════════════════════════════════════════════════════════════════════════

def compute_imbalance_ratio(y_train):
    """
    Returns neg_count / pos_count — the value XGBoost uses as scale_pos_weight
    to give the minority class (attacks) heavier penalty on wrong predictions.
    """
    neg_count = int((y_train == 0).sum())   # Normal / BENIGN samples
    pos_count = int((y_train == 1).sum())   # Attack / Intrusion samples
    ratio     = neg_count / pos_count
    print(f"\n  Class imbalance ratio (neg/pos) = {neg_count:,} / {pos_count:,} = {ratio:.2f}")
    return ratio


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Define all 4 models
# ══════════════════════════════════════════════════════════════════════════════

def build_models(imbalance_ratio: float) -> dict:
    """
    Returns an ordered dict of {model_name: estimator}.

    Notes:
      • Logistic Regression is wrapped in a Pipeline with StandardScaler
        because it is sensitive to feature scale.
      • Tree-based models (DT, RF, XGBoost) are scale-invariant — no scaler
        needed.  StandardScaler is applied only during LR inference inside
        the pipeline transparently.
      • NO SMOTE — class imbalance handled via class_weight / scale_pos_weight.
      • XGBoost uses tree_method="hist" for CPU efficiency (required by AGENTS.md).
    """
    models = {
        # ── 1. Logistic Regression — baseline linear classifier ──────────────
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf",    LogisticRegression(
                max_iter=500,
                class_weight="balanced",
                n_jobs=-1,
                random_state=42,
            )),
        ]),

        # ── 2. Decision Tree — fast white-box rule-based classifier ──────────
        "Decision Tree": DecisionTreeClassifier(
            max_depth=15,
            class_weight="balanced",
            random_state=42,
        ),

        # ── 3. Random Forest — ensemble of 100 trees (bagging) ──────────────
        "Random Forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=18,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        ),

        # ── 4. XGBoost — gradient boosting champion ──────────────────────────
        "XGBoost": XGBClassifier(
            n_estimators=150,
            max_depth=8,
            learning_rate=0.1,
            tree_method="hist",          # histogram binning — 80% faster on CPU
            scale_pos_weight=imbalance_ratio,
            n_jobs=-1,
            random_state=42,
            eval_metric="logloss",
            verbosity=0,                 # suppress XGBoost training chatter
        ),
    }
    return models


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Train & evaluate each model, return metrics dict
# ══════════════════════════════════════════════════════════════════════════════

def train_and_evaluate(models: dict, X_train, X_test, y_train, y_test) -> dict:
    """
    Trains every model on the full training set, evaluates on the held-out
    20% test set, and records:
      - Training time (seconds)
      - Inference latency per 1,000 flows (ms)
      - Accuracy, Precision, Recall, F1-Score, ROC-AUC
      - Confusion matrix [[TN, FP], [FN, TP]]
    """
    print("\n" + "═" * 60)
    print("  STEP 2 — Training & evaluating 4 models")
    print("═" * 60)

    results = {}

    for name, model in models.items():
        print(f"\n  ▶  Training: {name} ...")

        # ── Training ─────────────────────────────────────────────────────────
        t0 = time.perf_counter()
        model.fit(X_train, y_train)
        train_time = time.perf_counter() - t0
        print(f"     Training time : {train_time:.1f} s")

        # ── Inference (measure latency per 1,000 samples) ────────────────────
        # Use first 1,000 test samples as a representative batch
        sample = X_test[:1000]
        t1 = time.perf_counter()
        _ = model.predict(sample)
        latency_ms = (time.perf_counter() - t1) * 1000  # convert to ms
        print(f"     Latency/1k    : {latency_ms:.2f} ms")

        # ── Predictions on the full unseen 20% test set ──────────────────────
        y_pred = model.predict(X_test)

        # ROC-AUC requires probability scores
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test)[:, 1]
        else:
            y_prob = y_pred  # fallback (shouldn't happen with these models)

        # ── Compute all metrics ───────────────────────────────────────────────
        acc       = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall    = recall_score(y_test, y_pred, zero_division=0)
        f1        = f1_score(y_test, y_pred, zero_division=0)
        roc_auc   = roc_auc_score(y_test, y_prob)
        cm        = confusion_matrix(y_test, y_pred).tolist()  # [[TN,FP],[FN,TP]]

        print(f"     Accuracy      : {acc:.4f}")
        print(f"     Precision     : {precision:.4f}")
        print(f"     Recall        : {recall:.4f}")
        print(f"     F1-Score      : {f1:.4f}")
        print(f"     ROC-AUC       : {roc_auc:.4f}")

        results[name] = {
            "model":          model,
            "train_time_s":   round(train_time, 2),
            "latency_ms_1k":  round(latency_ms, 2),
            "accuracy":       round(float(acc),       4),
            "precision":      round(float(precision), 4),
            "recall":         round(float(recall),    4),
            "f1_score":       round(float(f1),        4),
            "roc_auc":        round(float(roc_auc),   4),
            "confusion_matrix": cm,
        }

    return results


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — Print comparison table in the terminal
# ══════════════════════════════════════════════════════════════════════════════

def print_comparison_table(results: dict):
    """Prints a clean ASCII comparison table of all 4 models."""
    print("\n" + "═" * 90)
    print("  MODEL BENCHMARK COMPARISON (20% Unseen Test Set)")
    print("═" * 90)

    header = f"{'Model':<22} {'Train(s)':>9} {'Lat(ms)':>9} {'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7} {'ROC-AUC':>9}"
    print(header)
    print("─" * 90)

    for name, m in results.items():
        row = (
            f"{name:<22} "
            f"{m['train_time_s']:>9.1f} "
            f"{m['latency_ms_1k']:>9.2f} "
            f"{m['accuracy']:>7.4f} "
            f"{m['precision']:>7.4f} "
            f"{m['recall']:>7.4f} "
            f"{m['f1_score']:>7.4f} "
            f"{m['roc_auc']:>9.4f}"
        )
        print(row)

    print("═" * 90)


# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 — Select best model by F1-Score
# ══════════════════════════════════════════════════════════════════════════════

def select_best_model(results: dict):
    """Returns the name of the model with the highest F1-Score."""
    best_name = max(results, key=lambda k: results[k]["f1_score"])
    best_f1   = results[best_name]["f1_score"]
    print(f"\n  🏆  Best model : {best_name}  (F1 = {best_f1:.4f})")
    return best_name


# ══════════════════════════════════════════════════════════════════════════════
# STEP 7 — Extract Top-15 feature importances from the best model
# ══════════════════════════════════════════════════════════════════════════════

def get_feature_importances(model, selected_features: list, top_n: int = 15):
    """
    Extracts feature_importances_ from tree-based models (RF, XGBoost, DT).
    For Logistic Regression, uses absolute coefficient values instead.
    Returns a list of {feature, importance} dicts sorted descending.
    """
    # Unwrap Pipeline to get the actual estimator
    estimator = model.named_steps["clf"] if hasattr(model, "named_steps") else model

    if hasattr(estimator, "feature_importances_"):
        importances = estimator.feature_importances_
    elif hasattr(estimator, "coef_"):
        # Logistic Regression: take absolute value of coefficients
        importances = np.abs(estimator.coef_[0])
    else:
        return []

    # Sort descending and take top N
    indices = np.argsort(importances)[::-1][:top_n]
    top_features = [
        {"feature": selected_features[i], "importance": round(float(importances[i]), 6)}
        for i in indices
    ]
    return top_features


# ══════════════════════════════════════════════════════════════════════════════
# STEP 8 — Save model bundle + metrics JSON
# ══════════════════════════════════════════════════════════════════════════════

def save_artifacts(results: dict, best_name: str, selected_features: list):
    """
    Saves:
      • ml/models/nids_bundle.joblib  — best model + feature list + metadata
      • ml/results/metrics.json       — full benchmark + best model details
    """
    print("\n" + "═" * 60)
    print("  STEP 4 — Saving artifacts")
    print("═" * 60)

    best_model = results[best_name]["model"]

    # ── 8a. Feature importances for best model ────────────────────────────────
    top_features = get_feature_importances(best_model, selected_features, top_n=15)

    # ── 8b. nids_bundle.joblib ────────────────────────────────────────────────
    # The bundle contains everything the FastAPI backend needs:
    #   model            — trained estimator (LR pipeline includes its own scaler)
    #   selected_features — feature names in correct order for inference
    #   threshold        — decision threshold (0.5 default)
    #   version          — artifact version string
    bundle = {
        "model":             best_model,
        "selected_features": selected_features,
        "threshold":         0.50,
        "version":           "1.0.0",
        "champion_model":    best_name,
    }
    bundle_path = MODELS_DIR / "nids_bundle.joblib"
    joblib.dump(bundle, bundle_path, compress=3)
    print(f"  ✔  Saved model bundle  → {bundle_path.relative_to(PROJECT_ROOT)}")

    # ── 8c. metrics.json ──────────────────────────────────────────────────────
    # Build a clean metrics dict (strip the actual model object — not JSON-safe)
    metrics_payload = {
        "champion_model": best_name,
        "models": {
            name: {
                "train_time_s":   m["train_time_s"],
                "latency_ms_1k":  m["latency_ms_1k"],
                "accuracy":       m["accuracy"],
                "precision":      m["precision"],
                "recall":         m["recall"],
                "f1_score":       m["f1_score"],
                "roc_auc":        m["roc_auc"],
            }
            for name, m in results.items()
        },
        "best_model_confusion_matrix": {
            "labels": ["Normal (0)", "Attack (1)"],
            "matrix": results[best_name]["confusion_matrix"],
        },
        "top_15_feature_importances": top_features,
    }

    metrics_path = RESULTS_DIR / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics_payload, f, indent=2)
    print(f"  ✔  Saved metrics JSON  → {metrics_path.relative_to(PROJECT_ROOT)}")

    return top_features


# ══════════════════════════════════════════════════════════════════════════════
# STEP 9 — Plot 1: Grouped bar chart comparing all 4 models
# ══════════════════════════════════════════════════════════════════════════════

def plot_model_comparison(results: dict):
    """
    Saves a dark-themed grouped bar chart of Accuracy, Precision, Recall, F1
    for all 4 models → ml/results/model_comparison.png
    """
    model_names = list(results.keys())
    metrics     = ["accuracy", "precision", "recall", "f1_score"]
    labels      = ["Accuracy", "Precision", "Recall", "F1-Score"]

    # Build matrix: shape (num_models, num_metrics)
    values = np.array([[results[m][metric] for metric in metrics] for m in model_names])

    fig, ax = plt.subplots(figsize=(13, 7))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    n_models  = len(model_names)
    n_metrics = len(metrics)
    x         = np.arange(n_models)   # one cluster per model
    bar_width  = 0.18
    offsets    = np.linspace(-(n_metrics - 1) / 2, (n_metrics - 1) / 2, n_metrics) * bar_width

    for idx, (label, offset, color) in enumerate(zip(labels, offsets, ACCENT_COLORS)):
        bars = ax.bar(
            x + offset,
            values[:, idx],
            width=bar_width,
            label=label,
            color=color,
            alpha=0.90,
            edgecolor="#ffffff20",
            linewidth=0.5,
        )
        # Annotate bar tops with the numeric value
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                height + 0.003,
                f"{height:.3f}",
                ha="center",
                va="bottom",
                fontsize=7.5,
                color="white",
                fontweight="bold",
            )

    # Styling
    ax.set_xticks(x)
    ax.set_xticklabels(model_names, fontsize=11, color="white")
    ax.set_ylim(0.80, 1.02)
    ax.set_ylabel("Score", fontsize=12, color="white")
    ax.set_title(
        "Model Performance Benchmark — CICIDS2017 (20% Test Set)",
        fontsize=14,
        fontweight="bold",
        color="white",
        pad=18,
    )
    ax.legend(fontsize=10, framealpha=0.3, labelcolor="white")
    ax.tick_params(colors="white", labelsize=10)
    ax.yaxis.grid(True, linestyle="--", alpha=0.3, color="white")
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_edgecolor("#ffffff30")

    plt.tight_layout()
    out_path = RESULTS_DIR / "model_comparison.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"  ✔  Saved bar chart     → {out_path.relative_to(PROJECT_ROOT)}")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 10 — Plot 2: Confusion matrix heatmap for the best model
# ══════════════════════════════════════════════════════════════════════════════

def plot_confusion_matrix(results: dict, best_name: str):
    """
    Saves a dark-themed annotated confusion matrix heatmap for the best model
    → ml/results/confusion_matrix.png
    """
    cm     = np.array(results[best_name]["confusion_matrix"])
    labels = ["Normal (0)", "Attack (1)"]

    fig, ax = plt.subplots(figsize=(7, 6))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    # Percentage annotations alongside raw counts
    cm_norm = cm.astype("float") / cm.sum(axis=1, keepdims=True) * 100
    annot   = np.array(
        [[f"{cm[i,j]:,}\n({cm_norm[i,j]:.1f}%)" for j in range(2)] for i in range(2)]
    )

    sns.heatmap(
        cm_norm,
        annot=annot,
        fmt="",
        cmap="Blues",
        xticklabels=labels,
        yticklabels=labels,
        ax=ax,
        linewidths=0.5,
        linecolor="#ffffff20",
        cbar_kws={"label": "% of True Class"},
        annot_kws={"size": 13, "weight": "bold", "color": "white"},
    )

    # Styling
    ax.set_title(
        f"Confusion Matrix — {best_name}\n(20% Unseen Test Set)",
        fontsize=13,
        fontweight="bold",
        color="white",
        pad=14,
    )
    ax.set_xlabel("Predicted Label", fontsize=11, color="white")
    ax.set_ylabel("True Label",      fontsize=11, color="white")
    ax.tick_params(colors="white", labelsize=10)
    ax.figure.axes[-1].tick_params(colors="white")
    ax.figure.axes[-1].yaxis.label.set_color("white")

    plt.tight_layout()
    out_path = RESULTS_DIR / "confusion_matrix.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"  ✔  Saved confusion mat → {out_path.relative_to(PROJECT_ROOT)}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN — orchestrate all steps
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print("\n" + "█" * 60)
    print("  NIDS — Phase 3: Multi-Model Training & Evaluation")
    print("█" * 60)

    # 1. Load data
    X_train, X_test, y_train, y_test, selected_features = load_data()

    # 2. Compute class imbalance ratio for XGBoost
    imbalance_ratio = compute_imbalance_ratio(y_train)

    # 3. Build model definitions
    models = build_models(imbalance_ratio)

    # 4. Train + evaluate all models
    results = train_and_evaluate(models, X_train, X_test, y_train, y_test)

    # 5. Print terminal comparison table
    print_comparison_table(results)

    # 6. Select best model by F1-Score
    best_name = select_best_model(results)

    # 7 & 8. Save nids_bundle.joblib + metrics.json
    print("\n" + "═" * 60)
    print("  STEP 3 — Generating charts")
    print("═" * 60)

    # 9. Plot grouped bar chart
    plot_model_comparison(results)

    # 10. Plot confusion matrix heatmap
    plot_confusion_matrix(results, best_name)

    # 11. Save model artifacts
    save_artifacts(results, best_name, selected_features)

    print("\n" + "█" * 60)
    print("  ✅  Training complete! Artifacts saved:")
    print(f"      ml/models/nids_bundle.joblib")
    print(f"      ml/results/metrics.json")
    print(f"      ml/results/model_comparison.png")
    print(f"      ml/results/confusion_matrix.png")
    print("█" * 60 + "\n")


if __name__ == "__main__":
    main()

