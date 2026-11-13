"""
ml/plot_charts.py — Standalone Chart Regeneration Utility
==========================================================
Reads evaluation metrics directly from ml/results/metrics.json and regenerates
publication-ready dark-themed charts without retraining models:
  1. ml/results/model_comparison.png  (grouped bar chart: 4 models × 4 metrics)
  2. ml/results/confusion_matrix.png  (annotated 2×2 heatmap with dynamic text colors)

Usage:
  python ml/plot_charts.py
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

# ── Matplotlib dark theme configuration ──────────────────────────────────────
plt.style.use("dark_background")
ACCENT_COLORS = ["#4FC3F7", "#81C784", "#FFB74D", "#F06292"]  # LR, DT, RF, XGB

# ── Relative paths (portable across Windows & macOS) ──────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR  = PROJECT_ROOT / "ml" / "results"
METRICS_PATH = RESULTS_DIR / "metrics.json"


def plot_model_comparison(models_data: dict, out_path: Path):
    """
    Generates a publication-quality dark-themed grouped bar chart comparing
    Accuracy, Precision, Recall, and F1-Score for all models.

    Key styling:
      - ylim(0.50, 1.04) ensures all bars (e.g., Logistic Regression Precision 0.627)
        and their text value labels sit comfortably above the x-axis.
      - Saved at 300 DPI with tight bounding box.
    """
    model_names = list(models_data.keys())
    metrics     = ["accuracy", "precision", "recall", "f1_score"]
    labels      = ["Accuracy", "Precision", "Recall", "F1-Score"]

    # Build matrix: shape (num_models, num_metrics)
    values = np.array([[models_data[m][metric] for metric in metrics] for m in model_names])

    fig, ax = plt.subplots(figsize=(13, 7))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    n_models  = len(model_names)
    n_metrics = len(metrics)
    x         = np.arange(n_models)   # one cluster per model
    bar_width = 0.18
    offsets   = np.linspace(-(n_metrics - 1) / 2, (n_metrics - 1) / 2, n_metrics) * bar_width

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
        # Annotate bar tops with numeric score (3 decimal places)
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                height + 0.005,
                f"{height:.3f}",
                ha="center",
                va="bottom",
                fontsize=7.5,
                color="white",
                fontweight="bold",
            )

    # Styling and axis limits
    ax.set_xticks(x)
    ax.set_xticklabels(model_names, fontsize=11, color="white")
    ax.set_ylim(0.50, 1.04)  # Accommodates LR Precision (0.627) and labels up to 1.000
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
    plt.savefig(out_path, dpi=300, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"  ✔  Saved comparison chart → {out_path.relative_to(PROJECT_ROOT)}")


def plot_confusion_matrix(cm_data: dict, champion_name: str, out_path: Path):
    """
    Generates a dark-themed annotated 2×2 confusion matrix heatmap for the champion model.

    Key styling:
      - Cell annotations show raw counts + row percentages: count\\n(pct%)
      - Dynamic text color: cells with percentage > 50% use 'white' text,
        while light cells (<= 50%) use dark navy '#0f172a' text for sharp legibility.
      - Saved at 300 DPI with tight bounding box.
    """
    cm     = np.array(cm_data["matrix"])
    labels = cm_data.get("labels", ["Normal (0)", "Attack (1)"])

    fig, ax = plt.subplots(figsize=(7, 6))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    # Percentage normalized per row (true class)
    cm_norm = cm.astype("float") / cm.sum(axis=1, keepdims=True) * 100
    annot   = np.array(
        [[f"{cm[i, j]:,}\n({cm_norm[i, j]:.1f}%)" for j in range(2)] for i in range(2)]
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
        annot_kws={"size": 13, "weight": "bold"},
    )

    # Dynamic text contrast: cells >50% white, cells <=50% dark navy (#0f172a)
    for i in range(2):
        for j in range(2):
            idx = i * 2 + j
            text_color = "white" if cm_norm[i, j] > 50 else "#0f172a"
            if idx < len(ax.texts):
                ax.texts[idx].set_color(text_color)

    # Axis styling
    ax.set_title(
        f"Confusion Matrix — {champion_name}\n(20% Unseen Test Set)",
        fontsize=13,
        fontweight="bold",
        color="white",
        pad=14,
    )
    ax.set_xlabel("Predicted Label", fontsize=11, color="white")
    ax.set_ylabel("True Label",      fontsize=11, color="white")
    ax.tick_params(colors="white", labelsize=10)

    # Colorbar label styling
    cbar = ax.figure.axes[-1]
    cbar.tick_params(colors="white")
    cbar.yaxis.label.set_color("white")

    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"  ✔  Saved confusion matrix  → {out_path.relative_to(PROJECT_ROOT)}")


def main():
    print("\n" + "═" * 60)
    print("  NIDS — Regenerating Charts from ml/results/metrics.json")
    print("═" * 60)

    if not METRICS_PATH.exists():
        raise FileNotFoundError(
            f"Metrics file not found at: {METRICS_PATH.relative_to(PROJECT_ROOT)}\n"
            f"Please run training first (python ml/train.py)."
        )

    with open(METRICS_PATH, "r") as f:
        metrics_data = json.load(f)

    champion_model = metrics_data.get("champion_model", "Champion Model")
    models_data    = metrics_data["models"]
    cm_data        = metrics_data["best_model_confusion_matrix"]

    # 1. Model comparison grouped bar chart
    plot_model_comparison(models_data, RESULTS_DIR / "model_comparison.png")

    # 2. Confusion matrix heatmap
    plot_confusion_matrix(cm_data, champion_model, RESULTS_DIR / "confusion_matrix.png")

    print("\n" + "█" * 60)
    print("  ✅  Both publication-ready charts successfully generated:")
    print(f"      - {RESULTS_DIR.relative_to(PROJECT_ROOT)}/model_comparison.png (DPI: 300)")
    print(f"      - {RESULTS_DIR.relative_to(PROJECT_ROOT)}/confusion_matrix.png (DPI: 300)")
    print("█" * 60 + "\n")


if __name__ == "__main__":
    main()

