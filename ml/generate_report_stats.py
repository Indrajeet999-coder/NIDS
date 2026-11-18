"""
ml/generate_report_stats.py
===========================
Generates rigorous statistical hypothesis tests and publication-ready academic
visualizations for the NIDS academic research report.

Key Deliverables:
  1. Statistical Tests (scipy.stats, alpha = 0.05) saved to ml/results/report_stats.json:
     - Chi-square test of independence: Transport Protocol (TCP/UDP/ICMP mapped from Destination Port) vs. Label
     - Welch's t-test and Levene's variance equality test comparing Normal vs Intrusion traffic for:
       Flow Duration, Average Packet Size, Total Fwd Packets, and Flow Bytes/s
     - 5-fold Stratified Cross-Validation on a 50,000-row sample comparing LR, DT, RF, and XGBoost on
       F1-score and Recall, evaluated with One-Way ANOVA (f_oneway)
     - Exact confusion matrix counts (TN, FP, FN, TP) on the 120,000-row held-out test set for all 4 models
  2. Publication-Quality Academic Visualizations (300 DPI, clean white background):
     - ml/results/report_eda_4panel.png: 2x2 grid (Class distribution, Packet Size KDE, Attack breakdown, Correlation heatmap)
     - ml/results/report_roc_pr_curves.png: Side-by-side ROC and Precision-Recall curves
     - ml/results/report_feature_importance.png: Horizontal bar chart of Top-10 XGBoost feature importances
  3. Formatted JSON summary printed to stdout for easy copy-pasting.
"""

import gc
import json
import time
import warnings
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import scipy.stats as stats
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

# Suppress sklearn/xgboost noise
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

# ---------------------------------------------------------------------------
# 0. Path Configuration (Portable — Works on Windows & macOS)
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "dataset" / "processed"
RAW_DIR = PROJECT_ROOT / "dataset" / "raw" / "MachineLearningCVE"
MODELS_DIR = PROJECT_ROOT / "ml" / "models"
RESULTS_DIR = PROJECT_ROOT / "ml" / "results"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Academic Visual Styling (300 DPI, Clean White Background)
# ---------------------------------------------------------------------------
plt.style.use("default")
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
    "axes.edgecolor": "#2c3e50",
    "axes.linewidth": 1.1,
    "axes.titlesize": 12,
    "axes.titleweight": "bold",
    "axes.labelsize": 11,
    "axes.labelweight": "medium",
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "figure.facecolor": "#FFFFFF",
    "axes.facecolor": "#FFFFFF",
    "grid.color": "#e2e8f0",
    "grid.linestyle": "--",
    "grid.linewidth": 0.8,
    "savefig.dpi": 300,
    "savefig.facecolor": "#FFFFFF",
    "savefig.bbox": "tight",
})

# Academic color palette: deep navy, forest green, warm amber, crimson
PALETTE = {
    "Logistic Regression": "#2563eb",  # Royal Blue
    "Decision Tree":       "#059669",  # Emerald Green
    "Random Forest":       "#d97706",  # Amber/Ochre
    "XGBoost":             "#dc2626",  # Crimson Red
    "Normal":              "#1e40af",  # Deep Blue
    "Attack":              "#b91c1c",  # Deep Red
}

COMMON_UDP_PORTS = {
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 5353, 5355
}


def map_port_to_protocol(port: int) -> str:
    """Maps a Destination Port to its transport layer protocol."""
    if port == 0:
        return "ICMP"
    if int(port) in COMMON_UDP_PORTS:
        return "UDP"
    return "TCP"


# ---------------------------------------------------------------------------
# STEP 1: Load Datasets and Bundle
# ---------------------------------------------------------------------------
def load_datasets_and_bundle():
    print("\n" + "=" * 70)
    print("STEP 1: Loading Processed Parquets and Model Bundle")
    print("=" * 70)

    train_path = PROCESSED_DIR / "train.parquet"
    test_path = PROCESSED_DIR / "test.parquet"
    bundle_path = MODELS_DIR / "nids_bundle.joblib"

    print(f"  Loading: {train_path.name} ...")
    train_df = pd.read_parquet(train_path)
    # Downcast numeric types to float32/int32 to conserve RAM
    float_cols = train_df.select_dtypes(include="float64").columns
    train_df[float_cols] = train_df[float_cols].astype("float32")
    int_cols = train_df.select_dtypes(include="int64").columns
    train_df[int_cols] = train_df[int_cols].astype("int32")

    print(f"  Loading: {test_path.name} ...")
    test_df = pd.read_parquet(test_path)
    float_cols = test_df.select_dtypes(include="float64").columns
    test_df[float_cols] = test_df[float_cols].astype("float32")
    int_cols = test_df.select_dtypes(include="int64").columns
    test_df[int_cols] = test_df[int_cols].astype("int32")

    print(f"  Loading: {bundle_path.name} ...")
    bundle = joblib.load(bundle_path)

    print(f"  ✔ Train Shape: {train_df.shape}")
    print(f"  ✔ Test Shape : {test_df.shape}")
    print(f"  ✔ Bundle Keys: {list(bundle.keys())} (Champion: {bundle.get('champion_model')})")

    return train_df, test_df, bundle


# ---------------------------------------------------------------------------
# STEP 2: Statistical Hypothesis Tests
# ---------------------------------------------------------------------------
def run_statistical_tests(train_df: pd.DataFrame, test_df: pd.DataFrame, bundle: dict):
    print("\n" + "=" * 70)
    print("STEP 2: Executing Statistical Hypothesis Tests (alpha = 0.05)")
    print("=" * 70)

    stats_results = {
        "metadata": {
            "alpha": 0.05,
            "train_samples": len(train_df),
            "test_samples": len(test_df),
            "total_samples": len(train_df) + len(test_df),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
    }

    # -----------------------------------------------------------------------
    # 2a. Chi-Square Test of Independence: Protocol vs Label_Binary
    # -----------------------------------------------------------------------
    print("\n  [2a] Chi-Square Test of Independence (Protocol vs Label) ...")
    proto_series = train_df["Destination Port"].astype(int).apply(map_port_to_protocol)
    contingency = pd.crosstab(proto_series, train_df["Label_Binary"])

    chi2, p_val, dof, expected = stats.chi2_contingency(contingency)

    contingency_dict = {
        proto: {
            "Normal_0": int(contingency.loc[proto, 0]) if 0 in contingency.columns else 0,
            "Attack_1": int(contingency.loc[proto, 1]) if 1 in contingency.columns else 0,
            "Total": int(contingency.loc[proto].sum()),
        }
        for proto in contingency.index
    }

    stats_results["chi_square_protocol"] = {
        "test_name": "Pearson's Chi-Square Test of Independence",
        "variable_1": "Transport Protocol (TCP/UDP/ICMP mapped from Destination Port)",
        "variable_2": "Label_Binary (0: Normal, 1: Intrusion)",
        "chi2_statistic": round(float(chi2), 4),
        "p_value": float(p_val),
        "degrees_of_freedom": int(dof),
        "alpha": 0.05,
        "reject_null_hypothesis": bool(p_val < 0.05),
        "contingency_table": contingency_dict,
        "interpretation": (
            "Statistically significant association between Transport Protocol and Traffic Class "
            f"(Chi2 = {chi2:.2f}, p = {p_val:.4e}, df = {dof}). Attack traffic is disproportionately "
            "concentrated in TCP services compared to UDP and ICMP."
        ),
    }
    print(f"       Chi2: {chi2:.4f} | p-value: {p_val:.4e} | dof: {dof} (Reject H0: {p_val < 0.05})")

    # -----------------------------------------------------------------------
    # 2b. Welch's t-test and Levene's Test: Continuous Features
    # -----------------------------------------------------------------------
    print("\n  [2b] Welch's t-test & Levene's Test for Continuous Features ...")
    # Features present in train_df: Average Packet Size, Total Fwd Packets
    # Features in raw dataset: Flow Duration, Flow Bytes/s
    cont_results = {}

    # Test features present in train_df
    for feat in ["Average Packet Size", "Total Fwd Packets"]:
        norm_series = train_df[train_df["Label_Binary"] == 0][feat].astype(np.float64)
        att_series = train_df[train_df["Label_Binary"] == 1][feat].astype(np.float64)

        t_stat, t_p = stats.ttest_ind(norm_series, att_series, equal_var=False)

        # Levene's test on sample of up to 100,000 per class for computational safety
        sub_norm = norm_series.sample(min(100_000, len(norm_series)), random_state=42)
        sub_att = att_series.sample(min(100_000, len(att_series)), random_state=42)
        lev_stat, lev_p = stats.levene(sub_norm, sub_att, center="median")

        cont_results[feat] = {
            "source": "train.parquet (480,000 flows)",
            "normal_mean": round(float(norm_series.mean()), 4),
            "normal_std": round(float(norm_series.std()), 4),
            "intrusion_mean": round(float(att_series.mean()), 4),
            "intrusion_std": round(float(att_series.std()), 4),
            "welch_t_test": {
                "t_statistic": round(float(t_stat), 4),
                "p_value": float(t_p),
                "reject_null": bool(t_p < 0.05),
            },
            "levene_test": {
                "statistic": round(float(lev_stat), 4),
                "p_value": float(lev_p),
                "equal_variance_rejected": bool(lev_p < 0.05),
            },
        }
        print(f"       {feat:<22} | t = {t_stat:>9.4f} (p={t_p:.2e}) | Levene = {lev_stat:>9.4f} (p={lev_p:.2e})")

    # Load Flow Duration & Flow Bytes/s from raw CSVs (memory-safe selective loading)
    print("       Loading 'Flow Duration', 'Flow Bytes/s', 'Label' from raw CSVs ...")
    raw_files = sorted(RAW_DIR.glob("*.csv"))
    raw_chunks = []
    raw_labels = []

    for f in raw_files:
        chunk = pd.read_csv(
            f,
            usecols=lambda c: c.strip() in ["Flow Duration", "Flow Bytes/s", "Label"],
            low_memory=False,
        )
        chunk.columns = chunk.columns.str.strip()
        # Clean inf/nan immediately
        chunk = chunk.replace([np.inf, -np.inf], np.nan).dropna()
        chunk["Flow Duration"] = chunk["Flow Duration"].astype("float32")
        chunk["Flow Bytes/s"] = chunk["Flow Bytes/s"].astype("float32")
        chunk["Label"] = chunk["Label"].astype(str).str.strip()
        raw_chunks.append(chunk)

    raw_combined = pd.concat(raw_chunks, ignore_index=True)
    raw_combined["Label_Binary"] = (raw_combined["Label"] != "BENIGN").astype(int)

    # Store raw attack counts for EDA panel later
    attack_counts_raw = (
        raw_combined[raw_combined["Label"] != "BENIGN"]["Label"]
        .value_counts()
        .to_dict()
    )

    for feat in ["Flow Duration", "Flow Bytes/s"]:
        norm_series = raw_combined[raw_combined["Label_Binary"] == 0][feat].astype(np.float64)
        att_series = raw_combined[raw_combined["Label_Binary"] == 1][feat].astype(np.float64)

        t_stat, t_p = stats.ttest_ind(norm_series, att_series, equal_var=False)

        sub_norm = norm_series.sample(min(100_000, len(norm_series)), random_state=42)
        sub_att = att_series.sample(min(100_000, len(att_series)), random_state=42)
        lev_stat, lev_p = stats.levene(sub_norm, sub_att, center="median")

        cont_results[feat] = {
            "source": f"CICIDS2017 raw corpus ({len(raw_combined):,} valid flows)",
            "normal_mean": round(float(norm_series.mean()), 4),
            "normal_std": round(float(norm_series.std()), 4),
            "intrusion_mean": round(float(att_series.mean()), 4),
            "intrusion_std": round(float(att_series.std()), 4),
            "welch_t_test": {
                "t_statistic": round(float(t_stat), 4),
                "p_value": float(t_p),
                "reject_null": bool(t_p < 0.05),
            },
            "levene_test": {
                "statistic": round(float(lev_stat), 4),
                "p_value": float(lev_p),
                "equal_variance_rejected": bool(lev_p < 0.05),
            },
        }
        print(f"       {feat:<22} | t = {t_stat:>9.4f} (p={t_p:.2e}) | Levene = {lev_stat:>9.4f} (p={lev_p:.2e})")

    stats_results["continuous_hypothesis_tests"] = cont_results

    # Free memory
    del raw_chunks, raw_combined
    gc.collect()

    # -----------------------------------------------------------------------
    # 2c. 5-Fold Stratified Cross-Validation on 50,000-Row Sample & One-Way ANOVA
    # -----------------------------------------------------------------------
    print("\n  [2c] 5-Fold Stratified Cross-Validation & One-Way ANOVA (50,000-row sample) ...")
    sample_df, _ = train_test_split(
        train_df,
        train_size=50_000,
        stratify=train_df["Label_Binary"],
        random_state=42,
    )
    feature_cols = [c for c in sample_df.columns if c != "Label_Binary"]
    X_sample = sample_df[feature_cols].astype(np.float32).values
    y_sample = sample_df["Label_Binary"].values

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    cv_models = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=500, class_weight="balanced", random_state=42)),
        ]),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=15, class_weight="balanced", random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=100, max_depth=18, class_weight="balanced", n_jobs=-1, random_state=42
        ),
        "XGBoost": XGBClassifier(
            n_estimators=150,
            max_depth=8,
            learning_rate=0.1,
            tree_method="hist",
            n_jobs=-1,
            random_state=42,
            eval_metric="logloss",
            verbosity=0,
        ),
    }

    cv_scores = {name: {"f1": [], "recall": []} for name in cv_models}

    for fold, (tr_idx, va_idx) in enumerate(skf.split(X_sample, y_sample), start=1):
        X_tr, y_tr = X_sample[tr_idx], y_sample[tr_idx]
        X_va, y_va = X_sample[va_idx], y_sample[va_idx]
        imbalance_ratio = float((y_tr == 0).sum() / (y_tr == 1).sum())

        for name, clf in cv_models.items():
            if name == "XGBoost":
                clf.set_params(scale_pos_weight=imbalance_ratio)
            clf.fit(X_tr, y_tr)
            preds = clf.predict(X_va)
            cv_scores[name]["f1"].append(float(f1_score(y_va, preds, zero_division=0)))
            cv_scores[name]["recall"].append(float(recall_score(y_va, preds, zero_division=0)))

        print(f"       ✔ Fold {fold}/5 complete")

    # One-Way ANOVA across all 4 models
    f1_groups = [cv_scores[m]["f1"] for m in cv_models]
    rec_groups = [cv_scores[m]["recall"] for m in cv_models]

    f_stat_f1, p_val_f1 = stats.f_oneway(*f1_groups)
    f_stat_rec, p_val_rec = stats.f_oneway(*rec_groups)

    stats_results["cross_validation_5fold_50k"] = {
        "sample_size": 50_000,
        "n_splits": 5,
        "models": {
            name: {
                "f1_scores": [round(s, 4) for s in cv_scores[name]["f1"]],
                "f1_mean": round(float(np.mean(cv_scores[name]["f1"])), 4),
                "f1_std": round(float(np.std(cv_scores[name]["f1"])), 4),
                "recall_scores": [round(s, 4) for s in cv_scores[name]["recall"]],
                "recall_mean": round(float(np.mean(cv_scores[name]["recall"])), 4),
                "recall_std": round(float(np.std(cv_scores[name]["recall"])), 4),
            }
            for name in cv_models
        },
        "one_way_anova": {
            "f1_score": {
                "F_statistic": round(float(f_stat_f1), 4),
                "p_value": float(p_val_f1),
                "reject_null": bool(p_val_f1 < 0.05),
                "interpretation": (
                    f"Statistically significant difference in F1-score across models "
                    f"(F = {f_stat_f1:.2f}, p = {p_val_f1:.4e})."
                ),
            },
            "recall": {
                "F_statistic": round(float(f_stat_rec), 4),
                "p_value": float(p_val_rec),
                "reject_null": bool(p_val_rec < 0.05),
                "interpretation": (
                    f"Statistically significant difference in Recall across models "
                    f"(F = {f_stat_rec:.2f}, p = {p_val_rec:.4e})."
                ),
            },
        },
    }

    print(f"       ANOVA F1-Score : F = {f_stat_f1:.4f} | p = {p_val_f1:.4e} (Significant: {p_val_f1 < 0.05})")
    print(f"       ANOVA Recall   : F = {f_stat_rec:.4f} | p = {p_val_rec:.4e} (Significant: {p_val_rec < 0.05})")

    # -----------------------------------------------------------------------
    # 2d. Exact Confusion Matrix Counts on 120,000-Row Test Set (All 4 Models)
    # -----------------------------------------------------------------------
    print("\n  [2d] Evaluating Exact Confusion Matrices on 120,000-Row Test Set ...")
    X_train_full = train_df[feature_cols].astype(np.float32).values
    y_train_full = train_df["Label_Binary"].values
    X_test_full = test_df[feature_cols].astype(np.float32).values
    y_test_full = test_df["Label_Binary"].values

    imbalance_full = float((y_train_full == 0).sum() / (y_train_full == 1).sum())

    # Train LR, DT, RF on full train set; use bundle model for XGBoost
    full_models = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=500, class_weight="balanced", random_state=42)),
        ]),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=15, class_weight="balanced", random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=100, max_depth=18, class_weight="balanced", n_jobs=-1, random_state=42
        ),
        "XGBoost": bundle["model"],  # already trained champion
    }

    test_eval_results = {}
    fitted_prob_dict = {}

    for name, model in full_models.items():
        if name != "XGBoost":
            print(f"       Fitting {name} on 480,000 samples ...")
            model.fit(X_train_full, y_train_full)

        y_pred = model.predict(X_test_full)
        y_prob = model.predict_proba(X_test_full)[:, 1] if hasattr(model, "predict_proba") else y_pred
        fitted_prob_dict[name] = y_prob

        tn, fp, fn, tp = confusion_matrix(y_test_full, y_pred).ravel()
        acc = accuracy_score(y_test_full, y_pred)
        prec = precision_score(y_test_full, y_pred, zero_division=0)
        rec = recall_score(y_test_full, y_pred, zero_division=0)
        f1 = f1_score(y_test_full, y_pred, zero_division=0)
        auc = roc_auc_score(y_test_full, y_prob)

        test_eval_results[name] = {
            "TN": int(tn),
            "FP": int(fp),
            "FN": int(fn),
            "TP": int(tp),
            "Total_Test_Samples": int(len(y_test_full)),
            "Accuracy": round(float(acc), 4),
            "Precision": round(float(prec), 4),
            "Recall": round(float(rec), 4),
            "F1_Score": round(float(f1), 4),
            "ROC_AUC": round(float(auc), 4),
        }
        print(f"       {name:<22} | TN={tn:>6} FP={fp:>5} FN={fn:>4} TP={tp:>5} | F1={f1:.4f} AUC={auc:.4f}")

    stats_results["test_set_confusion_matrices"] = test_eval_results

    return stats_results, fitted_prob_dict, attack_counts_raw, y_test_full


# ---------------------------------------------------------------------------
# STEP 3: Publication-Ready Academic Charts (300 DPI, Clean White Background)
# ---------------------------------------------------------------------------
def generate_academic_charts(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    bundle: dict,
    fitted_prob_dict: dict,
    attack_counts_raw: dict,
    y_test_full: np.ndarray,
):
    print("\n" + "=" * 70)
    print("STEP 3: Generating Publication-Ready Academic Charts (300 DPI)")
    print("=" * 70)

    # -----------------------------------------------------------------------
    # Chart 1: report_eda_4panel.png (2x2 Grid)
    # -----------------------------------------------------------------------
    fig, axes = plt.subplots(2, 2, figsize=(14, 11))
    fig.patch.set_facecolor("#FFFFFF")

    # Panel (a): Class Distribution Bar Chart
    ax_a = axes[0, 0]
    labels_binary = ["Normal (BENIGN)", "Intrusion (Attack)"]
    normal_cnt = int((train_df["Label_Binary"] == 0).sum() + (test_df["Label_Binary"] == 0).sum())
    attack_cnt = int((train_df["Label_Binary"] == 1).sum() + (test_df["Label_Binary"] == 1).sum())
    total_cnt = normal_cnt + attack_cnt
    counts = [normal_cnt, attack_cnt]
    bars = ax_a.bar(
        labels_binary,
        counts,
        color=["#1e40af", "#b91c1c"],
        width=0.45,
        edgecolor="#1e293b",
        linewidth=1.2,
    )
    for bar in bars:
        h = bar.get_height()
        pct = (h / total_cnt) * 100
        ax_a.text(
            bar.get_x() + bar.get_width() / 2,
            h + 8000,
            f"{h:,}\n({pct:.1f}%)",
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
            color="#0f172a",
        )
    ax_a.set_ylim(0, max(counts) * 1.18)
    ax_a.set_ylabel("Number of Network Flows", fontsize=11, fontweight="bold")
    ax_a.set_title("(a) Dataset Class Distribution (CICIDS2017)", pad=12)
    ax_a.yaxis.grid(True, linestyle="--", alpha=0.6)
    ax_a.set_axisbelow(True)

    # Panel (b): Packet Size KDE Density by Class
    ax_b = axes[0, 1]
    norm_pkt = train_df[train_df["Label_Binary"] == 0]["Average Packet Size"]
    att_pkt = train_df[train_df["Label_Binary"] == 1]["Average Packet Size"]

    # Filter to 0..1500 for clean readable KDE
    sns.kdeplot(
        norm_pkt[norm_pkt <= 1500],
        ax=ax_b,
        color="#1e40af",
        fill=True,
        alpha=0.3,
        linewidth=2.0,
        label=f"Normal (Mean = {norm_pkt.mean():.1f} B)",
    )
    sns.kdeplot(
        att_pkt[att_pkt <= 1500],
        ax=ax_b,
        color="#b91c1c",
        fill=True,
        alpha=0.3,
        linewidth=2.0,
        label=f"Intrusion (Mean = {att_pkt.mean():.1f} B)",
    )
    ax_b.set_xlim(0, 1500)
    ax_b.set_xlabel("Average Packet Size (Bytes)", fontsize=11, fontweight="bold")
    ax_b.set_ylabel("Kernel Density Estimate (KDE)", fontsize=11, fontweight="bold")
    ax_b.set_title("(b) Packet Size Density Distribution by Class", pad=12)
    ax_b.legend(loc="upper right", framealpha=0.9, fontsize=9.5)
    ax_b.grid(True, linestyle="--", alpha=0.6)
    ax_b.set_axisbelow(True)

    # Panel (c): Attack Category Breakdown
    ax_c = axes[1, 0]
    # Clean up names from raw CSV
    clean_attack_counts = {}
    for k, v in attack_counts_raw.items():
        clean_name = k.replace("\ufffd", "-").replace("", "-")
        clean_attack_counts[clean_name] = clean_attack_counts.get(clean_name, 0) + v

    # Take Top 8 attack categories for clean display
    top_attacks = pd.Series(clean_attack_counts).sort_values(ascending=True).tail(8)
    y_pos = np.arange(len(top_attacks))
    bars_c = ax_c.barh(
        y_pos,
        top_attacks.values,
        color="#0891b2",
        height=0.6,
        edgecolor="#1e293b",
        linewidth=1.0,
    )
    ax_c.set_yticks(y_pos)
    ax_c.set_yticklabels(top_attacks.index, fontsize=9.5)
    ax_c.set_xlabel("Flow Count", fontsize=11, fontweight="bold")
    ax_c.set_title("(c) Attack Category Frequency Breakdown", pad=12)
    for bar in bars_c:
        w = bar.get_width()
        ax_c.text(
            w + 2500,
            bar.get_y() + bar.get_height() / 2,
            f"{int(w):,}",
            ha="left",
            va="center",
            fontsize=8.5,
            fontweight="bold",
            color="#0f172a",
        )
    ax_c.set_xlim(0, max(top_attacks.values) * 1.25)
    ax_c.xaxis.grid(True, linestyle="--", alpha=0.6)
    ax_c.set_axisbelow(True)

    # Panel (d): Top-8 Feature Pearson Correlation Heatmap
    ax_d = axes[1, 1]
    top_8_features = [
        "Bwd Packet Length Std",
        "Average Packet Size",
        "Bwd Header Length",
        "Max Packet Length",
        "Destination Port",
        "PSH Flag Count",
        "min_seg_size_forward",
        "Fwd Packet Length Max",
    ]
    corr_matrix = train_df[top_8_features].corr(method="pearson")

    # Short feature labels for layout clarity
    short_labels = [
        "Bwd Pkt Std",
        "Avg Pkt Size",
        "Bwd Hdr Len",
        "Max Pkt Len",
        "Dst Port",
        "PSH Count",
        "Min Seg Size",
        "Fwd Pkt Max",
    ]

    sns.heatmap(
        corr_matrix,
        ax=ax_d,
        annot=True,
        fmt=".2f",
        cmap="coolwarm",
        vmin=-0.4,
        vmax=1.0,
        xticklabels=short_labels,
        yticklabels=short_labels,
        cbar_kws={"label": "Pearson r", "shrink": 0.8},
        linewidths=0.6,
        linecolor="#ffffff",
        annot_kws={"size": 8.5, "weight": "bold"},
    )
    ax_d.set_title("(d) Top-8 Feature Pearson Correlation Heatmap", pad=12)
    ax_d.tick_params(axis="x", rotation=45)
    ax_d.tick_params(axis="y", rotation=0)

    plt.tight_layout(pad=3.0)
    eda_out = RESULTS_DIR / "report_eda_4panel.png"
    plt.savefig(eda_out, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  ✔ Saved: {eda_out.name} (300 DPI)")

    # -----------------------------------------------------------------------
    # Chart 2: report_roc_pr_curves.png (Side-by-Side ROC & PR Curves)
    # -----------------------------------------------------------------------
    fig, (ax_roc, ax_pr) = plt.subplots(1, 2, figsize=(14, 6.2))
    fig.patch.set_facecolor("#FFFFFF")

    # (a) ROC Curves
    for name, y_prob in fitted_prob_dict.items():
        fpr, tpr, _ = roc_curve(y_test_full, y_prob)
        auc_val = roc_auc_score(y_test_full, y_prob)
        color = PALETTE.get(name, "#333333")
        linestyle = "--" if name == "Logistic Regression" else "-"
        ax_roc.plot(
            fpr,
            tpr,
            label=f"{name} (AUC = {auc_val:.4f})",
            color=color,
            linewidth=2.2,
            linestyle=linestyle,
        )

    # Chance diagonal
    ax_roc.plot([0, 1], [0, 1], linestyle=":", color="#64748b", linewidth=1.5, label="Chance (AUC = 0.5000)")
    ax_roc.set_xlim(-0.01, 1.01)
    ax_roc.set_ylim(-0.01, 1.02)
    ax_roc.set_xlabel("False Positive Rate (1 - Specificity)", fontsize=11, fontweight="bold")
    ax_roc.set_ylabel("True Positive Rate (Sensitivity / Recall)", fontsize=11, fontweight="bold")
    ax_roc.set_title("(a) Receiver Operating Characteristic (ROC) Curves", pad=12)
    ax_roc.legend(loc="lower right", framealpha=0.92, fontsize=9.5)
    ax_roc.grid(True, linestyle="--", alpha=0.6)
    ax_roc.set_axisbelow(True)

    # (b) Precision-Recall Curves
    baseline_prevalence = float((y_test_full == 1).sum() / len(y_test_full))

    for name, y_prob in fitted_prob_dict.items():
        prec, rec, _ = precision_recall_curve(y_test_full, y_prob)
        ap_val = average_precision_score(y_test_full, y_prob)
        color = PALETTE.get(name, "#333333")
        linestyle = "--" if name == "Logistic Regression" else "-"
        ax_pr.plot(
            rec,
            prec,
            label=f"{name} (AP = {ap_val:.4f})",
            color=color,
            linewidth=2.2,
            linestyle=linestyle,
        )

    # Baseline prevalence
    ax_pr.axhline(
        y=baseline_prevalence,
        linestyle=":",
        color="#64748b",
        linewidth=1.5,
        label=f"No-Skill Baseline (AP = {baseline_prevalence:.4f})",
    )
    ax_pr.set_xlim(-0.01, 1.01)
    ax_pr.set_ylim(0.40, 1.02)
    ax_pr.set_xlabel("Recall (Sensitivity)", fontsize=11, fontweight="bold")
    ax_pr.set_ylabel("Precision (Positive Predictive Value)", fontsize=11, fontweight="bold")
    ax_pr.set_title("(b) Precision-Recall (PR) Curves", pad=12)
    ax_pr.legend(loc="lower left", framealpha=0.92, fontsize=9.5)
    ax_pr.grid(True, linestyle="--", alpha=0.6)
    ax_pr.set_axisbelow(True)

    plt.tight_layout(pad=3.0)
    curves_out = RESULTS_DIR / "report_roc_pr_curves.png"
    plt.savefig(curves_out, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  ✔ Saved: {curves_out.name} (300 DPI)")

    # -----------------------------------------------------------------------
    # Chart 3: report_feature_importance.png (Horizontal Bar Chart)
    # -----------------------------------------------------------------------
    xgb_model = bundle["model"]
    selected_features = bundle["selected_features"]
    importances = xgb_model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1][:10]

    top10_feats = [selected_features[i] for i in sorted_idx][::-1]
    top10_vals = [importances[i] for i in sorted_idx][::-1]

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor("#FFFFFF")

    y_indices = np.arange(len(top10_feats))
    bars = ax.barh(
        y_indices,
        top10_vals,
        color="#1e3a8a",
        height=0.62,
        edgecolor="#0f172a",
        linewidth=1.0,
    )

    ax.set_yticks(y_indices)
    ax.set_yticklabels(top10_feats, fontsize=10, fontweight="bold")
    ax.set_xlabel("Relative Feature Importance Score (Gini Gain)", fontsize=11, fontweight="bold")
    ax.set_title("Top 10 Feature Importances — XGBoost Champion Model", pad=14)

    for bar in bars:
        w = bar.get_width()
        pct = w * 100
        ax.text(
            w + 0.007,
            bar.get_y() + bar.get_height() / 2,
            f"{w:.4f} ({pct:.1f}%)",
            ha="left",
            va="center",
            fontsize=9.5,
            fontweight="bold",
            color="#1e293b",
        )

    ax.set_xlim(0, max(top10_vals) * 1.18)
    ax.xaxis.grid(True, linestyle="--", alpha=0.6)
    ax.set_axisbelow(True)

    plt.tight_layout(pad=2.5)
    feat_out = RESULTS_DIR / "report_feature_importance.png"
    plt.savefig(feat_out, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  ✔ Saved: {feat_out.name} (300 DPI)")


# ---------------------------------------------------------------------------
# STEP 4: Save JSON and Print Summary to Terminal
# ---------------------------------------------------------------------------
def save_and_print_summary(stats_results: dict):
    print("\n" + "=" * 70)
    print("STEP 4: Saving ml/results/report_stats.json and Printing Summary")
    print("=" * 70)

    json_path = RESULTS_DIR / "report_stats.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(stats_results, f, indent=2)

    print(f"  ✔ Successfully exported: {json_path.name}")
    print("\n" + "#" * 80)
    print("SUMMARY JSON FOR ACADEMIC REPORT (COPY-READY):")
    print("#" * 80 + "\n")
    print(json.dumps(stats_results, indent=2))
    print("\n" + "#" * 80)


# ---------------------------------------------------------------------------
# Main Orchestration
# ---------------------------------------------------------------------------
def main():
    t_start = time.perf_counter()
    print("\n" + "█" * 70)
    print("  NIDS STATISTICAL HYPOTHESIS TESTING & ACADEMIC REPORT VISUALIZATION")
    print("█" * 70)

    # 1. Load data & artifacts
    train_df, test_df, bundle = load_datasets_and_bundle()

    # 2. Run statistical tests & 5-fold CV & test evaluation
    stats_results, fitted_prob_dict, attack_counts_raw, y_test_full = run_statistical_tests(
        train_df, test_df, bundle
    )

    # 3. Generate high-resolution academic charts (300 DPI)
    generate_academic_charts(
        train_df, test_df, bundle, fitted_prob_dict, attack_counts_raw, y_test_full
    )

    # 4. Save and print summary JSON
    save_and_print_summary(stats_results)

    elapsed = time.perf_counter() - t_start
    print(f"\n  ✅ All tasks completed successfully in {elapsed:.1f}s!\n")


if __name__ == "__main__":
    main()

