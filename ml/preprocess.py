"""
ml/preprocess.py
================
Phase 2 — Data Preprocessing Pipeline for the Network Intrusion Detection System.

Steps performed:
  1. Memory-safe loading of all 8 CICIDS2017 CSV files (float64->float32, int64->int32).
  2. Data cleaning  : inf/nan removal, deduplication, constant-column & ID-column drops.
  3. Target encoding: preserve Attack_Type string; create binary Label_Binary (0/1).
  4. Stratified cap  : sample at most 600,000 rows keeping Attack_Type proportions.
  5. Stratified 80/20 train-test split (zero data leakage).
  6. Feature selection: RandomForestClassifier fitted ONLY on training set → Top 25 features.
  7. Save outputs to dataset/processed/:
       train.parquet, test.parquet, demo_test_flows.csv, selected_features.json
"""

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import psutil                           # For RAM usage reporting
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# ---------------------------------------------------------------------------
# 0. Resolve project root & output directory (portable — works on Win & macOS)
# ---------------------------------------------------------------------------
# This file lives at  <project_root>/ml/preprocess.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR      = PROJECT_ROOT / "dataset" / "raw" / "MachineLearningCVE"
PROCESSED_DIR = PROJECT_ROOT / "dataset" / "processed"

# Create output directory if it doesn't exist yet
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Helper: print RAM currently used by this Python process
# ---------------------------------------------------------------------------
def ram_used_mb() -> float:
    """Return RSS memory used by the current process in megabytes."""
    process = psutil.Process()
    return process.memory_info().rss / (1024 ** 2)


# ---------------------------------------------------------------------------
# 1. Memory-Safe Loading
# ---------------------------------------------------------------------------
print("=" * 65)
print("STEP 1 — Loading all CSV files from dataset/raw/MachineLearningCVE/")
print("=" * 65)

csv_files = sorted(RAW_DIR.glob("*.csv"))
if not csv_files:
    print(f"ERROR: No CSV files found in {RAW_DIR}")
    sys.exit(1)

print(f"  Found {len(csv_files)} CSV file(s):")
for f in csv_files:
    print(f"    - {f.name}")

chunks = []
total_raw_rows = 0

for csv_path in csv_files:
    t0 = time.time()
    # Read one file at a time to control peak RAM
    df_chunk = pd.read_csv(csv_path, low_memory=False)

    # --- Strip whitespace from ALL column names ---
    df_chunk.columns = df_chunk.columns.str.strip()

    # --- Downcast float64 → float32 (saves ~50 % RAM) ---
    float_cols = df_chunk.select_dtypes(include="float64").columns
    df_chunk[float_cols] = df_chunk[float_cols].astype("float32")

    # --- Downcast int64 → int32 ---
    int_cols = df_chunk.select_dtypes(include="int64").columns
    df_chunk[int_cols] = df_chunk[int_cols].astype("int32")

    elapsed = time.time() - t0
    print(f"  Loaded '{csv_path.name}': {len(df_chunk):>8,} rows | "
          f"RAM: {ram_used_mb():.0f} MB | {elapsed:.1f}s")
    total_raw_rows += len(df_chunk)
    chunks.append(df_chunk)

# Concatenate all files into one DataFrame
print(f"\n  Concatenating all files …")
df = pd.concat(chunks, ignore_index=True)
del chunks   # Free list memory immediately
print(f"  Total rows loaded: {total_raw_rows:,}")
print(f"  Merged shape     : {df.shape}")
print(f"  RAM after merge  : {ram_used_mb():.0f} MB")


# ---------------------------------------------------------------------------
# 2. Data Cleaning
# ---------------------------------------------------------------------------
print("\n" + "=" * 65)
print("STEP 2 — Data Cleaning")
print("=" * 65)

rows_before = len(df)

# 2a. Replace +inf / -inf with NaN, then drop NaN rows
print("  Replacing ±inf with NaN and dropping NaN rows …")
df = df.replace([np.inf, -np.inf], np.nan).dropna()
print(f"  Rows after NaN drop : {len(df):,}  (removed {rows_before - len(df):,})")

# 2b. Drop exact duplicate rows
rows_before_dedup = len(df)
df = df.drop_duplicates()
print(f"  Rows after dedup    : {len(df):,}  (removed {rows_before_dedup - len(df):,} duplicates)")

# 2c. Drop constant (zero-variance) columns — they carry no information
constant_cols = [c for c in df.columns if df[c].nunique() <= 1]
if constant_cols:
    print(f"  Dropping {len(constant_cols)} constant column(s): {constant_cols}")
    df = df.drop(columns=constant_cols)
else:
    print("  No constant columns found.")

# 2d. Drop non-feature identifier columns if present
id_cols_to_drop = ["Flow ID", "Source IP", "Destination IP", "Timestamp"]
present_id_cols = [c for c in id_cols_to_drop if c in df.columns]
if present_id_cols:
    print(f"  Dropping identifier columns: {present_id_cols}")
    df.drop(columns=present_id_cols, inplace=True)
else:
    print("  No identifier columns (Flow ID / IP / Timestamp) found.")

print(f"  Shape after cleaning: {df.shape}")
print(f"  RAM after cleaning  : {ram_used_mb():.0f} MB")


# ---------------------------------------------------------------------------
# 3. Target Encoding
# ---------------------------------------------------------------------------
print("\n" + "=" * 65)
print("STEP 3 — Target Encoding")
print("=" * 65)

# Verify 'Label' column exists
if "Label" not in df.columns:
    print("ERROR: 'Label' column not found. Available columns:")
    print(list(df.columns))
    sys.exit(1)

# 3a. Preserve original attack-type string in a new column
df["Attack_Type"] = df["Label"].astype(str).str.strip()

# 3b. Create binary target: 0 = BENIGN, 1 = Intrusion
df["Label_Binary"] = (df["Attack_Type"] != "BENIGN").astype("int32")

print(f"  Unique attack types : {df['Attack_Type'].nunique()}")
print(f"  Class distribution  :")
class_counts = df["Label_Binary"].value_counts()
print(f"    BENIGN (0) : {class_counts.get(0, 0):>8,}")
print(f"    ATTACK (1) : {class_counts.get(1, 0):>8,}")


# ---------------------------------------------------------------------------
# 4. Stratified Cap (max 600,000 rows) + 80 / 20 Split
# ---------------------------------------------------------------------------
print("\n" + "=" * 65)
print("STEP 4 — Stratified Cap (600,000 rows) & 80/20 Train-Test Split")
print("=" * 65)

CAP = 600_000

if len(df) > CAP:
    # Stratified sample preserving Attack_Type proportions
    print(f"  Dataset has {len(df):,} rows — sampling {CAP:,} rows (stratified by Attack_Type) …")
    df, _ = train_test_split(
        df,
        train_size=CAP,
        stratify=df["Attack_Type"],
        random_state=42
    )
    df = df.reset_index(drop=True)
    print(f"  Shape after cap     : {df.shape}")
else:
    print(f"  Dataset has {len(df):,} rows — no cap needed.")

# 4a. Define feature matrix X and target y
#     Exclude Label, Attack_Type, Label_Binary from features
non_feature_cols = {"Label", "Attack_Type", "Label_Binary"}
feature_cols = [c for c in df.columns if c not in non_feature_cols]

X = df[feature_cols]
y = df["Label_Binary"]
attack_types = df["Attack_Type"]   # Keep for demo CSV later

# 4b. Stratified 80 / 20 split (BEFORE any scaling — prevents data leakage)
print("  Performing 80/20 stratified train-test split …")
(X_train, X_test,
 y_train, y_test,
 at_train, at_test) = train_test_split(
    X, y, attack_types,
    test_size=0.20,
    stratify=y,
    random_state=42
)

print(f"  Training set shape  : {X_train.shape}")
print(f"  Testing  set shape  : {X_test.shape}")
print(f"  RAM after split     : {ram_used_mb():.0f} MB")


# ---------------------------------------------------------------------------
# 5. Feature Selection — fit ONLY on training set (no leakage)
# ---------------------------------------------------------------------------
print("\n" + "=" * 65)
print("STEP 5 — Feature Selection (RandomForest fitted on training set only)")
print("=" * 65)

print("  Training RandomForestClassifier(n_estimators=50, max_depth=12) …")
t0 = time.time()
rf_selector = RandomForestClassifier(
    n_estimators=50,
    max_depth=12,
    n_jobs=-1,
    random_state=42
)
rf_selector.fit(X_train, y_train)
elapsed = time.time() - t0
print(f"  Training completed in {elapsed:.1f}s")

# Rank features by importance
importances = pd.Series(rf_selector.feature_importances_, index=feature_cols)
importances = importances.sort_values(ascending=False)

TOP_N = 25
top_features = importances.head(TOP_N).index.tolist()

print(f"\n  Top 10 selected features (of {TOP_N}):")
for rank, (feat, score) in enumerate(importances.head(10).items(), start=1):
    print(f"    {rank:>2}. {feat:<40}  importance={score:.6f}")

print(f"\n  Full Top {TOP_N} list: {top_features}")


# ---------------------------------------------------------------------------
# 6. Save Processed Outputs to dataset/processed/
# ---------------------------------------------------------------------------
print("\n" + "=" * 65)
print("STEP 6 — Saving processed outputs to dataset/processed/")
print("=" * 65)

# --- 6a. train.parquet ---
train_df = X_train[top_features].copy()
train_df["Label_Binary"] = y_train.values
train_path = PROCESSED_DIR / "train.parquet"
train_df.to_parquet(train_path, index=False)
print(f"  ✔ Saved train.parquet        : {train_df.shape}  →  {train_path}")

# --- 6b. test.parquet ---
test_df = X_test[top_features].copy()
test_df["Label_Binary"] = y_test.values
test_path = PROCESSED_DIR / "test.parquet"
test_df.to_parquet(test_path, index=False)
print(f"  ✔ Saved test.parquet         : {test_df.shape}  →  {test_path}")

# --- 6c. demo_test_flows.csv (500 stratified rows from test set) ---
#     Includes Top 25 features + Attack_Type + Label_Binary
demo_df_full = X_test[top_features].copy()
demo_df_full["Attack_Type"] = at_test.values
demo_df_full["Label_Binary"] = y_test.values

DEMO_SIZE = 500
# Stratified sample from test set preserving Label_Binary proportions
_, demo_df = train_test_split(
    demo_df_full,
    test_size=min(DEMO_SIZE, len(demo_df_full)),
    stratify=demo_df_full["Label_Binary"],
    random_state=42
)
demo_path = PROCESSED_DIR / "demo_test_flows.csv"
demo_df.to_csv(demo_path, index=False)
print(f"  ✔ Saved demo_test_flows.csv  : {demo_df.shape}  →  {demo_path}")

# --- 6d. selected_features.json ---
features_path = PROCESSED_DIR / "selected_features.json"
with open(features_path, "w") as fh:
    json.dump(top_features, fh, indent=2)
print(f"  ✔ Saved selected_features.json ({len(top_features)} features) →  {features_path}")


# ---------------------------------------------------------------------------
# 7. Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 65)
print("PREPROCESSING COMPLETE — Summary")
print("=" * 65)
print(f"  Final training set : {train_df.shape}")
print(f"  Final testing  set : {test_df.shape}")
print(f"  Demo CSV sample    : {demo_df.shape}")
print(f"  Selected features  : {len(top_features)}")
print(f"  RAM used at finish : {ram_used_mb():.0f} MB")
print(f"\n  Output files in: {PROCESSED_DIR}")
print("  - train.parquet")
print("  - test.parquet")
print("  - demo_test_flows.csv")
print("  - selected_features.json")
print("=" * 65)
print("All done! ✔")

