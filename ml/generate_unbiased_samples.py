"""
ml/generate_unbiased_samples.py
================================
Generates 5 completely unseen, unbiased demo CSV scenario files inside dataset/samples/
by sampling from the raw CICIDS2017 CSV files in dataset/raw/MachineLearningCVE/.

Guarantees:
  1. 100% Out-of-Sample: Explicitly filters out all rows present in dataset/processed/train.parquet
     and dataset/processed/test.parquet (zero data leakage / zero overlap).
  2. Mutually Exclusive: Ensures no flow is repeated across any of the 5 generated sample files.
  3. Preprocessing Fidelity: Cleans +/-inf and NaN values, downcasts types, and strips whitespace
     identically to ml/preprocess.py.
  4. Complete Feature Set: Contains all 25 model features listed in selected_features.json, PLUS:
       - Human-readable problem-statement metadata: Source IP, Destination IP, Protocol (derived accurately)
       - Ground-truth evaluation columns: label_binary (0/1) and attack_category
  5. Evaluation: Loads ml/models/nids_bundle.joblib, evaluates each scenario passing only the 25
     selected features, and reports terminal out-of-sample metrics (Accuracy, Precision, Recall, F1).

Generated Scenarios (inside dataset/samples/):
  1. 1_normal_office_traffic.csv  (300 flows: ~95% BENIGN normal traffic, ~5% attack noise)
  2. 2_ddos_flood_attack.csv      (300 flows: ~80% DDoS / DoS Hulk / GoldenEye floods, ~20% BENIGN)
  3. 3_port_scan_recon.csv        (300 flows: ~80% PortScan reconnaissance sweeps, ~20% BENIGN)
  4. 4_brute_force_ssh_web.csv    (300 flows: ~75% SSH-Patator / FTP-Patator / Web Attack, ~25% BENIGN)
  5. 5_mixed_enterprise_soc.csv   (500 flows: realistic enterprise SOC mix, ~75% BENIGN, ~25% attacks)
"""

import gc
import json
import random
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

# ---------------------------------------------------------------------------
# 0. Path Resolution (Portable across Windows & macOS — No hardcoded paths)
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "dataset" / "raw" / "MachineLearningCVE"
PROCESSED_DIR = PROJECT_ROOT / "dataset" / "processed"
SAMPLES_DIR = PROJECT_ROOT / "dataset" / "samples"
MODELS_DIR = PROJECT_ROOT / "ml" / "models"

BUNDLE_PATH = MODELS_DIR / "nids_bundle.joblib"
FEATURES_PATH = PROCESSED_DIR / "selected_features.json"
TRAIN_PARQUET = PROCESSED_DIR / "train.parquet"
TEST_PARQUET = PROCESSED_DIR / "test.parquet"

# Create output samples directory
SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

# Fixed random seed for deterministic, reproducible sampling
SEED = 42
random.seed(SEED)
np.random.seed(SEED)


# ---------------------------------------------------------------------------
# 1. Helper: Network Metadata Derivation (Source IP, Destination IP, Protocol)
# ---------------------------------------------------------------------------
# Realistic IP allocations matching the CICIDS2017 network topology
LAN_WORKSTATIONS = [
    "192.168.10.8",
    "192.168.10.9",
    "192.168.10.12",
    "192.168.10.14",
    "192.168.10.15",
    "192.168.10.17",
    "192.168.10.19",
]

TARGET_SERVERS = {
    "web": "192.168.10.50",       # HTTP/HTTPS Web Server
    "admin": "192.168.10.51",     # Ubuntu SSH/FTP Server
    "dns_dc": "192.168.10.3",     # Domain Controller / Local DNS / SMB
    "internal_db": "192.168.10.25"  # Internal Database Server
}

ATTACKER_IPS = {
    "kali": "205.174.165.73",      # Primary external attacker (Kali machine)
    "botnet": [                   # Distributed DDoS / zombie botnet reflection nodes
        "172.16.0.1",
        "185.190.140.42",
        "194.26.29.115",
        "45.33.32.156",
        "91.189.91.157",
        "104.160.18.23",
        "198.51.100.44",
        "203.0.113.88",
    ],
    "insider_recon": "192.168.10.14",  # Compromised workstation scanning internal subnet
}

PUBLIC_SERVICES = [
    "172.217.16.206",  # Google Search / Apps
    "151.101.1.140",   # Fastly Global CDN
    "13.107.42.14",    # Microsoft 365 / Cloud
    "52.84.22.99",     # AWS CloudFront CDN
    "104.244.42.1",    # Communication Services
]

PUBLIC_DNS = ["8.8.8.8", "1.1.1.1"]

COMMON_UDP_PORTS = {
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 5353, 5355
}


def derive_protocol(port: int, row_data: dict) -> str:
    """
    Accurately derives the transport layer protocol (TCP, UDP, or ICMP)
    based on Destination Port and TCP flag counts.
    """
    if port == 0:
        return "ICMP"
    if port in COMMON_UDP_PORTS:
        return "UDP"

    # Check for TCP connection indicators
    ack = row_data.get("ACK Flag Count", 0)
    syn = row_data.get("SYN Flag Count", 0)
    fin = row_data.get("FIN Flag Count", 0)
    rst = row_data.get("RST Flag Count", 0)
    psh = row_data.get("PSH Flag Count", 0)
    urg = row_data.get("URG Flag Count", 0)
    init_win = row_data.get("Init_Win_bytes_forward", 0)

    if (ack + syn + fin + rst + psh + urg) > 0 or init_win >= 0:
        return "TCP"
    if init_win == -1:
        return "UDP"

    # Default to TCP for standard stateful ports
    return "TCP"


def assign_ips(port: int, attack_category: str, label_binary: int, flow_idx: int) -> tuple[str, str]:
    """
    Assigns realistic, contextually accurate Source and Destination IP addresses
    based on the attack scenario, destination port, and host role.
    """
    if label_binary == 1:
        # Attack traffic
        if "DDoS" in attack_category:
            src_ip = ATTACKER_IPS["botnet"][flow_idx % len(ATTACKER_IPS["botnet"])]
            dst_ip = TARGET_SERVERS["web"]
        elif "DoS" in attack_category:
            src_ip = ATTACKER_IPS["kali"] if (flow_idx % 2 == 0) else ATTACKER_IPS["botnet"][0]
            dst_ip = TARGET_SERVERS["web"]
        elif "PortScan" in attack_category:
            src_ip = ATTACKER_IPS["kali"] if (flow_idx % 6 != 0) else ATTACKER_IPS["insider_recon"]
            target_list = [TARGET_SERVERS["web"], TARGET_SERVERS["admin"], TARGET_SERVERS["dns_dc"], TARGET_SERVERS["internal_db"]]
            dst_ip = target_list[flow_idx % len(target_list)]
        elif "SSH" in attack_category:
            src_ip = ATTACKER_IPS["kali"]
            dst_ip = TARGET_SERVERS["admin"]
        elif "FTP" in attack_category:
            src_ip = ATTACKER_IPS["kali"]
            dst_ip = TARGET_SERVERS["admin"]
        elif "Web Attack" in attack_category:
            src_ip = ATTACKER_IPS["kali"]
            dst_ip = TARGET_SERVERS["web"]
        elif "Bot" in attack_category:
            src_ip = LAN_WORKSTATIONS[flow_idx % len(LAN_WORKSTATIONS)]
            dst_ip = ATTACKER_IPS["kali"]
        elif "Infiltration" in attack_category:
            src_ip = ATTACKER_IPS["kali"]
            dst_ip = TARGET_SERVERS["internal_db"]
        else:
            src_ip = ATTACKER_IPS["kali"]
            dst_ip = TARGET_SERVERS["web"]
    else:
        # BENIGN office traffic originating from internal workstations
        src_ip = LAN_WORKSTATIONS[flow_idx % len(LAN_WORKSTATIONS)]
        if port == 53:
            dst_ip = TARGET_SERVERS["dns_dc"] if (flow_idx % 2 == 0) else PUBLIC_DNS[flow_idx % len(PUBLIC_DNS)]
        elif port in (80, 443):
            dst_ip = PUBLIC_SERVICES[flow_idx % len(PUBLIC_SERVICES)] if (flow_idx % 4 != 0) else TARGET_SERVERS["web"]
        elif port == 22:
            dst_ip = TARGET_SERVERS["admin"]
        elif port == 445:
            dst_ip = TARGET_SERVERS["dns_dc"]
        elif port == 21:
            dst_ip = TARGET_SERVERS["admin"]
        else:
            dst_ip = TARGET_SERVERS["web"] if (flow_idx % 2 == 0) else PUBLIC_SERVICES[flow_idx % len(PUBLIC_SERVICES)]

    return src_ip, dst_ip


def clean_label_string(label: str) -> str:
    """
    Normalizes corrupted character encodings in raw CSV labels (e.g., 'Web Attack ï¿½ Brute Force').
    """
    label_str = str(label).strip()
    if "Web Attack" in label_str:
        if "Brute Force" in label_str:
            return "Web Attack - Brute Force"
        elif "XSS" in label_str:
            return "Web Attack - XSS"
        elif "Sql Injection" in label_str:
            return "Web Attack - Sql Injection"
        return "Web Attack"
    return label_str


# ---------------------------------------------------------------------------
# 2. Step 1: Index Processed Train/Test Flows to Guarantee Zero Leakage
# ---------------------------------------------------------------------------
def build_processed_hash_index(selected_features: list[str]) -> set:
    """
    Loads train.parquet and test.parquet and hashes their 25 selected features.
    Any raw row matching any hash in this set is strictly discarded.
    """
    print("\n" + "=" * 70)
    print("STEP 1 — Indexing Processed train.parquet & test.parquet")
    print("=" * 70)

    if not TRAIN_PARQUET.exists() or not TEST_PARQUET.exists():
        print("ERROR: Processed parquet files not found in dataset/processed/.")
        sys.exit(1)

    t0 = time.time()
    train_df = pd.read_parquet(TRAIN_PARQUET, columns=selected_features)
    test_df = pd.read_parquet(TEST_PARQUET, columns=selected_features)

    combined = pd.concat([train_df, test_df], ignore_index=True)
    seen_hashes = set(pd.util.hash_pandas_object(combined, index=False).values)

    print(f"  ✔ train.parquet rows  : {len(train_df):,}")
    print(f"  ✔ test.parquet rows   : {len(test_df):,}")
    print(f"  ✔ Total processed     : {len(combined):,} flows")
    print(f"  ✔ Unique feature hashes: {len(seen_hashes):,}")
    print(f"  ✔ Indexing completed in {time.time() - t0:.2f}s")

    del train_df, test_df, combined
    gc.collect()

    return seen_hashes


# ---------------------------------------------------------------------------
# 3. Step 2: Extract Pools of Untouched Raw Out-of-Sample Flows
# ---------------------------------------------------------------------------
def extract_candidate_pools(selected_features: list[str], seen_hashes: set) -> dict[str, pd.DataFrame]:
    """
    Reads required raw CSV files one-by-one to conserve laptop RAM, cleans inf/nan,
    downcasts numeric types identically to preprocess.py, and filters out all rows
    present in seen_hashes.
    """
    print("\n" + "=" * 70)
    print("STEP 2 — Extracting Candidate Pools from Raw CICIDS2017 CSVs")
    print("=" * 70)

    # Global set tracking all hashes selected for samples (prevents duplicates across the 5 files)
    used_hashes = set(seen_hashes)

    # Configuration for source raw files and quotas needed
    extraction_configs = [
        {
            "filename": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
            "targets": {"DDoS": 300, "BENIGN": 150},
        },
        {
            "filename": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            "targets": {"PortScan": 320, "BENIGN": 150},
        },
        {
            "filename": "Tuesday-WorkingHours.pcap_ISCX.csv",
            "targets": {"SSH-Patator": 120, "FTP-Patator": 120, "BENIGN": 150},
        },
        {
            "filename": "Wednesday-workingHours.pcap_ISCX.csv",
            "targets": {"DoS Hulk": 150, "DoS GoldenEye": 60, "DoS slowloris": 40, "BENIGN": 200},
        },
        {
            "filename": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
            "targets": {"Web Attack": 130, "BENIGN": 150},
        },
        {
            "filename": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
            "targets": {"Bot": 25, "BENIGN": 100},
        },
        {
            "filename": "Monday-WorkingHours.pcap_ISCX.csv",
            "targets": {"BENIGN": 600},
        },
    ]

    pools = {}

    for cfg in extraction_configs:
        fname = cfg["filename"]
        fpath = RAW_DIR / fname
        if not fpath.exists():
            print(f"  WARNING: Raw file {fname} not found in {RAW_DIR}. Skipping.")
            continue

        t_file = time.time()
        print(f"  Loading '{fname}' ...")
        df_raw = pd.read_csv(fpath, encoding="cp1252", low_memory=False)

        # 1. Clean whitespace from columns
        df_raw.columns = df_raw.columns.str.strip()

        # 2. Downcast numeric dtypes
        float_cols = df_raw.select_dtypes(include="float64").columns
        df_raw[float_cols] = df_raw[float_cols].astype("float32")
        int_cols = df_raw.select_dtypes(include="int64").columns
        df_raw[int_cols] = df_raw[int_cols].astype("int32")

        # 3. Clean +/- inf and NaN values identically to preprocess.py
        df_raw = df_raw.replace([np.inf, -np.inf], np.nan).dropna()
        df_raw = df_raw.drop_duplicates()

        # 4. Hash selected 25 features and strictly exclude processed train/test flows
        row_hashes = pd.util.hash_pandas_object(df_raw[selected_features], index=False)
        untouched_mask = ~row_hashes.isin(used_hashes)
        df_untouched = df_raw[untouched_mask].copy()
        df_untouched["_flow_hash"] = row_hashes[untouched_mask].values

        # 5. Extract target samples per category
        for label_key, count in cfg["targets"].items():
            if label_key == "BENIGN":
                subset = df_untouched[df_untouched["Label"].astype(str).str.strip() == "BENIGN"]
            else:
                subset = df_untouched[df_untouched["Label"].astype(str).str.strip().str.contains(label_key, regex=False)]

            n_to_sample = min(count, len(subset))
            if n_to_sample > 0:
                sampled = subset.sample(n=n_to_sample, random_state=SEED)
                pool_key = f"{fname}::{label_key}"
                pools[pool_key] = sampled

                # Mark these hashes as used globally
                used_hashes.update(sampled["_flow_hash"].values)
                print(f"    ✔ [{label_key:<14}] Sampled: {n_to_sample:>4} flows (available untouched: {len(subset):,})")

        elapsed_file = time.time() - t_file
        print(f"    Completed '{fname}' in {elapsed_file:.1f}s")

        del df_raw, df_untouched
        gc.collect()

    return pools


# ---------------------------------------------------------------------------
# 4. Step 3: Assemble the 5 Specific Evaluation Scenarios
# ---------------------------------------------------------------------------
def assemble_and_format_scenario(
    dfs_to_combine: list[pd.DataFrame],
    target_count: int,
    scenario_name: str,
    selected_features: list[str],
) -> pd.DataFrame:
    """
    Combines sub-samples into a single scenario DataFrame, generates metadata columns
    (Source IP, Destination IP, Protocol, label_binary, attack_category), and shuffles rows.
    """
    merged_raw = pd.concat(dfs_to_combine, ignore_index=True)

    # Shuffle rows so attacks and normal flows are realistically interleaved
    merged_raw = merged_raw.sample(frac=1.0, random_state=SEED).reset_index(drop=True)

    # Trim to exact target count if slightly exceeded
    if len(merged_raw) > target_count:
        merged_raw = merged_raw.iloc[:target_count].copy()

    # Build metadata columns
    source_ips = []
    dest_ips = []
    protocols = []
    binary_labels = []
    attack_categories = []

    for idx, row in merged_raw.iterrows():
        port = int(row["Destination Port"])
        raw_label = str(row["Label"]).strip()
        cleaned_cat = clean_label_string(raw_label)
        is_attack = 0 if cleaned_cat == "BENIGN" else 1

        proto = derive_protocol(port, row.to_dict())
        src_ip, dst_ip = assign_ips(port, cleaned_cat, is_attack, idx)

        source_ips.append(src_ip)
        dest_ips.append(dst_ip)
        protocols.append(proto)
        binary_labels.append(is_attack)
        attack_categories.append(cleaned_cat)

    # Construct clean output DataFrame
    output_df = pd.DataFrame()
    output_df["Source IP"] = source_ips
    output_df["Destination IP"] = dest_ips
    output_df["Protocol"] = protocols

    # Attach all 25 model features
    for col in selected_features:
        output_df[col] = merged_raw[col].values

    # Attach ground truth evaluation columns
    output_df["label_binary"] = binary_labels
    output_df["attack_category"] = attack_categories

    return output_df


def build_all_scenarios(pools: dict[str, pd.DataFrame], selected_features: list[str]) -> dict[str, pd.DataFrame]:
    """
    Constructs the 5 distinct scenario DataFrames according to user-specified percentages and counts.
    """
    print("\n" + "=" * 70)
    print("STEP 3 — Constructing 5 Distinct Scenarios")
    print("=" * 70)

    scenarios = {}

    # Helper to slice from a pool safely
    pool_offsets = {k: 0 for k in pools.keys()}

    def get_slice(pool_key: str, count: int) -> pd.DataFrame:
        if pool_key not in pools:
            raise KeyError(f"Pool key {pool_key} not found.")
        df_pool = pools[pool_key]
        offset = pool_offsets[pool_key]
        sliced = df_pool.iloc[offset: offset + count].copy()
        pool_offsets[pool_key] += count
        return sliced

    # -----------------------------------------------------------------------
    # Scenario 1: 1_normal_office_traffic.csv (300 flows: ~95% BENIGN, ~5% attack noise)
    # -----------------------------------------------------------------------
    # 285 BENIGN + 15 attack noise (5 PortScan, 5 Web Attack, 3 SSH-Patator, 2 DDoS)
    s1_parts = [
        get_slice("Monday-WorkingHours.pcap_ISCX.csv::BENIGN", 150),
        get_slice("Tuesday-WorkingHours.pcap_ISCX.csv::BENIGN", 75),
        get_slice("Friday-WorkingHours-Morning.pcap_ISCX.csv::BENIGN", 60),
        get_slice("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv::PortScan", 5),
        get_slice("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv::Web Attack", 5),
        get_slice("Tuesday-WorkingHours.pcap_ISCX.csv::SSH-Patator", 3),
        get_slice("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv::DDoS", 2),
    ]
    scenarios["1_normal_office_traffic.csv"] = assemble_and_format_scenario(
        s1_parts, target_count=300, scenario_name="1_normal_office_traffic.csv", selected_features=selected_features
    )

    # -----------------------------------------------------------------------
    # Scenario 2: 2_ddos_flood_attack.csv (300 flows: ~80% DDoS / DoS Hulk / GoldenEye, ~20% BENIGN)
    # -----------------------------------------------------------------------
    # 240 DDoS/DoS (120 DDoS, 80 DoS Hulk, 40 DoS GoldenEye/slowloris) + 60 BENIGN
    s2_parts = [
        get_slice("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv::DDoS", 120),
        get_slice("Wednesday-workingHours.pcap_ISCX.csv::DoS Hulk", 80),
        get_slice("Wednesday-workingHours.pcap_ISCX.csv::DoS GoldenEye", 25),
        get_slice("Wednesday-workingHours.pcap_ISCX.csv::DoS slowloris", 15),
        get_slice("Wednesday-workingHours.pcap_ISCX.csv::BENIGN", 30),
        get_slice("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv::BENIGN", 30),
    ]
    scenarios["2_ddos_flood_attack.csv"] = assemble_and_format_scenario(
        s2_parts, target_count=300, scenario_name="2_ddos_flood_attack.csv", selected_features=selected_features
    )

    # -----------------------------------------------------------------------
    # Scenario 3: 3_port_scan_recon.csv (300 flows: ~80% PortScan sweeps, ~20% BENIGN)
    # -----------------------------------------------------------------------
    # 240 PortScan sweeps + 60 BENIGN
    s3_parts = [
        get_slice("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv::PortScan", 240),
        get_slice("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv::BENIGN", 60),
    ]
    scenarios["3_port_scan_recon.csv"] = assemble_and_format_scenario(
        s3_parts, target_count=300, scenario_name="3_port_scan_recon.csv", selected_features=selected_features
    )

    # -----------------------------------------------------------------------
    # Scenario 4: 4_brute_force_ssh_web.csv (300 flows: ~75% SSH/FTP/Web, ~25% BENIGN)
    # -----------------------------------------------------------------------
    # 225 Brute Force (75 SSH-Patator, 75 FTP-Patator, 75 Web Attack) + 75 BENIGN
    s4_parts = [
        get_slice("Tuesday-WorkingHours.pcap_ISCX.csv::SSH-Patator", 75),
        get_slice("Tuesday-WorkingHours.pcap_ISCX.csv::FTP-Patator", 75),
        get_slice("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv::Web Attack", 75),
        get_slice("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv::BENIGN", 45),
        get_slice("Tuesday-WorkingHours.pcap_ISCX.csv::BENIGN", 30),
    ]
    scenarios["4_brute_force_ssh_web.csv"] = assemble_and_format_scenario(
        s4_parts, target_count=300, scenario_name="4_brute_force_ssh_web.csv", selected_features=selected_features
    )

    # -----------------------------------------------------------------------
    # Scenario 5: 5_mixed_enterprise_soc.csv (500 flows: ~75% BENIGN, ~25% mixed attacks)
    # -----------------------------------------------------------------------
    # 375 BENIGN + 125 Attacks (25 DDoS, 25 DoS Hulk/GoldenEye, 25 PortScan, 25 Patator, 20 Web, 5 Bot)
    s5_parts = [
        get_slice("Monday-WorkingHours.pcap_ISCX.csv::BENIGN", 200),
        get_slice("Wednesday-workingHours.pcap_ISCX.csv::BENIGN", 100),
        get_slice("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv::BENIGN", 45),
        get_slice("Tuesday-WorkingHours.pcap_ISCX.csv::BENIGN", 30),
        get_slice("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv::DDoS", 25),
        get_slice("Wednesday-workingHours.pcap_ISCX.csv::DoS Hulk", 15),
        get_slice("Wednesday-workingHours.pcap_ISCX.csv::DoS GoldenEye", 10),
        get_slice("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv::PortScan", 25),
        get_slice("Tuesday-WorkingHours.pcap_ISCX.csv::SSH-Patator", 15),
        get_slice("Tuesday-WorkingHours.pcap_ISCX.csv::FTP-Patator", 10),
        get_slice("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv::Web Attack", 20),
        get_slice("Friday-WorkingHours-Morning.pcap_ISCX.csv::Bot", 5),
    ]
    scenarios["5_mixed_enterprise_soc.csv"] = assemble_and_format_scenario(
        s5_parts, target_count=500, scenario_name="5_mixed_enterprise_soc.csv", selected_features=selected_features
    )

    return scenarios


# ---------------------------------------------------------------------------
# 5. Step 4: Verification of Out-of-Sample Integrity & Save CSVs
# ---------------------------------------------------------------------------
def verify_and_save_scenarios(
    scenarios: dict[str, pd.DataFrame],
    selected_features: list[str],
    seen_hashes: set,
) -> None:
    """
    Validates that:
      1. Every row in each scenario has zero collisions with train.parquet and test.parquet.
      2. No flow is duplicated across different scenario files.
      3. Saves the CSV files into dataset/samples/.
    """
    print("\n" + "=" * 70)
    print("STEP 4 — Verifying 100% Out-of-Sample Integrity & Saving CSV Files")
    print("=" * 70)

    seen_scenario_hashes = set()

    for filename, df in scenarios.items():
        # Compute hashes of the 25 model features
        feature_hashes = pd.util.hash_pandas_object(df[selected_features], index=False)

        # 1. Check against train + test
        overlap_train_test = feature_hashes.isin(seen_hashes).sum()
        if overlap_train_test > 0:
            raise RuntimeError(
                f"INTEGRITY ERROR: {overlap_train_test} rows in {filename} overlap with train/test.parquet!"
            )

        # 2. Check against previous scenarios
        overlap_scenarios = feature_hashes.isin(seen_scenario_hashes).sum()
        if overlap_scenarios > 0:
            raise RuntimeError(
                f"INTEGRITY ERROR: {overlap_scenarios} rows in {filename} overlap with another scenario file!"
            )
        seen_scenario_hashes.update(feature_hashes.values)

        # 3. Save CSV to dataset/samples/
        out_path = SAMPLES_DIR / filename
        df.to_csv(out_path, index=False)

        # Print breakdown
        n_total = len(df)
        n_benign = int((df["label_binary"] == 0).sum())
        n_attack = int((df["label_binary"] == 1).sum())
        pct_attack = (n_attack / n_total) * 100

        print(f"  ✔ Saved: {out_path.name:<28} | Rows: {n_total:>3} "
              f"| Normal: {n_benign:>3} ({(n_benign/n_total)*100:.1f}%) "
              f"| Attack: {n_attack:>3} ({pct_attack:.1f}%) "
              f"| 0 Train/Test Overlap ✔")

    print("\n  ✔ All 5 files passed strict zero-leakage verification!")


# ---------------------------------------------------------------------------
# 6. Step 5: Evaluate Scenarios Against ml/models/nids_bundle.joblib
# ---------------------------------------------------------------------------
def evaluate_against_bundle(scenarios: dict[str, pd.DataFrame], selected_features: list[str]) -> None:
    """
    Loads nids_bundle.joblib, executes batch inference on each scenario passing ONLY
    the 25 selected features, and prints a terminal evaluation report.
    """
    print("\n" + "=" * 70)
    print("STEP 5 — Out-of-Sample Evaluation Against nids_bundle.joblib")
    print("=" * 70)

    if not BUNDLE_PATH.exists():
        print(f"ERROR: Model bundle not found at {BUNDLE_PATH}")
        sys.exit(1)

    bundle = joblib.load(BUNDLE_PATH)
    model = bundle["model"]
    champion_name = bundle.get("champion_model", "XGBoost")
    threshold = bundle.get("threshold", 0.50)
    bundle_features = bundle.get("selected_features", selected_features)

    print(f"  Active Model    : {champion_name}")
    print(f"  Decision Thresh : {threshold}")
    print(f"  Model Features  : {len(bundle_features)} columns")
    print("-" * 70)

    results_table = []

    for filename in sorted(scenarios.keys()):
        csv_path = SAMPLES_DIR / filename
        # Read back from disk to verify saved file format
        df = pd.read_csv(csv_path)

        # Strictly pass ONLY the 25 selected features to the model
        X = df[bundle_features].replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(np.float32).values
        y_true = df["label_binary"].values

        # Model inference
        probabilities = model.predict_proba(X)[:, 1]
        y_pred = (probabilities >= threshold).astype(int)

        # Compute evaluation metrics
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

        results_table.append({
            "Scenario File": filename,
            "Flows": len(df),
            "True Normal": int((y_true == 0).sum()),
            "True Attack": int((y_true == 1).sum()),
            "Accuracy": f"{acc * 100:.2f}%",
            "Precision": f"{prec * 100:.2f}%",
            "Recall": f"{rec * 100:.2f}%",
            "F1-Score": f"{f1 * 100:.2f}%",
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN": fn,
        })

    # Print formatted terminal report table
    print(f"\n{'Scenario File':<30} | {'Flows':>5} | {'Acc':>7} | {'Prec':>7} | {'Recall':>7} | {'F1':>7} | {'TP/FP/TN/FN':^15}")
    print("-" * 88)
    for r in results_table:
        matrix_str = f"{r['TP']}/{r['FP']}/{r['TN']}/{r['FN']}"
        print(f"{r['Scenario File']:<30} | {r['Flows']:>5} | {r['Accuracy']:>7} | {r['Precision']:>7} | {r['Recall']:>7} | {r['F1-Score']:>7} | {matrix_str:^15}")
    print("-" * 88)

    print("\n" + "=" * 70)
    print("SUMMARY OF GENERATED DEMO SCENARIO FILES")
    print("=" * 70)
    for r in results_table:
        print(f"  • {r['Scenario File']}")
        print(f"      Size: {r['Flows']} flows (Normal: {r['True Normal']}, Attack: {r['True Attack']})")
        print(f"      Out-of-Sample Accuracy: {r['Accuracy']} | F1-Score: {r['F1-Score']}")
        print(f"      Confusion Matrix [TP: {r['TP']}, FP: {r['FP']}, TN: {r['TN']}, FN: {r['FN']}]")
    print("=" * 70)


# ---------------------------------------------------------------------------
# 7. Main Execution Pipeline
# ---------------------------------------------------------------------------
def main():
    start_time = time.time()
    print("\n" + "█" * 70)
    print("  NIDS — Generate 5 Unbiased Out-of-Sample Demo CSV Scenarios")
    print("█" * 70)

    # Load 25 selected features
    with open(FEATURES_PATH, "r", encoding="utf-8") as f:
        selected_features = json.load(f)
    print(f"  Loaded {len(selected_features)} selected features from {FEATURES_PATH.name}")

    # Step 1: Index train + test flows to prevent leakage
    seen_hashes = build_processed_hash_index(selected_features)

    # Step 2: Extract untouched candidate pools
    pools = extract_candidate_pools(selected_features, seen_hashes)

    # Step 3: Construct the 5 scenarios
    scenarios = build_all_scenarios(pools, selected_features)

    # Step 4: Verify zero leakage and save CSV files
    verify_and_save_scenarios(scenarios, selected_features, seen_hashes)

    # Step 5: Evaluate against champion model bundle
    evaluate_against_bundle(scenarios, selected_features)

    total_time = time.time() - start_time
    print(f"\n✔ Completed entire workflow in {total_time:.1f}s")
    print(f"✔ 5 CSV files successfully generated in: {SAMPLES_DIR}")
    print("█" * 70 + "\n")


if __name__ == "__main__":
    main()

