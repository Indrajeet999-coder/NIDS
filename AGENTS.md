# Project Rulebook & Agent Guidelines

## 1. Project Overview
- **Project**: Machine Learning-Based Network Intrusion Detection System (NIDS).
- **Task**: Binary classification (`0` = Normal traffic, `1` = Intrusion / Attack).
- **Dataset**: CICIDS2017 dataset.

---

## 2. Hardware Constraints & Performance Requirements
- **Environment**: Laptop CPU only (AMD Ryzen 5 5500U, 16 GB RAM).
- **Memory Optimization**: Always downcast numeric columns to `float32` / `int32` upon loading to conserve RAM.
- **Resampling Strategy**: Never use SMOTE (memory and CPU prohibitive on large datasets; use class weights or undersampling if needed).
- **Model Efficiency**: Always set `tree_method="hist"` when training XGBoost models.

---

## 3. Folder Structure
- `dataset/raw/MachineLearningCVE/`: Contains the 8 original raw CSV files (**Read-only**).
- `dataset/processed/`: Cleaned, merged, or preprocessed datasets.
- `notebooks/`: Jupyter notebooks for exploratory data analysis (EDA), preprocessing experiments, and model prototyping.
- `ml/models/`: Serialized model files (`.joblib`).
- `ml/results/`: Evaluation metrics, confusion matrices, logs, and benchmark reports.
- `backend/`: FastAPI application serving predictions and handling inference requests.
- `frontend/`: React application providing user interface and dashboard visualization.

---

## 4. Development Rules
1. **Raw Data Protection**: Never modify or overwrite the raw CSV files in `dataset/raw/MachineLearningCVE/`.
2. **Code Simplicity & Readability**: Keep all code clean, beginner-friendly, and well-documented with clear inline comments.

