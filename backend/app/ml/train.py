import os
import joblib
import optuna
import mlflow
import numpy as np
import pandas as pd
import xgboost as xgb
from typing import Dict, Any, Tuple
from pathlib import Path
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score, confusion_matrix

from app.config import settings
from app.ml.features import (
    build_preprocessing_pipeline,
    check_data_leakage,
    AegisPreprocessTransformer,
    ENGINEERED_FEATURES
)

# Silence Optuna logs
optuna.logging.set_verbosity(optuna.logging.WARNING)

def train_ids_model(
    data_path: str = None,
    n_trials: int = 15,
    save_artifacts: bool = True
) -> Tuple[xgb.XGBClassifier, Dict[str, float]]:
    """
    Trains XGBoost Intrusion Detection System model using 5-Fold Stratified CV and Optuna.
    Logs metrics to MLflow and serializes joblib artifacts.
    """
    if data_path is None:
        data_path = settings.DATA_DIR / "synthetic_cicids2017.csv"
        if not os.path.exists(data_path):
            try:
                from scripts.simulate_attack import generate_synthetic_cicids
            except ModuleNotFoundError:
                import sys
                project_root = Path(__file__).resolve().parents[3]
                if str(project_root) not in sys.path:
                    sys.path.insert(0, str(project_root))
                try:
                    from scripts.simulate_attack import generate_synthetic_cicids
                except ModuleNotFoundError:
                    from app.ml.features import RAW_CICIDS_FEATURES
                    def generate_synthetic_cicids(n_samples: int = 5000, seed: int = 42) -> pd.DataFrame:
                        np.random.seed(seed)
                        records = []
                        for _ in range(n_samples):
                            rec = {feat: float(np.random.exponential(100.0)) for feat in RAW_CICIDS_FEATURES}
                            rec["Label"] = "BENIGN" if np.random.rand() > 0.2 else "DoS"
                            records.append(rec)
                        return pd.DataFrame(records)
            df = generate_synthetic_cicids(n_samples=5000)
            os.makedirs(settings.DATA_DIR, exist_ok=True)
            df.to_csv(data_path, index=False)
            
    print(f"[*] Loading training dataset from: {data_path}")
    df = pd.read_csv(data_path)
    
    # 1. Leakage Check
    leakage_info = check_data_leakage(df, label_col="Label")
    print(f"[!] Data Leakage Analysis: Dropping {len(leakage_info['dropped_leakage_columns'])} explicit leakage columns.")
    if leakage_info["suspected_leakage_features"]:
        print(f"[!] Warning: Suspected high correlation features: {leakage_info['suspected_leakage_features']}")
        
    label_col = "Label" if "Label" in df.columns else "label"
    X_raw = df.drop(columns=[label_col], errors="ignore")
    y_multiclass = df[label_col].astype(str)
    
    # Binary label: BENIGN = 0, Attack = 1
    y_binary = (y_multiclass.str.upper() != "BENIGN").astype(int)
    
    # Calculate scale_pos_weight
    neg_count = np.sum(y_binary == 0)
    pos_count = np.sum(y_binary == 1)
    scale_pos_weight = float(neg_count / max(pos_count, 1))
    
    # 2. Feature Preprocessing
    print("[*] Fitting Scikit-Learn Preprocessing Pipeline...")
    pipeline = build_preprocessing_pipeline()
    X_transformed = pipeline.fit_transform(X_raw)
    
    # Get feature names from transformer
    feature_names = pipeline.named_steps["preprocessor"].feature_names_
    X_df = pd.DataFrame(X_transformed, columns=feature_names)
    
    # 3. Optuna Hyperparameter Optimization with 5-Fold Stratified CV
    print(f"[*] Starting Optuna hyperparameter optimization ({n_trials} trials, 5-fold CV)...")
    
    def objective(trial: optuna.Trial) -> float:
        params = {
            "n_estimators": trial.suggest_int("n_estimators", 100, 300),
            "max_depth": trial.suggest_int("max_depth", 3, 8),
            "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
            "scale_pos_weight": scale_pos_weight,
            "random_state": 42,
            "n_jobs": -1,
            "eval_metric": "logloss"
        }
        
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        scores = []
        
        for train_idx, val_idx in skf.split(X_df, y_binary):
            X_tr, X_va = X_df.iloc[train_idx], X_df.iloc[val_idx]
            y_tr, y_va = y_binary.iloc[train_idx], y_binary.iloc[val_idx]
            
            clf = xgb.XGBClassifier(**params)
            clf.fit(X_tr, y_tr)
            preds = clf.predict(X_va)
            scores.append(f1_score(y_va, preds, average="macro"))
            
        return float(np.mean(scores))

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=n_trials)
    
    best_params = study.best_params
    best_params["scale_pos_weight"] = scale_pos_weight
    best_params["random_state"] = 42
    best_params["n_jobs"] = -1
    best_params["eval_metric"] = "logloss"
    
    print(f"[+] Best CV Macro F1: {study.best_value:.4f}")
    print(f"[+] Best Hyperparameters: {best_params}")
    
    # 4. Final Model Training & Full 5-Fold Stratified Evaluation
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    f1_list, prec_list, rec_list, fpr_list = [], [], [], []
    
    for train_idx, val_idx in skf.split(X_df, y_binary):
        X_tr, X_va = X_df.iloc[train_idx], X_df.iloc[val_idx]
        y_tr, y_va = y_binary.iloc[train_idx], y_binary.iloc[val_idx]
        
        model = xgb.XGBClassifier(**best_params)
        model.fit(X_tr, y_tr)
        
        preds = model.predict(X_va)
        tn, fp, fn, tp = confusion_matrix(y_va, preds).ravel()
        
        f1_list.append(f1_score(y_va, preds, average="macro"))
        prec_list.append(precision_score(y_va, preds, zero_division=0))
        rec_list.append(recall_score(y_va, preds, zero_division=0))
        fpr_list.append(fp / (fp + tn) if (fp + tn) > 0 else 0.0)
        
    final_metrics = {
        "f1_macro": float(np.mean(f1_list)),
        "precision": float(np.mean(prec_list)),
        "recall": float(np.mean(rec_list)),
        "fpr": float(np.mean(fpr_list)),
        "cv_f1_std": float(np.std(f1_list))
    }
    
    # Train final champion model on full dataset
    champion_model = xgb.XGBClassifier(**best_params)
    champion_model.fit(X_df, y_binary)
    
    print("\n" + "="*50)
    print("STAGE 1 MODEL BENCHMARK RESULTS")
    print("="*50)
    print(f"  Macro F1 Score : {final_metrics['f1_macro']:.4f}  (Target: > 0.97)")
    print(f"  Precision      : {final_metrics['precision']:.4f}  (Target: > 0.98)")
    print(f"  Recall         : {final_metrics['recall']:.4f}  (Target: > 0.96)")
    print(f"  FPR            : {final_metrics['fpr']:.4f}  (Target: < 0.01)")
    print("="*50 + "\n")
    
    # 5. MLflow Tracking
    try:
        mlflow.set_tracking_uri(settings.MLFLOW_TRACKING_URI)
        mlflow.set_experiment("aegis_ids")
        with mlflow.start_run(run_name="xgboost_optuna_ids"):
            mlflow.log_params(best_params)
            mlflow.log_metrics(final_metrics)
            mlflow.set_tag("model_type", "XGBoost")
            mlflow.set_tag("dataset", "CICIDS2017")
    except Exception as e:
        print(f"[!] Note: MLflow logging skipped/fallback ({e})")
        
    # 6. Artifact Serialization
    if save_artifacts:
        os.makedirs(settings.MODEL_PATH.parent, exist_ok=True)
        joblib.dump(champion_model, settings.MODEL_PATH)
        joblib.dump(pipeline, settings.SCALER_PATH)
        
        metadata = {
            "feature_names": feature_names,
            "metrics": final_metrics,
            "best_params": best_params,
            "multiclass_labels": list(y_multiclass.unique()),
            "model_version": settings.MODEL_VERSION
        }
        joblib.dump(metadata, settings.METADATA_PATH)
        print(f"[+] Model saved to: {settings.MODEL_PATH}")
        print(f"[+] Preprocessor saved to: {settings.SCALER_PATH}")
        print(f"[+] Metadata saved to: {settings.METADATA_PATH}")
        
    return champion_model, final_metrics

if __name__ == "__main__":
    train_ids_model(n_trials=10)
