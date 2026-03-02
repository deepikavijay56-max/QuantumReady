"""
train_model.py — QuantumReady ML Risk Predictor v2.0

What's improved:
  ✅ Expanded to 8 features: [RSA, ECC, MD5, SHA1, DiffieHellman, WeakTLS, AES, PQC]
     (original had only 5 — MD5, DiffieHellman, WeakTLS were missing!)
  ✅ 60-sample dataset (was 32) — better generalization
  ✅ Cross-validation (5-fold) for reliable accuracy estimate
  ✅ Saves feature names WITH model — prevents mismatch errors
  ✅ Feature importance bar chart printed to console

Usage:
    python train_model.py
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

FEATURE_NAMES = ['RSA', 'ECC', 'MD5', 'SHA1', 'DiffieHellman', 'WeakTLS', 'AES', 'PQC']


def create_synthetic_dataset():
    """
    Synthetic training data for quantum vulnerability classification.

    Feature order: [RSA, ECC, MD5, SHA1, DiffieHellman, WeakTLS, AES, PQC]

    Classes:
        0 = Low Risk   — modern/PQC algorithms
        1 = Medium Risk — RSA/ECC present but no stacking of broken algos
        2 = High Risk   — multiple broken algorithms, no PQC
    """

    # ── LOW RISK (Class 0) — PQC in use, or only safe algorithms ─────────────
    low = [
        [0, 0, 0, 0, 0, 0, 1, 1],  # AES-256 + PQC
        [0, 0, 0, 0, 0, 0, 1, 1],
        [0, 0, 0, 0, 0, 0, 0, 1],  # PQC only
        [0, 0, 0, 0, 0, 0, 0, 1],
        [1, 0, 0, 0, 0, 0, 1, 1],  # RSA + AES + PQC (migration in progress)
        [0, 1, 0, 0, 0, 0, 1, 1],  # ECC + AES + PQC
        [1, 1, 0, 0, 0, 0, 1, 1],  # RSA + ECC + AES + PQC
        [0, 0, 0, 0, 0, 0, 1, 0],  # AES only (safe)
        [0, 0, 0, 0, 0, 0, 1, 0],
        [0, 1, 0, 0, 0, 0, 0, 1],  # ECC + PQC
        [1, 0, 0, 0, 0, 0, 0, 1],  # RSA + PQC
        [0, 0, 0, 0, 0, 0, 0, 0],  # No crypto at all
        [1, 1, 0, 0, 0, 0, 0, 1],
        [0, 0, 0, 0, 0, 0, 1, 1],
        [0, 0, 0, 0, 0, 0, 0, 1],
    ]

    # ── MEDIUM RISK (Class 1) — RSA/ECC without PQC, or deprecated hashes ───
    medium = [
        [1, 0, 0, 0, 0, 0, 1, 0],  # RSA + AES (no PQC)
        [0, 1, 0, 0, 0, 0, 1, 0],  # ECC + AES
        [1, 1, 0, 0, 0, 0, 1, 0],  # RSA + ECC + AES
        [1, 0, 0, 0, 0, 0, 0, 0],  # RSA only
        [0, 1, 0, 0, 0, 0, 0, 0],  # ECC only
        [1, 1, 0, 0, 0, 0, 0, 0],  # RSA + ECC
        [0, 0, 0, 1, 0, 0, 1, 0],  # SHA1 + AES
        [0, 0, 1, 0, 0, 0, 1, 0],  # MD5 + AES
        [0, 0, 0, 1, 0, 1, 0, 0],  # SHA1 + WeakTLS
        [0, 0, 1, 1, 0, 0, 0, 0],  # MD5 + SHA1
        [1, 0, 0, 0, 0, 1, 0, 0],  # RSA + WeakTLS
        [0, 0, 0, 0, 0, 1, 1, 0],  # WeakTLS + AES
        [0, 0, 0, 0, 1, 0, 1, 0],  # DiffieHellman + AES
        [1, 0, 0, 1, 0, 0, 1, 0],  # RSA + SHA1 + AES
        [0, 1, 1, 0, 0, 0, 0, 0],  # ECC + MD5
        [0, 0, 0, 0, 0, 1, 0, 0],  # WeakTLS only
        [1, 0, 0, 0, 0, 0, 1, 0],
        [0, 1, 0, 1, 0, 0, 1, 0],
        [1, 0, 1, 0, 0, 0, 1, 0],
        [0, 0, 0, 0, 1, 0, 0, 0],  # DiffieHellman only
    ]

    # ── HIGH RISK (Class 2) — stacked broken algorithms, no PQC ──────────────
    high = [
        [1, 0, 1, 1, 0, 1, 0, 0],  # RSA + MD5 + SHA1 + WeakTLS
        [1, 1, 1, 1, 0, 0, 0, 0],  # RSA + ECC + MD5 + SHA1
        [1, 0, 1, 0, 1, 0, 0, 0],  # RSA + MD5 + DH
        [0, 1, 0, 1, 1, 1, 0, 0],  # ECC + SHA1 + DH + WeakTLS
        [1, 1, 1, 1, 1, 1, 0, 0],  # Everything broken
        [1, 0, 0, 1, 0, 1, 0, 0],  # RSA + SHA1 + WeakTLS
        [0, 1, 1, 0, 1, 0, 0, 0],  # ECC + MD5 + DH
        [1, 0, 1, 1, 1, 0, 0, 0],  # RSA + MD5 + SHA1 + DH
        [0, 0, 1, 1, 0, 1, 0, 0],  # MD5 + SHA1 + WeakTLS
        [1, 1, 0, 0, 1, 1, 0, 0],  # RSA + ECC + DH + WeakTLS
        [1, 0, 1, 0, 0, 1, 0, 0],  # RSA + MD5 + WeakTLS
        [0, 1, 1, 1, 0, 1, 0, 0],  # ECC + MD5 + SHA1 + WeakTLS
        [1, 1, 1, 0, 1, 0, 0, 0],  # RSA + ECC + MD5 + DH
        [1, 0, 0, 1, 1, 1, 0, 0],  # RSA + SHA1 + DH + WeakTLS
        [0, 1, 1, 1, 1, 1, 0, 0],  # ECC + MD5 + SHA1 + DH + WeakTLS
        [1, 1, 0, 1, 0, 1, 0, 0],  # RSA + ECC + SHA1 + WeakTLS
        [1, 0, 1, 1, 0, 0, 0, 0],  # RSA + MD5 + SHA1
        [0, 1, 0, 0, 1, 1, 0, 0],  # ECC + DH + WeakTLS
        [1, 1, 1, 1, 0, 1, 0, 0],  # RSA + ECC + MD5 + SHA1 + WeakTLS
        [1, 0, 0, 0, 1, 1, 0, 0],  # RSA + DH + WeakTLS
        [0, 0, 1, 0, 1, 1, 0, 0],  # MD5 + DH + WeakTLS
        [1, 1, 0, 0, 0, 1, 0, 0],  # RSA + ECC + WeakTLS
        [0, 1, 1, 0, 0, 1, 0, 0],  # ECC + MD5 + WeakTLS
        [1, 0, 1, 0, 1, 0, 0, 0],  # RSA + MD5 + DH
        [0, 0, 1, 1, 1, 0, 0, 0],  # MD5 + SHA1 + DH
    ]

    X = np.array(low + medium + high)
    y = np.array([0]*len(low) + [1]*len(medium) + [2]*len(high))
    return X, y


def train_and_save_model(output_path='quantum_model.pkl'):
    """Train Random Forest and save model + metadata."""
    print("=" * 55)
    print("  QuantumReady ML Model Training v2.0")
    print("=" * 55)

    X, y = create_synthetic_dataset()
    counts = np.bincount(y)
    print(f"\n📊 Dataset: {X.shape[0]} samples, {X.shape[1]} features")
    print(f"   Features: {FEATURE_NAMES}")
    print(f"   Classes : Low={counts[0]}, Medium={counts[1]}, High={counts[2]}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=150, max_depth=8, min_samples_split=2,
        min_samples_leaf=1, random_state=42, n_jobs=1
    )
    model.fit(X_train, y_train)

    train_score = model.score(X_train, y_train)
    test_score  = model.score(X_test, y_test)
    cv_scores   = cross_val_score(model, X, y, cv=5, scoring='accuracy')

    print(f"\n📈 Accuracy:")
    print(f"   Train      : {train_score:.4f}")
    print(f"   Test       : {test_score:.4f}")
    print(f"   CV (5-fold): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    y_pred = model.predict(X_test)
    print("\n📋 Classification Report:")
    print(classification_report(y_test, y_pred,
                                target_names=['Low Risk', 'Medium Risk', 'High Risk']))
    print("🗂  Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    print("\n🔍 Feature Importance:")
    for name, imp in zip(FEATURE_NAMES, model.feature_importances_):
        bar = "█" * int(imp * 40)
        print(f"   {name:<18} {imp:.4f}  {bar}")

    # Save model + metadata so app.py can validate feature count
    model_data = {
        'model': model,
        'feature_names': FEATURE_NAMES,
        'version': '2.0',
        'n_features': len(FEATURE_NAMES),
    }
    joblib.dump(model_data, output_path)
    print(f"\n✅ Saved to: {output_path}")
    print("=" * 55)
    return model


if __name__ == '__main__':
    train_and_save_model()