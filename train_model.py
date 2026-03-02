"""
train_model.py

Train a Random Forest Classifier to predict Quantum Vulnerability Risk Levels.

Feature vector: [rsa, ecc, sha1, aes, pqc]
Classes:
    - 0: Low Risk
    - 1: Medium Risk
    - 2: High Risk

Usage: python train_model.py
"""

import os

os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib


def create_synthetic_dataset():
    """Create a synthetic dataset for training.
    
    Returns:
        X: Feature vectors (n_samples, 5)
        y: Labels/Classes (n_samples,)
    """
    # Feature order: [RSA, ECC, SHA1, AES, PQC]
    
    # Low Risk (Class 0): Using modern secure algorithms with PQC
    low_risk_samples = [
        [0, 1, 0, 1, 1],  # ECC + AES + PQC
        [0, 1, 0, 1, 1],
        [0, 1, 0, 1, 1],
        [1, 0, 0, 1, 1],  # RSA (with PQC)
        [1, 0, 0, 1, 1],
        [0, 0, 0, 1, 1],  # AES + PQC only
        [0, 0, 0, 1, 1],
        [1, 1, 0, 1, 1],  # RSA + ECC + AES + PQC
        [0, 1, 0, 0, 1],  # ECC + PQC (no deprecated SHA1, AES)
        [1, 0, 0, 0, 1],  # RSA + PQC
    ]
    
    # Medium Risk (Class 1): Using modern algorithms but missing PQC or with SHA1
    medium_risk_samples = [
        [1, 0, 1, 1, 0],  # RSA + SHA1 + AES (no PQC)
        [0, 1, 1, 1, 0],  # ECC + SHA1 + AES (no PQC)
        [1, 1, 1, 1, 0],  # RSA + ECC + SHA1 + AES (no PQC)
        [1, 0, 0, 1, 0],  # RSA + AES (no PQC)
        [0, 1, 0, 1, 0],  # ECC + AES (no PQC)
        [1, 0, 1, 0, 0],  # RSA + SHA1 (no AES, no PQC)
        [0, 1, 1, 0, 0],  # ECC + SHA1 (no AES, no PQC)
        [1, 1, 0, 0, 0],  # RSA + ECC (no SHA1, AES, PQC)
        [1, 0, 0, 0, 0],  # RSA only (no PQC)
        [0, 1, 0, 0, 0],  # ECC only (no PQC)
        [0, 0, 0, 1, 0],  # AES only (no PQC, RSA, ECC)
        [0, 0, 1, 0, 0],  # SHA1 only
    ]
    
    # High Risk (Class 2): Using deprecated/weak algorithms without PQC
    high_risk_samples = [
        [1, 0, 1, 0, 0],  # RSA + SHA1 (no AES, no PQC)
        [0, 0, 1, 0, 0],  # SHA1 only (weak, no PQC)
        [1, 0, 1, 0, 0],  # RSA + SHA1
        [1, 1, 1, 0, 0],  # RSA + ECC + SHA1 (all weak combo, no PQC)
        [0, 0, 1, 1, 0],  # SHA1 + AES (SHA1 is deprecated)
        [1, 0, 1, 1, 0],  # RSA with SHA1 hashing + AES
        [0, 0, 1, 0, 0],
        [1, 1, 0, 0, 0],  # RSA + ECC (no modern hashing/encryption, no PQC)
        [1, 0, 1, 0, 0],
        [0, 0, 1, 1, 0],
    ]
    
    X = np.array(low_risk_samples + medium_risk_samples + high_risk_samples)
    y = np.array([0]*len(low_risk_samples) + 
                 [1]*len(medium_risk_samples) + 
                 [2]*len(high_risk_samples))
    
    return X, y


def train_and_save_model(output_path='quantum_model.pkl'):
    """Train the Random Forest Classifier and save it.
    
    Args:
        output_path: Path where to save the trained model
    """
    print("Creating synthetic dataset...")
    X, y = create_synthetic_dataset()
    
    print(f"Dataset shape: {X.shape}")
    print(f"Class distribution: {np.bincount(y)}")
    
    # Split into training and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print("\nTraining Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=2,
        random_state=42,
        n_jobs=1
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate on test set
    train_score = model.score(X_train, y_train)
    test_score = model.score(X_test, y_test)
    
    print(f"Training Accuracy: {train_score:.4f}")
    print(f"Test Accuracy: {test_score:.4f}")
    
    # Predictions and detailed metrics
    y_pred = model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, 
                              target_names=['Low Risk', 'Medium Risk', 'High Risk']))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Feature importance
    print("\nFeature Importance:")
    feature_names = ['RSA', 'ECC', 'SHA1', 'AES', 'PQC']
    for name, importance in zip(feature_names, model.feature_importances_):
        print(f"  {name}: {importance:.4f}")
    
    # Save the model
    joblib.dump(model, output_path)
    print(f"\nModel saved to: {output_path}")
    
    return model


if __name__ == '__main__':
    train_and_save_model()


