#!/usr/bin/env python3
"""
Network Anomaly Detection Model Training Script

This script generates synthetic network data and trains a machine learning model
for detecting various types of network anomalies.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import os
from ml_model import MLModel
from feature_extractor import FeatureExtractor

def generate_synthetic_dataset(n_samples=5000):
    """
    Generate synthetic network data for training
    
    Args:
        n_samples (int): Number of samples to generate
        
    Returns:
        tuple: (X_features, y_labels)
    """
    print("🔧 Generating synthetic network dataset...")
    
    np.random.seed(42)
    n_features = 16
    
    # Initialize feature matrix
    X = np.random.rand(n_samples, n_features)
    
    # Normalize features to realistic ranges
    X[:, 0] *= 200  # packet_count (0-200)
    X[:, 1:5] *= 1500  # packet sizes (0-1500 bytes)
    X[:, 5:8] *= 100  # protocol counts (0-100)
    X[:, 8:12] *= 50  # IP/port counts (0-50)
    X[:, 12:16] *= 1.0  # anomaly scores (0-1)
    
    # Initialize labels (0 = Normal)
    y = np.zeros(n_samples)
    
    # Create anomaly patterns based on feature combinations
    
    # 1. DDoS Attack (Label 1)
    # High packet count + high concentration to single destination
    ddos_mask = (X[:, 0] > 100) & (X[:, 13] > 0.6)
    y[ddos_mask] = 1
    print(f"   📊 DDoS samples: {np.sum(ddos_mask)}")
    
    # 2. Port Scan (Label 2)
    # High port diversity + many unique ports
    port_scan_mask = (X[:, 11] > 15) & (X[:, 12] > 0.5)
    y[port_scan_mask] = 2
    print(f"   📊 Port Scan samples: {np.sum(port_scan_mask)}")
    
    # 3. Botnet Activity (Label 3)
    # Many sources + many destinations + similar packet sizes
    botnet_mask = (X[:, 8] > 10) & (X[:, 9] > 10) & (X[:, 15] > 0.4)
    y[botnet_mask] = 3
    print(f"   📊 Botnet samples: {np.sum(botnet_mask)}")
    
    # 4. Data Exfiltration (Label 4)
    # Large packets + few destinations + consistent transfers
    data_exfilt_mask = (X[:, 1] > 1200) & (X[:, 9] < 5) & (X[:, 14] > 0.5)
    y[data_exfilt_mask] = 4
    print(f"   📊 Data Exfiltration samples: {np.sum(data_exfilt_mask)}")
    
    # Ensure we have some normal traffic
    normal_mask = (y == 0)
    print(f"   📊 Normal samples: {np.sum(normal_mask)}")
    
    # Add some noise to make it more realistic
    noise_mask = np.random.rand(n_samples) < 0.05
    y[noise_mask] = np.random.randint(1, 5, size=np.sum(noise_mask))
    
    print(f"   ✅ Total samples: {n_samples}")
    print(f"   ✅ Feature dimensions: {X.shape}")
    
    return X, y

def evaluate_model_performance(model, X_test, y_test, feature_names):
    """
    Evaluate model performance and print detailed metrics
    
    Args:
        model: Trained model
        X_test: Test features
        y_test: Test labels
        feature_names: List of feature names
    """
    print("\n📊 Model Performance Evaluation")
    print("=" * 50)
    
    # Make predictions
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    conf_matrix = confusion_matrix(y_test, y_pred)
    
    print(f"🎯 Overall Accuracy: {accuracy:.3f}")
    print(f"🎯 Overall Accuracy: {accuracy*100:.1f}%")
    
    # Print confusion matrix
    print("\n📋 Confusion Matrix:")
    print(conf_matrix)
    
    # Print detailed classification report
    label_names = ['Normal', 'DDoS', 'Port Scan', 'Botnet', 'Data Exfiltration']
    print("\n📋 Detailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=label_names))
    
    # Feature importance
    if hasattr(model, 'feature_importances_'):
        print("\n🔍 Feature Importance:")
        feature_importance = model.feature_importances_
        for i, (name, importance) in enumerate(zip(feature_names, feature_importance)):
            print(f"   {name:25s}: {importance:.3f}")
    
    # Per-class accuracy
    print("\n📊 Per-Class Accuracy:")
    for i, label in enumerate(label_names):
        class_mask = y_test == i
        if np.sum(class_mask) > 0:
            class_accuracy = accuracy_score(y_test[class_mask], y_pred[class_mask])
            print(f"   {label:20s}: {class_accuracy:.3f}")

def save_model_and_metadata(model, feature_names, accuracy, save_dir='models'):
    """
    Save the trained model and metadata
    
    Args:
        model: Trained model
        feature_names: List of feature names
        accuracy: Model accuracy
        save_dir: Directory to save model
    """
    os.makedirs(save_dir, exist_ok=True)
    
    # Save model
    model_path = os.path.join(save_dir, 'network_anomaly_model.pkl')
    joblib.dump(model, model_path)
    print(f"💾 Model saved to: {model_path}")
    
    # Save metadata
    metadata = {
        'feature_names': feature_names,
        'accuracy': accuracy,
        'model_type': type(model).__name__,
        'n_features': len(feature_names),
        'label_mapping': {
            0: "Normal",
            1: "DDoS",
            2: "Port Scan", 
            3: "Botnet",
            4: "Data Exfiltration"
        }
    }
    
    metadata_path = os.path.join(save_dir, 'model_metadata.json')
    import json
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"💾 Metadata saved to: {metadata_path}")

def main():
    """Main training function"""
    print("🚀 Network Anomaly Detection Model Training")
    print("=" * 50)
    
    # Generate synthetic dataset
    X, y = generate_synthetic_dataset(n_samples=5000)
    
    # Get feature names
    feature_extractor = FeatureExtractor()
    feature_names = feature_extractor.get_feature_names()
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\n📊 Dataset Split:")
    print(f"   Training samples: {X_train.shape[0]}")
    print(f"   Test samples: {X_test.shape[0]}")
    
    # Train model
    print("\n🤖 Training Random Forest Model...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    print("✅ Model training completed!")
    
    # Evaluate model
    evaluate_model_performance(model, X_test, y_test, feature_names)
    
    # Save model
    accuracy = accuracy_score(y_test, model.predict(X_test))
    save_model_and_metadata(model, feature_names, accuracy)
    
    # Test with MLModel class
    print("\n🧪 Testing MLModel Integration...")
    ml_model = MLModel()
    ml_model.model = model
    ml_model.is_trained = True
    
    # Test prediction
    test_features = X_test[:1]
    prediction, confidence = ml_model.predict(test_features)
    print(f"   Test prediction: {prediction} (confidence: {confidence:.3f})")
    
    print("\n🎉 Training completed successfully!")
    print("📝 You can now run the Flask application with: python app.py")

if __name__ == "__main__":
    main() 