import joblib
import numpy as np
import pandas as pd
import os
import time
import json
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    roc_auc_score, roc_curve, precision_recall_curve, f1_score,
    precision_score, recall_score
)
from sklearn.feature_selection import SelectKBest, mutual_info_classif, RFE
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
import matplotlib.pyplot as plt
import seaborn as sns

class MLModel:
    def __init__(self, model_type='random_forest', feature_selection='none', n_features=16):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_selector = None
        self.is_trained = False
        self.model_type = model_type
        self.feature_selection = feature_selection
        self.n_features = n_features
        self.feature_names = None
        self.selected_features = None
        self.training_time = 0
        self.inference_times = []
        
        # Label mapping
        self.label_mapping = {
            0: "Normal",
            1: "DDoS", 
            2: "Port Scan",
            3: "Botnet",
            4: "Data Exfiltration"
        }
        
        # Model configurations
        self.model_configs = {
            'random_forest': {
                'classifier': RandomForestClassifier,
                'params': {
                    'n_estimators': 100,
                    'max_depth': 10,
                    'random_state': 42,
                    'class_weight': 'balanced'
                }
            },
            'logistic_regression': {
                'classifier': LogisticRegression,
                'params': {
                    'random_state': 42,
                    'max_iter': 1000,
                    'class_weight': 'balanced'
                }
            },
            'svm': {
                'classifier': SVC,
                'params': {
                    'kernel': 'rbf',
                    'random_state': 42,
                    'class_weight': 'balanced',
                    'probability': True
                }
            },
            'mlp': {
                'classifier': MLPClassifier,
                'params': {
                    'hidden_layer_sizes': (100, 50),
                    'random_state': 42,
                    'max_iter': 500
                }
            },
            'isolation_forest': {
                'classifier': IsolationForest,
                'params': {
                    'random_state': 42,
                    'contamination': 0.1
                }
            }
        }
    
    def _create_model(self):
        """Create model based on configuration"""
        config = self.model_configs.get(self.model_type, self.model_configs['random_forest'])
        return config['classifier'](**config['params'])
    
    def _setup_feature_selection(self, X, y):
        """Setup feature selection based on configuration"""
        if self.feature_selection == 'mutual_info':
            self.feature_selector = SelectKBest(score_func=mutual_info_classif, k=self.n_features)
        elif self.feature_selection == 'rfe':
            # Use Random Forest for RFE
            base_model = RandomForestClassifier(n_estimators=50, random_state=42)
            self.feature_selector = RFE(estimator=base_model, n_features_to_select=self.n_features)
        else:
            self.feature_selector = None
            return X
        
        # Fit and transform
        X_selected = self.feature_selector.fit_transform(X, y)
        self.selected_features = self.feature_selector.get_support()
        return X_selected
    
    def load_model(self, model_path):
        """Load a trained model from file"""
        try:
            if os.path.exists(model_path):
                # Load model and metadata
                self.model = joblib.load(model_path)
                
                # Load metadata if available
                metadata_path = model_path.replace('.pkl', '_metadata.json')
                if os.path.exists(metadata_path):
                    with open(metadata_path, 'r') as f:
                        metadata = json.load(f)
                        self.model_type = metadata.get('model_type', 'random_forest')
                        self.feature_selection = metadata.get('feature_selection', 'none')
                        self.feature_names = metadata.get('feature_names', [])
                        self.selected_features = metadata.get('selected_features', None)
                        self.training_time = metadata.get('training_time', 0)
                
                # Load scaler if available
                scaler_path = model_path.replace('.pkl', '_scaler.pkl')
                if os.path.exists(scaler_path):
                    self.scaler = joblib.load(scaler_path)
                    print(f"✅ Scaler loaded from {scaler_path}")
                else:
                    print(f"⚠️ Scaler file not found: {scaler_path}")
                    print("🔧 Creating a new scaler...")
                    # Create and fit a new scaler with synthetic data
                    X, y = self._generate_synthetic_data()
                    X_selected = self._setup_feature_selection(X, y)
                    self.scaler.fit(X_selected)
                    print("✅ New scaler fitted with synthetic data")
                
                # Load feature selector if available
                selector_path = model_path.replace('.pkl', '_selector.pkl')
                if os.path.exists(selector_path) and self.feature_selection != 'none':
                    self.feature_selector = joblib.load(selector_path)
                    print(f"✅ Feature selector loaded from {selector_path}")
                
                self.is_trained = True
                print(f"✅ Model loaded from {model_path}")
                print(f"📊 Model type: {self.model_type}")
                print(f"🔍 Feature selection: {self.feature_selection}")
            else:
                print(f"⚠️ Model file not found: {model_path}")
                print("🔧 Creating a new model...")
                self._create_default_model()
                
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            self._create_default_model()
    
    def _create_default_model(self):
        """Create a default model for testing"""
        try:
            # Create model
            self.model = self._create_model()
            
            # Generate synthetic training data
            X, y = self._generate_synthetic_data()
            
            # Train the model
            self.train_model(X, y, save_path='models/network_anomaly_model.pkl')
            
        except Exception as e:
            print(f"❌ Error creating default model: {e}")
            self.is_trained = False
    
    def _generate_synthetic_data(self):
        """Generate synthetic training data for demonstration"""
        np.random.seed(42)
        
        # Generate 2000 samples with 16 features
        n_samples = 2000
        n_features = 16
        
        # Create synthetic features
        X = np.random.rand(n_samples, n_features)
        
        # Normalize features
        X[:, 0] *= 100  # packet_count
        X[:, 1:5] *= 1500  # packet sizes
        X[:, 5:8] *= 50  # protocol counts
        X[:, 8:12] *= 20  # IP/port counts
        X[:, 12:16] *= 1.0  # anomaly scores
        
        # Create labels based on feature patterns
        y = np.zeros(n_samples)
        
        # DDoS: high packet count, high concentration
        ddos_mask = (X[:, 0] > 50) & (X[:, 13] > 0.7)
        y[ddos_mask] = 1
        
        # Port Scan: high port diversity
        port_scan_mask = (X[:, 11] > 10) & (X[:, 12] > 0.6)
        y[port_scan_mask] = 2
        
        # Botnet: many sources, many destinations
        botnet_mask = (X[:, 8] > 5) & (X[:, 9] > 5) & (X[:, 15] > 0.5)
        y[botnet_mask] = 3
        
        # Data Exfiltration: large packets, few destinations
        data_exfilt_mask = (X[:, 1] > 1000) & (X[:, 9] < 3) & (X[:, 14] > 0.6)
        y[data_exfilt_mask] = 4
        
        return X, y
    
    def predict(self, features):
        """Make prediction on features with latency tracking"""
        if not self.is_trained or self.model is None:
            print("❌ Model not trained")
            return 0, 0.0
        
        try:
            start_time = time.time()
            
            # Ensure features are in correct shape
            if features.ndim == 1:
                features = features.reshape(1, -1)
            
            # Apply feature selection if configured
            if self.feature_selector is not None:
                features = self.feature_selector.transform(features)
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Make prediction
            if self.model_type == 'isolation_forest':
                # Isolation Forest returns -1 for anomalies, 1 for normal
                prediction = self.model.predict(features_scaled)[0]
                prediction = 0 if prediction == 1 else 1  # Convert to our format
                confidence = 0.8  # Default confidence for isolation forest
            else:
                prediction = self.model.predict(features_scaled)[0]
                # Get prediction probability
                try:
                    probabilities = self.model.predict_proba(features_scaled)[0]
                    confidence = max(probabilities)
                    
                    # Boost confidence for anomaly predictions to make them more visible
                    if prediction != 0:  # If it's an anomaly
                        confidence = max(confidence, 0.6)  # Minimum 60% confidence for anomalies
                    
                    # For normal traffic, ensure reasonable confidence
                    if prediction == 0 and confidence < 0.3:
                        confidence = 0.3  # Minimum 30% confidence for normal
                        
                except Exception as prob_error:
                    # Fallback if predict_proba fails
                    confidence = 0.5 if prediction == 0 else 0.7
            
            # Track inference time
            inference_time = (time.time() - start_time) * 1000  # Convert to ms
            self.inference_times.append(inference_time)
            
            # Keep only last 1000 inference times for memory management
            if len(self.inference_times) > 1000:
                self.inference_times = self.inference_times[-1000:]
            
            return int(prediction), confidence
            
        except Exception as e:
            print(f"❌ Error making prediction: {e}")
            return 0, 0.0
    
    def train_model(self, X, y, save_path='models/network_anomaly_model.pkl', 
                   test_size=0.2, random_state=42):
        """Train a new model with comprehensive evaluation"""
        try:
            start_time = time.time()
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y
            )
            
            # Setup feature selection
            X_train_selected = self._setup_feature_selection(X_train, y_train)
            X_test_selected = self.feature_selector.transform(X_test) if self.feature_selector else X_test
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train_selected)
            X_test_scaled = self.scaler.transform(X_test_selected)
            
            # Create and train model
            self.model = self._create_model()
            self.model.fit(X_train_scaled, y_train)
            
            # Calculate training time
            self.training_time = time.time() - start_time
            
            # Evaluate model
            evaluation_results = self._evaluate_model(X_test_scaled, y_test)
            
            # Save model and metadata
            self._save_model(save_path, evaluation_results)
            
            # Print results
            self._print_training_results(evaluation_results)
            
            self.is_trained = True
            return evaluation_results
            
        except Exception as e:
            print(f"❌ Error training model: {e}")
            return None
    
    def _evaluate_model(self, X_test, y_test):
        """Comprehensive model evaluation"""
        try:
            # Make predictions
            y_pred = self.model.predict(X_test)
            
            # Calculate basic metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
            recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
            
            # Calculate per-class metrics
            class_precision = precision_score(y_test, y_pred, average=None, zero_division=0)
            class_recall = recall_score(y_test, y_pred, average=None, zero_division=0)
            class_f1 = f1_score(y_test, y_pred, average=None, zero_division=0)
            
            # Calculate ROC AUC (for binary classification or one-vs-rest)
            if len(np.unique(y_test)) == 2:
                roc_auc = roc_auc_score(y_test, y_pred)
            else:
                # Multi-class ROC AUC
                y_test_bin = pd.get_dummies(y_test)
                y_pred_proba = self.model.predict_proba(X_test)
                roc_auc = roc_auc_score(y_test_bin, y_pred_proba, average='weighted')
            
            # Confusion matrix
            conf_matrix = confusion_matrix(y_test, y_pred)
            
            # Classification report
            class_report = classification_report(y_test, y_pred, output_dict=True)
            
            # Calculate latency metrics
            latency_metrics = self._calculate_latency_metrics()
            
            return {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'roc_auc': roc_auc,
                'class_precision': class_precision.tolist(),
                'class_recall': class_recall.tolist(),
                'class_f1': class_f1.tolist(),
                'confusion_matrix': conf_matrix.tolist(),
                'classification_report': class_report,
                'latency_metrics': latency_metrics,
                'training_time': self.training_time
            }
            
        except Exception as e:
            print(f"❌ Error evaluating model: {e}")
            return None
    
    def _calculate_latency_metrics(self):
        """Calculate latency statistics"""
        if not self.inference_times:
            return {
                'mean_latency_ms': 0,
                'p95_latency_ms': 0,
                'p99_latency_ms': 0,
                'min_latency_ms': 0,
                'max_latency_ms': 0
            }
        
        times = np.array(self.inference_times)
        return {
            'mean_latency_ms': float(np.mean(times)),
            'p95_latency_ms': float(np.percentile(times, 95)),
            'p99_latency_ms': float(np.percentile(times, 99)),
            'min_latency_ms': float(np.min(times)),
            'max_latency_ms': float(np.max(times))
        }
    
    def _save_model(self, save_path, evaluation_results):
        """Save model and metadata"""
        try:
            os.makedirs('models', exist_ok=True)
            
            # Save model
            joblib.dump(self.model, save_path)
            
            # Save scaler
            scaler_path = save_path.replace('.pkl', '_scaler.pkl')
            joblib.dump(self.scaler, scaler_path)
            
            # Save feature selector if exists
            if self.feature_selector is not None:
                selector_path = save_path.replace('.pkl', '_selector.pkl')
                joblib.dump(self.feature_selector, selector_path)
            
            # Save metadata
            metadata = {
                'model_type': self.model_type,
                'feature_selection': self.feature_selection,
                'feature_names': self.feature_names,
                'selected_features': self.selected_features.tolist() if self.selected_features is not None else None,
                'training_time': self.training_time,
                'evaluation_results': evaluation_results,
                'created_at': datetime.now().isoformat()
            }
            
            metadata_path = save_path.replace('.pkl', '_metadata.json')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            print(f"✅ Model saved to {save_path}")
            print(f"✅ Scaler saved to {scaler_path}")
            if self.feature_selector is not None:
                print(f"✅ Feature selector saved to {selector_path}")
            print(f"✅ Metadata saved to {metadata_path}")
            
        except Exception as e:
            print(f"❌ Error saving model: {e}")
    
    def _print_training_results(self, results):
        """Print training results"""
        if not results:
            return
        
        print(f"\n🎯 Training Results:")
        print(f"📊 Accuracy: {results['accuracy']:.3f}")
        print(f"🎯 Precision: {results['precision']:.3f}")
        print(f"📈 Recall: {results['recall']:.3f}")
        print(f"⚖️ F1-Score: {results['f1_score']:.3f}")
        print(f"📊 ROC AUC: {results['roc_auc']:.3f}")
        print(f"⏱️ Training Time: {results['training_time']:.2f}s")
        
        if results['latency_metrics']:
            latency = results['latency_metrics']
            print(f"🚀 Mean Latency: {latency['mean_latency_ms']:.2f}ms")
            print(f"🚀 P95 Latency: {latency['p95_latency_ms']:.2f}ms")
        
        print(f"\n📋 Per-Class Performance:")
        for i, (precision, recall, f1) in enumerate(zip(
            results['class_precision'], 
            results['class_recall'], 
            results['class_f1']
        )):
            class_name = self.label_mapping.get(i, f"Class {i}")
            print(f"  {class_name}: P={precision:.3f}, R={recall:.3f}, F1={f1:.3f}")
    
    def get_model_info(self):
        """Get comprehensive information about the current model"""
        if not self.is_trained:
            return {
                'status': 'Not trained',
                'model_type': 'None',
                'features': 0,
                'feature_selection': 'None'
            }
        
        latency_metrics = self._calculate_latency_metrics()
        
        return {
            'status': 'Trained',
            'model_type': self.model_type,
            'feature_selection': self.feature_selection,
            'features': self.model.n_features_in_ if hasattr(self.model, 'n_features_in_') else 'Unknown',
            'training_time': self.training_time,
            'latency_metrics': latency_metrics
        }
    
    def compare_models(self, X, y, models_to_test=None):
        """Compare multiple models and return results"""
        if models_to_test is None:
            models_to_test = ['random_forest', 'logistic_regression', 'svm', 'mlp']
        
        results = {}
        
        for model_type in models_to_test:
            print(f"\n🔬 Testing {model_type}...")
            
            # Create temporary model
            temp_model = MLModel(model_type=model_type, feature_selection=self.feature_selection)
            
            # Train and evaluate
            result = temp_model.train_model(X, y, save_path=None)
            
            if result:
                results[model_type] = result
        
        return results
    
    def generate_evaluation_plots(self, X_test, y_test, save_dir='results'):
        """Generate evaluation plots and save them"""
        try:
            os.makedirs(save_dir, exist_ok=True)
            
            # Make predictions
            y_pred = self.model.predict(X_test)
            y_pred_proba = self.model.predict_proba(X_test) if hasattr(self.model, 'predict_proba') else None
            
            # Confusion Matrix
            plt.figure(figsize=(10, 8))
            conf_matrix = confusion_matrix(y_test, y_pred)
            sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
                       xticklabels=list(self.label_mapping.values()),
                       yticklabels=list(self.label_mapping.values()))
            plt.title('Confusion Matrix')
            plt.ylabel('True Label')
            plt.xlabel('Predicted Label')
            plt.tight_layout()
            plt.savefig(f'{save_dir}/confusion_matrix.png', dpi=300, bbox_inches='tight')
            plt.close()
            
            # ROC Curve (if binary or one-vs-rest)
            if y_pred_proba is not None:
                if len(np.unique(y_test)) == 2:
                    # Binary classification
                    fpr, tpr, _ = roc_curve(y_test, y_pred_proba[:, 1])
                    roc_auc = roc_auc_score(y_test, y_pred_proba[:, 1])
                    
                    plt.figure(figsize=(8, 6))
                    plt.plot(fpr, tpr, color='darkorange', lw=2, 
                            label=f'ROC curve (AUC = {roc_auc:.2f})')
                    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
                    plt.xlim([0.0, 1.0])
                    plt.ylim([0.0, 1.05])
                    plt.xlabel('False Positive Rate')
                    plt.ylabel('True Positive Rate')
                    plt.title('Receiver Operating Characteristic (ROC) Curve')
                    plt.legend(loc="lower right")
                    plt.tight_layout()
                    plt.savefig(f'{save_dir}/roc_curve.png', dpi=300, bbox_inches='tight')
                    plt.close()
            
            print(f"✅ Evaluation plots saved to {save_dir}/")
            
        except Exception as e:
            print(f"❌ Error generating plots: {e}")
    
    def save_experiment_results(self, results, experiment_name, save_dir='results'):
        """Save experiment results to CSV"""
        try:
            os.makedirs(save_dir, exist_ok=True)
            
            # Create experiment record
            experiment_record = {
                'experiment_name': experiment_name,
                'timestamp': datetime.now().isoformat(),
                'model_type': self.model_type,
                'feature_selection': self.feature_selection,
                'accuracy': results['accuracy'],
                'precision': results['precision'],
                'recall': results['recall'],
                'f1_score': results['f1_score'],
                'roc_auc': results['roc_auc'],
                'training_time': results['training_time'],
                'mean_latency_ms': results['latency_metrics']['mean_latency_ms'],
                'p95_latency_ms': results['latency_metrics']['p95_latency_ms']
            }
            
            # Save to CSV
            csv_path = f'{save_dir}/experiments.csv'
            df = pd.DataFrame([experiment_record])
            
            if os.path.exists(csv_path):
                # Append to existing file
                existing_df = pd.read_csv(csv_path)
                df = pd.concat([existing_df, df], ignore_index=True)
            
            df.to_csv(csv_path, index=False)
            print(f"✅ Experiment results saved to {csv_path}")
            
        except Exception as e:
            print(f"❌ Error saving experiment results: {e}") 