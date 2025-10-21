#!/usr/bin/env python3
"""
Comprehensive evaluation script for network anomaly detection models
Generates ROC curves, PR curves, confusion matrices, and performance metrics
"""

import os
import sys
import argparse
import json
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml_model import MLModel
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    roc_curve, roc_auc_score, precision_recall_curve, average_precision_score,
    confusion_matrix, classification_report, f1_score, precision_score, recall_score
)

class ModelEvaluator:
    """Comprehensive model evaluator with visualization"""
    
    def __init__(self, results_dir='results'):
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)
        
        # Set up plotting style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
        # Color scheme for plots
        self.colors = {
            'Normal': '#2E8B57',
            'DDoS': '#DC143C', 
            'Port Scan': '#FF8C00',
            'Botnet': '#8A2BE2',
            'Data Exfiltration': '#FF1493'
        }
    
    def evaluate_model(self, model, X_test, y_test, model_name="model", save_plots=True):
        """Comprehensive model evaluation"""
        
        print(f"\n🔍 Evaluating {model_name}...")
        
        # Make predictions
        y_pred = model.model.predict(X_test)
        y_pred_proba = model.model.predict_proba(X_test) if hasattr(model.model, 'predict_proba') else None
        
        # Calculate metrics
        metrics = self._calculate_metrics(y_test, y_pred, y_pred_proba)
        
        # Generate plots
        if save_plots:
            self._generate_evaluation_plots(y_test, y_pred, y_pred_proba, model, model_name)
        
        # Print results
        self._print_evaluation_results(metrics, model_name)
        
        return metrics
    
    def _calculate_metrics(self, y_test, y_pred, y_pred_proba):
        """Calculate comprehensive evaluation metrics"""
        
        metrics = {}
        
        # Basic classification metrics
        metrics['accuracy'] = np.mean(y_test == y_pred)
        metrics['precision'] = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        metrics['recall'] = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        metrics['f1_score'] = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        # Per-class metrics
        metrics['class_precision'] = precision_score(y_test, y_pred, average=None, zero_division=0)
        metrics['class_recall'] = recall_score(y_test, y_pred, average=None, zero_division=0)
        metrics['class_f1'] = f1_score(y_test, y_pred, average=None, zero_division=0)
        
        # ROC AUC
        if y_pred_proba is not None:
            if len(np.unique(y_test)) == 2:
                # Binary classification
                metrics['roc_auc'] = roc_auc_score(y_test, y_pred_proba[:, 1])
            else:
                # Multi-class ROC AUC
                y_test_bin = pd.get_dummies(y_test)
                metrics['roc_auc'] = roc_auc_score(y_test_bin, y_pred_proba, average='weighted')
        else:
            metrics['roc_auc'] = None
        
        # Average Precision
        if y_pred_proba is not None:
            if len(np.unique(y_test)) == 2:
                metrics['avg_precision'] = average_precision_score(y_test, y_pred_proba[:, 1])
            else:
                # Multi-class average precision
                y_test_bin = pd.get_dummies(y_test)
                metrics['avg_precision'] = average_precision_score(y_test_bin, y_pred_proba, average='weighted')
        else:
            metrics['avg_precision'] = None
        
        # Confusion matrix
        metrics['confusion_matrix'] = confusion_matrix(y_test, y_pred)
        
        # Classification report
        metrics['classification_report'] = classification_report(y_test, y_pred, output_dict=True)
        
        return metrics
    
    def _generate_evaluation_plots(self, y_test, y_pred, y_pred_proba, model, model_name):
        """Generate comprehensive evaluation plots"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        plot_dir = os.path.join(self.results_dir, f'plots_{model_name}_{timestamp}')
        os.makedirs(plot_dir, exist_ok=True)
        
        # 1. Confusion Matrix
        self._plot_confusion_matrix(y_test, y_pred, model, plot_dir, model_name)
        
        # 2. ROC Curves
        if y_pred_proba is not None:
            self._plot_roc_curves(y_test, y_pred_proba, model, plot_dir, model_name)
        
        # 3. Precision-Recall Curves
        if y_pred_proba is not None:
            self._plot_pr_curves(y_test, y_pred_proba, model, plot_dir, model_name)
        
        # 4. Per-class Performance
        self._plot_per_class_performance(y_test, y_pred, model, plot_dir, model_name)
        
        # 5. Feature Importance (if available)
        if hasattr(model.model, 'feature_importances_'):
            self._plot_feature_importance(model, plot_dir, model_name)
        
        print(f"📊 Plots saved to: {plot_dir}")
    
    def _plot_confusion_matrix(self, y_test, y_pred, model, plot_dir, model_name):
        """Plot confusion matrix"""
        
        plt.figure(figsize=(10, 8))
        cm = confusion_matrix(y_test, y_pred)
        
        # Get class names
        class_names = list(model.label_mapping.values())
        
        # Create heatmap
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=class_names,
                   yticklabels=class_names)
        
        plt.title(f'Confusion Matrix - {model_name}')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        plt.savefig(os.path.join(plot_dir, 'confusion_matrix.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_roc_curves(self, y_test, y_pred_proba, model, plot_dir, model_name):
        """Plot ROC curves"""
        
        class_names = list(model.label_mapping.values())
        n_classes = len(class_names)
        
        if n_classes == 2:
            # Binary classification
            plt.figure(figsize=(8, 6))
            
            fpr, tpr, _ = roc_curve(y_test, y_pred_proba[:, 1])
            roc_auc = roc_auc_score(y_test, y_pred_proba[:, 1])
            
            plt.plot(fpr, tpr, color='darkorange', lw=2,
                    label=f'ROC curve (AUC = {roc_auc:.2f})')
            plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title(f'ROC Curve - {model_name}')
            plt.legend(loc="lower right")
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig(os.path.join(plot_dir, 'roc_curve.png'), dpi=300, bbox_inches='tight')
            plt.close()
            
        else:
            # Multi-class ROC curves
            plt.figure(figsize=(10, 8))
            
            # Compute ROC curve and ROC area for each class
            fpr = dict()
            tpr = dict()
            roc_auc = dict()
            
            y_test_bin = pd.get_dummies(y_test)
            
            for i in range(n_classes):
                fpr[i], tpr[i], _ = roc_curve(y_test_bin.iloc[:, i], y_pred_proba[:, i])
                roc_auc[i] = roc_auc_score(y_test_bin.iloc[:, i], y_pred_proba[:, i])
                
                plt.plot(fpr[i], tpr[i], lw=2,
                        label=f'{class_names[i]} (AUC = {roc_auc[i]:.2f})')
            
            plt.plot([0, 1], [0, 1], 'k--', lw=2)
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title(f'ROC Curves - {model_name}')
            plt.legend(loc="lower right")
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig(os.path.join(plot_dir, 'roc_curves.png'), dpi=300, bbox_inches='tight')
            plt.close()
    
    def _plot_pr_curves(self, y_test, y_pred_proba, model, plot_dir, model_name):
        """Plot Precision-Recall curves"""
        
        class_names = list(model.label_mapping.values())
        n_classes = len(class_names)
        
        if n_classes == 2:
            # Binary classification
            plt.figure(figsize=(8, 6))
            
            precision, recall, _ = precision_recall_curve(y_test, y_pred_proba[:, 1])
            avg_precision = average_precision_score(y_test, y_pred_proba[:, 1])
            
            plt.plot(recall, precision, color='darkorange', lw=2,
                    label=f'PR curve (AP = {avg_precision:.2f})')
            
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('Recall')
            plt.ylabel('Precision')
            plt.title(f'Precision-Recall Curve - {model_name}')
            plt.legend(loc="lower left")
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig(os.path.join(plot_dir, 'pr_curve.png'), dpi=300, bbox_inches='tight')
            plt.close()
            
        else:
            # Multi-class PR curves
            plt.figure(figsize=(10, 8))
            
            y_test_bin = pd.get_dummies(y_test)
            
            for i in range(n_classes):
                precision, recall, _ = precision_recall_curve(y_test_bin.iloc[:, i], y_pred_proba[:, i])
                avg_precision = average_precision_score(y_test_bin.iloc[:, i], y_pred_proba[:, i])
                
                plt.plot(recall, precision, lw=2,
                        label=f'{class_names[i]} (AP = {avg_precision:.2f})')
            
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('Recall')
            plt.ylabel('Precision')
            plt.title(f'Precision-Recall Curves - {model_name}')
            plt.legend(loc="lower left")
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig(os.path.join(plot_dir, 'pr_curves.png'), dpi=300, bbox_inches='tight')
            plt.close()
    
    def _plot_per_class_performance(self, y_test, y_pred, model, plot_dir, model_name):
        """Plot per-class performance metrics"""
        
        class_names = list(model.label_mapping.values())
        
        # Calculate per-class metrics
        precision = precision_score(y_test, y_pred, average=None, zero_division=0)
        recall = recall_score(y_test, y_pred, average=None, zero_division=0)
        f1 = f1_score(y_test, y_pred, average=None, zero_division=0)
        
        # Create bar plot
        fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 5))
        
        # Precision
        ax1.bar(class_names, precision, color='skyblue')
        ax1.set_title('Per-Class Precision')
        ax1.set_ylabel('Precision')
        ax1.tick_params(axis='x', rotation=45)
        ax1.set_ylim(0, 1)
        
        # Recall
        ax2.bar(class_names, recall, color='lightcoral')
        ax2.set_title('Per-Class Recall')
        ax2.set_ylabel('Recall')
        ax2.tick_params(axis='x', rotation=45)
        ax2.set_ylim(0, 1)
        
        # F1-Score
        ax3.bar(class_names, f1, color='lightgreen')
        ax3.set_title('Per-Class F1-Score')
        ax3.set_ylabel('F1-Score')
        ax3.tick_params(axis='x', rotation=45)
        ax3.set_ylim(0, 1)
        
        plt.suptitle(f'Per-Class Performance - {model_name}')
        plt.tight_layout()
        plt.savefig(os.path.join(plot_dir, 'per_class_performance.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_feature_importance(self, model, plot_dir, model_name):
        """Plot feature importance"""
        
        if not hasattr(model.model, 'feature_importances_'):
            return
        
        # Get feature names
        if model.feature_names:
            feature_names = model.feature_names
        else:
            feature_names = [f'Feature_{i}' for i in range(len(model.model.feature_importances_))]
        
        # Sort features by importance
        importances = model.model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        plt.figure(figsize=(12, 8))
        plt.title(f'Feature Importance - {model_name}')
        plt.bar(range(len(importances)), importances[indices])
        plt.xticks(range(len(importances)), [feature_names[i] for i in indices], rotation=45, ha='right')
        plt.ylabel('Importance')
        plt.tight_layout()
        plt.savefig(os.path.join(plot_dir, 'feature_importance.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    def _print_evaluation_results(self, metrics, model_name):
        """Print evaluation results"""
        
        print(f"\n📊 Evaluation Results for {model_name}:")
        print(f"Accuracy: {metrics['accuracy']:.3f}")
        print(f"Precision: {metrics['precision']:.3f}")
        print(f"Recall: {metrics['recall']:.3f}")
        print(f"F1-Score: {metrics['f1_score']:.3f}")
        
        if metrics['roc_auc'] is not None:
            print(f"ROC AUC: {metrics['roc_auc']:.3f}")
        
        if metrics['avg_precision'] is not None:
            print(f"Average Precision: {metrics['avg_precision']:.3f}")
        
        print(f"\n📋 Per-Class Performance:")
        for i, (precision, recall, f1) in enumerate(zip(
            metrics['class_precision'], 
            metrics['class_recall'], 
            metrics['class_f1']
        )):
            print(f"  Class {i}: P={precision:.3f}, R={recall:.3f}, F1={f1:.3f}")
    
    def benchmark_latency(self, model, X_test, n_runs=1000):
        """Benchmark model inference latency"""
        
        print(f"\n⏱️ Benchmarking latency with {n_runs} runs...")
        
        latencies = []
        
        for i in range(n_runs):
            start_time = time.time()
            model.model.predict(X_test[:1])  # Predict single sample
            latency = (time.time() - start_time) * 1000  # Convert to ms
            latencies.append(latency)
        
        latencies = np.array(latencies)
        
        latency_stats = {
            'mean_latency_ms': float(np.mean(latencies)),
            'median_latency_ms': float(np.median(latencies)),
            'p95_latency_ms': float(np.percentile(latencies, 95)),
            'p99_latency_ms': float(np.percentile(latencies, 99)),
            'min_latency_ms': float(np.min(latencies)),
            'max_latency_ms': float(np.max(latencies)),
            'std_latency_ms': float(np.std(latencies))
        }
        
        print(f"📊 Latency Statistics:")
        print(f"  Mean: {latency_stats['mean_latency_ms']:.2f} ms")
        print(f"  Median: {latency_stats['median_latency_ms']:.2f} ms")
        print(f"  P95: {latency_stats['p95_latency_ms']:.2f} ms")
        print(f"  P99: {latency_stats['p99_latency_ms']:.2f} ms")
        print(f"  Min: {latency_stats['min_latency_ms']:.2f} ms")
        print(f"  Max: {latency_stats['max_latency_ms']:.2f} ms")
        print(f"  Std: {latency_stats['std_latency_ms']:.2f} ms")
        
        # Plot latency distribution
        plt.figure(figsize=(10, 6))
        plt.hist(latencies, bins=50, alpha=0.7, color='skyblue', edgecolor='black')
        plt.axvline(latency_stats['mean_latency_ms'], color='red', linestyle='--', 
                   label=f'Mean: {latency_stats["mean_latency_ms"]:.2f} ms')
        plt.axvline(latency_stats['p95_latency_ms'], color='orange', linestyle='--', 
                   label=f'P95: {latency_stats["p95_latency_ms"]:.2f} ms')
        plt.xlabel('Latency (ms)')
        plt.ylabel('Frequency')
        plt.title('Inference Latency Distribution')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        
        plot_path = os.path.join(self.results_dir, 'latency_distribution.png')
        plt.savefig(plot_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"📊 Latency plot saved to: {plot_path}")
        
        return latency_stats
    
    def save_evaluation_report(self, metrics, latency_stats, model_name, save_path=None):
        """Save comprehensive evaluation report"""
        
        if save_path is None:
            save_path = os.path.join(self.results_dir, f'evaluation_report_{model_name}.json')
        
        report = {
            'model_name': model_name,
            'timestamp': datetime.now().isoformat(),
            'metrics': metrics,
            'latency_stats': latency_stats
        }
        
        with open(save_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"📄 Evaluation report saved to: {save_path}")

def main():
    """Main evaluation function"""
    parser = argparse.ArgumentParser(description='Evaluate network anomaly detection models')
    parser.add_argument('--model-path', type=str, required=True, help='Path to trained model')
    parser.add_argument('--data-path', type=str, help='Path to test data (optional)')
    parser.add_argument('--dataset', choices=['cic-ids2017', 'unsw-nb15', 'synthetic'], 
                       default='synthetic', help='Dataset type')
    parser.add_argument('--no-plots', action='store_true', help='Skip plot generation')
    parser.add_argument('--benchmark-latency', action='store_true', help='Run latency benchmarking')
    parser.add_argument('--n-runs', type=int, default=1000, help='Number of runs for latency benchmark')
    
    args = parser.parse_args()
    
    # Initialize evaluator
    evaluator = ModelEvaluator()
    
    # Load model
    print(f"📂 Loading model from: {args.model_path}")
    model = MLModel()
    model.load_model(args.model_path)
    
    if not model.is_trained:
        print("❌ Failed to load trained model")
        return
    
    # Load test data
    if args.data_path:
        # Load from file
        if args.dataset == 'cic-ids2017':
            from load_cic_ids2017 import CICIDS2017Loader
            loader = CICIDS2017Loader()
            X, y = loader.load_data(args.data_path)
        elif args.dataset == 'unsw-nb15':
            from load_unsw_nb15 import UNSWNB15Loader
            loader = UNSWNB15Loader()
            X, y = loader.load_data(args.data_path)
        else:
            print("❌ Invalid dataset type for file loading")
            return
    else:
        # Generate synthetic test data
        X, y = model._generate_synthetic_data()
        # Split for testing
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        X, y = X_test, y_test
    
    if X is None or y is None:
        print("❌ Failed to load test data")
        return
    
    print(f"✅ Loaded {len(X)} test samples")
    
    # Evaluate model
    model_name = os.path.basename(args.model_path).replace('.pkl', '')
    metrics = evaluator.evaluate_model(model, X, y, model_name, save_plots=not args.no_plots)
    
    # Benchmark latency if requested
    latency_stats = None
    if args.benchmark_latency:
        latency_stats = evaluator.benchmark_latency(model, X, args.n_runs)
    
    # Save evaluation report
    evaluator.save_evaluation_report(metrics, latency_stats, model_name)

if __name__ == "__main__":
    main()
