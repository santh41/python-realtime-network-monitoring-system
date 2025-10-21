#!/usr/bin/env python3
"""
Comprehensive training script for network anomaly detection models
Supports multiple algorithms, feature selection, and experiment logging
"""

import os
import sys
import argparse
import json
import time
import numpy as np
import pandas as pd
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml_model import MLModel
from load_cic_ids2017 import CICIDS2017Loader
from load_unsw_nb15 import UNSWNB15Loader

class ModelTrainer:
    """Comprehensive model trainer with experiment logging"""
    
    def __init__(self, results_dir='results'):
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)
        
        # Available models
        self.available_models = [
            'random_forest', 'logistic_regression', 'svm', 'mlp', 'isolation_forest'
        ]
        
        # Available feature selection methods
        self.available_feature_selection = [
            'none', 'mutual_info', 'rfe'
        ]
        
        # Experiment configuration
        self.experiment_config = {
            'test_size': 0.2,
            'random_state': 42,
            'cv_folds': 5,
            'n_jobs': -1
        }
    
    def train_single_model(self, X, y, model_type='random_forest', 
                          feature_selection='none', n_features=16,
                          experiment_name=None):
        """Train a single model with specified configuration"""
        
        if experiment_name is None:
            experiment_name = f"{model_type}_{feature_selection}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        print(f"\n🔬 Training {model_type} with {feature_selection} feature selection...")
        print(f"📊 Dataset: {X.shape[0]} samples, {X.shape[1]} features")
        print(f"🎯 Labels: {np.bincount(y)}")
        
        try:
            # Create model
            model = MLModel(
                model_type=model_type,
                feature_selection=feature_selection,
                n_features=n_features
            )
            
            # Train model
            results = model.train_model(
                X, y,
                test_size=self.experiment_config['test_size'],
                random_state=self.experiment_config['random_state']
            )
            
            if results:
                # Save experiment results
                model.save_experiment_results(results, experiment_name, self.results_dir)
                
                # Generate evaluation plots
                X_train, X_test, y_train, y_test = self._split_data(X, y)
                model.generate_evaluation_plots(X_test, y_test, self.results_dir)
                
                print(f"✅ Training completed for {experiment_name}")
                return model, results
            else:
                print(f"❌ Training failed for {experiment_name}")
                return None, None
                
        except Exception as e:
            print(f"❌ Error training {model_type}: {e}")
            return None, None
    
    def _split_data(self, X, y):
        """Split data for evaluation"""
        from sklearn.model_selection import train_test_split
        
        return train_test_split(
            X, y,
            test_size=self.experiment_config['test_size'],
            random_state=self.experiment_config['random_state'],
            stratify=y
        )
    
    def compare_models(self, X, y, models_to_test=None, feature_selection='none'):
        """Compare multiple models and return results"""
        
        if models_to_test is None:
            models_to_test = ['random_forest', 'logistic_regression', 'svm', 'mlp']
        
        print(f"\n🔬 Comparing {len(models_to_test)} models...")
        
        results = {}
        best_model = None
        best_score = 0
        
        for model_type in models_to_test:
            if model_type not in self.available_models:
                print(f"⚠️ Skipping unknown model: {model_type}")
                continue
            
            experiment_name = f"comparison_{model_type}_{feature_selection}"
            model, result = self.train_single_model(
                X, y, model_type, feature_selection, 
                experiment_name=experiment_name
            )
            
            if result:
                results[model_type] = result
                
                # Track best model
                if result['f1_score'] > best_score:
                    best_score = result['f1_score']
                    best_model = model_type
        
        # Print comparison summary
        self._print_comparison_summary(results, best_model)
        
        return results, best_model
    
    def _print_comparison_summary(self, results, best_model):
        """Print comparison summary"""
        print(f"\n📊 Model Comparison Summary:")
        print(f"{'Model':<20} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1-Score':<10} {'ROC AUC':<10}")
        print("-" * 80)
        
        for model_name, result in results.items():
            print(f"{model_name:<20} {result['accuracy']:<10.3f} {result['precision']:<10.3f} "
                  f"{result['recall']:<10.3f} {result['f1_score']:<10.3f} {result['roc_auc']:<10.3f}")
        
        print(f"\n🏆 Best Model: {best_model} (F1-Score: {results[best_model]['f1_score']:.3f})")
    
    def feature_selection_experiment(self, X, y, model_type='random_forest'):
        """Experiment with different feature selection methods"""
        
        print(f"\n🔍 Feature Selection Experiment with {model_type}...")
        
        results = {}
        
        for feature_selection in self.available_feature_selection:
            experiment_name = f"feature_selection_{model_type}_{feature_selection}"
            model, result = self.train_single_model(
                X, y, model_type, feature_selection,
                experiment_name=experiment_name
            )
            
            if result:
                results[feature_selection] = result
        
        # Print feature selection summary
        self._print_feature_selection_summary(results)
        
        return results
    
    def _print_feature_selection_summary(self, results):
        """Print feature selection summary"""
        print(f"\n🔍 Feature Selection Summary:")
        print(f"{'Method':<15} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1-Score':<10}")
        print("-" * 65)
        
        for method, result in results.items():
            print(f"{method:<15} {result['accuracy']:<10.3f} {result['precision']:<10.3f} "
                  f"{result['recall']:<10.3f} {result['f1_score']:<10.3f}")
    
    def hyperparameter_tuning(self, X, y, model_type='random_forest'):
        """Perform hyperparameter tuning"""
        
        print(f"\n⚙️ Hyperparameter Tuning for {model_type}...")
        
        from sklearn.model_selection import GridSearchCV
        
        # Define parameter grids
        param_grids = {
            'random_forest': {
                'n_estimators': [50, 100, 200],
                'max_depth': [5, 10, 15, None],
                'min_samples_split': [2, 5, 10]
            },
            'logistic_regression': {
                'C': [0.1, 1.0, 10.0],
                'penalty': ['l1', 'l2'],
                'solver': ['liblinear', 'saga']
            },
            'svm': {
                'C': [0.1, 1.0, 10.0],
                'kernel': ['rbf', 'linear'],
                'gamma': ['scale', 'auto']
            },
            'mlp': {
                'hidden_layer_sizes': [(50,), (100,), (100, 50)],
                'learning_rate': ['constant', 'adaptive'],
                'alpha': [0.0001, 0.001, 0.01]
            }
        }
        
        if model_type not in param_grids:
            print(f"⚠️ No hyperparameter grid defined for {model_type}")
            return None
        
        try:
            # Create base model
            model = MLModel(model_type=model_type)
            base_estimator = model._create_model()
            
            # Perform grid search
            grid_search = GridSearchCV(
                base_estimator,
                param_grids[model_type],
                cv=self.experiment_config['cv_folds'],
                scoring='f1_weighted',
                n_jobs=self.experiment_config['n_jobs'],
                verbose=1
            )
            
            # Split data
            X_train, X_test, y_train, y_test = self._split_data(X, y)
            
            # Fit grid search
            grid_search.fit(X_train, y_train)
            
            # Get best model
            best_model = grid_search.best_estimator_
            best_params = grid_search.best_params_
            best_score = grid_search.best_score_
            
            print(f"✅ Best parameters: {best_params}")
            print(f"✅ Best CV score: {best_score:.3f}")
            
            # Evaluate on test set
            y_pred = best_model.predict(X_test)
            from sklearn.metrics import f1_score
            test_f1 = f1_score(y_test, y_pred, average='weighted')
            print(f"✅ Test F1-score: {test_f1:.3f}")
            
            return {
                'best_params': best_params,
                'best_cv_score': best_score,
                'test_f1_score': test_f1,
                'best_estimator': best_model
            }
            
        except Exception as e:
            print(f"❌ Error in hyperparameter tuning: {e}")
            return None
    
    def run_comprehensive_experiment(self, X, y, dataset_name="synthetic"):
        """Run comprehensive experiment with all configurations"""
        
        print(f"\n🚀 Running Comprehensive Experiment on {dataset_name} dataset...")
        
        experiment_results = {
            'dataset': dataset_name,
            'timestamp': datetime.now().isoformat(),
            'model_comparison': {},
            'feature_selection': {},
            'hyperparameter_tuning': {}
        }
        
        # 1. Model comparison
        print("\n📊 Step 1: Model Comparison")
        model_results, best_model = self.compare_models(X, y)
        experiment_results['model_comparison'] = {
            'results': model_results,
            'best_model': best_model
        }
        
        # 2. Feature selection experiment
        print("\n🔍 Step 2: Feature Selection Experiment")
        feature_results = self.feature_selection_experiment(X, y, best_model)
        experiment_results['feature_selection'] = feature_results
        
        # 3. Hyperparameter tuning for best model
        print("\n⚙️ Step 3: Hyperparameter Tuning")
        hp_results = self.hyperparameter_tuning(X, y, best_model)
        experiment_results['hyperparameter_tuning'] = hp_results
        
        # Save comprehensive results
        results_file = os.path.join(self.results_dir, f"comprehensive_experiment_{dataset_name}.json")
        with open(results_file, 'w') as f:
            json.dump(experiment_results, f, indent=2, default=str)
        
        print(f"\n✅ Comprehensive experiment completed!")
        print(f"📁 Results saved to: {results_file}")
        
        return experiment_results

def main():
    """Main training function"""
    parser = argparse.ArgumentParser(description='Train network anomaly detection models')
    parser.add_argument('--dataset', choices=['cic-ids2017', 'unsw-nb15', 'synthetic'], 
                       default='synthetic', help='Dataset to use')
    parser.add_argument('--model', choices=['random_forest', 'logistic_regression', 'svm', 'mlp', 'isolation_forest'],
                       default='random_forest', help='Model type to train')
    parser.add_argument('--feature-selection', choices=['none', 'mutual_info', 'rfe'],
                       default='none', help='Feature selection method')
    parser.add_argument('--n-features', type=int, default=16, help='Number of features to select')
    parser.add_argument('--compare', action='store_true', help='Compare multiple models')
    parser.add_argument('--feature-experiment', action='store_true', help='Run feature selection experiment')
    parser.add_argument('--hyperparameter-tuning', action='store_true', help='Run hyperparameter tuning')
    parser.add_argument('--comprehensive', action='store_true', help='Run comprehensive experiment')
    parser.add_argument('--data-path', type=str, help='Path to dataset file')
    
    args = parser.parse_args()
    
    # Initialize trainer
    trainer = ModelTrainer()
    
    # Load data
    print(f"📂 Loading {args.dataset} dataset...")
    
    if args.dataset == 'cic-ids2017':
        loader = CICIDS2017Loader()
        X, y = loader.load_data(args.data_path)
    elif args.dataset == 'unsw-nb15':
        loader = UNSWNB15Loader()
        X, y = loader.load_data(args.data_path)
    else:
        # Use synthetic data
        model = MLModel()
        X, y = model._generate_synthetic_data()
    
    if X is None or y is None:
        print("❌ Failed to load data")
        return
    
    print(f"✅ Loaded {len(X)} samples with {X.shape[1]} features")
    
    # Run experiments based on arguments
    if args.comprehensive:
        trainer.run_comprehensive_experiment(X, y, args.dataset)
    elif args.compare:
        trainer.compare_models(X, y)
    elif args.feature_experiment:
        trainer.feature_selection_experiment(X, y, args.model)
    elif args.hyperparameter_tuning:
        trainer.hyperparameter_tuning(X, y, args.model)
    else:
        # Train single model
        experiment_name = f"{args.model}_{args.feature_selection}_{args.dataset}"
        model, results = trainer.train_single_model(
            X, y, args.model, args.feature_selection, args.n_features,
            experiment_name=experiment_name
        )
        
        if model and results:
            print(f"\n✅ Training completed successfully!")
            print(f"📊 Final F1-Score: {results['f1_score']:.3f}")
            print(f"📊 Final Accuracy: {results['accuracy']:.3f}")

if __name__ == "__main__":
    main()
