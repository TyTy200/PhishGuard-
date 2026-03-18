import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                           f1_score, confusion_matrix, classification_report)
import warnings
warnings.filterwarnings('ignore')

# Import our modules
from data_collection_processing import collect_dataset, preprocess_data, prepare_training_data
from eng_module import extract_features

def train_models():
    """Train and compare multiple ML models"""
    
    print("=" * 50)
    print("🤖 MODEL TRAINING PHASE")
    print("=" * 50)
    
    # Step 1: Collect and preprocess data
    print("\n📊 Step 1: Data Collection & Preprocessing")
    df = collect_dataset()
    features_df = preprocess_data(df, extract_features)
    
    # Step 2: Prepare training data
    print("\n🔧 Step 2: Preparing Training Data")
    X_train, X_test, y_train, y_test, scaler, feature_names = prepare_training_data(features_df)
    
    # Step 3: Train models
    print("\n🚀 Step 3: Training Models")
    
    models = {
        'Random Forest': RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        ),
        'Logistic Regression': LogisticRegression(
            max_iter=1000,
            random_state=42,
            class_weight='balanced'
        ),
        'Support Vector Machine': SVC(
            probability=True,
            random_state=42,
            class_weight='balanced'
        ),
        'Neural Network': MLPClassifier(
            hidden_layer_sizes=(64, 32),
            max_iter=1000,
            random_state=42
        )
    }
    
    results = {}
    
    for name, model in models.items():
        print(f"\nTraining {name}...")
        
        # Train model
        model.fit(X_train, y_train)
        
        # Predictions
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)[:, 1]
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        # Cross-validation
        cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='f1')
        
        # Store results
        results[name] = {
            'model': model,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std()
        }
        
        print(f"  Accuracy: {accuracy:.4f}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall: {recall:.4f}")
        print(f"  F1-Score: {f1:.4f}")
        print(f"  CV F1-Score: {cv_scores.mean():.4f} (±{cv_scores.std():.4f})")
    
    # Step 4: Select best model
    print("\n🏆 Step 4: Model Selection")
    
    best_model_name = max(results, key=lambda x: results[x]['f1'])
    best_model = results[best_model_name]['model']
    
    print(f"\nBest model: {best_model_name}")
    print(f"F1-Score: {results[best_model_name]['f1']:.4f}")
    
    # Step 5: Save best model and scaler
    print("\n💾 Step 5: Saving Model")
    
    with open('model.pkl', 'wb') as f:
        pickle.dump(best_model, f)
    
    with open('scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    
    # Save feature names
    with open('feature_names.pkl', 'wb') as f:
        pickle.dump(feature_names.tolist(), f)
    
    print("✓ Model saved as 'model.pkl'")
    print("✓ Scaler saved as 'scaler.pkl'")
    print("✓ Feature names saved as 'feature_names.pkl'")
    
    # Step 6: Feature importance (for tree-based models)
    if hasattr(best_model, 'feature_importances_'):
        print("\n📈 Step 6: Feature Importance")
        
        importance = pd.DataFrame({
            'feature': feature_names,
            'importance': best_model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\nTop 10 important features:")
        print(importance.head(10).to_string(index=False))
    
    return results, best_model_name

def evaluate_model_on_examples():
    """Test model on example URLs"""
    
    print("\n🧪 Step 7: Example Evaluation")
    
    # Load model and scaler
    with open('model.pkl', 'rb') as f:
        model = pickle.load(f)
    
    with open('scaler.pkl', 'rb') as f:
        scaler = pickle.load(f)
    
    # Example URLs
    examples = [
        ("https://www.google.com/search?q=phishing", "Legitimate"),
        ("https://github.com/open-source", "Legitimate"),
        ("http://secure-login-verify-account.xyz/login.php", "Phishing"),
        ("http://paypal-update-info.com/confirm", "Phishing"),
        ("https://www.amazon.co.uk/gp/buy", "Legitimate"),
        ("http://192.168.1.1/login.php", "Phishing"),
    ]
    
    print("\nTesting on example URLs:")
    print("-" * 60)
    
    for url, expected in examples:
        try:
            features = extract_features(url)
            feature_array = np.array([list(features.values())])
            scaled_features = scaler.transform(feature_array)
            
            prediction = model.predict(scaled_features)[0]
            probability = model.predict_proba(scaled_features)[0]
            
            result = "PHISHING" if prediction == 1 else "SAFE"
            confidence = probability[1] if prediction == 1 else probability[0]
            
            status = "✓" if result.lower() in expected.lower() else "✗"
            
            print(f"{status} {result:10} ({confidence*100:.1f}%) - {url[:50]}...")
        except Exception as e:
            print(f"✗ Error testing {url[:30]}...: {e}")

if __name__ == '__main__':
    # Train models
    results, best_model = train_models()
    
    # Evaluate on examples
    evaluate_model_on_examples()
    
    print("\n" + "=" * 50)
    print("✅ MODEL TRAINING COMPLETE")
    print("=" * 50)
    print("\nTo run the web application:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Run the app: python app.py")
    print("3. Open browser: http://localhost:5000")