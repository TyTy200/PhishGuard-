import pandas as pd
import numpy as np
import requests
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import pickle
import os

def collect_dataset():
    """
    Collect and preprocess dataset from various sources
    In production, replace with actual data collection
    """
    
    print("Collecting dataset...")
    
    np.random.seed(42)
    n_samples = 10000
    
    data = []
    for i in range(n_samples):
        if i < n_samples // 2:
            domains = ['google.com', 'github.com', 'wikipedia.org', 
                      'microsoft.com', 'amazon.co.uk', 'stackoverflow.com']
            domain = np.random.choice(domains)
            path = '/' + '/'.join(np.random.choice(['api', 'docs', 'products', 
                                                  'about', 'contact'], 
                                                 size=np.random.randint(0, 3)))
            url = f"https://www.{domain}{path}"
            label = 0 
        else:
            base_domains = ['secure-login', 'account-verify', 'update-info',
                           'payment-confirm', 'banking-access']
            domain = f"{np.random.choice(base_domains)}.xyz"
            url = f"http://{domain}/login.php?id={np.random.randint(1000,9999)}"
            label = 1 
        
        data.append({'url': url, 'label': label})
    
    df = pd.DataFrame(data)
    
    print(f"Dataset created: {len(df)} samples")
    print(f"Phishing: {df['label'].sum()}, Legitimate: {len(df) - df['label'].sum()}")
    
    return df

def preprocess_data(df, feature_extractor):
    """Preprocess data and extract features"""
    
    print("Extracting features...")
    
    features_list = []
    labels = []
    
    for _, row in df.iterrows():
        try:
            features = feature_extractor(row['url'])
            features_list.append(features)
            labels.append(row['label'])
        except Exception as e:
            print(f"Error processing URL {row['url']}: {e}")
            continue
    
    features_df = pd.DataFrame(features_list)
    features_df['label'] = labels
    
    print(f"Features extracted: {features_df.shape}")
    
    features_df = features_df.fillna(0)
    
    return features_df

def prepare_training_data(features_df):
    """Prepare data for model training"""
    
    X = features_df.drop('label', axis=1)
    y = features_df['label']
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print(f"Training set: {X_train_scaled.shape}")
    print(f"Test set: {X_test_scaled.shape}")
    
    return X_train_scaled, X_test_scaled, y_train, y_test, scaler, X.columns

if __name__ == '__main__':
    from eng_module import extract_features
    
    df = collect_dataset()
    features_df = preprocess_data(df, extract_features)
    
    features_df.to_csv('processed_features.csv', index=False)
    print("✓ Processed data saved to 'processed_features.csv'")