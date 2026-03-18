"""
Feature Engineering Module for URL Phishing Detection
"""

import re
import urllib.parse
import tldextract
import numpy as np
import ipaddress
from datetime import datetime

def extract_features(url):
    """
    Extract lexical features from a URL for phishing detection
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Dictionary of extracted features
    """
    
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    
    
    extracted = tldextract.extract(domain)
    subdomain = extracted.subdomain
    main_domain = extracted.domain
    suffix = extracted.suffix
    
   
    features = {}
    
   
    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    features['path_length'] = len(path)
    features['query_length'] = len(query)
    
  
    features['num_subdomains'] = subdomain.count('.') + 1 if subdomain else 0
    features['has_subdomain'] = int(bool(subdomain))
    features['tld_length'] = len(suffix)
    
   
    common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'uk', 'de', 'jp']
    suspicious_tlds = ['xyz', 'top', 'gq', 'tk', 'ml', 'cf', 'ga', 'pw']
    
    features['is_common_tld'] = int(suffix in common_tlds)
    features['is_suspicious_tld'] = int(suffix in suspicious_tlds)
    
    
    features['num_dots'] = domain.count('.')
    features['num_hyphens'] = domain.count('-')
    features['num_underscores'] = domain.count('_')
    features['num_slashes'] = url.count('/')
    features['num_question_marks'] = url.count('?')
    features['num_equals'] = url.count('=')
    features['num_ampersands'] = url.count('&')
    
   
    suspicious_keywords = [
        'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
        'banking', 'paypal', 'ebay', 'amazon', 'wallet', 'password', 'credential',
        'click', 'offer', 'free', 'win', 'prize', 'reward', 'bonus'
    ]
    
    url_lower = url.lower()
    features['suspicious_keywords_count'] = sum(
        1 for keyword in suspicious_keywords if keyword in url_lower
    )
    
  
    try:
      
        domain_part = domain.split(':')[0]
        ipaddress.ip_address(domain_part)
        features['has_ip_address'] = 1
    except:
        features['has_ip_address'] = 0
    
 
    features['has_at_symbol'] = int('@' in url)
    
    
    features['num_digits'] = sum(c.isdigit() for c in domain)
    features['digit_ratio'] = features['num_digits'] / len(domain) if domain else 0
    
    features['num_letters'] = sum(c.isalpha() for c in domain)
    features['letter_ratio'] = features['num_letters'] / len(domain) if domain else 0
    
   
    features['has_hex_encoding'] = int(bool(re.search(r'%[0-9a-fA-F]{2}', url)))
    
  
    features['has_ssl'] = int(parsed.scheme == 'https')
    features['has_http'] = int(parsed.scheme == 'http')
    
   
    popular_brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix']
    features['brand_in_domain'] = sum(1 for brand in popular_brands if brand in main_domain.lower())
    
   
    features['domain_entropy'] = calculate_entropy(domain)
    
   
    features['num_params'] = query.count('&') + 1 if query else 0
    features['has_file_extension'] = int(bool(re.search(r'\.(exe|zip|pdf|doc|js|php)$', path.lower())))
    
    
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 't.co']
    features['is_shortened'] = int(any(shortener in domain for shortener in shorteners))
    
    
    if ':' in domain:
        try:
            port = int(domain.split(':')[1])
            features['has_port'] = 1
            features['port_number'] = port
        except:
            features['has_port'] = 0
            features['port_number'] = 0
    else:
        features['has_port'] = 0
        features['port_number'] = 0
    
    
    features['has_double_slash'] = int('//' in path)
    
    
    features['fake_https'] = int('https-' in domain)
    
    return features


def calculate_entropy(text):
    """Calculate Shannon entropy of a string"""
    if not text or len(text) < 2:
        return 0
    
    
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    
    
    entropy = 0
    text_len = len(text)
    for count in freq.values():
        probability = count / text_len
        entropy -= probability * np.log2(probability)
    
    return entropy


def get_feature_names():
    """Return list of feature names for reference"""
    dummy_url = "https://www.example.com"
    features = extract_features(dummy_url)
    return list(features.keys())



if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://secure-login-verify.xyz/login.php",
        "https://www.github.com/user/repo",
        "http://192.168.1.1:8080/login"
    ]
    
    print("Testing eng_module feature extraction:")
    print("=" * 50)
    
    for url in test_urls:
        print(f"\nURL: {url}")
        features = extract_features(url)
        print(f"Number of features extracted: {len(features)}")
        print(f"Sample features: {list(features.items())[:5]}...")
