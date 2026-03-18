import re
import urllib.parse
import tldextract
from datetime import datetime
import ipaddress
import numpy as np

def extract_features(url):
    """Extract lexical features from URL"""
    
 
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    
   
    extracted = tldextract.extract(domain)
    subdomain = extracted.subdomain
    main_domain = extracted.domain
    suffix = extracted.suffix
    
 
    features = {}
    
 
    features['domain_length'] = len(domain)
    features['url_length'] = len(url)
    features['path_length'] = len(path)
    features['query_length'] = len(query)
    
 
    features['num_subdomains'] = subdomain.count('.') + 1 if subdomain else 0
    features['has_subdomain'] = int(bool(subdomain))
    

    features['tld_length'] = len(suffix)
    features['is_common_tld'] = int(suffix in ['com', 'org', 'net', 'edu', 'gov'])
    features['is_suspicious_tld'] = int(suffix in ['xyz', 'top', 'gq', 'tk', 'ml', 'cf', 'ga'])
    
  
    features['num_dots'] = domain.count('.')
    features['num_hyphens'] = domain.count('-')
    features['num_underscores'] = domain.count('_')
    features['num_slashes'] = url.count('/')
    features['num_question_marks'] = url.count('?')
    features['num_equals'] = url.count('=')
    features['num_ampersands'] = url.count('&')
    features['num_percent'] = url.count('%')
    

    suspicious_keywords = [
        'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
        'banking', 'paypal', 'ebay', 'amazon', 'wallet', 'password', 'credential',
        'click', 'offer', 'free', 'win', 'prize', 'reward', 'bonus'
    ]
    
    features['suspicious_keywords_count'] = sum(
        1 for keyword in suspicious_keywords if keyword in url.lower()
    )
    
  
    try:
        ipaddress.ip_address(domain.split(':')[0])
        features['has_ip_address'] = 1
    except:
        features['has_ip_address'] = 0
    
    features['has_at_symbol'] = int('@' in url)
    

    features['has_double_slash'] = int('//' in path)
    
  
    features['num_digits'] = sum(c.isdigit() for c in domain)
    features['digit_ratio'] = features['num_digits'] / len(domain) if domain else 0
    
    features['num_letters'] = sum(c.isalpha() for c in domain)
    features['letter_ratio'] = features['num_letters'] / len(domain) if domain else 0
    

    features['has_hex_encoding'] = int(bool(re.search(r'%[0-9a-fA-F]{2}', url)))
    
   
    features['has_ssl'] = int(parsed.scheme == 'https')
    
  
    popular_brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal']
    features['brand_in_domain'] = sum(1 for brand in popular_brands if brand in main_domain.lower())
    

    features['domain_entropy'] = calculate_entropy(domain)
    
  
    features['domain_age_days'] = np.random.randint(1, 365*5)  
    
  
    features['num_params'] = query.count('&') + 1 if query else 0
    features['has_file_extension'] = int(bool(re.search(r'\.(exe|zip|pdf|doc|js)$', path.lower())))
    
  
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd']
    features['is_shortened'] = int(any(shortener in domain for shortener in shorteners))
    
    return features

def calculate_entropy(text):
    """Calculate Shannon entropy of text"""
    if not text:
        return 0
    
    entropy = 0
    for char in set(text):
        p = text.count(char) / len(text)
        entropy -= p * np.log2(p)
    
    return entropy