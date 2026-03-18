from flask import Flask, render_template, request, jsonify, send_file
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
import re
import urllib.parse
import json
import os
import requests
import time
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor
import threading
from eng_module import extract_features
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)

class Config:
   
    VIRUSTOTAL_API_KEY = "3bf4596ce67b65cc9b4316e60ce39f02c71896e416e71f4bd748dabf1654bad3" 
    VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/"
    
    
    URL_SCAN_ENDPOINT = "urls"
    URL_REPORT_ENDPOINT = "analyses/"
    URL_BASE_REPORT = "urls/"
    
   
    CACHE_DURATION = 7200  
    CACHE_SIZE_LIMIT = 500 
    
    
    API_TIMEOUT = 10  
    MAX_RETRIES = 2
    RATE_LIMIT_DELAY = 15  
    
 
    MALICIOUS_THRESHOLD = 3  
    SUSPICIOUS_THRESHOLD = 5 
    
   
    LOCAL_BLACKLIST = {
        'phishing-example.com', 'malicious-site.net', 
        'fake-login-page.org', 'secure-verify-account.com',
        'verify-paypal.com', 'login-facebook.xyz',
        'update-banking.info', 'account-alert.net'
    }
    
    LOCAL_WHITELIST = {
        'google.com', 'facebook.com', 'github.com', 
        'microsoft.com', 'amazon.com', 'paypal.com',
        'apple.com', 'twitter.com', 'linkedin.com',
        'instagram.com', 'netflix.com', 'youtube.com'
    }


MODEL_PATH = 'model.pkl'
SCALER_PATH = 'scaler.pkl'


model = None
scaler = None

try:
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)
    print("✓ Model and scaler loaded successfully")
except FileNotFoundError:
    print("⚠ Model files not found. Please train the model first.")
except Exception as e:
    print(f"⚠ Error loading model: {e}")


scan_history = []
url_cache = {}
cache_lock = threading.Lock()
api_status = {
    'virustotal_available': True,
    'last_check': None,
    'error_count': 0,
    'last_request_time': 0,
    'requests_this_minute': 0,
    'rate_limit_reset': 0
}


executor = ThreadPoolExecutor(max_workers=1)

def check_rate_limit():
    """Check and enforce VirusTotal rate limits"""
    current_time = time.time()
    
  
    if current_time - api_status['rate_limit_reset'] > 60:
        api_status['requests_this_minute'] = 0
        api_status['rate_limit_reset'] = current_time
    
 
    if api_status['requests_this_minute'] >= 4:
        wait_time = 60 - (current_time - api_status['rate_limit_reset'])
        if wait_time > 0:
            print(f"⚠ Rate limit reached. Waiting {wait_time:.1f} seconds...")
            time.sleep(wait_time)
            api_status['requests_this_minute'] = 0
            api_status['rate_limit_reset'] = time.time()
    
    api_status['requests_this_minute'] += 1
    api_status['last_request_time'] = current_time
    
def check_virustotal_real(url):
    """Make actual API call to VirusTotal with better error handling"""
    start_time = time.time()
    
    try:
    
        check_rate_limit()
        
        headers = {
            'x-apikey': Config.VIRUSTOTAL_API_KEY,
            'Accept': 'application/json',
            'User-Agent': 'PhishGuard/1.0'
        }
        
      
        url_id = encode_url_for_vt(url)
        report_url = f"{Config.VIRUSTOTAL_API_URL}{Config.URL_BASE_REPORT}{url_id}"
        
        response = requests.get(
            report_url,
            headers=headers,
            timeout=Config.API_TIMEOUT
        )
        
        response_time = time.time() - start_time
        
        if response.status_code == 200:
       
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            return {
                'status': 'success',
                'stats': stats,
                'reputation': attributes.get('reputation', 0),
                'last_analysis_date': attributes.get('last_analysis_date'),
                'details': {
                    'categories': attributes.get('categories', {}),
                    'first_submission_date': attributes.get('first_submission_date'),
                    'last_submission_date': attributes.get('last_submission_date'),
                    'times_submitted': attributes.get('times_submitted', 0)
                },
                'response_time': response_time
            }
        
        elif response.status_code == 404:
        
            print(f"⚠ URL not in VirusTotal database, submitting for analysis...")
            
            submit_url = f"{Config.VIRUSTOTAL_API_URL}{Config.URL_SCAN_ENDPOINT}"
            submit_data = {'url': url}
            
            submit_response = requests.post(
                submit_url,
                headers=headers,
                data=submit_data,
                timeout=Config.API_TIMEOUT
            )
            
            if submit_response.status_code == 200:
                submit_data = submit_response.json()
                analysis_id = submit_data.get('data', {}).get('id')
                
               
                return {
                    'status': 'submitted',
                    'stats': {'malicious': 0, 'suspicious': 0, 'undetected': 0, 'harmless': 0},
                    'reputation': 0,
                    'last_analysis_date': datetime.now().isoformat(),
                    'details': {
                        'analysis_id': analysis_id,
                        'status': 'submitted',
                        'message': 'URL submitted for analysis'
                    },
                    'response_time': response_time
                }
            else:
                return {
                    'status': 'error',
                    'error': f'Submission failed: HTTP {submit_response.status_code}',
                    'response_time': response_time
                }
        
        elif response.status_code == 401:
          
            return {
                'status': 'error',
                'error': 'Invalid VirusTotal API key. Please check your API key.',
                'response_time': response_time
            }
        
        elif response.status_code == 429:
            
            wait_time = 60 - (time.time() - api_status['rate_limit_reset'])
            return {
                'status': 'error',
                'error': f'VirusTotal API rate limit exceeded. Try again in {int(wait_time)} seconds.',
                'response_time': response_time
            }
        
        else:
            return {
                'status': 'error',
                'error': f'HTTP {response.status_code}: {response.text[:100]}',
                'response_time': response_time
            }
            
    except requests.exceptions.Timeout:
        return {
            'status': 'error',
            'error': 'Request timed out after 10 seconds',
            'response_time': Config.API_TIMEOUT
        }
    except requests.exceptions.ConnectionError:
        return {
            'status': 'error',
            'error': 'Connection to VirusTotal failed. Check your internet connection.',
            'response_time': time.time() - start_time
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'response_time': time.time() - start_time
        }

def encode_url_for_vt(url):
    """Encode URL for VirusTotal API (base64 without padding)"""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return url_id

def format_vt_timestamp(timestamp):
    """Format VirusTotal timestamp to human readable"""
    if not timestamp:
        return "Never analyzed"
    
    try:
        
        if isinstance(timestamp, int):
            date_obj = datetime.fromtimestamp(timestamp)
        else:
       
            date_obj = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        return date_obj.strftime('%d %b %Y, %H:%M:%S')
    except:
        return str(timestamp)

def check_virustotal_api(url, force_real=False):
    """Check URL against VirusTotal API"""
    result = {
        'source': 'virustotal_api',
        'is_phishing': False,
        'malicious_count': 0,
        'suspicious_count': 0,
        'total_engines': 0,
        'reputation': 0,
        'last_analysis': None,
        'last_analysis_human': None,
        'details': {},
        'response_time': 0,
        'error': None,
        'api_key_valid': True
    }
    
 
    placeholder_key = "3bf4596ce67b65cc9b4316e60ce39f02c71896e416e71f4bd748dabf1654bad3"
    
    if not Config.VIRUSTOTAL_API_KEY or Config.VIRUSTOTAL_API_KEY == placeholder_key:
      
        result.update({
            'source': 'virustotal_api_error',
            'error': 'VirusTotal API key not configured. Please add a valid API key.',
            'api_key_valid': False
        })
        return result
    
   
    try:
        print(f"🔗 Using real VirusTotal API with key: {Config.VIRUSTOTAL_API_KEY[:10]}...")
        api_result = check_virustotal_real(url)
        
        if api_result['status'] == 'success':
            stats = api_result.get('stats', {})
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            total_engines = sum(stats.values()) if stats else 0
            
            result.update({
                'source': 'virustotal_api',
                'is_phishing': malicious_count >= Config.MALICIOUS_THRESHOLD or 
                              suspicious_count >= Config.SUSPICIOUS_THRESHOLD,
                'malicious_count': malicious_count,
                'suspicious_count': suspicious_count,
                'total_engines': total_engines,
                'reputation': api_result.get('reputation', 0),
                'last_analysis': api_result.get('last_analysis_date'),
                'last_analysis_human': format_vt_timestamp(api_result.get('last_analysis_date')),
                'details': api_result.get('details', {}),
                'response_time': api_result.get('response_time', 0),
                'api_key_valid': True
            })
            
         
            api_status['virustotal_available'] = True
            api_status['error_count'] = 0
            
        elif api_result['status'] == 'submitted':
      
            result.update({
                'source': 'virustotal_submitted',
                'is_phishing': False,
                'malicious_count': 0,
                'suspicious_count': 0,
                'total_engines': 0,
                'reputation': 0,
                'last_analysis': datetime.now().isoformat(),
                'last_analysis_human': 'Submitted for analysis',
                'details': api_result.get('details', {}),
                'response_time': api_result.get('response_time', 0),
                'api_key_valid': True,
                'message': 'URL submitted to VirusTotal for analysis'
            })
            
        else:
        
            error_msg = api_result.get('error', 'Unknown API error')
            print(f"✗ VirusTotal API error: {error_msg}")
            
          
            if '401' in str(error_msg) or 'Invalid' in str(error_msg) or 'unauthorized' in str(error_msg).lower():
                result.update({
                    'source': 'virustotal_auth_error',
                    'error': 'Invalid VirusTotal API key',
                    'api_key_valid': False
                })
            else:
             
                result.update({
                    'source': 'virustotal_api_error',
                    'error': error_msg,
                    'api_key_valid': True 
                })
    
    except Exception as e:
        print(f"✗ Exception in VirusTotal API call: {e}")
        result.update({
            'source': 'virustotal_exception',
            'error': str(e),
            'api_key_valid': True  
        })
    
    return result

@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    """API endpoint to scan URL"""
 
    scan_start_time = datetime.now()
    
    data = request.json
    url = data.get('url', '').strip()
    force_real_api = data.get('force_real_api', False)
    use_cache = data.get('use_cache', True)
    source = data.get('source', 'web')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
   
    timestamp_iso = scan_start_time.isoformat()
    timestamp_human = scan_start_time.strftime('%d %b %Y, %H:%M:%S')
    timestamp_short = scan_start_time.strftime('%Y-%m-%d %H:%M:%S')
    
  
    if not re.match(r'^https?://', url):
        url = 'http://' + url
    
    try:
        
        cache_key = hashlib.md5(url.encode()).hexdigest()
        if use_cache:
            with cache_lock:
                if cache_key in url_cache:
                    cached_result = url_cache[cache_key]
                    cache_age = time.time() - cached_result.get('cache_timestamp', 0)
                    
                   
                    if cache_age < 900:
                        
                        cached_result = cached_result.copy()
                        cached_result['scan_id'] = generate_scan_id_with_timestamp(scan_start_time)
                        cached_result['timestamp'] = timestamp_iso
                        cached_result['timestamp_human'] = timestamp_human
                        cached_result['timestamp_short'] = timestamp_short
                        cached_result['scan_date'] = scan_start_time.strftime('%Y-%m-%d')
                        cached_result['scan_time'] = scan_start_time.strftime('%H:%M:%S')
                        cached_result['cache_age_seconds'] = int(cache_age)
                        cached_result['cached'] = True
                        cached_result['last_scan_time'] = timestamp_human
                        
                     
                        scan_history.append(cached_result)
                        return jsonify(cached_result)
        
 
        features = extract_features(url)
        
      
        ml_prediction = get_ml_prediction(features)
        
        
        virustotal_result = check_virustotal_api(url, force_real_api)
        
   
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        in_blacklist = any(black_domain in domain for black_domain in Config.LOCAL_BLACKLIST)
        in_whitelist = any(white_domain in domain for white_domain in Config.LOCAL_WHITELIST)
        
    
        is_phishing, confidence, sources = determine_verdict(
            ml_prediction, virustotal_result, in_blacklist, in_whitelist, features
        )
        
      
        scan_end_time = datetime.now()
        scan_duration = (scan_end_time - scan_start_time).total_seconds()
        
   
        scan_id = generate_scan_id_with_timestamp(scan_start_time)
        
    
        result = {
            'scan_id': scan_id,
            'url': url,
            'is_phishing': is_phishing,
            'confidence': round(confidence, 2),
            'domain': domain,
            'domain_age': features.get('domain_age_days', 'Unknown'),
            'has_ssl': features.get('has_ssl', False),
            'virustotal_result': virustotal_result,
            'ml_prediction': ml_prediction,
            'local_checks': {
                'blacklisted': in_blacklist,
                'whitelisted': in_whitelist
            },
            'verdict_sources': sources,
            'suspicious_keywords': features.get('suspicious_keywords_count', 0),
            
         
            'timestamp': timestamp_iso,
            'timestamp_human': timestamp_human,
            'timestamp_short': timestamp_short,
            'scan_date': scan_start_time.strftime('%Y-%m-%d'),
            'scan_time': scan_start_time.strftime('%H:%M:%S'),
            'scan_datetime': f"{scan_start_time.strftime('%d %b %Y')} at {scan_start_time.strftime('%H:%M:%S')}",
            'last_scan_time': timestamp_human,
            'scan_duration_seconds': round(scan_duration, 3),
            
            'risk_level': get_risk_level(confidence, is_phishing),
            'features_used': len(features),
            'api_status': api_status['virustotal_available'],
            'cache_hit': False
        }
        
       
        with cache_lock:
            cache_entry = result.copy()
            cache_entry['cache_timestamp'] = time.time()
            url_cache[cache_key] = cache_entry
            
           
            if len(url_cache) > Config.CACHE_SIZE_LIMIT:
                oldest_keys = sorted(url_cache.keys(), 
                                   key=lambda k: url_cache[k].get('cache_timestamp', 0))[:50]
                for key in oldest_keys:
                    del url_cache[key]
        
       
        scan_history.append(result)
        
    
        if len(scan_history) > 1000:
            scan_history.pop(0)
        
        print(f"✓ Scan completed in {scan_duration:.2f}s: {url[:50]}...")
        return jsonify(result)
    
    except Exception as e:
        print(f"Error scanning URL: {e}")
        return jsonify({
            'error': 'Failed to scan URL', 
            'details': str(e),
            'timestamp': timestamp_iso,
            'timestamp_human': timestamp_human
        }), 500

def generate_scan_id():
    """Generate unique scan ID"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    counter = len(scan_history) + 1
    return f"PG-{timestamp}-{counter:06d}"

def generate_scan_id_with_timestamp(timestamp=None):
    """Generate unique scan ID with timestamp"""
    if timestamp is None:
        timestamp = datetime.now()
    
  
    date_part = timestamp.strftime('%Y%m%d')
    time_part = timestamp.strftime('%H%M%S')
    milliseconds = timestamp.strftime('%f')[:3]
    counter = len(scan_history) + 1
    return f"PG-{date_part}-{time_part}{milliseconds}-{counter:04d}"

def get_ml_prediction(features):
    """Get prediction from ML model"""
    if model is not None and scaler is not None:
        try:
            feature_array = np.array([list(features.values())])
            scaled_features = scaler.transform(feature_array)
            prediction = model.predict(scaled_features)
            probability = model.predict_proba(scaled_features)[0]
            
            return {
                'is_phishing': bool(prediction[0]),
                'confidence': float(probability[1] if bool(prediction[0]) else probability[0]) * 100,
                'available': True
            }
        except Exception as e:
            print(f"ML prediction error: {e}")
    
  
    return {
        'is_phishing': False,
        'confidence': 50.0,
        'available': False,
        'error': 'Model not available'
    }

def determine_verdict(ml_prediction, virustotal_result, in_blacklist, in_whitelist, features):
    """Determine final verdict based on multiple sources"""
    sources = []
    confidence_factors = []
    

    if ml_prediction['available']:
        sources.append(f"ml:{ml_prediction['confidence']:.1f}%")
        confidence_factors.append({
            'weight': 0.4,
            'value': ml_prediction['confidence'] if ml_prediction['is_phishing'] else 100 - ml_prediction['confidence']
        })
    
   
    if virustotal_result.get('api_key_valid') and virustotal_result['source'] not in ['virustotal_api_error', 'virustotal_auth_error', 'virustotal_exception']:
        source_name = virustotal_result['source'].replace('_', '-')
        sources.append(f"{source_name}:{'positive' if virustotal_result['is_phishing'] else 'negative'}")
        
       
        total_engines = virustotal_result['total_engines']
        malicious_engines = virustotal_result['malicious_count']
        suspicious_engines = virustotal_result['suspicious_count']
        
        if total_engines > 0:
            malicious_ratio = (malicious_engines + suspicious_engines * 0.5) / total_engines
        else:
            malicious_ratio = 0
        
        if virustotal_result['is_phishing']:
            weight = 0.5 + (malicious_ratio * 0.3)  
            value = 70 + (malicious_ratio * 25)  
        else:
            weight = 0.4
            value = 85 - (malicious_ratio * 15)  
        
        confidence_factors.append({'weight': weight, 'value': value})
    
  
    if in_blacklist:
        sources.append("local-blacklist:positive")
        confidence_factors.append({'weight': 0.6, 'value': 95})
    elif in_whitelist:
        sources.append("local-whitelist:negative")
        confidence_factors.append({'weight': 0.3, 'value': 85})
    

    heuristic_score = 0
    if features.get('suspicious_keywords_count', 0) > 2:
        heuristic_score += 1
    if features.get('url_length', 0) > 100:
        heuristic_score += 1
    if not features.get('has_ssl', False):
        heuristic_score += 1
    if features.get('special_char_ratio', 0) > 0.2:
        heuristic_score += 1
    
    if heuristic_score >= 2:
        sources.append(f"heuristics:positive({heuristic_score})")
        confidence_factors.append({'weight': 0.2, 'value': 80})
    else:
        sources.append(f"heuristics:negative({heuristic_score})")
        confidence_factors.append({'weight': 0.1, 'value': 60})
    
    
    if confidence_factors:
        total_weight = sum(f['weight'] for f in confidence_factors)
        weighted_sum = sum(f['weight'] * f['value'] for f in confidence_factors)
        base_confidence = weighted_sum / total_weight
        
  
        phishing_votes = 0
        total_votes = len(confidence_factors)
        
        if ml_prediction['available'] and ml_prediction['is_phishing']:
            phishing_votes += 1
        if virustotal_result.get('is_phishing', False):
            phishing_votes += 1
        if in_blacklist:
            phishing_votes += 1
        if heuristic_score >= 2:
            phishing_votes += 1
        
        is_phishing = phishing_votes >= (total_votes / 2)
        
        agreement_ratio = phishing_votes / total_votes if total_votes > 0 else 0.5
        
        if agreement_ratio >= 0.75:
            base_confidence = min(base_confidence + 15, 99)
        elif agreement_ratio >= 0.5:
            base_confidence = min(base_confidence + 5, 95)
        
      
        if virustotal_result.get('reputation'):
            reputation = virustotal_result.get('reputation', 50)
            if reputation < 0 and virustotal_result.get('is_phishing', False):
                base_confidence = min(base_confidence + 10, 99)
            elif reputation > 80 and not virustotal_result.get('is_phishing', False):
                base_confidence = min(base_confidence + 5, 95)
        
        
        final_confidence = min(max(base_confidence, 1), 99)
        
        return is_phishing, final_confidence, sources
    

    return False, 50.0, ['no-sources']

def get_risk_level(confidence, is_phishing):
    """Determine risk level based on confidence"""
    if is_phishing:
        if confidence >= 90:
            return 'CRITICAL'
        elif confidence >= 75:
            return 'HIGH'
        elif confidence >= 60:
            return 'MEDIUM'
        else:
            return 'LOW'
    else:
        if confidence >= 90:
            return 'VERY LOW'
        elif confidence >= 75:
            return 'LOW'
        else:
            return 'CAUTION'

@app.route('/api/status')
def api_status_check():
    """Check API status"""
  
    test_url = "http://example.com"
    test_result = check_virustotal_real(test_url)
    
    return jsonify({
        'virustotal': {
            'available': api_status['virustotal_available'],
            'api_key_valid': Config.VIRUSTOTAL_API_KEY != "3bf4596ce67b65cc9b4316e60ce39f02c71896e416e71f4bd748dabf1654bad3",
            'rate_limit': {
                'requests_this_minute': api_status['requests_this_minute'],
                'max_per_minute': 4,
                'reset_in': max(0, 60 - (time.time() - api_status['rate_limit_reset']))
            },
            'last_check': api_status['last_check']
        },
        'cache': {
            'size': len(url_cache),
            'hits': sum(1 for r in scan_history if r.get('cache_hit', False)),
            'total_scans': len(scan_history)
        }
    })


@app.after_request
def add_cors_headers(response):
    """Add CORS headers for browser extension"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    

    if request.method == 'OPTIONS':
        response.headers['Access-Control-Max-Age'] = '86400'  
    
    return response

@app.route('/api/extension/check', methods=['POST'])
def extension_check_url():
    """Check URL for browser extension with enhanced error handling"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data received'}), 400
            
        url = data.get('url', '').strip()
        
        # Enhanced URL validation
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Sanitize and validate URL
        try:
            # Remove any control characters
            url = ''.join(char for char in url if ord(char) >= 32 or ord(char) <= 126)
            
            # Check for extremely long URLs
            if len(url) > 2048:
                return jsonify({
                    'url': url[:50] + '...',
                    'is_phishing': True,
                    'confidence': 95,
                    'risk_level': 'HIGH',
                    'source': 'validation',
                    'error': 'URL exceeds maximum length',
                    'message': 'URL rejected due to excessive length'
                })
            
            # Check for null bytes and dangerous patterns
            dangerous_patterns = [r'\x00', r'%00', r'\\x00', r'%0d%0a', r'%0a', r'%0d']
            for pattern in dangerous_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    return jsonify({
                        'url': url[:50] + '...',
                        'is_phishing': True,
                        'confidence': 98,
                        'risk_level': 'CRITICAL',
                        'source': 'validation',
                        'error': 'Malformed URL detected',
                        'message': 'URL contains invalid characters'
                    })
            
            # Validate URL format
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc and not parsed.path:
                # Try adding scheme
                if not url.startswith(('http://', 'https://')):
                    test_url = 'http://' + url
                    parsed = urllib.parse.urlparse(test_url)
                    if parsed.netloc:
                        url = test_url
                    else:
                        return jsonify({
                            'url': url,
                            'is_phishing': False,
                            'confidence': 30,
                            'risk_level': 'INVALID',
                            'source': 'validation',
                            'error': 'Invalid URL format',
                            'message': 'Please enter a valid URL (e.g., https://example.com)'
                        })
            elif not parsed.scheme:
                url = 'http://' + url
                
        except Exception as e:
            return jsonify({
                'url': url[:50] + '...',
                'is_phishing': False,
                'confidence': 20,
                'risk_level': 'INVALID',
                'source': 'validation',
                'error': f'URL parsing failed: {str(e)}',
                'message': 'Invalid URL format'
            })
        
        # Check cache
        cache_key = hashlib.md5(url.encode()).hexdigest()
        with cache_lock:
            if cache_key in url_cache:
                cached = url_cache[cache_key]
                cache_age = time.time() - cached.get('timestamp', 0)
                if cache_age < 900:
                    return jsonify({
                        'url': url,
                        'is_phishing': cached.get('is_phishing', False),
                        'confidence': cached.get('confidence', 50),
                        'risk_level': cached.get('risk_level', 'UNKNOWN'),
                        'cached': True,
                        'source': 'cache'
                    })
        
        # Check blacklist/whitelist
        domain = urllib.parse.urlparse(url).netloc
        if any(black in domain for black in Config.LOCAL_BLACKLIST):
            return jsonify({
                'url': url,
                'is_phishing': True,
                'confidence': 95,
                'risk_level': 'HIGH',
                'source': 'local_blacklist',
                'message': 'Domain in blacklist'
            })
        
        if any(white in domain for white in Config.LOCAL_WHITELIST):
            return jsonify({
                'url': url,
                'is_phishing': False,
                'confidence': 90,
                'risk_level': 'LOW',
                'source': 'local_whitelist',
                'message': 'Domain in whitelist'
            })
        
        # Return quick result and trigger background scan
        result = {
            'url': url,
            'is_phishing': False,
            'confidence': 50,
            'risk_level': 'CAUTION',
            'requires_full_scan': True,
            'message': 'Quick scan complete, full analysis in background'
        }
        
        executor.submit(do_full_scan_for_extension, url)
        return jsonify(result)
        
    except Exception as e:
        print(f"Extension check error: {e}")
        return jsonify({
            'error': 'Internal server error',
            'url': url if 'url' in locals() else 'unknown',
            'is_phishing': False,
            'confidence': 0,
            'risk_level': 'ERROR'
        }), 500

@app.route('/api/extension/status', methods=['GET'])
def extension_status():
    """Check if extension API is working"""
    return jsonify({
        'status': 'online',
        'name': 'PhishGuard',
        'version': '1.0',
        'model_loaded': model is not None,
        'cache_size': len(url_cache),
        'time': datetime.now().isoformat()
    })

@app.route('/api/extension/blocked')
def show_block_page():
    """Show blocked page for phishing URLs"""
    url = request.args.get('url', 'Unknown URL')
    risk = request.args.get('risk', 'HIGH')
    

    scan_history.append({
        'scan_id': generate_scan_id_with_timestamp(),
        'url': url,
        'action': 'blocked_by_extension',
        'timestamp': datetime.now().isoformat(),
        'is_phishing': True,
        'risk_level': risk
    })
    
    return render_template('blocked.html')

@app.route('/api/debug/virustotal')
def debug_virustotal():
    """Debug VirusTotal API connection"""
    test_url = "http://example.com"
    
 
    placeholder_key = "3bf4596ce67b65cc9b4316e60ce39f02c71896e416e71f4bd748dabf1654bad3"
    
    result = {
        'api_key_provided': bool(Config.VIRUSTOTAL_API_KEY),
        'is_placeholder': Config.VIRUSTOTAL_API_KEY == placeholder_key if Config.VIRUSTOTAL_API_KEY else None,
        'api_key_preview': Config.VIRUSTOTAL_API_KEY[:10] + "..." if Config.VIRUSTOTAL_API_KEY and len(Config.VIRUSTOTAL_API_KEY) > 10 else Config.VIRUSTOTAL_API_KEY,
        'api_key_length': len(Config.VIRUSTOTAL_API_KEY) if Config.VIRUSTOTAL_API_KEY else 0,
        'current_time': datetime.now().isoformat()
    }
    
   
    if Config.VIRUSTOTAL_API_KEY and Config.VIRUSTOTAL_API_KEY != placeholder_key:
        try:
            headers = {
                'x-apikey': Config.VIRUSTOTAL_API_KEY,
                'Accept': 'application/json'
            }
            
            response = requests.get(
                "https://www.virustotal.com/api/v3/users/me",
                headers=headers,
                timeout=10
            )
            
            result['api_test_response'] = {
                'status_code': response.status_code,
                  'status': 'success' if response.status_code == 200 else 'failed'
            }
            
            if response.status_code == 200:
                result['api_key_valid'] = True
                result['user_info'] = response.json().get('data', {})
            elif response.status_code == 401:
                result['api_key_valid'] = False
                result['error'] = 'Unauthorized - Invalid API key'
            else:
                result['api_key_valid'] = False
                result['error'] = f'HTTP {response.status_code}'
                
        except Exception as e:
            result['api_test_response'] = {'error': str(e)}
            result['api_key_valid'] = False
    else:
        result['api_key_valid'] = False
        result['error'] = 'No valid API key configured'
    
    return jsonify(result)

if __name__ == '__main__':
 
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    print("=" * 60)
    print("🚀 URL Phishing Detector with VirusTotal Integration")
    print("=" * 60)
    print(f"📊 Model Status: {'Loaded' if model else 'Not trained'}")
    print(f"🛡️ VirusTotal API: {'Configured' if Config.VIRUSTOTAL_API_KEY != '3bf4596ce67b65cc9b4316e60ce39f02c71896e416e71f4bd748dabf1654bad3' else 'Not configured'}")
    print(f"⏱️ Rate Limit: 4 requests/minute (free tier)")
    print(f"💾 Cache: {Config.CACHE_SIZE_LIMIT} entries max")
    print(f"🌍 Server running on: http://localhost:5000")
    print("=" * 60)
    
    if Config.VIRUSTOTAL_API_KEY == "3bf4596ce67b65cc9b4316e60ce39f02c71896e416e71f4bd748dabf1654bad3":
        print("⚠ IMPORTANT: Get VirusTotal API key from:")
        print("   https://www.virustotal.com/gui/join-us")
        print("   Free tier: 500 requests/day, 4 requests/minute")
        print("   Without it, the system will NOT use mock data")
        print("=" * 60)
    
    app.run(debug=True, port=5000, threaded=True)
               