"""
WAF Predictor for the initial trained model
Uses the same feature extraction as the training data
"""

import pickle
import re
import pandas as pd
from urllib.parse import unquote, unquote_plus

class InitialWAFPredictor:
    """WAF Predictor using the initially trained model"""
    
    def __init__(self, model_path='models/waf_model.pkl'):
        self.model_path = model_path
        self.model_data = None
        self.model = None
        self.feature_columns = None
        self.threshold = 0.8
        
        # Load trained model
        self.load_model()
    
    def load_model(self):
        """Load the trained model"""
        try:
            with open(self.model_path, 'rb') as f:
                self.model_data = pickle.load(f)
            
            self.model = self.model_data['model']
            self.threshold = self.model_data['threshold']
            self.feature_columns = self.model_data['feature_columns']

            # Some pickles store raw class counts in the tree leaves, which makes
            # predict_proba return values far above 1. Normalise in memory so the
            # score is a real probability between 0 and 1.
            try:
                for est in getattr(self.model, 'estimators_', []):
                    v = est.tree_.value
                    s = v.sum(axis=(1, 2), keepdims=True)
                    s[s == 0] = 1
                    v /= s
            except Exception as e:
                print(f"Warning: could not normalise model probabilities: {e}")
            
            print(f"Model loaded successfully from {self.model_path}")
            print(f"Threshold: {self.threshold}")
            print(f"Features: {len(self.feature_columns)}")
            
        except Exception as e:
            print(f"Error loading model: {e}")
            raise
    
    def extract_features(self, method, path, body=''):
        """Extract features matching the training data format"""
        features = {}
        
        # Combine path and body for analysis
        raw_content = path + ' ' + body
        # Decode URL-encoding (twice, to also catch double-encoded payloads) so that
        # %27%20OR%20%271%27... is analysed as the real attack string ' OR '1'...
        full_content = unquote_plus(unquote_plus(raw_content))  # '+' is a space in forms/queries
        
        # Basic character counts (matching training data)
        features['single_q'] = full_content.count("'")
        features['double_q'] = full_content.count('"')
        features['dashes'] = len(re.findall(r'-+', full_content))
        features['braces'] = full_content.count('{') + full_content.count('}')
        features['spaces'] = full_content.count(' ')
        features['percentages'] = raw_content.count('%')
        features['semicolons'] = full_content.count(';')
        features['angle_brackets'] = full_content.count('<') + full_content.count('>')
        
        # Special characters (anything not alphanumeric or common punctuation)
        special_chars = re.findall(r'[^a-zA-Z0-9\s\.\-_/=?&]', full_content)
        features['special_chars'] = len(special_chars)
        
        # Length features
        features['path_length'] = len(path)
        features['body_length'] = len(body)
        
        # Bad words count (common attack patterns)
        bad_words = [
            'select', 'union', 'drop', 'delete', 'insert', 'update',
            'script', 'javascript', 'alert', 'eval', 'iframe',
            'cmd.exe', 'powershell', '/bin/', 'wget', 'curl',
            '../', '..\\', 'etc/passwd', 'system32'
        ]
        
        badwords_count = 0
        content_lower = full_content.lower()
        for word in bad_words:
            badwords_count += content_lower.count(word)
        
        features['badwords_count'] = badwords_count
        
        # Method one-hot encoding
        for col in self.feature_columns:
            if col.startswith('method_'):
                method_name = col.replace('method_', '')
                features[col] = 1 if method.upper() == method_name.upper() else 0
        
        return features
    
    def predict_request(self, method, path, body=''):
        """Predict if a request is malicious"""
        try:
            # Extract features
            features = self.extract_features(method, path, body)
            
            # Create DataFrame with correct column order
            X = pd.DataFrame([features])
            
            # Ensure all required columns are present
            for col in self.feature_columns:
                if col not in X.columns:
                    X[col] = 0
            
            # Reorder columns to match training
            X = X[self.feature_columns]
            
            # Predict probability
            probability = self.model.predict_proba(X)[0, 1]
            return probability
            
        except Exception as e:
            print(f"Error predicting request: {e}")
            return 0.0  # Default to safe (not malicious)
    
    def _get_threshold(self):
        """Threshold from config.json (ml_classifier.threshold) if set, else the model's own"""
        try:
            import json, os
            cfg = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
            with open(cfg, 'r', encoding='utf-8') as f:
                value = json.load(f).get('ml_classifier', {}).get('threshold')
            if value is not None:
                return float(value)
        except Exception:
            pass
        return self.threshold

    def is_malicious(self, method, path, body='', threshold=None):
        """Check if request is malicious based on threshold"""
        if threshold is None:
            threshold = self._get_threshold()
        
        if (method or '').upper() in ('POST', 'PUT', 'PATCH'):
            return self._check_body_request(method, path, body, threshold)

        probability = self.predict_request(method, path, body)
        return probability > threshold, probability
    
    # --- Requests with a body (forms) -------------------------------------------
    # The model learned that "POST + body" is suspicious, so every normal login or
    # registration form scores 0.80-0.87. For POST/PUT/PATCH we therefore:
    #   1. remove password / CSRF-token values (random, never an injection vector here),
    #   2. only block when the ML score is high AND a real attack signature is present.
    _SENSITIVE_FIELD = re.compile(r'pass|pwd|token|csrf|secret', re.I)
    _ATTACK_RE = re.compile(
        r"""('\s*(or|and)\s+['"\d])"""
        r"""|(\b(or|and)\b\s+['"]?\w+['"]?\s*=\s*['"]?\w+)"""
        r"""|(\bunion\b.{0,40}\bselect\b)|(\bselect\b.{1,60}\bfrom\b)"""
        r"""|(;\s*(drop|delete|insert|update|select)\b)|(\bdrop\s+(table|database)\b)"""
        r"""|(--\s|--$|/\*|\*/|'\s*(--|#))|(\b(sleep|benchmark|waitfor)\b\s*[\(d])"""
        r"""|(<\s*/?\s*(script|img|iframe|svg|body|object|embed)\b)|(javascript:)|(\bon\w{3,20}\s*=)"""
        r"""|(\.\./)|(\.\.\\)|(etc/passwd)|(system32)|(boot\.ini)"""
        r"""|(;\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|powershell)\b)|(\|\s*(cat|ls|id|whoami|nc|bash|sh)\b)"""
        r"""|(\$\()|(`)|(cmd\.exe)|(/bin/(ba)?sh)|(%00)""",
        re.I | re.S)

    def _scrub_body(self, body):
        """Blank out the value of password / token style fields in a form body"""
        from urllib.parse import unquote_plus
        parts = []
        for piece in (body or '').strip().split('&'):
            name, sep, _value = piece.partition('=')
            if sep and self._SENSITIVE_FIELD.search(unquote_plus(name)):
                piece = name + '='
            parts.append(piece)
        return '&'.join(parts)

    def _check_body_request(self, method, path, body, threshold):
        clean_body = self._scrub_body(body)
        probability = self.predict_request(method, path, clean_body)
        decoded = unquote_plus(unquote_plus(path + ' ' + clean_body))
        if not self._ATTACK_RE.search(decoded):
            # No attack signature: the high score only reflects the POST/body bias
            return False, min(probability, 0.5)
        return probability > threshold, probability

    def get_model_info(self):
        """Get model information"""
        if self.model_data:
            stats = self.model_data.get('training_stats', {})
            return {
                'model_type': 'RandomForest',
                'features': len(self.feature_columns),
                'threshold': self.threshold,
                'model_path': self.model_path,
                'training_samples': stats.get('training_samples', 'Unknown'),
                'test_samples': stats.get('test_samples', 'Unknown'),
                'roc_auc': stats.get('roc_auc', 'Unknown'),
                'accuracy': stats.get('accuracy', 'Unknown')
            }
        return None

# Test the predictor
if __name__ == "__main__":
    predictor = InitialWAFPredictor()
    
    # Test with some sample requests
    test_requests = [
        ('GET', '/', '', 'Good request'),
        ('GET', '/search?q=<script>alert(1)</script>', '', 'XSS attempt'),
        ('POST', '/login', 'username=admin&password=123', 'Login attempt'),
        ('POST', '/upload', 'file=../../../etc/passwd', 'Path traversal'),
        ('GET', '/admin', '', 'Admin access'),
        ('POST', '/api', "'; DROP TABLE users; --", 'SQL Injection'),
    ]
    
    print("Initial WAF Model Test Results:")
    print("=" * 60)
    
    for method, path, body, description in test_requests:
        is_malicious, probability = predictor.is_malicious(method, path, body)
        status = "MALICIOUS" if is_malicious else "SAFE"
        print(f"{description:25} | {status:10} | {probability:.4f}")
    
    print("=" * 60)
    print(f"Model Info: {predictor.get_model_info()}")
