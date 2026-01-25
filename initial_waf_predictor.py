"""
WAF Predictor for the initial trained model
Uses the same feature extraction as the training data
"""

import pickle
import re
import pandas as pd
from urllib.parse import unquote

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
        full_content = path + ' ' + body
        
        # Basic character counts (matching training data)
        features['single_q'] = full_content.count("'")
        features['double_q'] = full_content.count('"')
        features['dashes'] = len(re.findall(r'-+', full_content))
        features['braces'] = full_content.count('{') + full_content.count('}')
        features['spaces'] = full_content.count(' ')
        features['percentages'] = full_content.count('%')
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
    
    def is_malicious(self, method, path, body='', threshold=None):
        """Check if request is malicious based on threshold"""
        if threshold is None:
            threshold = self.threshold
        
        probability = self.predict_request(method, path, body)
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
