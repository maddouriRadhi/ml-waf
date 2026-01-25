"""
WAF Predictor Module
Integrates trained model with WAF system for real-time prediction
"""

import pickle
import os
import logging
import pandas as pd
from feature_extractor import FeatureExtractor
from feature_adapter import FeatureAdapter

class WAFPredictor:
    """WAF Predictor using trained model"""
    
    def __init__(self, model_path='models/waf_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.feature_extractor = FeatureExtractor()
        self.feature_adapter = FeatureAdapter()
        self.logger = logging.getLogger(__name__)
        
        # Load trained model
        self.load_model()
    
    def load_model(self):
        """Load the trained model"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    obj = pickle.load(f)
                # sklearn dict format produced by train_model.py
                if isinstance(obj, dict) and 'model' in obj:
                    self.clf = obj['model']
                    self.threshold = obj.get('threshold', 0.8)
                    self.model_type = 'sklearn'
                    self.logger.info(f"Loaded sklearn model from {self.model_path} (threshold={self.threshold})")
                else:
                    # fallback to legacy threshold model
                    self.model = obj
                    self.model_type = obj.get('type', 'unknown')
                    self.logger.info(f"Model loaded from {self.model_path} type={self.model_type}")
            else:
                self.logger.error(f"Model file not found: {self.model_path}")
                raise FileNotFoundError(f"Model not found at {self.model_path}")
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            raise
    
    def predict_request(self, method, path, body=''):
        """Predict if a request is malicious"""
        try:
            # Create request string for FeatureExtractor
            request_str = f"{method} {path} HTTP/1.1\n\n{body}"
            
            feats = self.feature_extractor.extract(request_str)
            
            # sklearn model dict path
            if hasattr(self, 'clf'):
                X = pd.DataFrame([feats])
                prob = self.clf.predict_proba(X)[0,1]
                return prob
            
            # legacy threshold model
            adapted = self.feature_adapter.adapt_features(feats, method, path, body)
            if self.model_type == 'threshold_based':
                return self._predict_threshold(adapted)
            return 0.0
                
        except Exception as e:
            self.logger.error(f"Error predicting request: {e}")
            return 0.0  # Default to safe (not malicious)
    
    def _predict_threshold(self, features):
        """Predict using threshold-based model"""
        try:
            thresholds = self.model['thresholds']
            feature_columns = self.model['feature_columns']
            
            # Map features to correct order
            feature_values = []
            for col in feature_columns:
                if col in features:
                    feature_values.append(float(features[col]))
                else:
                    feature_values.append(0.0)
            
            # Calculate score based on thresholds
            score = 0
            for i, (value, threshold) in enumerate(zip(feature_values, thresholds)):
                if value > threshold:
                    score += 1
            
            # Normalize to probability
            probability = score / len(feature_values)
            return probability
            
        except Exception as e:
            self.logger.error(f"Error in threshold prediction: {e}")
            return 0.0
    
    def _predict_sklearn(self, features):
        """Predict using sklearn model (if available)"""
        try:
            # This would be used if we had sklearn models
            # For now, fallback to simple logic
            return 0.0
        except Exception as e:
            self.logger.error(f"Error in sklearn prediction: {e}")
            return 0.0
    
    def is_malicious(self, method, path, body='', threshold=0.5):
        """Check if request is malicious based on threshold"""
        probability = self.predict_request(method, path, body)
        return probability > threshold, probability
    
    def get_feature_importance(self):
        """Get feature importance from model"""
        if self.model and 'bad_avg' in self.model and 'good_avg' in self.model:
            return {
                'feature_columns': self.model['feature_columns'],
                'bad_averages': self.model['bad_avg'],
                'good_averages': self.model['good_avg'],
                'thresholds': self.model['thresholds']
            }
        return None
    
    def get_model_info(self):
        """Get model information"""
        if self.model:
            return {
                'type': self.model.get('type', 'unknown'),
                'features': len(self.model.get('feature_columns', [])),
                'model_path': self.model_path
            }
        return None

# Test the predictor
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    predictor = WAFPredictor()
    
    # Test with some sample requests
    test_requests = [
        ('GET', '/', '', 'Good request'),
        ('GET', '/admin', '', 'Admin access'),
        ('POST', '/login', 'username=admin&password=123', 'Login attempt'),
        ('GET', '/search?q=<script>alert(1)</script>', '', 'XSS attempt'),
        ('POST', '/upload', 'file=../../../etc/passwd', 'Path traversal'),
    ]
    
    print("WAF Predictor Test Results:")
    print("=" * 50)
    
    for method, path, body, description in test_requests:
        is_malicious, probability = predictor.is_malicious(method, path, body)
        status = "MALICIOUS" if is_malicious else "SAFE"
        print(f"{description:25} | {status:10} | {probability:.3f}")
    
    print("=" * 50)
