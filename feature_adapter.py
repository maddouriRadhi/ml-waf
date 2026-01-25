"""
Feature Adapter
Maps FeatureExtractor output to match trained model's expected features
"""

import re
from urllib.parse import unquote

class FeatureAdapter:
    """Adapter to convert FeatureExtractor output to match CSV-trained model features"""
    
    def __init__(self):
        self.expected_features = [
            'single_q', 'double_q', 'dashes', 'braces', 'spaces', 
            'percentages', 'semicolons', 'angle_brackets', 'special_chars',
            'path_length', 'body_length', 'badwords_count'
        ]
    
    def adapt_features(self, extractor_features, method, path, body=''):
        """Adapt FeatureExtractor output to match model's expected features"""
        try:
            adapted = {}
            
            # Extract path and body from request
            full_path = path
            full_body = body
            
            # Count specific characters in path and body
            full_request = full_path + ' ' + full_body
            
            adapted['single_q'] = full_request.count("'")
            adapted['double_q'] = full_request.count('"')
            adapted['dashes'] = full_request.count('-')
            adapted['braces'] = full_request.count('{') + full_request.count('}')
            adapted['spaces'] = full_request.count(' ')
            adapted['percentages'] = full_request.count('%')
            adapted['semicolons'] = full_request.count(';')
            adapted['angle_brackets'] = full_request.count('<') + full_request.count('>')
            
            # Count special characters (everything except alphanumeric and common safe chars)
            special_chars_pattern = r'[^a-zA-Z0-9_\-./=&?]'
            adapted['special_chars'] = len(re.findall(special_chars_pattern, full_request))
            
            # Path length
            adapted['path_length'] = len(full_path)
            
            # Body length
            adapted['body_length'] = len(full_body)
            
            # Bad words count (common attack patterns)
            bad_words = [
                'select', 'union', 'insert', 'delete', 'drop', 'script', 'alert',
                'javascript', 'onerror', 'onload', 'eval', 'document', 'cookie',
                'cmd', 'bash', 'powershell', 'wget', 'curl', '../', '..\\',
                'etc/passwd', 'system32', 'admin', 'root', 'password'
            ]
            
            badword_count = 0
            request_lower = full_request.lower()
            for word in bad_words:
                if word in request_lower:
                    badword_count += request_lower.count(word)
            
            adapted['badwords_count'] = badword_count
            
            return adapted
            
        except Exception as e:
            # Return default values if adaptation fails
            return {feature: 0 for feature in self.expected_features}
    
    def get_feature_mapping(self):
        """Get the mapping of expected features"""
        return self.expected_features.copy()
