"""
Feature Extractor for ML-WAF
Extracts relevant features from HTTP requests for ML classification
"""

import re
from urllib.parse import urlparse, unquote
import math

class FeatureExtractor:
    def __init__(self):
        # Common attack patterns
        self.sql_patterns = [
            r"union.*select", r"select.*from", r"insert.*into",
            r"delete.*from", r"drop.*table", r"'; drop", r"or 1=1",
            r"' or '1'='1", r"admin'--", r"' or 1=1--"
        ]
        
        self.xss_patterns = [
            r"<script", r"javascript:", r"onerror=", r"onload=",
            r"<iframe", r"eval\(", r"alert\(", r"document\.cookie"
        ]
        
        self.rce_patterns = [
            r"\|", r";", r"&&", r"\$\(", r"`", r"bash", r"sh -c",
            r"cmd.exe", r"powershell", r"/bin/", r"wget", r"curl"
        ]
        
        self.traversal_patterns = [
            r"\.\./", r"\.\.\\", r"%2e%2e", r"etc/passwd",
            r"windows/system32"
        ]

    def extract(self, request_str):
        """Extract features from HTTP request"""
        features = {}
        
        # Parse request line
        lines = request_str.split('\n')
        request_line = lines[0] if lines else ""
        
        # Extract URL
        parts = request_line.split(' ')
        method = parts[0] if len(parts) > 0 else "GET"
        url = parts[1] if len(parts) > 1 else "/"
        
        # Decode URL
        decoded_url = unquote(url)
        
        # Feature 1: URL Length
        features['url_length'] = len(url)
        
        # Feature 2: Number of special characters
        special_chars = re.findall(r'[^a-zA-Z0-9\s]', url)
        features['special_char_count'] = len(special_chars)
        
        # Feature 3: Number of digits
        features['digit_count'] = len(re.findall(r'\d', url))
        
        # Feature 4: Entropy of URL (randomness measure)
        features['url_entropy'] = self.calculate_entropy(url)
        
        # Feature 5: HTTP Method encoding
        method_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3, 'HEAD': 4, 'OPTIONS': 5}
        features['method_encoded'] = method_map.get(method, 6)
        
        # Feature 6-9: Attack pattern detection
        features['sql_injection_score'] = self.detect_pattern(decoded_url, self.sql_patterns)
        features['xss_score'] = self.detect_pattern(decoded_url, self.xss_patterns)
        features['rce_score'] = self.detect_pattern(decoded_url, self.rce_patterns)
        features['traversal_score'] = self.detect_pattern(decoded_url, self.traversal_patterns)
        
        # Feature 10: Number of query parameters
        features['param_count'] = url.count('&') + (1 if '?' in url else 0)
        
        # Feature 11: Presence of encoding (%xx)
        features['has_encoding'] = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
        
        # Feature 12: Number of slashes
        features['slash_count'] = url.count('/')
        
        # Feature 13: Number of dots
        features['dot_count'] = url.count('.')
        
        # Feature 14: Suspicious keywords
        suspicious_keywords = ['admin', 'root', 'config', 'passwd', 'shadow', 'cmd', 'exec']
        features['suspicious_keyword_count'] = sum(1 for kw in suspicious_keywords if kw in url.lower())
        
        # Feature 15: Request body size
        body_start = request_str.find('\r\n\r\n')
        body = request_str[body_start:] if body_start != -1 else ""
        features['body_length'] = len(body)
        
        # Feature 16: Contains null byte
        features['has_null_byte'] = 1 if '\x00' in request_str or '%00' in url else 0
        
        # Feature 17: Double encoding check
        features['double_encoded'] = 1 if re.search(r'%25[0-9a-fA-F]{2}', url) else 0
        
        # Feature 18: Unusual port in URL
        parsed = urlparse(url)
        features['unusual_port'] = 1 if parsed.port and parsed.port not in [80, 443, 8080] else 0
        
        # Feature 19: Contains base64-like patterns
        features['has_base64'] = 1 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', url) else 0
        
        # Feature 20: Total risk score (sum of pattern detections)
        features['total_risk_score'] = (
            features['sql_injection_score'] +
            features['xss_score'] +
            features['rce_score'] +
            features['traversal_score']
        )
        
        return features

    def calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy

    def detect_pattern(self, text, patterns):
        """Detect attack patterns and return score"""
        text_lower = text.lower()
        score = 0
        
        for pattern in patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                score += 1
        
        return score

    def get_feature_names(self):
        """Return list of feature names"""
        return [
            'url_length', 'special_char_count', 'digit_count', 'url_entropy',
            'method_encoded', 'sql_injection_score', 'xss_score', 'rce_score',
            'traversal_score', 'param_count', 'has_encoding', 'slash_count',
            'dot_count', 'suspicious_keyword_count', 'body_length', 'has_null_byte',
            'double_encoded', 'unusual_port', 'has_base64', 'total_risk_score'
        ]