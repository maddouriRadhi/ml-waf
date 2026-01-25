"""
Popup Blocker Module
Detects and blocks popup windows in HTTP responses
"""

import re
import logging

class PopupBlocker:
    def __init__(self, config):
        self.config = config
        self.enabled = config.get('enabled', True)
        self.aggressiveness = config.get('aggressiveness', 'moderate')  # strict, moderate, permissive
        self.logger = logging.getLogger(__name__)
        
        # Popup detection patterns
        self.popup_patterns = [
            r'window\.open\s*\(',
            r'target\s*=\s*["\']_blank["\']',
            r'popup',
            r'window\.showModalDialog',
            r'onclick\s*=\s*["\'].*window\.open',
            r'<a[^>]*target=["\']_blank["\'][^>]*>',
        ]
        
        # Aggressive patterns (only used in strict mode)
        self.strict_patterns = [
            r'target\s*=\s*["\']_blank["\']',
            r'rel\s*=\s*["\']noopener["\']',
            r'window\.location',
        ]
        
        self.logger.info(f"Popup Blocker initialized. Mode: {self.aggressiveness}")

    def detect_popup(self, response_str):
        """Detect if response contains popup code"""
        if not self.enabled:
            return False
        
        response_lower = response_str.lower()
        
        # Check standard popup patterns
        for pattern in self.popup_patterns:
            if re.search(pattern, response_lower, re.IGNORECASE):
                self.logger.debug(f"Popup detected with pattern: {pattern}")
                return True
        
        # Check strict patterns if in strict mode
        if self.aggressiveness == 'strict':
            for pattern in self.strict_patterns:
                if re.search(pattern, response_lower, re.IGNORECASE):
                    self.logger.debug(f"Popup detected (strict mode): {pattern}")
                    return True
        
        return False

    def block_popup(self, response_data):
        """Remove or neutralize popup code from response"""
        try:
            response_str = response_data.decode('utf-8', errors='ignore')
            
            # Remove window.open calls
            response_str = re.sub(
                r'window\.open\s*\([^)]*\)',
                '/* popup blocked */',
                response_str,
                flags=re.IGNORECASE
            )
            
            # Modify target="_blank" to target="_self"
            if self.aggressiveness in ['moderate', 'strict']:
                response_str = re.sub(
                    r'target\s*=\s*["\']_blank["\']',
                    'target="_self"',
                    response_str,
                    flags=re.IGNORECASE
                )
            
            # Remove onclick popup triggers
            response_str = re.sub(
                r'onclick\s*=\s*["\'][^"\']*window\.open[^"\']*["\']',
                'onclick="return false;"',
                response_str,
                flags=re.IGNORECASE
            )
            
            # Inject Content Security Policy
            response_str = self._inject_csp(response_str)
            
            # Inject popup blocking JavaScript
            response_str = self._inject_popup_blocker_js(response_str)
            
            return response_str.encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error blocking popup: {str(e)}")
            return response_data

    def _inject_csp(self, response_str):
        """Inject Content Security Policy header to prevent popups"""
        # Check if headers section exists
        header_end = response_str.find('\r\n\r\n')
        if header_end == -1:
            return response_str
        
        # Add CSP header
        csp_header = "Content-Security-Policy: script-src 'self' 'unsafe-inline'; default-src 'self'\r\n"
        
        headers = response_str[:header_end]
        body = response_str[header_end:]
        
        # Only add if CSP not already present
        if 'Content-Security-Policy' not in headers:
            headers += csp_header
        
        return headers + body

    def _inject_popup_blocker_js(self, response_str):
        """Inject JavaScript to block popups client-side"""
        popup_blocker_script = """
<script>
// ML-WAF Popup Blocker
(function() {
    // Override window.open
    var originalOpen = window.open;
    window.open = function() {
        console.log('[ML-WAF] Popup blocked');
        return null;
    };
    
    // Block target="_blank" clicks
    document.addEventListener('click', function(e) {
        if (e.target.tagName === 'A' && e.target.target === '_blank') {
            e.preventDefault();
            e.target.target = '_self';
            console.log('[ML-WAF] Redirected _blank to _self');
        }
    }, true);
    
    // Prevent showModalDialog
    if (window.showModalDialog) {
        window.showModalDialog = function() {
            console.log('[ML-WAF] Modal dialog blocked');
            return null;
        };
    }
})();
</script>
"""
        
        # Inject before </head> or at start of <body>
        if '</head>' in response_str:
            response_str = response_str.replace('</head>', popup_blocker_script + '</head>', 1)
        elif '<body>' in response_str:
            response_str = response_str.replace('<body>', '<body>' + popup_blocker_script, 1)
        
        return response_str

    def set_aggressiveness(self, level):
        """Set popup blocking aggressiveness level"""
        valid_levels = ['strict', 'moderate', 'permissive']
        if level in valid_levels:
            self.aggressiveness = level
            self.logger.info(f"Popup blocker aggressiveness set to: {level}")
            return True
        return False

    def enable(self):
        """Enable popup blocker"""
        self.enabled = True
        self.logger.info("Popup blocker enabled")

    def disable(self):
        """Disable popup blocker"""
        self.enabled = False
        self.logger.info("Popup blocker disabled")

    def is_enabled(self):
        """Check if popup blocker is enabled"""
        return self.enabled

    def get_stats(self):
        """Return popup blocker statistics"""
        return {
            'enabled': self.enabled,
            'aggressiveness': self.aggressiveness
        }