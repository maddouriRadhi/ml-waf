#!/usr/bin/env python3
"""
Test script to verify WAF proxy request logging functionality
"""

import requests
import time
import json

def test_proxy_logging():
    """Test if WAF proxy is properly logging requests to database"""
    print("🧪 Testing WAF Proxy Request Logging...")
    
    # Test 1: Send a legitimate request
    print("\n📤 Test 1: Sending legitimate request...")
    try:
        response = requests.get('http://127.0.0.1:8085/E-Learning-APP/test.php', timeout=5)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:200]}...")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    time.sleep(2)
    
    # Test 2: Send a malicious request
    print("\n🚫 Test 2: Sending malicious request...")
    try:
        response = requests.get('http://127.0.0.1:8085/E-Learning-APP/test.php?malicious=1', timeout=5)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:200]}...")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    time.sleep(2)
    
    # Test 3: Send request with content that should be blocked
    print("\n🚫 Test 3: Sending content filter blocked request...")
    try:
        response = requests.get('http://127.0.0.1:8085/E-Learning-APP/test.php?block_content=1', timeout=5)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:200]}...")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    time.sleep(2)
    
    # Test 4: Send request with popup content
    print("\n🚫 Test 4: Sending popup blocked request...")
    try:
        response = requests.get('http://127.0.0.1:8085/E-Learning-APP/test.php?popup=1', timeout=5)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:200]}...")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n⏱ Checking database for logged requests...")
    
    # Check database for recent logs
    try:
        from database_config import db_manager
        result = db_manager.execute_query("""
            SELECT COUNT(*) as count 
            FROM requests 
            WHERE timestamp >= NOW() - INTERVAL '5 minutes'
            AND decision IN ('blocked_ml', 'blocked_content', 'blocked_popup')
        """)
        
        if result:
            blocked_count = result[0]['count']
            print(f"   ✅ Found {blocked_count} blocked requests in last 5 minutes")
        else:
            print("   ❌ No blocked requests found in last 5 minutes")
            
    except Exception as e:
        print(f"   ❌ Database error: {e}")
    
    print("\n🎯 Test Results:")
    print("   ✅ All tests completed!")
    print("   📊 Expected: All requests should be logged to database")
    print("   🔍 Check the dashboard to see if blocked requests appear in statistics")

if __name__ == '__main__':
    test_proxy_logging()
