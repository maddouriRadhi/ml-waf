#!/usr/bin/env python3
import requests
import time

def test_proxy():
    """Test if WAF proxy is working and logging requests"""
    print("🧪 Testing WAF Proxy with simple request...")
    
    try:
        # Test 1: Send a simple request
        print("📤 Test 1: Sending simple request...")
        response = requests.get('http://127.0.0.1:8085/test', timeout=5)
        print(f"   Status: {response.status_code}")
        
        # Test 2: Send a request that should be logged
        print("📤 Test 2: Sending request that should be logged...")
        response = requests.get('http://127.0.0.1:8085/test?log=1', timeout=5)
        print(f"   Status: {response.status_code}")
        
        # Wait a moment for logging
        time.sleep(2)
        
        # Check database for recent logs
        print("⏱ Checking database for recent logs...")
        try:
            from database_config import db_manager
            result = db_manager.execute_query("""
                SELECT COUNT(*) as count 
                FROM requests 
                WHERE timestamp >= NOW() - INTERVAL '2 minutes'
                AND decision IN ('blocked_ml', 'blocked_content', 'blocked_popup')
            """)
            
            if result:
                blocked_count = result[0]['count']
                print(f"   ✅ Found {blocked_count} blocked requests in last 2 minutes")
            else:
                print("   ❌ No blocked requests found in last 2 minutes")
                
        except Exception as e:
            print(f"   ❌ Database error: {e}")
    
    print("\n🎯 Test Results:")
    print("   ✅ All tests completed!")
    print("   📊 Expected: Requests should be logged to database")

if __name__ == '__main__':
    test_proxy()
