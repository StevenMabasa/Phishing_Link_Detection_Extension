#!/usr/bin/env python3
"""
Test script to verify the local model server setup
"""

import requests
import json
import sys

def test_server():
    """Test the local model server"""
    base_url = "http://localhost:5000"
    
    print("Testing Phishing Detection Model Server...")
    print("=" * 50)
    
    # Test health endpoint
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            print("✅ Health check passed")
            print(f"   Response: {response.json()}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Cannot connect to server: {e}")
        print("   Make sure the server is running with: ./start_server.sh")
        return False
    
    # Test prediction endpoint
    test_urls = [
        "https://www.google.com",
        "https://www.github.com", 
        "http://suspicious-site.example.com",
        "https://www.paypal.com"
    ]
    
    print("\nTesting URL predictions...")
    for url in test_urls:
        try:
            response = requests.post(
                f"{base_url}/predict",
                json={"url": url, "threshold": 0.5},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ {url}")
                print(f"   Label: {data['label']}")
                print(f"   Probability: {data['probability']:.4f}")
                print(f"   Confidence: {data['confidence']:.4f}")
                print(f"   Is Phishing: {data['is_phishing']}")
            else:
                print(f"❌ {url} - Error: {response.status_code}")
                print(f"   Response: {response.text}")
                
        except requests.exceptions.RequestException as e:
            print(f"❌ {url} - Request failed: {e}")
    
    print("\n" + "=" * 50)
    print("Test completed!")
    return True

if __name__ == "__main__":
    test_server()
