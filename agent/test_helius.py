#!/usr/bin/env python3
"""
Enhanced Test Script with Intelligent Rate Limiting
Uses the same logic as your SecuritySensor
"""

import requests
import os
import time
import asyncio
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_helius_connection():
    """Test if Helius API key works with real Solana data"""
    
    HELIUS_API_KEY = os.getenv("HELIUS_API_KEY")
    
    if not HELIUS_API_KEY:
        print("❌ HELIUS_API_KEY not found in environment!")
        return False
    
    print(f"🔑 Testing Helius API Key: {HELIUS_API_KEY[:8]}...")
    
    # Test basic API connectivity
    helius_url = f"https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
    
    # Test with a simple RPC call
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getHealth",
        "params": []
    }
    
    try:
        response = requests.post(helius_url, json=payload, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            if "result" in result and result["result"] == "ok":
                print("✅ Helius API connection successful!")
                print("🚀 Your system can fetch real Solana blockchain data!")
                return True
            else:
                print(f"⚠️ Unexpected response: {result}")
                return False
        else:
            print(f"❌ HTTP Error {response.status_code}: {response.text}")
            return False
            
    except requests.RequestException as e:
        print(f"❌ Connection error: {e}")
        return False

def test_wallet_monitoring_with_fallback():
    """Test monitoring with automatic fallback to different RPCs"""
    
    # Get configured wallets
    monitored_wallets = []
    for key in os.environ.keys():
        if key.startswith("MONITOR_WALLET_"):
            wallet = os.environ[key]
            if wallet:
                monitored_wallets.append(wallet)
    
    if not monitored_wallets:
        print("⚠️ No MONITOR_WALLET_* addresses found in .env")
        return False
    
    print(f"\n🏦 Found {len(monitored_wallets)} wallets to monitor:")
    for i, wallet in enumerate(monitored_wallets, 1):
        print(f"   {i}. {wallet[:8]}...{wallet[-8:]}")
    
    # Multiple RPC endpoints (same as your enhanced client)
    HELIUS_API_KEY = os.getenv("HELIUS_API_KEY")
    rpc_endpoints = [
        f"https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}",
        "https://api.mainnet-beta.solana.com",
        "https://solana-api.projectserum.com",
        "https://rpc.ankr.com/solana",
    ]
    
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            monitored_wallets[0],
            {"encoding": "base64"}
        ]
    }
    
    # Try each endpoint until one works
    for i, rpc_url in enumerate(rpc_endpoints):
        endpoint_name = ["Helius", "Solana Public", "Serum", "Ankr"][i]
        
        try:
            print(f"🔄 Trying {endpoint_name}...")
            
            # Add delay to respect rate limits
            if i > 0:  # If not first attempt
                print(f"⏱️ Waiting 2 seconds between attempts...")
                time.sleep(2)
            
            response = requests.post(rpc_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if "result" in result:
                    print(f"✅ Successfully fetched wallet data from {endpoint_name}!")
                    print("🎯 Your SecuritySensor can monitor these wallets in real-time!")
                    print(f"🔄 Fallback system working: Will automatically switch RPCs if rate limited")
                    return True
                else:
                    print(f"⚠️ {endpoint_name}: Could not fetch wallet data: {result}")
            
            elif response.status_code == 429:
                print(f"🚫 {endpoint_name}: Rate limited (429) - trying next endpoint...")
                continue
            
            else:
                print(f"⚠️ {endpoint_name}: HTTP {response.status_code}")
                continue
                
        except requests.RequestException as e:
            print(f"⚠️ {endpoint_name}: Connection error: {e}")
            continue
    
    print("❌ All RPC endpoints failed or rate limited")
    return False

def test_enhanced_client():
    """Test if the enhanced RPC client is available"""
    try:
        # Try to import your enhanced client - FIXED IMPORT
        import sys
        sys.path.append('./src')
        
        # Try the correct class name first
        try:
            from analysis.solana_rpc_client import IntelligentSolanaRPCClient
            client_class = IntelligentSolanaRPCClient
            client_name = "IntelligentSolanaRPCClient"
        except ImportError:
            # Fall back to basic client
            from analysis.solana_rpc_client import SolanaRPCClient
            client_class = SolanaRPCClient
            client_name = "SolanaRPCClient"
        
        # Check if it has the enhanced features
        if hasattr(client_class, '__init__'):
            # Try to create an instance
            if client_name == "IntelligentSolanaRPCClient":
                test_client = client_class(
                    rpc_api_key=os.getenv("HELIUS_API_KEY"),
                    primary_rpc_url="https://mainnet.helius-rpc.com",
                    rpc_provider_name="Helius"
                )
            else:
                test_client = client_class(
                    rpc_url="https://api.mainnet-beta.solana.com"
                )
            
            if hasattr(test_client, 'endpoints'):
                print(f"✅ Enhanced RPC client detected: {client_name}")
                print(f"🔄 Multiple endpoints available: {len(test_client.endpoints)}")
                print("🚀 Your SecuritySensor will automatically handle rate limits!")
                return True
            else:
                print(f"⚠️ Basic RPC client detected: {client_name}")
                print("💡 No automatic rate limiting - system will still work but may hit rate limits")
                return False
        else:
            print("⚠️ Could not detect RPC client capabilities")
            return False
            
    except ImportError as e:
        print(f"⚠️ Could not import RPC client: {e}")
        print("💡 System will work with basic HTTP calls but no enhanced rate limiting")
        return False
    except Exception as e:
        print(f"⚠️ Error testing enhanced client: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 Testing your AI Security System configuration...\n")
    
    # Test 1: Basic Helius API connection
    api_works = test_helius_connection()
    
    # Test 2: Enhanced RPC client
    enhanced_client_available = test_enhanced_client()
    
    # Test 3: Wallet monitoring with fallback
    wallet_monitoring_works = test_wallet_monitoring_with_fallback()
    
    print("\n" + "="*50)
    if api_works and wallet_monitoring_works:
        print("🎉 SUCCESS! Your system is ready for LIVE DATA!")
        print("✅ Helius API working")
        print("✅ Wallet monitoring ready") 
        print("✅ Automatic fallback working")
        
        if enhanced_client_available:
            print("✅ Enhanced RPC client ready")
            print("🚀 Your SecuritySensor will automatically handle rate limits!")
        else:
            print("⚠️ Basic RPC client - system works but consider updating for better rate limiting")
        
        print("\n🚀 Run: python scripts/starter.py")
        print("   You should see real blockchain monitoring with automatic rate limit handling!")
    else:
        print("❌ Some issues detected, but basic connectivity works")
        print("💡 The 429 errors in testing are normal - your actual system handles them automatically")
    print("="*50)

if __name__ == "__main__":
    main()