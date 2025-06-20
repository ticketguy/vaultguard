import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / "src"))

from security.security_agent import SecurityAgent

async def test_security_scenarios():
    agent = SecurityAgent("starter/security.json")
    await agent.initialize()
    
    # Test 1: Obvious scam
    scam_transaction = {
        'hash': '0xscam123',
        'from_address': '0x000000000000000000000000000000000000dead',
        'to_address': '0x123...',
        'value': '0.0001',
        'value_usd': 0.20,
        'token_name': 'FakeUSDC',
        'token_symbol': 'USDC'
    }
    
    result1 = await agent.analyze_transaction(scam_transaction)
    print("🚨 Scam Transaction Analysis:")
    print(json.dumps(result1, indent=2))
    
    # Test 2: Legitimate transaction
    legit_transaction = {
        'hash': '0xlegit123',
        'from_address': '0xa0b86a33e6e89c4c2f89e2b6c2b5dbe8c3d0e1f2',
        'to_address': '0x987...',
        'value': '1.5',
        'value_usd': 3000,
        'token_name': 'Ethereum',
        'token_symbol': 'ETH'
    }
    
    result2 = await agent.analyze_transaction(legit_transaction)
    print("\n✅ Legitimate Transaction Analysis:")
    print(json.dumps(result2, indent=2))
    
    # Test quarantine summary
    if agent.quarantine_manager:
        summary = agent.quarantine_manager.get_quarantine_summary()
        print("\n📊 Quarantine Summary:")
        print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    asyncio.run(test_security_scenarios())