#!/usr/bin/env python3
"""
Complete Phase 2 Testing Suite
Validates all enhanced components work together
"""

import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / "src"))

from security.enhanced_security_agent import EnhancedSecurityAgent

async def comprehensive_phase2_test():
    """Comprehensive test of Phase 2 enhanced features"""
    
    print("🧪 Comprehensive Phase 2 Testing Suite")
    print("=" * 50)
    
    # Initialize enhanced agent
    agent = EnhancedSecurityAgent("starter/enhanced_security.json", "test_provider")
    await agent.initialize()
    
    # Test 1: Component Integration
    print("\n1️⃣ Testing Component Integration...")
    status = await agent.get_enhanced_system_status()
    
    required_components = [
        'smart_contract_explainer',
        'deep_pattern_analyzer', 
        'cross_wallet_intelligence',
        'enhanced_quarantine',
        'background_agent'
    ]
    
    for component in required_components:
        is_active = status['components_status'].get(component, False)
        status_icon = "✅" if is_active else "❌"
        print(f"  {status_icon} {component}: {'Active' if is_active else 'Failed'}")
    
    # Test 2: Smart Contract Analysis
    print("\n2️⃣ Testing Smart Contract Analysis...")
    contract_test = {
        'hash': '0xcontract_test',
        'to_address': '0xmalicious_contract',
        'contract_functions': ['setApprovalForAll', 'emergencyWithdraw'],
        'contract_bytecode': 'selfdestruct_pattern_detected'
    }
    
    try:
        contract_result = await agent.enhanced_transaction_analysis(contract_test)
        components_used = contract_result.get('components_used', [])
        contract_used = 'smart_contract_explainer' in components_used
        print(f"  {'✅' if contract_used else '❌'} Smart contract analysis: {'Working' if contract_used else 'Failed'}")
    except Exception as e:
        print(f"  ❌ Smart contract analysis: Failed ({str(e)[:50]}...)")
        contract_used = False
    
    # Test 3: Pattern Analysis
    print("\n3️⃣ Testing Deep Pattern Analysis...")
    pattern_test = {
        'hash': '0xpattern_test',
        'from_address': '0x000000000000000000000000000000000000dead',
        'value': '0.00001',
        'token_name': 'FakeAirdrop'
    }
    
    try:
        pattern_result = await agent.enhanced_transaction_analysis(pattern_test)
        components_used = pattern_result.get('components_used', [])
        pattern_used = 'deep_pattern_analyzer' in components_used
        print(f"  {'✅' if pattern_used else '❌'} Deep pattern analysis: {'Working' if pattern_used else 'Failed'}")
    except Exception as e:
        print(f"  ❌ Deep pattern analysis: Failed ({str(e)[:50]}...)")
        pattern_used = False
    
    # Test 4: Cross-Wallet Intelligence
    print("\n4️⃣ Testing Cross-Wallet Intelligence...")
    intel_test = {
        'hash': '0xintel_test',
        'from_address': '0x000000000000000000000000000000000000dead'
    }
    
    try:
        intel_result = await agent.enhanced_transaction_analysis(intel_test)
        components_used = intel_result.get('components_used', [])
        intel_used = 'cross_wallet_intelligence' in components_used
        print(f"  {'✅' if intel_used else '❌'} Cross-wallet intelligence: {'Working' if intel_used else 'Failed'}")
    except Exception as e:
        print(f"  ❌ Cross-wallet intelligence: Failed ({str(e)[:50]}...)")
        intel_used = False
    
    # Test 5: Enhanced Quarantine
    print("\n5️⃣ Testing Enhanced Quarantine System...")
    quarantine_test = {
        'hash': '0xquarantine_test',
        'from_address': '0x000000000000000000000000000000000000dead',
        'value': '0.00001'
    }
    
    try:
        quarantine_result = await agent.enhanced_transaction_analysis(quarantine_test)
        components_used = quarantine_result.get('components_used', [])
        quarantine_used = 'enhanced_quarantine' in components_used
        
        final_decision = quarantine_result.get('final_decision', {})
        should_quarantine = final_decision.get('action', 'unknown') in ['quarantine', 'quarantine_with_auto_burn']
        
        print(f"  {'✅' if quarantine_used else '❌'} Enhanced quarantine: {'Working' if quarantine_used else 'Failed'}")
        print(f"  {'✅' if should_quarantine else '❌'} Threat detection: {'Working' if should_quarantine else 'Failed'}")
    except Exception as e:
        print(f"  ❌ Enhanced quarantine: Failed ({str(e)[:50]}...)")
        quarantine_used = False
        should_quarantine = False
    
    # Test 6: User Feedback Learning
    print("\n6️⃣ Testing User Feedback Learning...")
    try:
        feedback_result = await agent.process_enhanced_user_feedback(
            'test_transaction_id', 'burned', 'Confirmed scam'
        )
        
        feedback_working = feedback_result.get('feedback_processed', False)
        print(f"  {'✅' if feedback_working else '❌'} User feedback learning: {'Working' if feedback_working else 'Failed'}")
    except Exception as e:
        print(f"  ❌ User feedback learning: Failed ({str(e)[:50]}...)")
        feedback_working = False
    
    # Final Assessment
    print("\n📊 Phase 2 Test Results Summary")
    print("=" * 30)
    
    total_tests = 8  # Number of individual tests
    passed_tests = sum([
        status['system_health'] in ['optimal', 'good'],
        contract_used,
        pattern_used, 
        intel_used,
        quarantine_used,
        should_quarantine,
        feedback_working,
        len([c for c in status['components_status'].values() if c]) >= 4
    ])
    
    success_rate = (passed_tests / total_tests) * 100
    
    print(f"Tests Passed: {passed_tests}/{total_tests}")
    print(f"Success Rate: {success_rate:.1f}%")
    print(f"System Status: {status['system_health'].upper()}")
    print(f"Active Components: {sum(status['components_status'].values())}/5")
    
    if success_rate >= 90:
        print("\n🎉 PHASE 2 COMPLETE - EXCELLENT!")
        print("Enhanced security system is fully operational")
    elif success_rate >= 70:
        print("\n✅ PHASE 2 COMPLETE - GOOD")
        print("Enhanced security system is working with minor issues")
    else:
        print("\n⚠️ PHASE 2 INCOMPLETE")
        print("Some enhanced components need attention")
    
    return success_rate >= 70

if __name__ == "__main__":
    success = asyncio.run(comprehensive_phase2_test())
    sys.exit(0 if success else 1)