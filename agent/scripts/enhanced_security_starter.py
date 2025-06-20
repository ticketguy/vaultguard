#!/usr/bin/env python3
"""
Enhanced Security Starter - Phase 2 Complete
Tests the fully integrated enhanced security system
"""

import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime

# Add src to path
current_dir = Path(__file__).parent
src_dir = current_dir.parent / "src"
sys.path.insert(0, str(src_dir))

from security.enhanced_security_agent import EnhancedSecurityAgent

async def main():
    """Test the complete Phase 2 enhanced security system"""
    print("🚀 Enhanced Web3 Wallet Security Agent - Phase 2 Complete")
    print("=" * 60)
    
    # Initialize enhanced agent
    config_path = current_dir.parent / "starter" / "security.json"
    agent = EnhancedSecurityAgent(str(config_path), "demo_wallet_provider")
    
    await agent.initialize()
    
    # System status check
    status = await agent.get_enhanced_system_status()
    print(f"📊 System Status: {status['system_health'].upper()}")
    print(f"🔧 Active Components: {sum(status['components_status'].values())}/5")
    print(f"🏆 Reputation Score: {status.get('reputation_score', 0.5):.2f}")
    print()
    
    # Test scenarios
    test_scenarios = [
        {
            'name': 'Obvious Scam Contract',
            'data': {
                'hash': '0xscam_contract_test',
                'from_address': '0x000000000000000000000000000000000000dead',
                'to_address': '0xmalicious_contract_address',
                'value': '0.00001',
                'token_name': 'FreeAirdropScam',
                'contract_functions': ['setApprovalForAll', 'emergencyWithdraw', 'blacklistUser'],
                'contract_bytecode': 'contains selfdestruct and delegatecall patterns',
                'contract_verified': False
            }
        },
        {
            'name': 'Sophisticated Phishing',
            'data': {
                'hash': '0xphishing_test',
                'from_address': '0x1234567890123456789012345678901234567890',
                'to_address': '0xuser_wallet_address',
                'value': '1.5',
                'token_name': 'USDĊ',  # Unicode spoofing
                'data': '0xa9059cbb000000000000000000000000ffffffffffffffffffffffffffffffff',
                'gas_price': '75000000000'
            }
        },
        {
            'name': 'Legitimate Transaction',
            'data': {
                'hash': '0xlegit_transaction',
                'from_address': '0xa0b86a33e6e89c4c2f89e2b6c2b5dbe8c3d0e1f2',
                'to_address': '0xuser_wallet_address',
                'value': '0.5',
                'token_name': 'USDC',
                'contract_verified': True,
                'gas_price': '25000000000'
            }
        }
    ]
    
    # Run enhanced analysis on each scenario
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"🧪 Test {i}: {scenario['name']}")
        print("-" * 40)
        
        result = await agent.enhanced_transaction_analysis(scenario['data'])
        
        # Display results
        print(f"🔍 Components Used: {', '.join(result['components_used'])}")
        print(f"⚡ Analysis Time: {result['analysis_performance']['total_time_seconds']:.3f}s")
        print(f"🎯 Decision: {result['final_decision']['action'].upper()}")
        print(f"📊 Confidence: {result['final_decision']['confidence_score']:.2f}")
        print(f"💬 User Message: {result['final_decision']['user_message']}")
        
        # Show user explanation if available
        if result.get('user_explanation', {}).get('contract_explanation'):
            print(f"📜 Contract Analysis: {result['user_explanation']['contract_explanation'][:100]}...")
        
        if result.get('user_explanation', {}).get('threat_explanation'):
            print(f"🚨 Threat Analysis: {result['user_explanation']['threat_explanation'][:100]}...")
        
        print()
        
        # Simulate user feedback for learning
        if result['final_decision']['action'] in ['quarantine', 'quarantine_with_auto_burn']:
            user_decision = 'burned' if 'scam' in scenario['name'].lower() else 'approved'
            feedback = f"Test feedback for {scenario['name']}"
            
            await agent.process_enhanced_user_feedback(
                result['transaction_id'], user_decision, feedback
            )
            print(f"👤 Simulated user feedback: {user_decision}")
            print()
    
    # Final system statistics
    final_status = await agent.get_enhanced_system_status()
    print("📈 Enhanced Security Agent Statistics")
    print("=" * 40)
    print(f"Total Analyses: {final_status['performance_stats']['total_analyses']}")
    print(f"Quarantine Decisions: {final_status['performance_stats']['quarantine_decisions']}")
    print(f"User Feedback Events: {final_status['performance_stats']['user_feedback_events']}")
    print(f"Accuracy Improvements: {final_status['performance_stats']['accuracy_improvements']}")
    print()
    
    print("🎉 Phase 2 Enhanced Security System - COMPLETE!")
    print("Ready for wallet provider integration!")

if __name__ == "__main__":
    asyncio.run(main())