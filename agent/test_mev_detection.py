#!/usr/bin/env python3
"""
Test MEV Detection functionality
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from security.enhanced_security_agent import EnhancedSecurityAgent

async def test_mev_detection():
    """Test MEV detection with various scenarios"""
    
    print("⚡ Testing MEV Detection")
    print("=" * 40)
    
    # Initialize enhanced agent
    agent = EnhancedSecurityAgent("starter/enhanced_security.json", "test_provider")
    await agent.initialize()
    
    # Test scenarios
    test_scenarios = [
        {
            'name': 'High-Value Swap (Sandwich Risk)',
            'data': {
                'hash': '0xmev_sandwich_test',
                'instruction_type': 'swap',
                'program_id': 'jupiter',
                'value': '5000',  # $5000 trade
                'slippage_tolerance': 0.05,  # 5% slippage
                'priority_fee': 0.002  # 2x normal fee
            }
        },
        {
            'name': 'Token Launch Front-Running',
            'data': {
                'hash': '0xmev_frontrun_test',
                'instruction_type': 'mint',
                'is_token_launch': True,
                'priority_fee': 0.005,  # 5x normal fee
                'operation_type': 'token_launch'
            }
        },
        {
            'name': 'Liquidation MEV',
            'data': {
                'hash': '0xmev_liquidation_test',
                'instruction_type': 'liquidate',
                'program_id': 'marginfi',
                'health_factor': 1.05,  # Close to liquidation
                'priority_fee': 0.003
            }
        },
        {
            'name': 'Normal Transaction (Low MEV Risk)',
            'data': {
                'hash': '0xnormal_transaction',
                'instruction_type': 'transfer',
                'value': '10',  # Small transfer
                'priority_fee': 0.0005  # Normal fee
            }
        }
    ]
    
    # Test each scenario
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n{i}️⃣ Testing: {scenario['name']}")
        print("-" * 50)
        
        result = await agent.enhanced_transaction_analysis(scenario['data'])
        
        # Display MEV analysis results
        mev_analysis = result.get('technical_details', {}).get('mev_analysis', {})
        
        if mev_analysis:
            print(f"🎯 Overall MEV Risk: {mev_analysis.get('overall_mev_risk', 0):.2f}")
            print(f"⚡ MEV Threats: {', '.join(mev_analysis.get('mev_threats', ['None']))}")
            
            if mev_analysis.get('user_warnings'):
                print("⚠️  MEV Warnings:")
                for warning in mev_analysis['user_warnings']:
                    print(f"   • {warning}")
            
            if mev_analysis.get('recommended_actions'):
                print("💡 Recommendations:")
                for rec in mev_analysis['recommended_actions'][:2]:  # Show first 2
                    print(f"   • {rec}")
        
        # Show quarantine decision
        decision = result.get('final_decision', {})
        print(f"🛡️  Decision: {decision.get('action', 'unknown')}")
        print(f"📊 Confidence: {decision.get('confidence_score', 0):.2f}")

if __name__ == "__main__":
    asyncio.run(test_mev_detection())