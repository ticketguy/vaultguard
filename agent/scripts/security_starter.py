#!/usr/bin/env python3
"""
Security Agent Starter Script
Adapts the original trading starter for security operations.
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add the src directory to Python path
current_dir = Path(__file__).parent
src_dir = current_dir.parent / "src"
sys.path.insert(0, str(src_dir))

# Now import the security agent
from security.security_agent import SecurityAgent

async def main():
    """Main execution function"""
    print("🛡️  Starting Web3 Wallet Security Agent")
    print("=" * 50)
    
    # Configuration path
    config_path = current_dir.parent / "starter" / "security.json"
    
    if not config_path.exists():
        print(f"❌ Configuration file not found: {config_path}")
        print("Please create security.json based on the template")
        print("\nCreating a basic security.json now...")
        await create_basic_config(config_path)
    
    try:
        # Initialize security agent
        agent = SecurityAgent(str(config_path))
        await agent.initialize()
        
        print(f"✅ Security Agent {agent.agent_id} initialized successfully")
        print(f"📊 Quarantine threshold: {agent.security_config['quarantine_threshold']}")
        
        # Run continuous security monitoring
        await run_security_monitoring(agent)
        
    except Exception as e:
        print(f"❌ Error starting security agent: {str(e)}")
        import traceback
        traceback.print_exc()

async def create_basic_config(config_path: Path):
    """Create a basic security configuration if none exists"""
    basic_config = {
        "agent_id": "wallet_security_agent_001",
        "model": "claude",
        "role": "Web3 Wallet Security Specialist",
        "time_horizon": "continuous",
        "metric_goal": "threat_prevention_rate",
        "research_tools": [
            "blockchain_scanner",
            "contract_analyzer", 
            "community_intelligence",
            "threat_feeds"
        ],
        "security_config": {
            "quarantine_threshold": 0.7,
            "auto_burn_delay": 168,
            "simulation_required_value": 1000,
            "reputation_weight_threshold": 0.8
        },
        "prompts": {
            "system": "You are a Web3 wallet security specialist agent.",
            "threat_analysis": "Analyze the following transaction for potential security threats.",
            "quarantine_decision": "Based on the risk analysis, decide whether this item should be quarantined."
        }
    }
    
    # Create starter directory if it doesn't exist
    config_path.parent.mkdir(exist_ok=True)
    
    with open(config_path, 'w') as f:
        json.dump(basic_config, f, indent=2)
    
    print(f"✅ Created basic configuration: {config_path}")

async def run_security_monitoring(agent: SecurityAgent):
    """Run continuous security monitoring loop"""
    print("\n🔍 Starting continuous security monitoring...")
    print("Press Ctrl+C to stop\n")
    
    try:
        # Simulation of continuous monitoring
        transaction_count = 0
        
        while True:
            # In a real implementation, this would receive transactions from
            # blockchain monitoring or wallet integration
            
            # Simulate incoming transaction for testing
            test_transaction = generate_test_transaction(transaction_count)
            
            print(f"📥 Analyzing transaction {transaction_count + 1}...")
            
            # Analyze transaction
            result = await agent.analyze_transaction(test_transaction)
            
            # Display result
            display_analysis_result(result)
            
            # Simulate user feedback (in real implementation, this comes from UI)
            if result.get('quarantine_recommended'):
                await simulate_user_feedback(agent, result)
            
            # Auto-burn check
            if agent.quarantine_manager:
                burned_count = await agent.quarantine_manager.process_auto_burns()
                if burned_count > 0:
                    print(f"🔥 Auto-burned {burned_count} expired items")
            
            transaction_count += 1
            
            # Wait before next transaction (remove in production)
            await asyncio.sleep(5)  # Reduced from 10 to 5 seconds for faster testing
            
    except KeyboardInterrupt:
        print("\n🛑 Stopping security monitoring...")
        
        # Display final statistics
        print(f"\n📊 Agent Performance Metrics:")
        print(f"   Accuracy Rate: {agent.performance_metrics['accuracy_rate']:.1%}")
        print(f"   Total Threats Detected: {agent.performance_metrics['threats_detected']}")
        print(f"   False Positives: {agent.performance_metrics['false_positives']}")
        print(f"   User Approvals: {agent.performance_metrics['user_approvals']}")
        print(f"   User Rejections: {agent.performance_metrics['user_rejections']}")
        
        if agent.quarantine_manager:
            summary = agent.quarantine_manager.get_quarantine_summary()
            print(f"\n📋 Quarantine Statistics:")
            print(f"   Currently Quarantined: {summary['currently_quarantined']}")
            print(f"   Total Quarantined: {summary['statistics']['total_quarantined']}")
            print(f"   Total Approved: {summary['statistics']['total_approved']}")
            print(f"   Total Burned: {summary['statistics']['total_burned']}")

def generate_test_transaction(count: int) -> dict:
    """Generate test transactions for demonstration"""
    test_transactions = [
        {
            'hash': f'0xscam{count:06d}',
            'from_address': '0x000000000000000000000000000000000000dead',
            'to_address': '0x123456789abcdef123456789abcdef1234567890',
            'value': '0.0001',
            'value_usd': 0.20,
            'token_name': 'FakeUSDC',
            'token_symbol': 'USDC',
            'gas_price': '20000000000',
            'data': '0x'
        },
        {
            'hash': f'0xlegit{count:06d}',
            'from_address': '0xa0b86a33e6e89c4c2f89e2b6c2b5dbe8c3d0e1f2',
            'to_address': '0x987654321fedcba987654321fedcba9876543210',
            'value': '1.5',
            'value_usd': 3000,
            'token_name': 'Ethereum',
            'token_symbol': 'ETH',
            'gas_price': '25000000000',
            'data': '0x'
        },
        {
            'hash': f'0xdust{count:06d}',
            'from_address': '0x1111111111111111111111111111111111111111',
            'to_address': '0x555555555555555555555555555555555555555',
            'value': '0.00001',
            'value_usd': 0.02,
            'token_name': 'DustToken',
            'token_symbol': 'DUST',
            'gas_price': '30000000000',
            'data': '0x'
        }
    ]
    
    return test_transactions[count % len(test_transactions)]

def display_analysis_result(result: dict):
    """Display analysis result in a user-friendly format"""
    print(f"  🆔 Transaction ID: {result.get('transaction_id', 'N/A')}")
    print(f"  ⚠️  Risk Score: {result.get('risk_score', 0):.2f}")
    
    if result.get('quarantine_recommended'):
        print(f"  🚨 Decision: QUARANTINED")
    else:
        print(f"  ✅ Decision: APPROVED")
    
    print(f"  🎯 Confidence: {result.get('confidence', 0):.2f}")
    print(f"  📝 Reasoning: {result.get('reasoning', 'N/A')}")
    
    if result.get('threat_analysis', {}).get('warnings'):
        warnings = result['threat_analysis']['warnings']
        print(f"  ⚠️  Warnings: {', '.join(warnings[:2])}")  # Show first 2 warnings
    
    print(f"  ⏱️  Analysis Time: {result.get('analysis_time_seconds', 0):.3f}s")
    print("-" * 50)

async def simulate_user_feedback(agent: SecurityAgent, result: dict):
    """Simulate user feedback for quarantined items"""
    transaction_id = result.get('transaction_id')
    risk_score = result.get('risk_score', 0)
    
    # Simulate user decision based on risk score
    # In real implementation, this comes from user interface
    if risk_score > 0.9:
        # User likely agrees with high-risk quarantine
        decision = "rejected"
        feedback = "Clearly malicious"
    elif risk_score < 0.75:
        # User might disagree with low-risk quarantine
        decision = "approved"
        feedback = "False positive"
    else:
        # Mixed decision for medium risk
        decision = "rejected" if risk_score > 0.8 else "approved"
        feedback = "Borderline case"
    
    print(f"  👤 Simulated user feedback: {decision} ({feedback})")
    
    await agent.process_user_feedback(transaction_id, decision, feedback)

if __name__ == "__main__":
    asyncio.run(main())