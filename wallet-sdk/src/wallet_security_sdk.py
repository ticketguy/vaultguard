"""
Wallet Security SDK for Wallet Providers
Main integration point for wallet applications
"""

import asyncio
import json
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from enum import Enum
import logging

class WalletSecuritySDK:
    """
    SDK for wallet providers to integrate AI security agent
    Provides simple API for wallet apps to use quarantine system
    """
    
    def __init__(self, wallet_provider_id: str, config: Dict = None):
        self.wallet_provider_id = wallet_provider_id
        self.config = config or {}
        
        # Security agent connection
        self.security_agent = None
        self.agent_url = self.config.get('agent_url', 'http://localhost:8001')
        
        # Wallet provider callbacks
        self.callbacks = {
            'on_item_quarantined': None,
            'on_user_decision': None,
            'on_threat_detected': None
        }
        
        # Quarantine storage for this wallet provider
        self.quarantine_storage = {}
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(f"WalletSDK-{wallet_provider_id}")
    
    async def initialize(self):
        """Initialize the wallet security SDK"""
        self.logger.info(f"🔌 Initializing Wallet Security SDK for {self.wallet_provider_id}")
        
        # Connect to security agent
        await self.connect_to_security_agent()
        
        # Load existing quarantine data
        await self.load_quarantine_data()
        
        self.logger.info("✅ Wallet Security SDK initialized")
    
    async def connect_to_security_agent(self):
        """Connect to the AI security agent"""
        try:
            # In production, this would establish connection to security agent
            # For now, simulate connection
            self.logger.info(f"🤖 Connected to AI Security Agent at {self.agent_url}")
            return True
        except Exception as e:
            self.logger.error(f"❌ Failed to connect to security agent: {e}")
            return False
    
    # Core API for Wallet Providers
    
    async def check_incoming_transaction(self, transaction_data: Dict) -> Dict:
        """
        Main API: Check if incoming transaction should be quarantined
        Called by wallet when receiving new transactions
        """
        self.logger.info(f"🔍 Checking transaction: {transaction_data.get('hash', 'unknown')}")
        
        # Enhanced transaction data for analysis
        enhanced_data = {
            **transaction_data,
            'wallet_provider_id': self.wallet_provider_id,
            'timestamp': datetime.now().isoformat(),
            'user_id': transaction_data.get('user_id'),  # Wallet user identifier
        }
        
        # Analyze with AI agent
        analysis_result = await self.analyze_with_ai_agent(enhanced_data)
        
        # Make quarantine decision
        should_quarantine = analysis_result.get('quarantine_recommended', False)
        
        if should_quarantine:
            # Add to quarantine
            quarantine_item = await self.add_to_quarantine(enhanced_data, analysis_result)
            
            # Notify wallet app
            if self.callbacks['on_item_quarantined']:
                await self.callbacks['on_item_quarantined'](quarantine_item)
            
            return {
                'action': 'quarantine',
                'quarantine_id': quarantine_item['id'],
                'risk_score': analysis_result.get('risk_score', 0),
                'reasoning': analysis_result.get('reasoning', ''),
                'threat_categories': analysis_result.get('threat_categories', []),
                'user_message': self.generate_user_message(analysis_result)
            }
        else:
            # Allow to main wallet
            return {
                'action': 'approve',
                'risk_score': analysis_result.get('risk_score', 0),
                'reasoning': 'Transaction passed security checks'
            }
    
    async def check_incoming_token(self, token_data: Dict) -> Dict:
        """
        Check if incoming token should be quarantined
        Called when user receives new tokens
        """
        self.logger.info(f"🪙 Checking token: {token_data.get('name', 'unknown')}")
        
        # Enhanced token data
        enhanced_data = {
            **token_data,
            'type': 'token_transfer',
            'wallet_provider_id': self.wallet_provider_id,
            'timestamp': datetime.now().isoformat()
        }
        
        return await self.check_incoming_transaction(enhanced_data)
    
    async def get_quarantine_summary(self, user_id: str) -> Dict:
        """Get quarantine summary for a specific user"""
        user_quarantine = self.quarantine_storage.get(user_id, {})
        
        return {
            'total_quarantined': len(user_quarantine),
            'high_risk_items': len([item for item in user_quarantine.values() 
                                  if item.get('risk_score', 0) > 0.8]),
            'pending_review': len([item for item in user_quarantine.values() 
                                 if item.get('status') == 'pending_review']),
            'items': list(user_quarantine.values())
        }
    
    async def get_quarantine_items(self, user_id: str) -> List[Dict]:
        """Get all quarantined items for a user"""
        user_quarantine = self.quarantine_storage.get(user_id, {})
        return [
            {
                'id': item_id,
                'type': item['type'],
                'risk_score': item['risk_score'],
                'reasoning': item['reasoning'],
                'quarantined_at': item['quarantined_at'],
                'token_name': item['data'].get('token_name', 'Unknown'),
                'amount': item['data'].get('amount', '0'),
                'from_address': item['data'].get('from_address', ''),
                'threat_categories': item.get('threat_categories', [])
            }
            for item_id, item in user_quarantine.items()
        ]
    
    async def approve_quarantine_item(self, user_id: str, item_id: str, 
                                    user_feedback: str = "") -> Dict:
        """
        User approves quarantined item - move to main wallet
        This is a key user interaction that trains the AI
        """
        if user_id not in self.quarantine_storage:
            return {'success': False, 'error': 'User not found'}
        
        if item_id not in self.quarantine_storage[user_id]:
            return {'success': False, 'error': 'Item not found'}
        
        item = self.quarantine_storage[user_id][item_id]
        
        # Update item status
        item['status'] = 'approved'
        item['approved_at'] = datetime.now().isoformat()
        item['user_feedback'] = user_feedback
        
        # Remove from quarantine
        approved_item = self.quarantine_storage[user_id].pop(item_id)
        
        # Send feedback to AI agent for learning
        await self.send_user_feedback(approved_item, 'approved', user_feedback)
        
        # Notify wallet app
        if self.callbacks['on_user_decision']:
            await self.callbacks['on_user_decision']('approved', approved_item)
        
        self.logger.info(f"✅ User approved quarantine item: {item_id}")
        
        return {
            'success': True,
            'action': 'approved',
            'item': approved_item['data'],
            'message': 'Item moved to main wallet'
        }
    
    async def burn_quarantine_item(self, user_id: str, item_id: str, 
                                 user_feedback: str = "") -> Dict:
        """
        User burns/deletes quarantined item
        This confirms the AI made the right decision
        """
        if user_id not in self.quarantine_storage:
            return {'success': False, 'error': 'User not found'}
        
        if item_id not in self.quarantine_storage[user_id]:
            return {'success': False, 'error': 'Item not found'}
        
        item = self.quarantine_storage[user_id][item_id]
        
        # Update item status
        item['status'] = 'burned'
        item['burned_at'] = datetime.now().isoformat()
        item['user_feedback'] = user_feedback
        
        # Remove from quarantine (permanently delete)
        burned_item = self.quarantine_storage[user_id].pop(item_id)
        
        # Send feedback to AI agent for learning
        await self.send_user_feedback(burned_item, 'burned', user_feedback)
        
        # Notify wallet app
        if self.callbacks['on_user_decision']:
            await self.callbacks['on_user_decision']('burned', burned_item)
        
        self.logger.info(f"🔥 User burned quarantine item: {item_id}")
        
        return {
            'success': True,
            'action': 'burned',
            'message': 'Item permanently deleted'
        }
    
    async def burn_all_quarantine(self, user_id: str, confirmed: bool = False) -> Dict:
        """Burn all quarantined items for a user"""
        if not confirmed:
            return {
                'success': False, 
                'error': 'Confirmation required',
                'requires_confirmation': True
            }
        
        if user_id not in self.quarantine_storage:
            return {'success': False, 'error': 'User not found'}
        
        items_count = len(self.quarantine_storage[user_id])
        
        # Burn all items
        for item_id in list(self.quarantine_storage[user_id].keys()):
            await self.burn_quarantine_item(user_id, item_id, "Bulk burn operation")
        
        return {
            'success': True,
            'items_burned': items_count,
            'message': f'Burned {items_count} quarantined items'
        }
    
    async def report_address(self, user_id: str, address: str, reason: str) -> Dict:
        """User reports a suspicious address to community blacklist"""
        report_data = {
            'reporter_wallet_provider': self.wallet_provider_id,
            'reporter_user_id': user_id,
            'reported_address': address,
            'reason': reason,
            'timestamp': datetime.now().isoformat()
        }
        
        # Send to community intelligence system
        await self.send_community_report(report_data)
        
        self.logger.info(f"📝 User reported address: {address}")
        
        return {
            'success': True,
            'message': 'Address reported to community blacklist'
        }
    
    # Wallet Provider Configuration
    
    def set_callback(self, event: str, callback: Callable):
        """Set callback functions for wallet provider"""
        if event in self.callbacks:
            self.callbacks[event] = callback
            self.logger.info(f"📞 Set callback for {event}")
    
    async def update_settings(self, settings: Dict):
        """Update security settings for this wallet provider"""
        self.config.update(settings)
        
        # Send updated settings to AI agent
        await self.send_settings_to_agent(settings)
        
        self.logger.info("⚙️ Updated security settings")
    
    # Internal Methods
    
    async def analyze_with_ai_agent(self, transaction_data: Dict) -> Dict:
        """Send transaction to AI agent for analysis"""
        try:
            # In production, this would make HTTP request to security agent
            # For now, simulate AI analysis
            
            risk_score = await self.simulate_ai_analysis(transaction_data)
            
            return {
                'quarantine_recommended': risk_score > 0.7,
                'risk_score': risk_score,
                'reasoning': f"AI analysis completed - risk score: {risk_score:.2f}",
                'threat_categories': ['simulated_analysis'],
                'confidence': 0.85
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing with AI agent: {e}")
            # Fail safe - quarantine on error
            return {
                'quarantine_recommended': True,
                'risk_score': 1.0,
                'reasoning': 'Analysis failed - quarantining for safety',
                'threat_categories': ['analysis_error']
            }
    
    async def simulate_ai_analysis(self, transaction_data: Dict) -> float:
        """Simulate AI analysis (replace with real agent call)"""
        risk_factors = 0.0
        
        # Check for suspicious patterns
        from_address = transaction_data.get('from_address', '').lower()
        token_name = transaction_data.get('token_name', '').lower()
        value = float(transaction_data.get('value', 0))
        
        # Known scammer patterns
        if 'dead' in from_address or '1111' in from_address:
            risk_factors += 0.8
        
        # Fake token patterns  
        if 'fake' in token_name or any(char in token_name for char in ['usdc', 'ethereum']):
            risk_factors += 0.6
        
        # Dust transactions
        if 0 < value < 0.001:
            risk_factors += 0.7
        
        return min(risk_factors, 1.0)
    
    async def add_to_quarantine(self, transaction_data: Dict, analysis_result: Dict) -> Dict:
        """Add item to quarantine storage"""
        user_id = transaction_data.get('user_id')
        if not user_id:
            raise ValueError("user_id required for quarantine")
        
        if user_id not in self.quarantine_storage:
            self.quarantine_storage[user_id] = {}
        
        item_id = f"q_{datetime.now().timestamp():.0f}"
        
        quarantine_item = {
            'id': item_id,
            'type': transaction_data.get('type', 'transaction'),
            'data': transaction_data,
            'risk_score': analysis_result.get('risk_score', 0),
            'reasoning': analysis_result.get('reasoning', ''),
            'threat_categories': analysis_result.get('threat_categories', []),
            'quarantined_at': datetime.now().isoformat(),
            'status': 'pending_review'
        }
        
        self.quarantine_storage[user_id][item_id] = quarantine_item
        
        return quarantine_item
    
    async def send_user_feedback(self, item: Dict, decision: str, feedback: str):
        """Send user feedback to AI agent for learning"""
        feedback_data = {
            'wallet_provider_id': self.wallet_provider_id,
            'item_id': item['id'],
            'original_analysis': {
                'risk_score': item['risk_score'],
                'reasoning': item['reasoning']
            },
            'user_decision': decision,
            'user_feedback': feedback,
            'timestamp': datetime.now().isoformat()
        }
        
        # In production, send to AI agent for learning
        self.logger.info(f"📚 Sent user feedback to AI: {decision}")
    
    async def send_community_report(self, report_data: Dict):
        """Send community report to shared blacklist system"""
        # In production, this would integrate with community intelligence
        self.logger.info(f"🌐 Sent community report: {report_data['reported_address']}")
    
    async def send_settings_to_agent(self, settings: Dict):
        """Send updated settings to AI agent"""
        # In production, this would update agent configuration
        self.logger.info("⚙️ Updated AI agent settings")
    
    async def load_quarantine_data(self):
        """Load existing quarantine data from storage"""
        # In production, this would load from persistent storage
        self.logger.info("📚 Loaded quarantine data")
    
    def generate_user_message(self, analysis_result: Dict) -> str:
        """Generate user-friendly message for quarantine decision"""
        risk_score = analysis_result.get('risk_score', 0)
        threat_categories = analysis_result.get('threat_categories', [])
        
        if risk_score > 0.9:
            return "⚠️ High risk item detected - likely malicious"
        elif risk_score > 0.7:
            return "🚨 Suspicious item quarantined for your review"
        elif 'fake_token' in threat_categories:
            return "🪙 Potential fake token detected"
        elif 'dust_attack' in threat_categories:
            return "💨 Spam/dust transaction blocked"
        else:
            return "🛡️ Item quarantined as a precaution"

# Example Usage for Wallet Providers
class ExampleWalletIntegration:
    """Example of how a wallet provider would integrate the SDK"""
    
    def __init__(self):
        self.wallet_sdk = WalletSecuritySDK("example_wallet_provider")
        
        # Set up callbacks
        self.wallet_sdk.set_callback('on_item_quarantined', self.on_item_quarantined)
        self.wallet_sdk.set_callback('on_user_decision', self.on_user_decision)
    
    async def initialize(self):
        """Initialize wallet with security"""
        await self.wallet_sdk.initialize()
    
    async def on_item_quarantined(self, quarantine_item: Dict):
        """Called when item is quarantined"""
        print(f"🚨 Item quarantined: {quarantine_item['id']}")
        print(f"   Risk: {quarantine_item['risk_score']:.2f}")
        print(f"   Reason: {quarantine_item['reasoning']}")
        
        # Wallet would show notification to user
        await self.show_quarantine_notification(quarantine_item)
    
    async def on_user_decision(self, decision: str, item: Dict):
        """Called when user makes decision on quarantined item"""
        print(f"👤 User {decision} item: {item['id']}")
        
        # Wallet would update UI accordingly
        await self.update_wallet_ui(decision, item)
    
    async def show_quarantine_notification(self, item: Dict):
        """Show notification in wallet UI"""
        print(f"📱 Wallet Notification: New item in quarantine")
        print(f"   Check your quarantine section to review")
    
    async def update_wallet_ui(self, decision: str, item: Dict):
        """Update wallet UI based on user decision"""
        if decision == 'approved':
            print(f"✅ Added to main wallet: {item['data'].get('token_name', 'Unknown')}")
        elif decision == 'burned':
            print(f"🔥 Item deleted permanently")
    
    # Wallet-specific methods that would call the SDK
    
    async def process_incoming_transaction(self, tx_data: Dict):
        """Process incoming transaction through security check"""
        result = await self.wallet_sdk.check_incoming_transaction(tx_data)
        
        if result['action'] == 'quarantine':
            print(f"🚨 Transaction quarantined: {result['user_message']}")
            return {'status': 'quarantined', 'quarantine_id': result['quarantine_id']}
        else:
            print(f"✅ Transaction approved - adding to main wallet")
            return {'status': 'approved'}
    
    async def show_quarantine_section(self, user_id: str):
        """Show quarantine section in wallet UI"""
        summary = await self.wallet_sdk.get_quarantine_summary(user_id)
        items = await self.wallet_sdk.get_quarantine_items(user_id)
        
        print(f"\n🛡️ Quarantine Section")
        print(f"   Total Items: {summary['total_quarantined']}")
        print(f"   High Risk: {summary['high_risk_items']}")
        print(f"   Pending Review: {summary['pending_review']}")
        
        for item in items[:3]:  # Show first 3 items
            print(f"\n   📦 {item['token_name']} ({item['amount']})")
            print(f"      Risk: {item['risk_score']:.2f} - {item['reasoning']}")
            print(f"      From: {item['from_address'][:10]}...")
        
        return items
    
    async def user_approves_item(self, user_id: str, item_id: str, feedback: str = ""):
        """User approves quarantined item"""
        result = await self.wallet_sdk.approve_quarantine_item(user_id, item_id, feedback)
        
        if result['success']:
            print(f"✅ {result['message']}")
            # Add to main wallet UI
            await self.add_to_main_wallet(result['item'])
        else:
            print(f"❌ Error: {result['error']}")
    
    async def user_burns_item(self, user_id: str, item_id: str, feedback: str = ""):
        """User burns quarantined item"""
        result = await self.wallet_sdk.burn_quarantine_item(user_id, item_id, feedback)
        
        if result['success']:
            print(f"🔥 {result['message']}")
        else:
            print(f"❌ Error: {result['error']}")
    
    async def add_to_main_wallet(self, item_data: Dict):
        """Add approved item to main wallet"""
        print(f"💰 Added to main wallet: {item_data.get('token_name', 'Token')}")

# Testing the wallet integration
if __name__ == "__main__":
    async def test_wallet_integration():
        # Initialize example wallet
        wallet = ExampleWalletIntegration()
        await wallet.initialize()
        
        # Simulate incoming transaction
        test_transaction = {
            'hash': '0xtest123',
            'from_address': '0x000000000000000000000000000000000000dead',
            'to_address': '0xuser_wallet_address',
            'token_name': 'FakeUSDC',
            'amount': '1000',
            'value': '0.001',
            'user_id': 'user123',
            'type': 'token_transfer'
        }
        
        print("📥 Processing incoming transaction...")
        result = await wallet.process_incoming_transaction(test_transaction)
        print(f"Result: {result}")
        
        if result['status'] == 'quarantined':
            print("\n📱 Showing quarantine section...")
            items = await wallet.show_quarantine_section('user123')
            
            if items:
                print(f"\n👤 User reviewing first item...")
                await wallet.user_burns_item('user123', items[0]['id'], "Obviously fake USDC")
    
    asyncio.run(test_wallet_integration())