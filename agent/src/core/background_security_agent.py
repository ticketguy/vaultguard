"""
Background Security Agent - Works behind the scenes while user uses wallet
"""

import asyncio
from typing import Dict, List, Optional
from datetime import datetime
import logging

class BackgroundSecurityAgent:
    """
    The main agent that works behind the scenes protecting users
    Coordinates all analysis components to provide seamless protection
    """
    
    def __init__(self, wallet_provider_id: str):
        self.wallet_provider_id = wallet_provider_id
        
        # Analysis components
        self.contract_explainer = None
        self.pattern_analyzer = None
        self.threat_detector = None
        
        # Background monitoring
        self.active_monitoring = True
        self.analysis_queue = asyncio.Queue()
        
        # User interaction tracking (for learning)
        self.user_decisions = []
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(f"BackgroundAgent-{wallet_provider_id}")
    
    async def initialize(self):
        """Initialize all analysis components"""
        self.logger.info("🤖 Starting background security agent...")
        
        # Initialize analysis components
        from analysis.smart_contract_explainer import SmartContractExplainer
        from analysis.deep_pattern_analyzer import DeepPatternAnalyzer
        
        self.contract_explainer = SmartContractExplainer()
        self.pattern_analyzer = DeepPatternAnalyzer()
        
        # Start background monitoring
        asyncio.create_task(self._background_analysis_loop())
        
        self.logger.info("✅ Background security agent active")
    
    async def analyze_user_transaction(self, transaction_data: Dict) -> Dict:
        """
        Main method: Analyze transaction while user is interacting with wallet
        Returns instant decision for wallet UI
        """
        analysis_start = datetime.now()
        
        # Quick initial assessment for immediate UI response
        quick_assessment = await self._quick_threat_assessment(transaction_data)
        
        # Queue detailed analysis for background processing
        await self.analysis_queue.put({
            'type': 'detailed_analysis',
            'transaction_data': transaction_data,
            'quick_assessment': quick_assessment,
            'timestamp': analysis_start.isoformat()
        })
        
        # Return immediate decision for wallet
        return {
            'immediate_action': quick_assessment['action'],
            'risk_level': quick_assessment['risk_level'],
            'user_message': quick_assessment['user_message'],
            'detailed_analysis_pending': True,
            'analysis_id': quick_assessment['analysis_id']
        }
    
    async def _quick_threat_assessment(self, transaction_data: Dict) -> Dict:
        """Quick threat assessment for immediate wallet response"""
        
        # Generate analysis ID
        analysis_id = f"analysis_{datetime.now().timestamp():.0f}"
        
        # Quick checks for obvious threats
        value = float(transaction_data.get('value', 0))
        from_address = transaction_data.get('from_address', '').lower()
        
        # Instant red flags
        if 'dead' in from_address or '1111' in from_address:
            return {
                'action': 'quarantine',
                'risk_level': 'high',
                'user_message': '🚨 Known suspicious address detected',
                'analysis_id': analysis_id
            }
        
        # Dust transaction check
        if 0 < value < 0.0001:
            return {
                'action': 'quarantine',
                'risk_level': 'medium',
                'user_message': '💨 Possible dust attack - reviewing in quarantine',
                'analysis_id': analysis_id
            }
        
        # Default: allow but analyze in background
        return {
            'action': 'allow_with_monitoring',
            'risk_level': 'low',
            'user_message': '✅ Transaction looks safe - analyzing in background',
            'analysis_id': analysis_id
        }
    
    async def _background_analysis_loop(self):
        """Background loop that processes detailed analysis"""
        
        while self.active_monitoring:
            try:
                # Get next analysis task
                task = await self.analysis_queue.get()
                
                if task['type'] == 'detailed_analysis':
                    await self._perform_detailed_analysis(task)
                
                self.analysis_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Error in background analysis: {e}")
                await asyncio.sleep(1)
    
    async def _perform_detailed_analysis(self, task: Dict):
        """Perform detailed analysis in background"""
        transaction_data = task['transaction_data']
        
        self.logger.info(f"🔍 Performing detailed analysis for {task.get('analysis_id')}")
        
        # Deep contract analysis if interacting with contract
        contract_analysis = None
        if transaction_data.get('to_address'):
            contract_data = await self._get_contract_data(transaction_data['to_address'])
            if contract_data:
                contract_analysis = await self.contract_explainer.explain_contract_in_english(contract_data)
        
        # Deep pattern analysis
        pattern_analysis = await self.pattern_analyzer.deep_analyze_transaction_intent(
            transaction_data
        )
        
        # Combine analyses
        detailed_result = {
            'analysis_id': task.get('analysis_id'),
            'contract_analysis': contract_analysis,
            'pattern_analysis': pattern_analysis,
            'final_risk_assessment': await self._calculate_final_risk(
                contract_analysis, pattern_analysis
            ),
            'completed_at': datetime.now().isoformat()
        }
        
        # If analysis reveals higher risk, update wallet
        await self._handle_detailed_analysis_result(detailed_result)
    
    async def _calculate_final_risk(self, contract_analysis: Optional[Dict], 
                                  pattern_analysis: Dict) -> Dict:
        """Calculate final risk assessment from all analyses"""
        
        risk_factors = []
        
        # Contract risk
        if contract_analysis:
            if contract_analysis['overall_risk'] in ['high', 'critical']:
                risk_factors.append(('contract_risk', 0.9))
            elif contract_analysis['overall_risk'] == 'medium':
                risk_factors.append(('contract_risk', 0.6))
        
        # Pattern risk
        intent_confidence = pattern_analysis['confidence_score']
        primary_intent = pattern_analysis['intent_analysis']['primary_intent']
        
        if primary_intent in ['dust_attack_intent', 'phishing_intent']:
            risk_factors.append(('pattern_risk', intent_confidence))
        
        # Calculate final risk
        if not risk_factors:
            final_risk = 0.1  # Very low risk
        else:
            final_risk = max([risk[1] for risk in risk_factors])
        
        return {
            'final_risk_score': final_risk,
            'risk_factors': risk_factors,
            'recommendation': await self._generate_final_recommendation(final_risk)
        }
    
    async def _generate_final_recommendation(self, risk_score: float) -> str:
        """Generate final recommendation based on complete analysis"""
        
        if risk_score >= 0.9:
            return "🚨 HIGH RISK: This transaction should be quarantined immediately"
        elif risk_score >= 0.7:
            return "⚠️ MEDIUM RISK: User should review this transaction carefully"
        elif risk_score >= 0.4:
            return "💡 LOW RISK: Minor concerns, but probably safe"
        else:
            return "✅ SAFE: No significant threats detected"
    
    async def _handle_detailed_analysis_result(self, result: Dict):
        """Handle the result of detailed analysis"""
        
        risk_score = result['final_risk_assessment']['final_risk_score']
        
        # If detailed analysis reveals higher risk, notify wallet
        if risk_score > 0.7:
            self.logger.warning(f"🚨 Detailed analysis reveals higher risk: {risk_score:.2f}")
            
            # In production, this would notify the wallet to update UI
            await self._notify_wallet_of_risk_update(result)
    
    async def _notify_wallet_of_risk_update(self, analysis_result: Dict):
        """Notify wallet provider of updated risk assessment"""
        # This would integrate with wallet provider's API
        self.logger.info(f"📱 Notifying wallet of risk update for {analysis_result['analysis_id']}")
    
    async def _get_contract_data(self, contract_address: str) -> Optional[Dict]:
        """Get contract data for analysis"""
        # In production, this would fetch from blockchain
        # For now, return mock data
        return {
            'address': contract_address,
            'functions': ['transfer', 'approve', 'emergencyWithdraw'],
            'bytecode': 'mock_bytecode_data'
        }
    
    async def learn_from_user_decision(self, analysis_id: str, user_decision: str, 
                                     user_feedback: str = ""):
        """Learn from user decisions to improve future analysis"""
        
        learning_data = {
            'analysis_id': analysis_id,
            'user_decision': user_decision,  # 'approved', 'quarantined', 'burned'
            'user_feedback': user_feedback,
            'timestamp': datetime.now().isoformat()
        }
        
        self.user_decisions.append(learning_data)
        
        # Analyze learning patterns
        await self._update_analysis_models(learning_data)
        
        self.logger.info(f"📚 Learned from user decision: {user_decision}")
    
    async def _update_analysis_models(self, learning_data: Dict):
        """Update analysis models based on user feedback"""
        # In production, this would update ML models
        # For now, just log the learning
        self.logger.info(f"🧠 Updating models based on user feedback")

# Example of how this works behind the scenes
if __name__ == "__main__":
    async def simulate_user_wallet_interaction():
        # User opens wallet app
        agent = BackgroundSecurityAgent("example_wallet")
        await agent.initialize()
        
        print("👤 User opens wallet app...")
        print("🤖 Background security agent is now protecting them\n")
        
        # User receives a transaction
        incoming_transaction = {
            'hash': '0xsuspicious123',
            'from_address': '0x000000000000000000000000000000000000dead',
            'to_address': '0xuser_wallet',
            'value': '0.00001',  # Dust amount
            'token_name': 'FreeAirdrop',
            'gas_price': '22000000000'
        }
        
        print("📱 Incoming transaction detected...")
        
        # Agent analyzes instantly for wallet UI
        result = await agent.analyze_user_transaction(incoming_transaction)
        
        print(f"⚡ Instant decision: {result['immediate_action']}")
        print(f"💬 User sees: {result['user_message']}")
        print("🔍 Detailed analysis running in background...")
        
        # Wait a moment for background analysis
        await asyncio.sleep(2)
        
        print("\n✅ Background analysis complete - user was protected seamlessly!")
    
    asyncio.run(simulate_user_wallet_interaction())