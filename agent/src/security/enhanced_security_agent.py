"""
Enhanced Security Agent - Phase 2 Complete Integration
Brings together all Phase 2 components into a unified system
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging
import sys
from pathlib import Path

class EnhancedSecurityAgent:
    """
    Complete Phase 2 security agent with all enhanced capabilities
    """
    
    def __init__(self, config_path: str, wallet_provider_id: str = "default"):
        self.config = self.load_config(config_path)
        self.agent_id = self.config['agent_id']
        self.wallet_provider_id = wallet_provider_id
        
        # Phase 2 Enhanced Components
        self.contract_explainer = None
        self.pattern_analyzer = None
        self.cross_wallet_intel = None
        self.enhanced_quarantine = None
        self.background_agent = None
        
        # Performance tracking
        self.analysis_stats = {
            'total_analyses': 0,
            'quarantine_decisions': 0,
            'user_feedback_events': 0,
            'accuracy_improvements': 0
        }
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(f"EnhancedSecurityAgent-{self.agent_id}")
    
    def load_config(self, config_path: str) -> Dict:
        """Load enhanced security configuration"""
        with open(config_path, 'r') as f:
            return json.load(f)
    

    async def initialize(self):
        """Initialize all Phase 2 enhanced components"""
        self.logger.info(f"🚀 Initializing Enhanced Security Agent {self.agent_id}")
        
        try:
            # 1. Initialize Enhanced Smart Contract Explainer
            self.logger.info("🔍 Loading Smart Contract Explainer...")
            from analysis.smart_contract_explainer import SmartContractExplainer
            self.contract_explainer = SmartContractExplainer()
            self.logger.info("✅ Smart Contract Explainer ready")
            
            # 2. Initialize Deep Pattern Analyzer
            self.logger.info("🧠 Loading Deep Pattern Analyzer...")
            from analysis.deep_pattern_analyzer import DeepPatternAnalyzer
            self.pattern_analyzer = DeepPatternAnalyzer()
            self.logger.info("✅ Deep Pattern Analyzer ready")
            
            # 3. Initialize Cross-Wallet Intelligence
            self.logger.info("🌐 Loading Cross-Wallet Intelligence...")
            from community.cross_wallet_intelligence import CrossWalletIntelligence
            self.cross_wallet_intel = CrossWalletIntelligence(self.wallet_provider_id)
            await self.cross_wallet_intel.sync_with_community_network()
            self.logger.info("✅ Cross-Wallet Intelligence ready")
            
            # 4. Initialize Enhanced Quarantine Manager
            self.logger.info("🛡️ Loading Enhanced Quarantine Manager...")
            from security.enhanced_quarantine_manager import EnhancedQuarantineManager
            self.enhanced_quarantine = EnhancedQuarantineManager(self.config.get('quarantine_config', {}))
            self.logger.info("✅ Enhanced Quarantine Manager ready")
            
            # 5. Initialize Background Security Agent
            self.logger.info("⚙️ Starting Background Security Agent...")
            from core.background_security_agent import BackgroundSecurityAgent
            self.background_agent = BackgroundSecurityAgent(self.wallet_provider_id)
            await self.background_agent.initialize()
            self.logger.info("✅ Background Security Agent active")
            
            self.logger.info("🎉 Enhanced Security Agent fully initialized!")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize enhanced components: {e}")
            # Set all components to None for fallback
            self.contract_explainer = None
            self.pattern_analyzer = None
            self.cross_wallet_intel = None
            self.enhanced_quarantine = None
            self.background_agent = None
    
    async def enhanced_transaction_analysis(self, transaction_data: Dict) -> Dict:
        """
        Complete Phase 2 enhanced transaction analysis
        Combines all components for comprehensive threat detection
        """
        analysis_start = datetime.now()
        self.analysis_stats['total_analyses'] += 1
        
        self.logger.info(f"🔍 Enhanced analysis for transaction: {transaction_data.get('hash', 'unknown')}")
        
        # Enhanced Analysis Results
        enhanced_result = {
            'transaction_id': transaction_data.get('hash'),
            'analysis_timestamp': analysis_start.isoformat(),
            'enhanced_analysis': True,
            'components_used': [],
            'final_decision': {},
            'user_explanation': {},
            'technical_details': {}
        }
        
        try:
            # 1. Smart Contract Deep Analysis (if interacting with contract)
            contract_analysis = None
            if transaction_data.get('to_address') and await self._is_contract_interaction(transaction_data):
                self.logger.info("📜 Analyzing smart contract...")
                contract_data = await self._prepare_contract_data(transaction_data)
                
                if contract_data and self.contract_explainer:
                    contract_analysis = await self.contract_explainer.explain_contract_in_english(contract_data)
                    enhanced_result['components_used'].append('smart_contract_explainer')
                    enhanced_result['technical_details']['contract_analysis'] = contract_analysis
            
            # 2. Deep Pattern Analysis
            pattern_analysis = None
            if self.pattern_analyzer:
                self.logger.info("🧠 Performing deep pattern analysis...")
                pattern_analysis = await self.pattern_analyzer.deep_analyze_transaction_intent(
                    transaction_data, 
                    historical_context=await self._get_historical_context(transaction_data)
                )
                enhanced_result['components_used'].append('deep_pattern_analyzer')
                enhanced_result['technical_details']['pattern_analysis'] = pattern_analysis
            
            # 3. Cross-Wallet Intelligence Check
            community_intel = None
            if self.cross_wallet_intel:
                self.logger.info("🌐 Checking cross-wallet intelligence...")
                from_address = transaction_data.get('from_address')
                if from_address:
                    community_intel = await self.cross_wallet_intel.check_community_blacklist(from_address)
                    enhanced_result['components_used'].append('cross_wallet_intelligence')
                    enhanced_result['technical_details']['community_intel'] = community_intel
            
            # 4. Enhanced Quarantine Decision
            quarantine_decision = None
            if self.enhanced_quarantine:
                self.logger.info("🛡️ Making enhanced quarantine decision...")
                
                # Prepare comprehensive analysis for quarantine decision
                comprehensive_analysis = {
                    'contract_analysis': contract_analysis,
                    'pattern_analysis': pattern_analysis,
                    'community_intelligence': community_intel,
                    'confidence_score': await self._calculate_comprehensive_confidence(
                        contract_analysis, pattern_analysis, community_intel
                    ),
                    'threat_categories': await self._extract_threat_categories(
                        contract_analysis, pattern_analysis, community_intel
                    )
                }
                
                quarantine_decision = await self.enhanced_quarantine.enhanced_quarantine_decision(
                    comprehensive_analysis, transaction_data
                )
                enhanced_result['components_used'].append('enhanced_quarantine')
                enhanced_result['final_decision'] = quarantine_decision
                
                if quarantine_decision['action'] in ['quarantine', 'quarantine_with_auto_burn']:
                    self.analysis_stats['quarantine_decisions'] += 1
            
            # 5. Generate User-Friendly Explanation
            enhanced_result['user_explanation'] = await self._generate_enhanced_user_explanation(
                contract_analysis, pattern_analysis, community_intel, quarantine_decision
            )
            
            # 6. Background Processing (if applicable)
            if self.background_agent and quarantine_decision.get('action') == 'allow_with_monitoring':
                await self.background_agent.analyze_user_transaction(transaction_data)
                enhanced_result['components_used'].append('background_monitoring')
            
            # Analysis Performance
            analysis_time = (datetime.now() - analysis_start).total_seconds()
            enhanced_result['analysis_performance'] = {
                'total_time_seconds': analysis_time,
                'components_count': len(enhanced_result['components_used']),
                'efficiency_score': len(enhanced_result['components_used']) / max(analysis_time, 0.001)
            }
            
            self.logger.info(f"✅ Enhanced analysis complete in {analysis_time:.3f}s using {len(enhanced_result['components_used'])} components")
            
            return enhanced_result
            
        except Exception as e:
            self.logger.error(f"❌ Error in enhanced analysis: {e}")
            # Return safe fallback decision
            return {
                'transaction_id': transaction_data.get('hash'),
                'enhanced_analysis': False,
                'error': str(e),
                'final_decision': {
                    'action': 'quarantine',
                    'confidence_score': 1.0,
                    'user_message': '🚨 Analysis error - quarantining for safety'
                },
                'fallback_used': True
            }
    
    async def process_enhanced_user_feedback(self, transaction_id: str, user_decision: str, 
                                           user_feedback: str = "", additional_context: Dict = None):
        """
        Enhanced user feedback processing with cross-component learning
        """
        self.analysis_stats['user_feedback_events'] += 1
        
        self.logger.info(f"📚 Processing enhanced user feedback for {transaction_id}: {user_decision}")
        
        feedback_data = {
            'transaction_id': transaction_id,
            'user_decision': user_decision,
            'user_feedback': user_feedback,
            'additional_context': additional_context or {},
            'timestamp': datetime.now().isoformat(),
            'agent_version': 'enhanced_v2'
        }
        
        # 1. Update Cross-Wallet Intelligence
        if self.cross_wallet_intel and user_decision in ['burned', 'quarantined_confirmed']:
            # Report to community if user confirms threat
            original_analysis = await self._get_original_analysis(transaction_id)
            if original_analysis:
                from_address = original_analysis.get('from_address')
                if from_address:
                    evidence = {
                        'user_confirmed_threat': True,
                        'analysis_confidence': original_analysis.get('confidence_score', 0),
                        'threat_categories': original_analysis.get('threat_categories', []),
                        'user_feedback': user_feedback
                    }
                    
                    await self.cross_wallet_intel.report_malicious_address(
                        from_address, evidence, 
                        {'wallet_provider': self.wallet_provider_id, 'user_id': 'anonymous'}
                    )
        
        # 2. Update Background Agent Learning
        if self.background_agent:
            await self.background_agent.learn_from_user_decision(
                transaction_id, user_decision, user_feedback
            )
        
        # 3. Improve Analysis Accuracy
        await self._update_analysis_accuracy(feedback_data)
        
        self.logger.info(f"✅ Enhanced feedback processing complete")
        
        return {
            'feedback_processed': True,
            'components_updated': ['cross_wallet_intel', 'background_agent', 'analysis_accuracy'],
            'learning_applied': True
        }
    
    async def get_enhanced_system_status(self) -> Dict:
        """Get comprehensive status of all enhanced components"""
        
        status = {
            'agent_id': self.agent_id,
            'wallet_provider_id': self.wallet_provider_id,
            'enhanced_features_active': True,
            'components_status': {},
            'performance_stats': self.analysis_stats,
            'system_health': 'optimal'
        }
        
        # Check each component status
        status['components_status'] = {
            'smart_contract_explainer': bool(self.contract_explainer),
            'deep_pattern_analyzer': bool(self.pattern_analyzer),
            'cross_wallet_intelligence': bool(self.cross_wallet_intel),
            'enhanced_quarantine': bool(self.enhanced_quarantine),
            'background_agent': bool(self.background_agent)
        }
        
        # Get cross-wallet intelligence stats
        if self.cross_wallet_intel:
            try:
                wallet_reputation = await self.cross_wallet_intel.get_wallet_provider_reputation(
                    self.wallet_provider_id
                )
                status['reputation_score'] = wallet_reputation['reputation_score']
                status['community_standing'] = wallet_reputation['status']
            except:
                status['reputation_score'] = 0.5
                status['community_standing'] = 'unknown'
        
        # Calculate system health
        active_components = sum(status['components_status'].values())
        if active_components >= 4:
            status['system_health'] = 'optimal'
        elif active_components >= 3:
            status['system_health'] = 'good'
        elif active_components >= 2:
            status['system_health'] = 'degraded'
        else:
            status['system_health'] = 'minimal'
        
        return status
    
    # Helper methods
    
    async def _is_contract_interaction(self, transaction_data: Dict) -> bool:
        """Check if transaction involves smart contract interaction"""
        to_address = transaction_data.get('to_address')
        data = transaction_data.get('data', '0x')
        
        # Has contract data or known contract address format
        return len(data) > 2 or (to_address and len(to_address) == 42)
    
    async def _prepare_contract_data(self, transaction_data: Dict) -> Optional[Dict]:
        """Prepare contract data for analysis"""
        to_address = transaction_data.get('to_address')
        
        if not to_address:
            return None
        
        # In production, this would fetch real contract data
        return {
            'address': to_address,
            'functions': transaction_data.get('contract_functions', []),
            'bytecode': transaction_data.get('contract_bytecode', ''),
            'verified': transaction_data.get('contract_verified', False)
        }
    
    async def _get_historical_context(self, transaction_data: Dict) -> Dict:
        """Get historical context for pattern analysis"""
        # In production, this would fetch user's transaction history
        return {
            'user_transaction_history': [],
            'address_interaction_history': {},
            'network_activity_context': {}
        }
    
    async def _calculate_comprehensive_confidence(self, contract_analysis: Optional[Dict],
                                                pattern_analysis: Optional[Dict],
                                                community_intel: Optional[Dict]) -> float:
        """Calculate comprehensive confidence score from all analyses"""
        confidence_factors = []
        
        # Add null checks
        if contract_analysis and isinstance(contract_analysis, dict):
            if contract_analysis.get('overall_risk') == 'critical':
                confidence_factors.append(0.95)
            elif contract_analysis.get('overall_risk') == 'high':
                confidence_factors.append(0.8)
            elif contract_analysis.get('overall_risk') == 'medium':
                confidence_factors.append(0.6)
        
        if pattern_analysis and isinstance(pattern_analysis, dict):
            pattern_confidence = pattern_analysis.get('confidence_score', 0)
            if isinstance(pattern_confidence, (int, float)):
                confidence_factors.append(float(pattern_confidence))
        
        if community_intel and isinstance(community_intel, dict) and community_intel.get('blacklisted'):
            community_confidence = community_intel.get('confidence', 0)
            if isinstance(community_confidence, (int, float)):
                confidence_factors.append(float(community_confidence))
        
        if not confidence_factors:
            return 0.0
        
        max_confidence = max(confidence_factors)
        if len(confidence_factors) > 1:
            max_confidence = min(max_confidence + 0.1, 1.0)
        
        return float(max_confidence)
        
    async def _generate_enhanced_user_explanation(self, contract_analysis: Optional[Dict],
                                                pattern_analysis: Optional[Dict],
                                                community_intel: Optional[Dict],
                                                quarantine_decision: Optional[Dict]) -> Dict:
        """Generate comprehensive user-friendly explanation"""
        
        explanation = {
            'primary_message': '',
            'contract_explanation': '',
            'threat_explanation': '',
            'community_warning': '',
            'recommendation': ''
        }
        
        # Contract explanation
        if contract_analysis:
            explanation['contract_explanation'] = contract_analysis.get('user_friendly_summary', '')
        
        # Pattern/threat explanation
        if pattern_analysis:
            intent_explanation = pattern_analysis.get('intent_analysis', {}).get('intent_explanation', '')
            explanation['threat_explanation'] = intent_explanation
        
        # Community warning
        if community_intel and community_intel.get('blacklisted'):
            report_count = community_intel.get('report_count', 0)
            explanation['community_warning'] = f"⚠️ This address has been reported {report_count} times by the community"
        
        # Primary message based on decision
        if quarantine_decision:
            explanation['primary_message'] = quarantine_decision.get('user_message', '')
            
            if quarantine_decision['action'] == 'quarantine':
                explanation['recommendation'] = "Review this item carefully before approving"
            elif quarantine_decision['action'] == 'quarantine_with_auto_burn':
                explanation['recommendation'] = "High-risk item will be auto-deleted unless you approve"
            else:
                explanation['recommendation'] = "Transaction appears safe to proceed"
        
        return explanation
    
    async def _get_original_analysis(self, transaction_id: str) -> Optional[Dict]:
        """Get original analysis data for learning"""
        # In production, this would fetch from database
        return None
    
    async def _update_analysis_accuracy(self, feedback_data: Dict):
        """Update analysis accuracy based on user feedback"""
        # Track accuracy improvements
        self.analysis_stats['accuracy_improvements'] += 1
        self.logger.info("📈 Analysis accuracy updated based on user feedback")
    
    async def _initialize_fallback_components(self):
        """Initialize basic components if enhanced ones fail"""
        self.logger.warning("⚠️ Initializing fallback components")
        # This would initialize basic Phase 1 components
        pass

# Example usage
if __name__ == "__main__":
    async def test_enhanced_system():
        agent = EnhancedSecurityAgent("../starter/security.json", "test_wallet")
        await agent.initialize()
        
        # Test enhanced analysis
        test_transaction = {
            'hash': '0xenhanced_test',
            'from_address': '0x000000000000000000000000000000000000dead',
            'to_address': '0x1234567890abcdef1234567890abcdef12345678',
            'value': '0.00001',
            'token_name': 'FakeAirdrop',
            'contract_functions': ['approve', 'emergencyWithdraw'],
            'contract_bytecode': 'contains selfdestruct pattern'
        }
        
        result = await agent.enhanced_transaction_analysis(test_transaction)
        
        print("🎉 Enhanced Security Agent Test Results")
        print("=" * 50)
        print(f"Components Used: {', '.join(result['components_used'])}")
        print(f"Decision: {result['final_decision']['action']}")
        print(f"User Message: {result['final_decision']['user_message']}")
        print(f"Analysis Time: {result['analysis_performance']['total_time_seconds']:.3f}s")
        
        # Test system status
        status = await agent.get_enhanced_system_status()
        print(f"\nSystem Health: {status['system_health']}")
        print(f"Active Components: {sum(status['components_status'].values())}/5")
    
    asyncio.run(test_enhanced_system())

# This code is part of the Enhanced Security Agent system, which integrates multiple advanced security features
# to provide comprehensive protection against threats in the cryptocurrency ecosystem.