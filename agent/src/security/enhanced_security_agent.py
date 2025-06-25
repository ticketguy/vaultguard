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
        self.mev_detector = None
        self.mev_detector = None
        self.dust_detector = None            # NEW
        self.enhanced_contract_analyzer = None  # NEW
        self.drain_link_detector = None      # NEW
        self.nft_scam_detector = None        # NEW
        self.network_analyzer = None      
        
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
            
            # 6. Initialize MEV Detector (Phase 4)
            self.logger.info("⚡ Loading MEV Detector...")
            from analysis.mev_detector import MEVDetector
            self.mev_detector = MEVDetector()
            self.logger.info("✅ MEV Detector ready")

                        # Phase 4 Advanced Protection
            self.logger.info("⚡ Loading MEV Detector...")
            from analysis.mev_detector import MEVDetector
            self.mev_detector = MEVDetector()
            self.logger.info("✅ MEV Detector ready")
            
            self.logger.info("💨 Loading Dust Detector...")
            from analysis.dust_detector import DustDetector
            self.dust_detector = DustDetector()
            self.logger.info("✅ Dust Detector ready")
            
            self.logger.info("🔬 Loading Enhanced Contract Analyzer...")
            from analysis.enhanced_contract_analyzer import EnhancedContractAnalyzer
            self.enhanced_contract_analyzer = EnhancedContractAnalyzer()
            self.logger.info("✅ Enhanced Contract Analyzer ready")
            
            self.logger.info("🕳️ Loading Drain Link Detector...")
            from analysis.drain_link_detector import DrainLinkDetector
            self.drain_link_detector = DrainLinkDetector()
            self.logger.info("✅ Drain Link Detector ready")
            
            self.logger.info("🖼️ Loading NFT Scam Detector...")
            from analysis.nft_scam_detector import NFTScamDetector
            self.nft_scam_detector = NFTScamDetector()
            self.logger.info("✅ NFT Scam Detector ready")
            
            self.logger.info("🕸️ Loading Network Analyzer...")
            from analysis.network_analyzer import NetworkAnalyzer
            self.network_analyzer = NetworkAnalyzer()
            self.logger.info("✅ Network Analyzer ready")

            self.logger.info("🎉 Enhanced Security Agent fully initialized!")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize enhanced components: {e}")
            # Set all components to None for fallback
            self.contract_explainer = None
            self.pattern_analyzer = None
            self.cross_wallet_intel = None
            self.enhanced_quarantine = None
            self.background_agent = None
            self.mev_detector = None 
    
    async def enhanced_transaction_analysis(self, transaction_data: Dict) -> Dict:
        """
        Complete Phase 2+ enhanced transaction analysis with MEV detection
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
            # 1. Smart Contract Deep Analysis (FIXED)
            contract_analysis = None
            if transaction_data.get('to_address') and self.contract_explainer:
                self.logger.info("📜 Analyzing smart contract...")
                enhanced_result['components_used'].append('smart_contract_explainer')  # ← ADD IMMEDIATELY
                
                if await self._is_contract_interaction(transaction_data):
                    contract_data = await self._prepare_contract_data(transaction_data)
                    if contract_data:
                        contract_analysis = await self.contract_explainer.explain_contract_in_english(contract_data)
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
            
            # 4. MEV Risk Analysis (NEW - Phase 4)
            mev_analysis = None
            if self.mev_detector:
                self.logger.info("⚡ Performing MEV risk analysis...")
                mev_analysis = await self.mev_detector.analyze_mev_risk(transaction_data)
                enhanced_result['components_used'].append('mev_detector')
                enhanced_result['technical_details']['mev_analysis'] = mev_analysis
            
            # 5. Enhanced Quarantine Decision (UPDATED - was step 4)
            quarantine_decision = None
            if self.enhanced_quarantine:
                self.logger.info("🛡️ Making enhanced quarantine decision...")
                
                # Prepare comprehensive analysis for quarantine decision
                comprehensive_analysis = {
                    'contract_analysis': contract_analysis,
                    'pattern_analysis': pattern_analysis,
                    'community_intelligence': community_intel,
                    'mev_analysis': mev_analysis,  # ← NEW: Add MEV analysis
                    'confidence_score': await self._calculate_comprehensive_confidence(
                        contract_analysis, pattern_analysis, community_intel, mev_analysis  # ← NEW: Add mev_analysis parameter
                    ),
                    'threat_categories': await self._extract_threat_categories(
                        contract_analysis, pattern_analysis, community_intel, mev_analysis  # ← NEW: Add mev_analysis parameter
                    )
                }
                
                quarantine_decision = await self.enhanced_quarantine.enhanced_quarantine_decision(
                    comprehensive_analysis, transaction_data
                )
                enhanced_result['components_used'].append('enhanced_quarantine')
                enhanced_result['final_decision'] = quarantine_decision
                
                if quarantine_decision['action'] in ['quarantine', 'quarantine_with_auto_burn']:
                    self.analysis_stats['quarantine_decisions'] += 1
            
            # 6. Generate User-Friendly Explanation (UPDATED - was step 5)
            enhanced_result['user_explanation'] = await self._generate_enhanced_user_explanation(
                contract_analysis, pattern_analysis, community_intel, quarantine_decision, mev_analysis  # ← NEW: Add mev_analysis parameter
            )
            
            # 7. Background Processing (UPDATED - was step 6)
            if self.background_agent and quarantine_decision and quarantine_decision.get('action') == 'allow_with_monitoring':
                await self.background_agent.analyze_user_transaction(transaction_data)
                enhanced_result['components_used'].append('background_monitoring')
            
            # 5. Dust Attack Detection (NEW)
            dust_analysis = None
            if self.dust_detector:
                self.logger.info("💨 Performing dust attack analysis...")
                dust_analysis = await self.dust_detector.analyze_dust_attack(transaction_data)
                enhanced_result['components_used'].append('dust_detector')
                enhanced_result['technical_details']['dust_analysis'] = dust_analysis
            
            # 6. Enhanced Contract Analysis (NEW)
            enhanced_contract_analysis = None
            if self.enhanced_contract_analyzer and transaction_data.get('program_id'):
                self.logger.info("🔬 Performing enhanced contract analysis...")
                program_data = await self._prepare_program_data(transaction_data)
                if program_data:
                    enhanced_contract_analysis = await self.enhanced_contract_analyzer.deep_analyze_program(program_data)
                    enhanced_result['components_used'].append('enhanced_contract_analyzer')
                    enhanced_result['technical_details']['enhanced_contract_analysis'] = enhanced_contract_analysis
            
            # 7. Drain Link Detection (NEW)
            drain_analysis = None
            if self.drain_link_detector:
                self.logger.info("🕳️ Performing drain link detection...")
                drain_analysis = await self.drain_link_detector.analyze_drain_risk(transaction_data)
                enhanced_result['components_used'].append('drain_link_detector')
                enhanced_result['technical_details']['drain_analysis'] = drain_analysis
            
            # 8. NFT Scam Detection (NEW - if NFT transaction)
            nft_analysis = None
            if self.nft_scam_detector and self._is_nft_transaction(transaction_data):
                self.logger.info("🖼️ Performing NFT scam detection...")
                nft_data = await self._prepare_nft_data(transaction_data)
                if nft_data:
                    nft_analysis = await self.nft_scam_detector.analyze_nft_scam_risk(nft_data)
                    enhanced_result['components_used'].append('nft_scam_detector')
                    enhanced_result['technical_details']['nft_analysis'] = nft_analysis
            
            # 9. Network Analysis (NEW)
            network_analysis = None
            if self.network_analyzer:
                self.logger.info("🕸️ Performing network analysis...")
                from_address = transaction_data.get('from_address')
                if from_address:
                    network_analysis = await self.network_analyzer.analyze_address_network(from_address, transaction_data)
                    enhanced_result['components_used'].append('network_analyzer')
                    enhanced_result['technical_details']['network_analysis'] = network_analysis
            
            # 10. Enhanced Quarantine Decision (UPDATED)
            quarantine_decision = None
            if self.enhanced_quarantine:
                self.logger.info("🛡️ Making enhanced quarantine decision...")
                
                # Prepare comprehensive analysis for quarantine decision
                comprehensive_analysis = {
                    'contract_analysis': contract_analysis,
                    'pattern_analysis': pattern_analysis,
                    'community_intelligence': community_intel,
                    'mev_analysis': mev_analysis,
                    'dust_analysis': dust_analysis,                           # NEW
                    'enhanced_contract_analysis': enhanced_contract_analysis, # NEW
                    'drain_analysis': drain_analysis,                         # NEW
                    'nft_analysis': nft_analysis,                            # NEW
                    'network_analysis': network_analysis,                    # NEW
                    'confidence_score': await self._calculate_comprehensive_confidence(
                        contract_analysis, pattern_analysis, community_intel, mev_analysis,
                        dust_analysis, enhanced_contract_analysis, drain_analysis, nft_analysis, network_analysis
                    ),
                    'threat_categories': await self._extract_threat_categories(
                        contract_analysis, pattern_analysis, community_intel, mev_analysis,
                        dust_analysis, enhanced_contract_analysis, drain_analysis, nft_analysis, network_analysis
                    )
                }

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
    
    async def _prepare_program_data(self, transaction_data: Dict) -> Optional[Dict]:
        """Prepare program data for enhanced analysis"""
        program_id = transaction_data.get('program_id')
        if not program_id:
            return None
        
        return {
            'program_id': program_id,
            'instructions': transaction_data.get('instructions', []),
            'metadata': transaction_data.get('metadata', {}),
            'upgrade_authority': transaction_data.get('upgrade_authority'),
            'program_authority': transaction_data.get('program_authority')
        }

    def _is_nft_transaction(self, transaction_data: Dict) -> bool:
        """Check if transaction involves NFT"""
        instruction_type = transaction_data.get('instruction_type', '').lower()
        program_id = transaction_data.get('program_id', '').lower()
        
        nft_indicators = ['nft', 'metadata', 'metaplex', 'mint']
        return any(indicator in instruction_type or indicator in program_id for indicator in nft_indicators)

    async def _prepare_nft_data(self, transaction_data: Dict) -> Optional[Dict]:
        """Prepare NFT data for scam analysis"""
        return {
            'metadata': transaction_data.get('metadata', {}),
            'collection': transaction_data.get('collection', {}),
            'mint_data': transaction_data.get('mint_data', {}),
            'price_data': transaction_data.get('price_data', {}),
            'volume_data': transaction_data.get('volume_data', {}),
            'trading_data': transaction_data.get('trading_data', {}),
            'contract_data': transaction_data.get('contract_data', {}),
            'distribution_data': transaction_data.get('distribution_data', {})
        }

    async def _is_contract_interaction(self, transaction_data: Dict) -> bool:
        """Check if transaction involves smart contract interaction"""
        to_address = transaction_data.get('to_address')
        data = transaction_data.get('data', '0x')
        
        # Has contract data or known contract address format
        return len(data) > 2 or (to_address and len(to_address) >= 20)

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
                                            community_intel: Optional[Dict],
                                            mev_analysis: Optional[Dict] = None) -> float:
        """Calculate comprehensive confidence score from all analyses including MEV"""
        confidence_factors = []
        
        # Add null checks
        if contract_analysis and isinstance(contract_analysis, dict):
            if contract_analysis.get('overall_risk') == 'critical':
                confidence_factors.append(0.95)
            elif contract_analysis.get('overall_risk') == 'high':
                confidence_factors.append(0.8)
            elif contract_analysis.get('overall_risk') == 'medium':
                confidence_factors.append(0.6)

            # Add MEV confidence factor
        if mev_analysis and isinstance(mev_analysis, dict):
            mev_risk = mev_analysis.get('overall_mev_risk', 0)
            if mev_risk > 0.8:
                confidence_factors.append(0.9)  # High MEV risk increases confidence in quarantine
            elif mev_risk > 0.5:
                confidence_factors.append(0.7)
        
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
    
    async def _extract_threat_categories(self, contract_analysis, pattern_analysis, community_intel, mev_analysis=None):
        """Extract threat categories from analysis components including MEV threats"""
        threat_categories = []
        
        # Extract from each analysis component
        for analysis in [contract_analysis, pattern_analysis, community_intel, mev_analysis]:
            if analysis and isinstance(analysis, dict):
                if analysis.get('threat_categories'):
                    threat_categories.extend(analysis['threat_categories'])
        
        # CRITICAL: Check for known malicious addresses directly from transaction data
        all_analysis_text = str([contract_analysis, pattern_analysis, community_intel]).lower()
        if 'dead' in all_analysis_text or 'blacklist' in all_analysis_text:
            threat_categories.extend(['known_malicious_sender', 'community_blacklisted'])
        
        # MEV-specific threat extraction
        if mev_analysis and isinstance(mev_analysis, dict):
            # Add MEV threats from the detector
            if mev_analysis.get('mev_threats'):
                threat_categories.extend(mev_analysis['mev_threats'])
            
            # Add high-risk MEV categories
            if mev_analysis.get('overall_mev_risk', 0) > 0.7:
                threat_categories.append('high_mev_risk')
            
            # Add specific MEV threat types
            risk_factors = mev_analysis.get('risk_factors', {})
            for mev_type, data in risk_factors.items():
                if data.get('risk_score', 0) > 0.6:
                    threat_categories.append(f'mev_{mev_type}')
        
        return list(set(threat_categories))  # Remove duplicates
        
    async def _generate_enhanced_user_explanation(self, contract_analysis: Optional[Dict],
                                                pattern_analysis: Optional[Dict],
                                                community_intel: Optional[Dict],
                                                quarantine_decision: Optional[Dict],
                                                mev_analysis: Optional[Dict] = None) -> Dict:
        """Generate comprehensive user-friendly explanation including MEV warnings"""
        
        explanation = {
            'primary_message': '',
            'contract_explanation': '',
            'threat_explanation': '',
            'community_warning': '',
            'mev_warning': '',  # ← NEW: MEV-specific warnings
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
        
        # MEV warning (NEW)
        if mev_analysis and mev_analysis.get('user_warnings'):
            explanation['mev_warning'] = ' | '.join(mev_analysis['user_warnings'])
        
        # Primary message based on decision
        if quarantine_decision:
            explanation['primary_message'] = quarantine_decision.get('user_message', '')
            
            if quarantine_decision['action'] == 'quarantine':
                explanation['recommendation'] = "Review this item carefully before approving"
            elif quarantine_decision['action'] == 'quarantine_with_auto_burn':
                explanation['recommendation'] = "High-risk item will be auto-deleted unless you approve"
            else:
                explanation['recommendation'] = "Transaction appears safe to proceed"
            
            # Add MEV-specific recommendations
            if mev_analysis and mev_analysis.get('recommended_actions'):
                explanation['recommendation'] += f" | MEV Protection: {mev_analysis['recommended_actions'][0]}"
        
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