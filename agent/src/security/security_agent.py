import asyncio
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging
import sys
import os


class SecurityAgent:
    """
    Core security agent that adapts the trading agent framework
    for Web3 wallet security operations.
    """
    
    def __init__(self, config_path: str):
        self.config = self.load_config(config_path)
        self.agent_id = self.config['agent_id']
        self.model = self.config['model']
        self.security_config = self.config['security_config']
        
        # Initialize components (will be loaded during initialize())
        self.quarantine_manager = None
        self.threat_analyzer = None
        self.community_intel = None
        self.behavior_analyzer = None
        
        # Learning system
        self.learning_history = []
        self.performance_metrics = {
            'threats_detected': 0,
            'false_positives': 0,
            'user_approvals': 0,
            'user_rejections': 0,
            'accuracy_rate': 0.0
        }
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(f"SecurityAgent-{self.agent_id}")
    
    def load_config(self, config_path: str) -> Dict:
        """Load security agent configuration"""
        with open(config_path, 'r') as f:
            return json.load(f)
    
    async def initialize(self):
        """Initialize all agent components"""
        self.logger.info(f"Initializing Security Agent {self.agent_id}")
        
        try:
            # Initialize quarantine manager
            from security.quarantine_manager import QuarantineManager
            self.quarantine_manager = QuarantineManager(self.security_config)
            self.logger.info("✅ Quarantine Manager initialized")
            
        except ImportError as e:
            self.logger.warning(f"⚠️  Could not import QuarantineManager: {e}")
            self.quarantine_manager = None
                
        try:
            # Initialize Security Intelligence (Phase 2)
            import sys
            from pathlib import Path
            # Fix: Adjust the path to point to the correct rag directory
            current_file = Path(__file__)  # agent/src/security/security_agent.py
            project_root = current_file.parent.parent.parent  # Go up to superior-agents/
            rag_path = project_root / "rag-api" / "src"  # 
            
            if rag_path.exists():
                sys.path.insert(0, str(rag_path))
                from security_intelligence import SecurityIntelligence
                self.security_intelligence = SecurityIntelligence()
                await self.security_intelligence.initialize()
                self.logger.info("🧠 Security Intelligence initialized")
            else:
                self.logger.warning(f"⚠️  RAG path not found: {rag_path}")
                self.security_intelligence = None
                
        except ImportError as e:
            self.logger.warning(f"⚠️  Security Intelligence not available: {e}")
            self.security_intelligence = None
        
        try:
            # Initialize Enhanced Threat Analyzer (Phase 2)
            from security.enhanced_threat_analyzer import EnhancedThreatAnalyzer
            self.threat_analyzer = EnhancedThreatAnalyzer(self.config)
            await self.threat_analyzer.initialize(self.security_intelligence)
            self.logger.info("🔍 Enhanced Threat Analyzer initialized")
            
        except ImportError as e:
            self.logger.warning(f"⚠️  Could not import Enhanced Threat Analyzer: {e}")
            # Fall back to basic analyzer
            try:
                from security.threat_analyzer import ThreatAnalyzer
                self.threat_analyzer = ThreatAnalyzer(self.config)
                self.logger.info("✅ Basic Threat Analyzer initialized")
            except ImportError as e2:
                self.logger.warning(f"⚠️  Could not import basic ThreatAnalyzer: {e2}")
                self.threat_analyzer = BasicThreatAnalyzer()
                self.logger.info("✅ Fallback Basic Threat Analyzer initialized")
        
        try:
            # Initialize community intelligence (Phase 3 component)
            from community.community_intel import CommunityIntelligence
            self.community_intel = CommunityIntelligence()
            self.logger.info("✅ Community Intelligence initialized")
            
        except ImportError as e:
            self.logger.warning(f"⚠️  Community Intelligence not available (Phase 3): {e}")
            self.community_intel = None
        
        try:
            # Initialize behavior analyzer (Phase 4 component)
            from analysis.behavior_analyzer import BehaviorAnalyzer
            self.behavior_analyzer = BehaviorAnalyzer()
            self.logger.info("✅ Behavior Analyzer initialized")
            
        except ImportError as e:
            self.logger.warning(f"⚠️  Behavior Analyzer not available (Phase 4): {e}")
            self.behavior_analyzer = None
        
        await self.load_threat_intelligence()
        self.logger.info("🛡️  Security Agent initialized successfully")
    
    async def analyze_transaction(self, transaction_data: Dict) -> Dict:
        """
        Main transaction analysis method - equivalent to trading agent's
        market analysis but for security threats.
        """
        analysis_start = datetime.now()
        
        try:
            # Multi-layered threat analysis
            if self.threat_analyzer:
                threat_analysis = await self.threat_analyzer.analyze(transaction_data)
            else:
                threat_analysis = {'risk_score': 0.5, 'warnings': ['Threat analyzer unavailable']}
            
            # Community intelligence (if available)
            if self.community_intel:
                community_intel = await self.community_intel.check_reputation(
                    transaction_data.get('from_address')
                )
            else:
                community_intel = {'risk_score': 0.0, 'status': 'unknown'}
            
            # Behavior analysis (if available)
            if self.behavior_analyzer:
                behavior_score = await self.behavior_analyzer.analyze_deviation(
                    transaction_data
                )
            else:
                behavior_score = {'anomaly_score': 0.0, 'status': 'unavailable'}
            
            # Combine all analyses
            risk_assessment = await self.calculate_combined_risk(
                threat_analysis, community_intel, behavior_score
            )
            
            # Make quarantine decision
            quarantine_decision = await self.make_quarantine_decision(
                risk_assessment, transaction_data
            )
            
            # Process quarantine if manager is available
            if self.quarantine_manager and quarantine_decision['quarantine']:
                await self.quarantine_manager.quarantine_item(
                    transaction_data, 
                    risk_assessment['combined_score'],
                    quarantine_decision['reasoning']
                )
            
            # Log for learning
            await self.log_analysis(transaction_data, risk_assessment, quarantine_decision)
            
            analysis_time = (datetime.now() - analysis_start).total_seconds()
            
            return {
                'transaction_id': transaction_data.get('hash'),
                'risk_score': risk_assessment['combined_score'],
                'threat_analysis': threat_analysis,
                'community_intel': community_intel,
                'behavior_analysis': behavior_score,
                'quarantine_recommended': quarantine_decision['quarantine'],
                'confidence': quarantine_decision['confidence'],
                'reasoning': quarantine_decision['reasoning'],
                'analysis_time_seconds': analysis_time,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing transaction: {str(e)}")
            return {
                'error': str(e),
                'quarantine_recommended': True,  # Fail safe
                'confidence': 1.0,
                'reasoning': 'Analysis failed - quarantining for safety'
            }
    
    async def calculate_combined_risk(self, threat_analysis: Dict, 
                                    community_intel: Dict, 
                                    behavior_score: Dict) -> Dict:
        """Calculate combined risk score from all analyses"""
        
        # Weight different analysis types
        weights = {
            'threat_analysis': 0.4,
            'community_intel': 0.3,
            'behavior_analysis': 0.3
        }
        
        combined_score = (
            threat_analysis.get('risk_score', 0) * weights['threat_analysis'] +
            community_intel.get('risk_score', 0) * weights['community_intel'] +
            behavior_score.get('anomaly_score', 0) * weights['behavior_analysis']
        )
        
        return {
            'combined_score': combined_score,
            'components': {
                'threat': threat_analysis.get('risk_score', 0),
                'community': community_intel.get('risk_score', 0),
                'behavior': behavior_score.get('anomaly_score', 0)
            },
            'weights': weights
        }
    
    async def make_quarantine_decision(self, risk_assessment: Dict, 
                                     transaction_data: Dict) -> Dict:
        """
        Make quarantine decision based on risk assessment.
        Equivalent to trading agent's strategy formulation.
        """
        combined_score = risk_assessment['combined_score']
        threshold = self.security_config['quarantine_threshold']
        
        # Base decision on threshold
        quarantine = combined_score > threshold
        
        # Adjust based on transaction value and type
        transaction_value = transaction_data.get('value_usd', 0)
        if transaction_value > 10000:  # High value transactions get extra scrutiny
            threshold *= 0.8  # Lower threshold for high-value transactions
            quarantine = combined_score > threshold
        
        # Calculate confidence based on how far above/below threshold
        confidence = abs(combined_score - threshold) / threshold
        confidence = min(confidence, 1.0)  # Cap at 1.0
        
        reasoning = self.generate_reasoning(risk_assessment, quarantine, threshold)
        
        return {
            'quarantine': quarantine,
            'confidence': confidence,
            'threshold_used': threshold,
            'reasoning': reasoning
        }
    
    def generate_reasoning(self, risk_assessment: Dict, quarantine: bool, 
                          threshold: float) -> str:
        """Generate human-readable reasoning for the decision"""
        score = risk_assessment['combined_score']
        components = risk_assessment['components']
        
        if quarantine:
            high_risk_factors = []
            if components['threat'] > 0.7:
                high_risk_factors.append("smart contract analysis")
            if components['community'] > 0.7:
                high_risk_factors.append("community blacklist")
            if components['behavior'] > 0.7:
                high_risk_factors.append("unusual behavior pattern")
            
            if high_risk_factors:
                return f"Quarantined due to high risk in: {', '.join(high_risk_factors)}. Combined risk score: {score:.2f}"
            else:
                return f"Quarantined as combined risk score ({score:.2f}) exceeds threshold ({threshold:.2f})"
        else:
            return f"Approved - risk score ({score:.2f}) below threshold ({threshold:.2f})"
    
    async def process_user_feedback(self, transaction_id: str, 
                                   user_decision: str, feedback: str = ""):
        """
        Process user feedback to improve future decisions.
        This is the core learning mechanism adapted from trading agent.
        """
        self.logger.info(f"Processing user feedback for {transaction_id}: {user_decision}")
        
        # Update performance metrics
        if user_decision == "approved":
            self.performance_metrics['user_approvals'] += 1
        elif user_decision == "rejected":
            self.performance_metrics['user_rejections'] += 1
        
        # Find the original analysis
        analysis = await self.get_analysis_by_id(transaction_id)
        if analysis:
            # Determine if this was a correct or incorrect prediction
            was_correct = (
                (analysis['quarantine_decision']['quarantine'] and user_decision == "rejected") or
                (not analysis['quarantine_decision']['quarantine'] and user_decision == "approved")
            )
            
            if was_correct:
                # Reinforce successful patterns
                await self.reinforce_successful_analysis(analysis)
            else:
                # Learn from mistakes
                await self.learn_from_mistake(analysis, user_decision, feedback)
                if not was_correct:
                    self.performance_metrics['false_positives'] += 1
        
        # Update accuracy rate
        total_decisions = (self.performance_metrics['user_approvals'] + 
                          self.performance_metrics['user_rejections'])
        if total_decisions > 0:
            correct_decisions = total_decisions - self.performance_metrics['false_positives']
            self.performance_metrics['accuracy_rate'] = correct_decisions / total_decisions
        
        # Adapt thresholds if accuracy is poor
        await self.adapt_thresholds()
    
    async def adapt_thresholds(self):
        """Adapt quarantine thresholds based on performance"""
        accuracy = self.performance_metrics['accuracy_rate']
        
        if accuracy < 0.7 and self.performance_metrics['false_positives'] > 10:
            # Too many false positives - increase threshold
            current_threshold = self.security_config['quarantine_threshold']
            new_threshold = min(current_threshold * 1.1, 0.95)
            self.security_config['quarantine_threshold'] = new_threshold
            self.logger.info(f"📈 Increased quarantine threshold to {new_threshold:.2f} due to high false positive rate")
        
        elif accuracy > 0.9 and self.performance_metrics['user_rejections'] > 20:
            # Very accurate and users are rejecting many items - might be too lenient
            current_threshold = self.security_config['quarantine_threshold']
            new_threshold = max(current_threshold * 0.95, 0.3)
            self.security_config['quarantine_threshold'] = new_threshold
            self.logger.info(f"📉 Decreased quarantine threshold to {new_threshold:.2f} to catch more threats")
    
    async def load_threat_intelligence(self):
        """Load latest threat intelligence data"""
        # This will be expanded in Phase 2
        self.logger.info("📚 Loading threat intelligence...")
        pass
    
    async def log_analysis(self, transaction_data: Dict, risk_assessment: Dict, 
                          quarantine_decision: Dict):
        """Log analysis for learning purposes"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'transaction_data': transaction_data,
            'risk_assessment': risk_assessment,
            'quarantine_decision': quarantine_decision,
            'agent_version': self.agent_id
        }
        self.learning_history.append(log_entry)
        
        # Keep only last 1000 entries in memory
        if len(self.learning_history) > 1000:
            self.learning_history = self.learning_history[-1000:]
    
    async def get_analysis_by_id(self, transaction_id: str) -> Optional[Dict]:
        """Retrieve analysis by transaction ID"""
        for entry in reversed(self.learning_history):
            if entry['transaction_data'].get('hash') == transaction_id:
                return entry
        return None
    
    async def reinforce_successful_analysis(self, analysis: Dict):
        """Reinforce patterns that led to successful analysis"""
        # Implementation for reinforcement learning
        self.logger.info("✅ Reinforcing successful analysis patterns")
        pass
    
    async def learn_from_mistake(self, analysis: Dict, correct_decision: str, 
                               feedback: str):
        """Learn from incorrect predictions"""
        self.logger.info(f"📖 Learning from mistake. Correct decision was: {correct_decision}")
        if feedback:
            self.logger.info(f"💬 User feedback: {feedback}")
        # Implementation for learning from mistakes
        pass


class BasicThreatAnalyzer:
    """Fallback threat analyzer when main analyzer is not available"""
    
    async def analyze(self, transaction_data: Dict) -> Dict:
        """Basic threat analysis with simple rules"""
        risk_score = 0.0
        warnings = []
        
        # Simple pattern matching
        from_address = transaction_data.get('from_address', '').lower()
        value = float(transaction_data.get('value', 0))
        
        # Check for obvious scammer patterns
        if 'dead' in from_address or '1111' in from_address:
            risk_score = 0.9
            warnings.append("Suspicious sender address pattern")
        
        # Check for dust transactions
        if 0 < value < 0.001:
            risk_score = max(risk_score, 0.8)
            warnings.append("Dust transaction detected")
        
        # Check token names
        token_name = transaction_data.get('token_name', '').lower()
        if 'fake' in token_name or 'scam' in token_name:
            risk_score = max(risk_score, 0.95)
            warnings.append("Suspicious token name")
        
        return {
            'risk_score': risk_score,
            'warnings': warnings,
            'threat_categories': ['basic_analysis'],
            'analyzer': 'basic_fallback'
        }


# Example usage and testing
if __name__ == "__main__":
    async def test_security_agent():
        agent = SecurityAgent("../../starter/security.json")
        await agent.initialize()
        
        # Test transaction
        test_transaction = {
            'hash': '0x123...',
            'from_address': '0xabc...',
            'to_address': '0xdef...',
            'value': '1000000000000000000',  # 1 ETH
            'value_usd': 2000,
            'gas_price': '20000000000',
            'data': '0x'
        }
        
        result = await agent.analyze_transaction(test_transaction)
        print(f"Analysis result: {json.dumps(result, indent=2)}")
    
    asyncio.run(test_security_agent())