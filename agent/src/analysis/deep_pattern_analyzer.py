"""
Deep Transaction Pattern Analysis
Goes beyond surface patterns to understand intent and behavior
"""

import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import numpy as np

class DeepPatternAnalyzer:
    """
    Deep analysis of transaction patterns to understand true intent
    Not just pattern matching - actual behavioral understanding
    """
    
    def __init__(self):
        # Deep pattern models (in production, these would be ML models)
        self.behavioral_models = {
            'dust_attack_patterns': self._load_dust_attack_model(),
            'phishing_patterns': self._load_phishing_model(),
            'rug_pull_patterns': self._load_rug_pull_model(),
            'sandwich_attack_patterns': self._load_sandwich_model(),
            'wash_trading_patterns': self._load_wash_trading_model()
        }
        self.dust_threshold = 0.0001
        self.suspicious_patterns = [
            'airdrop', 'claim', 'reward', 'free', 'bonus'
        ]

        self.advanced_patterns = {
            'address_patterns': {
                'honeypot_contracts': [
                    r'0x[a-f0-9]{38}00dead',
                    r'0x[a-f0-9]{38}beef',
                ],
                'mixer_services': [
                    r'0x[a-f0-9]*tornado[a-f0-9]*',
                ],
                'known_exploiters': []
            }
        }
    
    async def deep_analyze_transaction_intent(self, transaction_data: Dict, 
                                            historical_context: Dict = None) -> Dict:
        """Analyze transaction intent with deep pattern recognition"""
        
        value = float(transaction_data.get('value', 0))
        from_address = transaction_data.get('from_address', '').lower()
        token_name = transaction_data.get('token_name', '').lower()
        
        analysis = {
            'intent_analysis': {},
            'confidence_score': 0.0,  # Make sure this is always a float
            'protection_recommendations': []
        }
        
        confidence = 0.0  # Start with float
        intent = 'legitimate_transfer_intent'
        
        # Dust attack detection
        if 0 < value < self.dust_threshold:
            confidence += 0.7
            intent = 'dust_attack_intent'
            analysis['protection_recommendations'].append("Quarantine dust transaction")
        
        # Suspicious address patterns
        if any(pattern in from_address for pattern in ['dead', '1111', '0000']):
            confidence += 0.8
            intent = 'phishing_intent'
            analysis['protection_recommendations'].append("Block suspicious sender")
        
        # Fake airdrop detection
        if any(pattern in token_name for pattern in self.suspicious_patterns):
            confidence += 0.6
            intent = 'phishing_intent'
            analysis['protection_recommendations'].append("Review token legitimacy")
        
        # Ensure confidence is always a float
        confidence = min(float(confidence), 1.0)
        
        analysis['intent_analysis'] = {
            'primary_intent': intent,
            'confidence': confidence,  # This should be a float
            'intent_explanation': self._explain_intent(intent, confidence)
        }
        
        analysis['confidence_score'] = confidence  # This should be a float
        
        return analysis
    
    async def deep_analyze_transaction_intent(self, transaction_data: Dict, 
                                            historical_context: Dict = None) -> Dict:
        """Analyze transaction intent with deep pattern recognition"""
        
        # Handle None historical_context
        if historical_context is None:
            historical_context = {}
        
        value = float(transaction_data.get('value', 0))
        from_address = transaction_data.get('from_address', '').lower()
        token_name = transaction_data.get('token_name', '').lower()
        
        analysis = {
            'intent_analysis': {},
            'confidence_score': 0.0,
            'protection_recommendations': [],
            'behavioral_indicators': {}  # Add this to prevent None errors
        }
        
        confidence = 0.0
        intent = 'legitimate_transfer_intent'
        
        # Dust attack detection
        if 0 < value < self.dust_threshold:
            confidence += 0.7
            intent = 'dust_attack_intent'
            analysis['protection_recommendations'].append("Quarantine dust transaction")
        
        # Suspicious address patterns
        if any(pattern in from_address for pattern in ['dead', '1111', '0000']):
            confidence += 0.8
            intent = 'phishing_intent'
            analysis['protection_recommendations'].append("Block suspicious sender")
        
        # Fake airdrop detection
        if any(pattern in token_name for pattern in self.suspicious_patterns):
            confidence += 0.6
            intent = 'phishing_intent'
            analysis['protection_recommendations'].append("Review token legitimacy")
        
        confidence = min(float(confidence), 1.0)
        
        analysis['intent_analysis'] = {
            'primary_intent': intent,
            'confidence': confidence,
            'intent_explanation': self._explain_intent(intent, confidence)  # Now regular function call
        }
        
        analysis['confidence_score'] = confidence
        
        return analysis
    
    async def _analyze_dust_attack_intent(self, value: float, gas_price: int, 
                                        from_address: str, transaction_data: Dict) -> Dict:
        """Deep analysis of dust attack intent"""
        
        dust_indicators = []
        confidence = 0.0
        
        # Micro-value analysis
        if 0 < value < 0.0001:
            dust_indicators.append("extremely_small_value")
            confidence += 0.4
        
        # Gas price analysis (dust attackers often use specific gas prices)
        if gas_price in range(20000000000, 25000000000):  # Common dust attack gas prices
            dust_indicators.append("typical_dust_gas_price")
            confidence += 0.3
        
        # Address entropy analysis
        address_entropy = self._calculate_address_entropy(from_address)
        if address_entropy < 0.3:  # Low entropy = generated address
            dust_indicators.append("low_entropy_sender")
            confidence += 0.4
        
        # Token name analysis for fake airdrops
        token_name = transaction_data.get('token_name', '').lower()
        if any(keyword in token_name for keyword in ['airdrop', 'claim', 'reward', 'free']):
            dust_indicators.append("fake_airdrop_language")
            confidence += 0.5
        
        return {
            'confidence': min(confidence, 1.0),
            'indicators': dust_indicators,
            'explanation': f"Dust attack confidence: {confidence:.1%} based on {len(dust_indicators)} indicators"
        }
    
    async def _analyze_phishing_intent(self, transaction_data: Dict, 
                                     gas_price: int, data: str) -> Dict:
        """Deep analysis of phishing attempt intent"""
        
        phishing_indicators = []
        confidence = 0.0
        
        # Contract interaction analysis
        if len(data) > 10:  # Has contract interaction data
            # Check for approval patterns
            if 'approve' in data.lower():
                phishing_indicators.append("approval_request")
                confidence += 0.6
            
            # Check for unlimited approval patterns
            if 'ffffffff' in data.lower():  # Max uint256
                phishing_indicators.append("unlimited_approval")
                confidence += 0.8
        
        # URL/domain analysis in token metadata
        metadata = transaction_data.get('token_metadata', {})
        if 'url' in str(metadata).lower():
            suspicious_domains = self._check_suspicious_domains(str(metadata))
            if suspicious_domains:
                phishing_indicators.append("suspicious_domains")
                confidence += 0.7
        
        # High gas price for phishing urgency
        if gas_price > 50000000000:  # Very high gas
            phishing_indicators.append("urgency_gas_price")
            confidence += 0.3
        
        return {
            'confidence': min(confidence, 1.0),
            'indicators': phishing_indicators,
            'explanation': f"Phishing confidence: {confidence:.1%} based on {len(phishing_indicators)} indicators"
        }
    
    async def _analyze_legitimate_intent(self, value: float, gas_price: int, 
                                       gas_limit: int, from_address: str, 
                                       to_address: str) -> Dict:
        """Analyze if this is a legitimate transaction"""
        
        legitimate_indicators = []
        confidence = 0.0
        
        # Normal value range
        if 0.001 < value < 10000:  # Reasonable transaction amount
            legitimate_indicators.append("normal_value_range")
            confidence += 0.3
        
        # Standard gas settings
        if 15000000000 <= gas_price <= 30000000000:  # Normal gas price range
            legitimate_indicators.append("standard_gas_price")
            confidence += 0.2
        
        if gas_limit == 21000:  # Standard ETH transfer
            legitimate_indicators.append("standard_eth_transfer")
            confidence += 0.3
        
        # Address patterns (established addresses are more likely legitimate)
        from_entropy = self._calculate_address_entropy(from_address)
        to_entropy = self._calculate_address_entropy(to_address)
        
        if from_entropy > 0.7 and to_entropy > 0.7:
            legitimate_indicators.append("normal_address_entropy")
            confidence += 0.2
        
        return {
            'confidence': min(confidence, 1.0),
            'indicators': legitimate_indicators,
            'explanation': f"Legitimate confidence: {confidence:.1%} based on {len(legitimate_indicators)} indicators"
        }
    
    def _calculate_address_entropy(self, address: str) -> float:
        """Calculate entropy of an address (how random it looks)"""
        if len(address) < 10:
            return 0.0
        
        # Remove 0x prefix
        addr = address[2:] if address.startswith('0x') else address
        
        # Calculate character distribution entropy
        char_counts = {}
        for char in addr.lower():
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        addr_length = len(addr)
        
        for count in char_counts.values():
            probability = count / addr_length
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        # Normalize to 0-1 scale (max entropy for hex is log2(16) = 4)
        return min(entropy / 4.0, 1.0)
    
    def _check_suspicious_domains(self, metadata: str) -> List[str]:
        """Check for suspicious domains in metadata"""
        suspicious_patterns = [
            r'bit\.ly',
            r'tinyurl',
            r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
            r'[a-z0-9]+\.tk',  # .tk domains (often free/disposable)
        ]
        
        import re
        found_suspicious = []
        
        for pattern in suspicious_patterns:
            if re.search(pattern, metadata.lower()):
                found_suspicious.append(pattern)
        
        return found_suspicious
    
    def _explain_intent(self, intent: str, confidence: float) -> str:
        """Generate human-readable explanation of transaction intent"""
        
        explanations = {
            'dust_attack_intent': f"This looks like a dust attack - someone trying to track your wallet by sending tiny amounts. Confidence: {confidence:.1%}",
            'phishing_intent': f"This appears to be a phishing attempt - trying to trick you into approving token access. Confidence: {confidence:.1%}",
            'legitimate_transfer_intent': f"This seems like a normal, legitimate transaction. Confidence: {confidence:.1%}",
            'trading_intent': f"This looks like a trading or DEX interaction. Confidence: {confidence:.1%}",
            'contract_interaction_intent': f"This is interacting with a smart contract for some purpose. Confidence: {confidence:.1%}"
        }
        
        return explanations.get(intent, f"Intent unclear. Confidence: {confidence:.1%}")
    
    # Placeholder model loaders (in production, these would load actual ML models)
    def _load_dust_attack_model(self):
        return {"type": "dust_detection", "version": "1.0"}
    
    def _load_phishing_model(self):
        return {"type": "phishing_detection", "version": "1.0"}
    
    def _load_rug_pull_model(self):
        return {"type": "rug_pull_detection", "version": "1.0"}
    
    def _load_sandwich_model(self):
        return {"type": "sandwich_detection", "version": "1.0"}
    
    def _load_wash_trading_model(self):
        return {"type": "wash_trading_detection", "version": "1.0"}

    async def _analyze_behavioral_patterns(self, transaction_data: Dict, historical_context: Dict) -> Dict:
        """Analyze behavioral patterns across transaction history"""
        return {
            'behavioral_indicators': {},
            'risk_score': 0.0,  # Always float
            'anomaly_score': 0.0,  # Always float
            'patterns_detected': [],
            'status': 'analyzed'
        }
    
    async def _assess_true_risk(self, intent_analysis: Dict, behavioral_indicators: Dict) -> Dict:
        """Assess the true risk of the transaction based on intent and behavior"""
        risk_score = 0.0
        risk_explanation = []
        
        # Combine intent confidence with behavioral indicators
        if intent_analysis['confidence'] < 0.5:
            risk_score += 0.5
            risk_explanation.append("Low confidence in intent analysis")
        
        if behavioral_indicators:
            for indicator, score in behavioral_indicators.items():
                if score > 0.5:
                    risk_score += score * 0.5
                    risk_explanation.append(f"High risk indicator detected: {indicator}")
        
        return {
            'risk_score': min(risk_score, 1.0),
            'explanation': " | ".join(risk_explanation)
        }
    
    async def _generate_protection_recommendations(self, intent_analysis: Dict,
                                                  risk_assessment: Dict) -> List[str]:
        """Generate protection recommendations based on analysis"""
        recommendations = []
        
        if intent_analysis['primary_intent'] == 'dust_attack_intent':
            recommendations.append("Consider blocking dust attacks from this address.")
        
        if intent_analysis['primary_intent'] == 'phishing_intent':
            recommendations.append("Do not approve any token access. Report this transaction.")
        
        if risk_assessment['risk_score'] > 0.5:
            recommendations.append("High risk detected. Consider quarantining this transaction.")
        
        if risk_assessment['risk_score'] < 0.2:
            recommendations.append("This transaction appears safe. Proceed with caution.")
        
        return recommendations
    