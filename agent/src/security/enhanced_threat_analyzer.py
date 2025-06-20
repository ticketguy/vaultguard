"""
Enhanced Threat Analyzer with AI-powered intelligence
Replaces the basic threat analyzer from Phase 1
"""

import re
import hashlib
import asyncio
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

class EnhancedThreatAnalyzer:
    """
    Enhanced threat analysis engine with AI-powered intelligence
    Integrates with the RAG-based security intelligence system
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.security_intelligence = None
        
        # Enhanced threat detection patterns
        self.advanced_patterns = {
            'address_patterns': {
                'honeypot_contracts': [
                    r'0x[a-f0-9]{38}00dead',
                    r'0x[a-f0-9]{38}beef',
                ],
                'mixer_services': [
                    r'0x[a-f0-9]*tornado[a-f0-9]*',
                ],
                'known_exploiters': []  # Populated from intelligence
            },
            'transaction_patterns': {
                'flash_loan_attacks': {
                    'gas_limit_min': 1000000,
                    'value_patterns': ['large_sudden_movements']
                },
                'sandwich_attacks': {
                    'gas_price_multiplier': 1.5,
                    'timing_window': 3  # blocks
                },
                'rug_pulls': {
                    'liquidity_drain_threshold': 0.8
                }
            },
            'token_patterns': {
                'fake_tokens': {
                    'name_similarity_threshold': 0.8,
                    'unicode_tricks': True,
                    'zero_width_chars': True
                },
                'honeypot_tokens': {
                    'sell_restriction_patterns': ['transfer_disabled', 'high_tax']
                }
            }
        }
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("EnhancedThreatAnalyzer")
    
    async def initialize(self, security_intelligence=None):
        """Initialize enhanced threat analyzer"""
        self.security_intelligence = security_intelligence
        if self.security_intelligence:
            self.logger.info("🧠 Enhanced Threat Analyzer connected to Security Intelligence")
        else:
            self.logger.warning("⚠️  Enhanced Threat Analyzer running without Security Intelligence")
    
    async def analyze(self, transaction_data: Dict) -> Dict:
        """Enhanced threat analysis with AI-powered intelligence"""
        analysis_start = datetime.now()
        
        # Multi-layered analysis
        analysis_results = {
            'risk_score': 0.0,
            'threat_categories': [],
            'warnings': [],
            'details': {},
            'intelligence_enhanced': bool(self.security_intelligence),
            'analysis_depth': 'enhanced'
        }
        
        # 1. Basic analysis (from Phase 1)
        basic_analysis = await self.basic_threat_analysis(transaction_data)
        analysis_results['details']['basic_analysis'] = basic_analysis
        
        # 2. Intelligence-enhanced analysis
        if self.security_intelligence:
            intel_analysis = await self.intelligence_enhanced_analysis(transaction_data)
            analysis_results['details']['intelligence_analysis'] = intel_analysis
        else:
            intel_analysis = {'risk_score': 0.0, 'warnings': []}
        
        # 3. Advanced pattern analysis
        pattern_analysis = await self.advanced_pattern_analysis(transaction_data)
        analysis_results['details']['pattern_analysis'] = pattern_analysis
        
        # 4. Behavioral anomaly detection
        behavioral_analysis = await self.behavioral_anomaly_detection(transaction_data)
        analysis_results['details']['behavioral_analysis'] = behavioral_analysis
        
        # 5. Contract security analysis
        contract_analysis = await self.contract_security_analysis(transaction_data)
        analysis_results['details']['contract_analysis'] = contract_analysis
        
        # Calculate composite risk score
        risk_components = [
            basic_analysis.get('risk_score', 0) * 0.2,
            intel_analysis.get('risk_score', 0) * 0.3,
            pattern_analysis.get('risk_score', 0) * 0.2,
            behavioral_analysis.get('risk_score', 0) * 0.15,
            contract_analysis.get('risk_score', 0) * 0.15
        ]
        
        analysis_results['risk_score'] = sum(risk_components)
        
        # Compile warnings and threat categories
        for component in [basic_analysis, intel_analysis, pattern_analysis, 
                         behavioral_analysis, contract_analysis]:
            if component.get('warnings'):
                analysis_results['warnings'].extend(component['warnings'])
            if component.get('threat_categories'):
                analysis_results['threat_categories'].extend(component['threat_categories'])
        
        # Remove duplicates
        analysis_results['threat_categories'] = list(set(analysis_results['threat_categories']))
        analysis_results['warnings'] = list(set(analysis_results['warnings']))
        
        # Analysis performance
        analysis_time = (datetime.now() - analysis_start).total_seconds()
        analysis_results['analysis_time'] = analysis_time
        
        return analysis_results
    
    async def basic_threat_analysis(self, transaction_data: Dict) -> Dict:
        """Basic threat analysis (Phase 1 functionality)"""
        # Reuse Phase 1 logic but enhanced
        from_address = transaction_data.get('from_address', '').lower()
        value = float(transaction_data.get('value', 0))
        
        risk_score = 0.0
        warnings = []
        threat_categories = []
        
        # Enhanced address analysis
        if self._is_known_malicious_address(from_address):
            risk_score = 1.0
            warnings.append("Sender is a known malicious address")
            threat_categories.append("known_malicious")
        
        # Enhanced dust detection
        if 0 < value < 0.0001:
            risk_score = max(risk_score, 0.9)
            warnings.append("Micro-dust transaction - likely spam/tracking")
            threat_categories.append("dust_attack")
        
        # Enhanced token analysis
        token_risk = await self._enhanced_token_analysis(transaction_data)
        risk_score = max(risk_score, token_risk['risk_score'])
        warnings.extend(token_risk['warnings'])
        threat_categories.extend(token_risk['threat_categories'])
        
        return {
            'risk_score': risk_score,
            'warnings': warnings,
            'threat_categories': threat_categories,
            'analysis_type': 'basic_enhanced'
        }
    
    async def intelligence_enhanced_analysis(self, transaction_data: Dict) -> Dict:
        """Intelligence-enhanced analysis using RAG system"""
        if not self.security_intelligence:
            return {'risk_score': 0.0, 'warnings': [], 'threat_categories': []}
        
        # Query security intelligence
        intel_query = {
            'address': transaction_data.get('from_address'),
            'token_name': transaction_data.get('token_name'),
            'contract_data': transaction_data.get('contract_data', {}),
            'value': transaction_data.get('value'),
            'timestamp': transaction_data.get('timestamp')
        }
        
        intel_result = await self.security_intelligence.query_threat_intelligence(intel_query)
        
        # Convert intelligence to risk assessment
        intelligence_confidence = intel_result.get('confidence_score', 0.0)
        threat_level = intel_result.get('threat_level', 'minimal')
        
        # Map threat level to risk score
        threat_level_mapping = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4,
            'minimal': 0.1
        }
        
        risk_score = threat_level_mapping.get(threat_level, 0.0)
        
        warnings = []
        threat_categories = []
        
        # Process intelligence results
        address_intel = intel_result.get('address_intelligence', {})
        if address_intel.get('status') == 'known_scammer':
            warnings.append(f"Address flagged by intelligence: {address_intel.get('details')}")
            threat_categories.append('intelligence_flagged')
        
        token_intel = intel_result.get('token_intelligence', {})
        if token_intel.get('status') == 'potential_fake':
            warnings.append(f"Token flagged by intelligence: {token_intel.get('details')}")
            threat_categories.append('fake_token')
        
        contract_intel = intel_result.get('contract_intelligence', {})
        if contract_intel.get('status') in ['known_malicious', 'potential_exploit']:
            warnings.append(f"Contract flagged by intelligence: {contract_intel.get('details')}")
            threat_categories.append('malicious_contract')
        
        return {
            'risk_score': risk_score,
            'warnings': warnings,
            'threat_categories': threat_categories,
            'intelligence_result': intel_result,
            'analysis_type': 'intelligence_enhanced'
        }
    
    async def advanced_pattern_analysis(self, transaction_data: Dict) -> Dict:
        """Advanced pattern analysis for sophisticated attacks"""
        risk_score = 0.0
        warnings = []
        threat_categories = []
        
        # Flash loan attack detection
        if await self._detect_flash_loan_attack(transaction_data):
            risk_score = max(risk_score, 0.9)
            warnings.append("Potential flash loan attack pattern detected")
            threat_categories.append("flash_loan_attack")
        
        # Sandwich attack detection
        if await self._detect_sandwich_attack(transaction_data):
            risk_score = max(risk_score, 0.8)
            warnings.append("Potential sandwich attack pattern detected")
            threat_categories.append("sandwich_attack")
        
        # MEV exploitation detection
        if await self._detect_mev_exploitation(transaction_data):
            risk_score = max(risk_score, 0.7)
            warnings.append("MEV exploitation pattern detected")
            threat_categories.append("mev_exploitation")
        
        # Rug pull detection
        if await self._detect_rug_pull(transaction_data):
            risk_score = max(risk_score, 0.95)
            warnings.append("Potential rug pull pattern detected")
            threat_categories.append("rug_pull")
        
        return {
            'risk_score': risk_score,
            'warnings': warnings,
            'threat_categories': threat_categories,
            'analysis_type': 'advanced_patterns'
        }
    
    async def behavioral_anomaly_detection(self, transaction_data: Dict) -> Dict:
        """Detect behavioral anomalies in transaction patterns"""
        risk_score = 0.0
        warnings = []
        threat_categories = []
        
        # Unusual timing patterns
        if await self._detect_timing_anomalies(transaction_data):
            risk_score = max(risk_score, 0.6)
            warnings.append("Unusual timing pattern detected")
            threat_categories.append("timing_anomaly")
        
        # Unusual gas patterns
        if await self._detect_gas_anomalies(transaction_data):
            risk_score = max(risk_score, 0.5)
            warnings.append("Unusual gas usage pattern detected")
            threat_categories.append("gas_anomaly")
        
        # Unusual value patterns
        if await self._detect_value_anomalies(transaction_data):
            risk_score = max(risk_score, 0.7)
            warnings.append("Unusual transaction value pattern detected")
            threat_categories.append("value_anomaly")
        
        return {
            'risk_score': risk_score,
            'warnings': warnings,
            'threat_categories': threat_categories,
            'analysis_type': 'behavioral_anomaly'
        }
    
    async def contract_security_analysis(self, transaction_data: Dict) -> Dict:
        """Analyze smart contract security"""
        contract_address = transaction_data.get('to_address')
        
        if not contract_address or not await self._is_contract_address(contract_address):
            return {
                'risk_score': 0.0,
                'warnings': [],
                'threat_categories': [],
                'analysis_type': 'contract_security'
            }
        
        risk_score = 0.0
        warnings = []
        threat_categories = []
        
        # Check for unverified contracts
        if await self._is_unverified_contract(contract_address):
            risk_score = max(risk_score, 0.7)
            warnings.append("Interacting with unverified smart contract")
            threat_categories.append("unverified_contract")
        
        # Check for dangerous permissions
        if await self._has_dangerous_permissions(contract_address):
            risk_score = max(risk_score, 0.8)
            warnings.append("Contract has dangerous permissions")
            threat_categories.append("dangerous_permissions")
        
        # Check for known vulnerable patterns
        if await self._has_vulnerable_patterns(contract_address):
            risk_score = max(risk_score, 0.9)
            warnings.append("Contract contains known vulnerable patterns")
            threat_categories.append("vulnerable_contract")
        
        return {
            'risk_score': risk_score,
            'warnings': warnings,
            'threat_categories': threat_categories,
            'analysis_type': 'contract_security'
        }
    
    # Helper methods for enhanced detection
    def _is_known_malicious_address(self, address: str) -> bool:
        """Check if address is known to be malicious"""
        # Enhanced version with more comprehensive checking
        malicious_patterns = [
            r'0x000000000000000000000000000000000000dead',
            r'0x[0-9a-f]*dead[0-9a-f]*',
            r'0x[1]{40}',
            r'0x[0]{40}'
        ]
        
        for pattern in malicious_patterns:
            if re.match(pattern, address.lower()):
                return True
        
        return False
    
    async def _enhanced_token_analysis(self, transaction_data: Dict) -> Dict:
        """Enhanced token analysis with more sophisticated detection"""
        token_name = transaction_data.get('token_name', '').lower()
        token_symbol = transaction_data.get('token_symbol', '').lower()
        
        risk_score = 0.0
        warnings = []
        threat_categories = []
        
        # Unicode spoofing detection
        if self._has_unicode_spoofing(token_name) or self._has_unicode_spoofing(token_symbol):
            risk_score = 0.9
            warnings.append("Token uses Unicode spoofing characters")
            threat_categories.append("unicode_spoofing")
        
        # Similarity to popular tokens
        similarity_score = await self._calculate_token_similarity(token_name, token_symbol)
        if similarity_score > 0.8:
            risk_score = max(risk_score, 0.85)
            warnings.append("Token name highly similar to popular token")
            threat_categories.append("token_impersonation")
        
        return {
            'risk_score': risk_score,
            'warnings': warnings,
            'threat_categories': threat_categories
        }
    
    def _has_unicode_spoofing(self, text: str) -> bool:
        """Check for Unicode spoofing characters"""
        # Check for zero-width characters
        zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
        for char in zero_width_chars:
            if char in text:
                return True
        
        # Check for homograph attacks
        suspicious_unicode_ranges = [
            (0x0400, 0x04FF),  # Cyrillic
            (0x0370, 0x03FF),  # Greek
        ]
        
        for char in text:
            char_code = ord(char)
            for start, end in suspicious_unicode_ranges:
                if start <= char_code <= end:
                    return True
        
        return False
    
    async def _calculate_token_similarity(self, token_name: str, token_symbol: str) -> float:
        """Calculate similarity to popular tokens"""
        popular_tokens = [
            ('usdc', 'usdc'), ('ethereum', 'eth'), ('bitcoin', 'btc'),
            ('binancecoin', 'bnb'), ('cardano', 'ada'), ('solana', 'sol'),
            ('ripple', 'xrp'), ('polkadot', 'dot'), ('dogecoin', 'doge'),
            ('avalanche', 'avax'), ('chainlink', 'link'), ('polygon', 'matic')
        ]
        
        max_similarity = 0.0
        
        for popular_name, popular_symbol in popular_tokens:
            name_similarity = self._calculate_string_similarity(token_name, popular_name)
            symbol_similarity = self._calculate_string_similarity(token_symbol, popular_symbol)
            
            overall_similarity = max(name_similarity, symbol_similarity)
            max_similarity = max(max_similarity, overall_similarity)
        
        return max_similarity
    
    def _calculate_string_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity using Levenshtein distance"""
        if len(str1) == 0:
            return len(str2)
        if len(str2) == 0:
            return len(str1)
        
        # Create matrix
        matrix = [[0] * (len(str2) + 1) for _ in range(len(str1) + 1)]
        
        # Initialize first row and column
        for i in range(len(str1) + 1):
            matrix[i][0] = i
        for j in range(len(str2) + 1):
            matrix[0][j] = j
        
        # Fill matrix
        for i in range(1, len(str1) + 1):
            for j in range(1, len(str2) + 1):
                if str1[i-1] == str2[j-1]:
                    matrix[i][j] = matrix[i-1][j-1]
                else:
                    matrix[i][j] = min(
                        matrix[i-1][j] + 1,    # deletion
                        matrix[i][j-1] + 1,    # insertion
                        matrix[i-1][j-1] + 1   # substitution
                    )
        
        # Calculate similarity (0 to 1)
        max_len = max(len(str1), len(str2))
        distance = matrix[len(str1)][len(str2)]
        
        return 1.0 - (distance / max_len)
    
    # Advanced attack detection methods
    async def _detect_flash_loan_attack(self, transaction_data: Dict) -> bool:
        """Detect flash loan attack patterns"""
        gas_limit = int(transaction_data.get('gas_limit', 0))
        value = float(transaction_data.get('value', 0))
        
        # Flash loans typically use high gas and move large amounts quickly
        if gas_limit > 1000000 and value > 1000:
            return True
        
        # Check for rapid successive transactions (would need transaction history)
        return False
    
    async def _detect_sandwich_attack(self, transaction_data: Dict) -> bool:
        """Detect sandwich attack patterns"""
        gas_price = int(transaction_data.get('gas_price', 0))
        
        # Sandwich attacks often use high gas prices to front-run
        average_gas_price = 20000000000  # 20 gwei (example)
        if gas_price > average_gas_price * 2:
            return True
        
        return False
    
    async def _detect_mev_exploitation(self, transaction_data: Dict) -> bool:
        """Detect MEV exploitation patterns"""
        # MEV bots often use specific gas price patterns
        gas_price = int(transaction_data.get('gas_price', 0))
        
        # Check for gas price patterns typical of MEV bots
        if gas_price % 1000000000 == 1:  # Ending in ...000000001
            return True
        
        return False
    
    async def _detect_rug_pull(self, transaction_data: Dict) -> bool:
        """Detect rug pull patterns"""
        # Look for large liquidity removals
        value = float(transaction_data.get('value', 0))
        token_data = transaction_data.get('token_data', {})
        
        # Large percentage of token supply being moved
        total_supply = float(token_data.get('total_supply', 0))
        if total_supply > 0 and (value / total_supply) > 0.1:  # 10% of supply
            return True
        
        return False
    
    async def _detect_timing_anomalies(self, transaction_data: Dict) -> bool:
        """Detect timing anomalies"""
        # Would analyze timing patterns with historical data
        # Placeholder implementation
        return False
    
    async def _detect_gas_anomalies(self, transaction_data: Dict) -> bool:
        """Detect gas usage anomalies"""
        gas_limit = int(transaction_data.get('gas_limit', 21000))
        gas_price = int(transaction_data.get('gas_price', 0))
        
        # Unusually high gas settings
        if gas_limit > 500000 or gas_price > 100000000000:  # 100 gwei
            return True
        
        return False
    
    async def _detect_value_anomalies(self, transaction_data: Dict) -> bool:
        """Detect value anomalies"""
        value = float(transaction_data.get('value', 0))
        
        # Extremely high values might be suspicious
        if value > 100000:  # $100k+ transactions
            return True
        
        return False
    
    async def _is_contract_address(self, address: str) -> bool:
        """Check if address is a smart contract"""
        # Placeholder - would check on-chain
        return len(address) == 42 and address.startswith('0x')
    
    async def _is_unverified_contract(self, address: str) -> bool:
        """Check if contract is unverified"""
        # Placeholder - would check Etherscan/similar
        return True  # Assume unverified for demo
    
    async def _has_dangerous_permissions(self, address: str) -> bool:
        """Check if contract has dangerous permissions"""
        # Placeholder - would analyze contract bytecode
        return False
    
    async def _has_vulnerable_patterns(self, address: str) -> bool:
        """Check if contract has known vulnerable patterns"""
        # Placeholder - would analyze contract for known vulnerabilities
        return False

# Example usage
if __name__ == "__main__":
    async def test_enhanced_analyzer():
        config = {}
        analyzer = EnhancedThreatAnalyzer(config)
        await analyzer.initialize()
        
        test_transaction = {
            'from_address': '0x000000000000000000000000000000000000dead',
            'to_address': '0x123...',
            'value': '0.0001',
            'token_name': 'USĐC',  # Note the Unicode character
            'token_symbol': 'USDC',
            'gas_price': '50000000000',
            'gas_limit': '1500000'
        }
        
        result = await analyzer.analyze(test_transaction)
        print(f"Enhanced analysis result:")
        print(f"Risk Score: {result['risk_score']:.2f}")
        print(f"Threat Categories: {result['threat_categories']}")
        print(f"Warnings: {result['warnings'][:3]}")  # Show first 3 warnings
    
    asyncio.run(test_enhanced_analyzer())