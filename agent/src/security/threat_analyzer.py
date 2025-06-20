import re
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio

class ThreatAnalyzer:
    """
    Basic threat analysis engine. This will be expanded in later phases
    but provides core functionality for Phase 1.
    """
    
    def __init__(self, config: Dict):
        self.config = config
        
        # Basic threat patterns (will be enhanced with AI in later phases)
        self.known_scammer_patterns = [
            r'0x000000000000000000000000000000000000dead',
            r'0x1111111111111111111111111111111111111111',
        ]
        
        # Suspicious token patterns
        self.suspicious_token_patterns = [
            r'.*usdc.*',  # Fake USDC variants
            r'.*ethereum.*',  # Fake ETH variants
            r'.*bitcoin.*',  # Fake BTC variants
        ]
        
        # Known good addresses (whitelist)
        self.whitelisted_addresses = set([
            '0xa0b86a33e6e89c4c2f89e2b6c2b5dbe8c3d0e1f2',  # Example: Uniswap
        ])
    
    async def analyze(self, transaction_data: Dict) -> Dict:
        """Main threat analysis method"""
        analysis_results = {
            'risk_score': 0.0,
            'threat_categories': [],
            'warnings': [],
            'details': {}
        }
        
        # Address analysis
        address_risk = await self.analyze_addresses(transaction_data)
        analysis_results['details']['address_analysis'] = address_risk
        
        # Token analysis
        token_risk = await self.analyze_token(transaction_data)
        analysis_results['details']['token_analysis'] = token_risk
        
        # Transaction pattern analysis
        pattern_risk = await self.analyze_transaction_patterns(transaction_data)
        analysis_results['details']['pattern_analysis'] = pattern_risk
        
        # Smart contract analysis (basic)
        contract_risk = await self.analyze_smart_contract(transaction_data)
        analysis_results['details']['contract_analysis'] = contract_risk
        
        # Calculate combined risk score
        risk_components = [
            address_risk.get('risk_score', 0),
            token_risk.get('risk_score', 0),
            pattern_risk.get('risk_score', 0),
            contract_risk.get('risk_score', 0)
        ]
        
        analysis_results['risk_score'] = sum(risk_components) / len(risk_components)
        
        # Compile warnings and threat categories
        for component in [address_risk, token_risk, pattern_risk, contract_risk]:
            if component.get('warnings'):
                analysis_results['warnings'].extend(component['warnings'])
            if component.get('threat_categories'):
                analysis_results['threat_categories'].extend(component['threat_categories'])
        
        return analysis_results
    
    async def analyze_addresses(self, transaction_data: Dict) -> Dict:
        """Analyze sender and recipient addresses"""
        from_address = transaction_data.get('from_address', '').lower()
        to_address = transaction_data.get('to_address', '').lower()
        
        risk_score = 0.0
        warnings = []
        threat_categories = []
        
        # Check whitelist first
        if from_address in self.whitelisted_addresses:
            return {
                'risk_score': 0.0,
                'status': 'whitelisted',
                'warnings': [],
                'threat_categories': []
            }
        
        # Check against known scammer patterns
        for pattern in self.known_scammer_patterns:
            if re.match(pattern, from_address):
                risk_score = 1.0
                warnings.append(f"Sender matches known scammer pattern: {pattern}")
                threat_categories.append("known_scammer")
                break
        
        # Check for suspicious address characteristics
        if self._is_suspicious_address(from_address):
            risk_score = max(risk_score, 0.8)
            warnings.append("Sender address has suspicious characteristics")
            threat_categories.append("suspicious_address")
        
        # Check for new/unused addresses
        if await self._is_new_address(from_address):
            risk_score = max(risk_score, 0.6)
            warnings.append("Sender is a new/unused address")
            threat_categories.append("new_address")
        
        return {
            'risk_score': risk_score,
            'from_address': from_address,
            'to_address': to_address,
            'warnings': warnings,
            'threat_categories': threat_categories
        }
    
    async def analyze_token(self, transaction_data: Dict) -> Dict:
        """Analyze token characteristics"""
        token_name = transaction_data.get('token_name', '').lower()
        token_symbol = transaction_data.get('token_symbol', '').lower()
        token_address = transaction_data.get('token_address', '').lower()
        
        risk_score = 0.0
        warnings = []
        threat_categories = []
        
        # Check for fake token patterns
        for pattern in self.suspicious_token_patterns:
            if re.search(pattern, token_name) or re.search(pattern, token_symbol):
                risk_score = 0.9
                warnings.append(f"Token name/symbol matches suspicious pattern: {pattern}")
                threat_categories.append("fake_token")
                break
        
        # Check for unusual token characteristics
        if len(token_name) > 50 or len(token_symbol) > 10:
            risk_score = max(risk_score, 0.7)
            warnings.append("Token has unusually long name or symbol")
            threat_categories.append("suspicious_token")
        
        # Check for Unicode/special characters
        if not token_name.isascii() or not token_symbol.isascii():
            risk_score = max(risk_score, 0.6)
            warnings.append("Token contains non-ASCII characters")
            threat_categories.append("unicode_token")
        
        return {
            'risk_score': risk_score,
            'token_name': token_name,
            'token_symbol': token_symbol,
            'token_address': token_address,
            'warnings': warnings,
            'threat_categories': threat_categories
        }
    
    async def analyze_transaction_patterns(self, transaction_data: Dict) -> Dict:
        """Analyze transaction patterns for suspicious behavior"""
        amount = float(transaction_data.get('value', 0))
        gas_price = int(transaction_data.get('gas_price', 0))
        
        risk_score = 0.0
        warnings = []
        threat_categories = []
        
        # Check for dust transactions (common scammer technique)
        if 0 < amount < 0.001:  # Very small amounts
            risk_score = 0.8
            warnings.append("Dust transaction detected - common scammer technique")
            threat_categories.append("dust_transaction")
        
        # Check for unusual gas prices
        if gas_price > 100000000000:  # Very high gas price
            risk_score = max(risk_score, 0.6)
            warnings.append("Unusually high gas price")
            threat_categories.append("high_gas")
        
        # Check transaction data
        tx_data = transaction_data.get('data', '')
        if tx_data and len(tx_data) > 1000:  # Large data payload
            risk_score = max(risk_score, 0.5)
            warnings.append("Large transaction data payload")
            threat_categories.append("large_data")
        
        return {
            'risk_score': risk_score,
            'amount': amount,
            'gas_price': gas_price,
            'warnings': warnings,
            'threat_categories': threat_categories
        }
    
    async def analyze_smart_contract(self, transaction_data: Dict) -> Dict:
        """Basic smart contract analysis"""
        to_address = transaction_data.get('to_address', '')
        
        risk_score = 0.0
        warnings = []
        threat_categories = []
        
        # Check if interacting with a contract
        if await self._is_contract_address(to_address):
            # Basic contract risk assessment
            if await self._is_unverified_contract(to_address):
                risk_score = 0.7
                warnings.append("Interacting with unverified smart contract")
                threat_categories.append("unverified_contract")
            
            if await self._has_suspicious_permissions(to_address):
                risk_score = max(risk_score, 0.8)
                warnings.append("Contract has suspicious permissions")
                threat_categories.append("dangerous_permissions")
        
        return {
            'risk_score': risk_score,
            'contract_address': to_address,
            'warnings': warnings,
            'threat_categories': threat_categories
        }
    
    def _is_suspicious_address(self, address: str) -> bool:
        """Check if address has suspicious characteristics"""
        # Check for sequential or repeated patterns
        if len(set(address[2:])) < 8:  # Very few unique characters
            return True
        
        # Check for common vanity patterns
        vanity_patterns = ['dead', 'beef', '1111', '0000', 'face']
        for pattern in vanity_patterns:
            if pattern in address.lower():
                return True
        
        return False
    
    async def _is_new_address(self, address: str) -> bool:
        """Check if address is new/unused (placeholder implementation)"""
        # In a real implementation, this would check blockchain history
        # For now, return False (assuming all addresses have history)
        return False
    
    async def _is_contract_address(self, address: str) -> bool:
        """Check if address is a smart contract (placeholder implementation)"""
        # In a real implementation, this would check if address contains code
        # For now, simple heuristic based on address characteristics
        return len(address) == 42 and address.startswith('0x')
    
    async def _is_unverified_contract(self, address: str) -> bool:
        """Check if contract is unverified (placeholder implementation)"""
        # In a real implementation, this would check Etherscan or similar
        # For now, return True for demonstration
        return True
    
    async def _has_suspicious_permissions(self, address: str) -> bool:
        """Check if contract has suspicious permissions (placeholder implementation)"""
        # In a real implementation, this would analyze contract permissions
        # For now, return False
        return False

# Example usage
if __name__ == "__main__":
    async def test_threat_analyzer():
        config = {}
        analyzer = ThreatAnalyzer(config)
        
        test_transaction = {
            'from_address': '0x000000000000000000000000000000000000dead',
            'to_address': '0x123...',
            'value': '0.0001',
            'token_name': 'FakeUSDC',
            'token_symbol': 'USDC',
            'gas_price': '20000000000',
            'data': '0x'
        }
        
        result = await analyzer.analyze(test_transaction)
        print(f"Threat analysis result:")
        print(f"Risk Score: {result['risk_score']:.2f}")
        print(f"Threat Categories: {result['threat_categories']}")
        print(f"Warnings: {result['warnings']}")
    
    asyncio.run(test_threat_analyzer())