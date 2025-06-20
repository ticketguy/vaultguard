"""
Enhanced Smart Contract Analysis
Improved detection of drain contracts and malicious permissions
"""

import asyncio
import json
from typing import Dict, List, Optional, Any
import re

class EnhancedContractAnalyzer:
    """
    Enhanced smart contract analysis for better drain detection
    and permission analysis
    """
    
    def __init__(self):
        # Enhanced drain contract patterns
        self.drain_patterns = {
            'unlimited_approval': {
                'functions': ['approve', 'setApprovalForAll'],
                'risk_score': 0.9,
                'warning': 'Contract requests unlimited token approval'
            },
            'hidden_drain_functions': {
                'patterns': [r'emergencyWithdraw', r'rescueTokens', r'adminWithdraw'],
                'risk_score': 0.95,
                'warning': 'Contract has hidden withdrawal functions'
            },
            'owner_privileges': {
                'functions': ['transferOwnership', 'mint', 'burn', 'pause'],
                'risk_score': 0.8,
                'warning': 'Contract has dangerous owner privileges'
            },
            'proxy_upgrades': {
                'patterns': [r'upgradeTo', r'upgradeToAndCall'],
                'risk_score': 0.85,
                'warning': 'Upgradeable contract - code can change'
            }
        }
        
        # Known safe contract patterns
        self.safe_patterns = {
            'verified_dexes': [
                '0x7a250d5630b4cf539739df2c5dacb4c659f2488d',  # Uniswap V2
                '0xe592427a0aece92de3edee1f18e0157c05861564',  # Uniswap V3
            ],
            'verified_protocols': [
                '0xa0b86a33e6e89c4c2f89e2b6c2b5dbe8c3d0e1f2',  # Example verified
            ]
        }
    
    async def analyze_contract_for_drain_risk(self, contract_data: Dict) -> Dict:
        """Enhanced analysis specifically for drain contract detection"""
        contract_address = contract_data.get('address', '').lower()
        contract_code = contract_data.get('bytecode', '')
        function_signatures = contract_data.get('functions', [])
        
        analysis_result = {
            'is_drain_contract': False,
            'drain_risk_score': 0.0,
            'drain_warnings': [],
            'safe_contract': False,
            'permission_risks': [],
            'upgrade_risks': []
        }
        
        # Check if it's a known safe contract
        if contract_address in self.safe_patterns['verified_dexes'] or \
           contract_address in self.safe_patterns['verified_protocols']:
            analysis_result['safe_contract'] = True
            analysis_result['drain_risk_score'] = 0.0
            return analysis_result
        
        # Analyze for drain patterns
        for pattern_name, pattern_data in self.drain_patterns.items():
            risk = await self._check_drain_pattern(
                pattern_name, pattern_data, function_signatures, contract_code
            )
            
            if risk['detected']:
                analysis_result['drain_risk_score'] = max(
                    analysis_result['drain_risk_score'], 
                    risk['risk_score']
                )
                analysis_result['drain_warnings'].append(risk['warning'])
                
                if pattern_name in ['unlimited_approval', 'hidden_drain_functions']:
                    analysis_result['is_drain_contract'] = True
        
        # Analyze permission structure
        permission_analysis = await self._analyze_permissions(function_signatures)
        analysis_result['permission_risks'] = permission_analysis
        
        # Check for upgrade risks
        upgrade_analysis = await self._analyze_upgrade_risks(contract_code)
        analysis_result['upgrade_risks'] = upgrade_analysis
        
        return analysis_result
    
    async def _check_drain_pattern(self, pattern_name: str, pattern_data: Dict, 
                                 functions: List[str], bytecode: str) -> Dict:
        """Check for specific drain patterns"""
        if pattern_name == 'unlimited_approval':
            # Check for unlimited approval functions
            dangerous_functions = pattern_data['functions']
            found_functions = [f for f in functions if any(df in f for df in dangerous_functions)]
            
            if found_functions:
                return {
                    'detected': True,
                    'risk_score': pattern_data['risk_score'],
                    'warning': f"{pattern_data['warning']}: {', '.join(found_functions)}"
                }
        
        elif pattern_name == 'hidden_drain_functions':
            # Check bytecode for hidden withdrawal patterns
            patterns = pattern_data['patterns']
            for pattern in patterns:
                if re.search(pattern, bytecode, re.IGNORECASE):
                    return {
                        'detected': True,
                        'risk_score': pattern_data['risk_score'],
                        'warning': f"{pattern_data['warning']}: {pattern}"
                    }
        
        return {'detected': False, 'risk_score': 0.0, 'warning': ''}
    
    async def _analyze_permissions(self, functions: List[str]) -> List[Dict]:
        """Analyze contract permission structure"""
        permission_risks = []
        
        # Check for admin/owner functions
        admin_functions = [f for f in functions if any(
            admin_term in f.lower() 
            for admin_term in ['owner', 'admin', 'gov', 'emergency']
        )]
        
        if admin_functions:
            permission_risks.append({
                'type': 'admin_functions',
                'risk_score': 0.7,
                'details': f"Admin functions detected: {', '.join(admin_functions[:3])}"
            })
        
        # Check for pause/unpause functions
        pause_functions = [f for f in functions if any(
            pause_term in f.lower() 
            for pause_term in ['pause', 'stop', 'emergency']
        )]
        
        if pause_functions:
            permission_risks.append({
                'type': 'pause_controls',
                'risk_score': 0.6,
                'details': f"Pause controls detected: {', '.join(pause_functions)}"
            })
        
        return permission_risks
    
    async def _analyze_upgrade_risks(self, bytecode: str) -> List[Dict]:
        """Analyze contract upgrade risks"""
        upgrade_risks = []
        
        # Check for proxy patterns
        proxy_patterns = [
            'delegatecall',
            'upgradeTo',
            'implementation',
            'proxy'
        ]
        
        for pattern in proxy_patterns:
            if pattern.lower() in bytecode.lower():
                upgrade_risks.append({
                    'type': 'proxy_pattern',
                    'risk_score': 0.8,
                    'details': f"Proxy pattern detected: {pattern}"
                })
                break
        
        return upgrade_risks

# Integration with main threat analyzer
class EnhancedThreatAnalyzer:
    def __init__(self, config: Dict):
        self.config = config
        self.contract_analyzer = EnhancedContractAnalyzer()
        self.dust_detector = EnhancedDustDetector()
        self.mev_detector = EnhancedMEVDetector()
        self.nft_analyzer = EnhancedNFTAnalyzer()
    
    async def analyze_for_wallet_security(self, transaction_data: Dict) -> Dict:
        """
        Main analysis method optimized for wallet security features
        """
        analysis_results = {
            'should_quarantine': False,
            'confidence_score': 0.0,
            'threat_categories': [],
            'user_warnings': [],
            'technical_details': {}
        }
        
        # 1. Enhanced Smart Contract Analysis
        if transaction_data.get('to_address'):
            contract_analysis = await self.contract_analyzer.analyze_contract_for_drain_risk({
                'address': transaction_data['to_address'],
                'bytecode': transaction_data.get('contract_bytecode', ''),
                'functions': transaction_data.get('contract_functions', [])
            })
            
            analysis_results['technical_details']['contract_analysis'] = contract_analysis
            
            if contract_analysis['is_drain_contract']:
                analysis_results['should_quarantine'] = True
                analysis_results['confidence_score'] = max(analysis_results['confidence_score'], 0.95)
                analysis_results['threat_categories'].append('drain_contract')
                analysis_results['user_warnings'].append(
                    "🚨 Potential drain contract detected - could steal your tokens"
                )
        
        # 2. Enhanced Dust Detection
        dust_analysis = await self.dust_detector.analyze_dust_attack(transaction_data)
        analysis_results['technical_details']['dust_analysis'] = dust_analysis
        
        if dust_analysis['is_dust_attack']:
            analysis_results['should_quarantine'] = True
            analysis_results['confidence_score'] = max(analysis_results['confidence_score'], 0.85)
            analysis_results['threat_categories'].append('dust_attack')
            analysis_results['user_warnings'].append(
                "💨 Dust attack detected - scammer trying to track your wallet"
            )
        
        # 3. Enhanced MEV Detection
        mev_analysis = await self.mev_detector.analyze_mev_risk(transaction_data)
        analysis_results['technical_details']['mev_analysis'] = mev_analysis
        
        if mev_analysis['mev_risk'] > 0.7:
            analysis_results['user_warnings'].append(
                f"⚡ MEV Risk: {mev_analysis['warning']} - Consider increasing gas or waiting"
            )
        
        # 4. Enhanced NFT Analysis (for scam NFTs)
        if transaction_data.get('token_type') == 'NFT':
            nft_analysis = await self.nft_analyzer.analyze_scam_nft(transaction_data)
            analysis_results['technical_details']['nft_analysis'] = nft_analysis
            
            if nft_analysis['is_scam_nft']:
                analysis_results['should_quarantine'] = True
                analysis_results['confidence_score'] = max(analysis_results['confidence_score'], 0.9)
                analysis_results['threat_categories'].append('scam_nft')
                analysis_results['user_warnings'].append(
                    "🖼️ Scam NFT detected - designed to deceive users"
                )
        
        return analysis_results

class EnhancedDustDetector:
    """Enhanced dust attack detection"""
    
    def __init__(self):
        # Enhanced dust patterns for different networks
        self.dust_thresholds = {
            'ethereum': 0.001,  # ETH
            'solana': 0.001,    # SOL  
            'polygon': 0.01,    # MATIC
            'bsc': 0.001        # BNB
        }
        
        # Scammer dust patterns
        self.dust_patterns = {
            'tracking_dust': {
                'amounts': [0.000001, 0.00001, 0.0001],
                'purpose': 'wallet_tracking'
            },
            'fake_airdrop_dust': {
                'token_patterns': [r'airdrop', r'claim', r'reward'],
                'purpose': 'phishing_bait'
            }
        }
    
    async def analyze_dust_attack(self, transaction_data: Dict) -> Dict:
        """Enhanced dust attack analysis"""
        network = transaction_data.get('network', 'ethereum')
        value = float(transaction_data.get('value', 0))
        token_name = transaction_data.get('token_name', '').lower()
        from_address = transaction_data.get('from_address', '')
        
        dust_analysis = {
            'is_dust_attack': False,
            'dust_type': None,
            'risk_score': 0.0,
            'warning': '',
            'recommended_action': 'quarantine'
        }
        
        # Check if value is below dust threshold
        threshold = self.dust_thresholds.get(network, 0.001)
        
        if 0 < value < threshold:
            dust_analysis['is_dust_attack'] = True
            dust_analysis['risk_score'] = 0.8
            
            # Determine dust type
            if any(pattern in token_name for pattern in ['airdrop', 'claim', 'reward']):
                dust_analysis['dust_type'] = 'fake_airdrop_dust'
                dust_analysis['risk_score'] = 0.9
                dust_analysis['warning'] = 'Fake airdrop dust - likely phishing attempt'
            else:
                dust_analysis['dust_type'] = 'tracking_dust'
                dust_analysis['warning'] = 'Tracking dust - scammer registering your wallet'
            
            # Check sender patterns
            if await self._is_known_dust_sender(from_address):
                dust_analysis['risk_score'] = 0.95
                dust_analysis['warning'] += ' from known dust attacker'
        
        return dust_analysis
    
    async def _is_known_dust_sender(self, address: str) -> bool:
        """Check if sender is known for dust attacks"""
        # This would check against community blacklist
        known_dust_senders = [
            '0x000000000000000000000000000000000000dead',
            # Add more known dust attackers
        ]
        return address.lower() in known_dust_senders

class EnhancedMEVDetector:
    """Enhanced MEV detection and user warnings"""
    
    async def analyze_mev_risk(self, transaction_data: Dict) -> Dict:
        """Analyze MEV risk for user transactions"""
        gas_price = int(transaction_data.get('gas_price', 0))
        transaction_type = transaction_data.get('type', '')
        value = float(transaction_data.get('value', 0))
        
        mev_analysis = {
            'mev_risk': 0.0,
            'mev_type': None,
            'warning': '',
            'protection_suggestions': []
        }
        
        # Check for sandwich attack risk
        if transaction_type in ['swap', 'trade'] and value > 1000:  # Large trades
            mev_analysis['mev_risk'] = 0.8
            mev_analysis['mev_type'] = 'sandwich_attack_risk'
            mev_analysis['warning'] = 'Large trade susceptible to sandwich attacks'
            mev_analysis['protection_suggestions'] = [
                'Use private mempool',
                'Increase slippage tolerance',
                'Split into smaller trades'
            ]
        
        # Check for frontrunning risk
        if gas_price < 20000000000:  # Low gas price
            mev_analysis['mev_risk'] = max(mev_analysis['mev_risk'], 0.6)
            mev_analysis['warning'] = 'Low gas price - may be frontrun by MEV bots'
            mev_analysis['protection_suggestions'].append('Increase gas price')
        
        return mev_analysis

class EnhancedNFTAnalyzer:
    """Enhanced NFT scam detection"""
    
    def __init__(self):
        self.scam_nft_patterns = {
            'fake_collection': {
                'name_patterns': [r'bored.*ape', r'crypto.*punk', r'azuki'],
                'risk_score': 0.9
            },
            'phishing_nft': {
                'description_patterns': [r'claim.*reward', r'visit.*website', r'connect.*wallet'],
                'risk_score': 0.95
            },
            'malicious_metadata': {
                'url_patterns': [r'bit\.ly', r'tinyurl', r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'],
                'risk_score': 0.85
            }
        }
    
    async def analyze_scam_nft(self, transaction_data: Dict) -> Dict:
        """Analyze NFT for scam indicators"""
        nft_name = transaction_data.get('nft_name', '').lower()
        nft_description = transaction_data.get('nft_description', '').lower()
        nft_image_url = transaction_data.get('nft_image_url', '')
        
        nft_analysis = {
            'is_scam_nft': False,
            'scam_type': None,
            'risk_score': 0.0,
            'warning': ''
        }
        
        # Check for fake collection patterns
        for pattern in self.scam_nft_patterns['fake_collection']['name_patterns']:
            if re.search(pattern, nft_name):
                nft_analysis['is_scam_nft'] = True
                nft_analysis['scam_type'] = 'fake_collection'
                nft_analysis['risk_score'] = 0.9
                nft_analysis['warning'] = f'Fake NFT collection detected: {pattern}'
                break
        
        # Check for phishing descriptions
        for pattern in self.scam_nft_patterns['phishing_nft']['description_patterns']:
            if re.search(pattern, nft_description):
                nft_analysis['is_scam_nft'] = True
                nft_analysis['scam_type'] = 'phishing_nft'
                nft_analysis['risk_score'] = 0.95
                nft_analysis['warning'] = 'Phishing NFT - trying to trick users'
                break
        
        return nft_analysis