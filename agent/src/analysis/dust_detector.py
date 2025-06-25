"""
Dust Attack Detection for Solana
Detects small-value transactions used for wallet tracking and phishing
Adapted to work with SecuritySensor framework
"""

import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timedelta


class DustDetector:
    """
    Detect dust attacks on Solana blockchain.
    Dust attacks use tiny token amounts to track wallets and setup phishing campaigns.
    """
    
    def __init__(self):
        # Solana-specific dust attack patterns and thresholds
        self.dust_patterns = {
            'solana_dust_thresholds': {
                'tiny_dust': 0.00001,         # Extremely small amounts for tracking
                'small_dust': 0.0001,         # Small dust amounts
                'medium_dust': 0.001,         # Medium dust amounts
                'tracking_threshold': 0.01    # Above this not considered dust
            },
            'suspicious_patterns': {
                'mass_sender_threshold': 100,     # Sent to 100+ different wallets
                'timing_window_hours': 24,        # Time window for mass sending
                'identical_amounts': True,        # Same amount to multiple recipients
                'new_wallet_targeting': 0.8       # Targeting 80%+ new wallets
            },
            'known_dust_programs': [
                'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',  # SPL Token Program
                '11111111111111111111111111111111',             # System Program
                'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'   # Associated Token Program
            ],
            'phishing_keywords': [
                'airdrop', 'claim', 'reward', 'free', 'bonus', 
                'gift', 'winner', 'prize', 'lucky', 'congratulations'
            ]
        }
    
    async def analyze_dust_attack(self, transaction_data: Dict) -> Dict:
        """
        Analyze transaction for dust attack patterns and tracking attempts.
        Returns comprehensive analysis compatible with SecuritySensor framework.
        """
        # Initialize analysis result structure for framework compatibility
        dust_analysis = {
            'is_dust_attack': False,           # Framework expects this field
            'dust_risk_score': 0.0,
            'dust_type': 'none',
            'dust_indicators': [],
            'sender_analysis': {},
            'recommended_action': 'none',
            'threats_found': 0,                # SecuritySensor expects this field
            'analysis': "",                    # SecuritySensor expects analysis description
            'user_warnings': [],               # User-friendly warnings
            'technical_details': {}            # Detailed technical analysis
        }
        
        try:
            # Extract transaction details for analysis
            amount = float(transaction_data.get('value', 0))
            from_address = transaction_data.get('from_address', '')
            to_address = transaction_data.get('to_address', '')
            token_name = transaction_data.get('token_name', '').lower()
            
            # 1. Classify dust amount level
            dust_classification = self._classify_dust_amount(amount)
            dust_analysis['technical_details']['dust_classification'] = dust_classification
            
            if dust_classification['is_dust']:
                dust_analysis['dust_type'] = dust_classification['dust_level']
                dust_analysis['dust_indicators'].append(f"dust_amount_{dust_classification['dust_level']}")
                
                # 2. Analyze sender behavior patterns
                sender_analysis = await self._analyze_sender_behavior(transaction_data)
                dust_analysis['sender_analysis'] = sender_analysis
                dust_analysis['technical_details']['sender_analysis'] = sender_analysis
                
                # 3. Check for mass distribution patterns
                mass_distribution = await self._check_mass_distribution(transaction_data)
                dust_analysis['technical_details']['mass_distribution'] = mass_distribution
                if mass_distribution['is_mass_sender']:
                    dust_analysis['dust_indicators'].extend(mass_distribution['indicators'])
                
                # 4. Check for tracking and phishing patterns
                tracking_patterns = await self._detect_tracking_patterns(transaction_data)
                dust_analysis['technical_details']['tracking_patterns'] = tracking_patterns
                if tracking_patterns['is_tracking']:
                    dust_analysis['dust_indicators'].extend(tracking_patterns['indicators'])
                
                # 5. Check for phishing token patterns
                phishing_analysis = await self._analyze_phishing_patterns(transaction_data)
                dust_analysis['technical_details']['phishing_analysis'] = phishing_analysis
                if phishing_analysis['is_phishing_attempt']:
                    dust_analysis['dust_indicators'].extend(phishing_analysis['indicators'])
                
                # 6. Calculate overall dust risk score
                dust_analysis['dust_risk_score'] = await self._calculate_dust_risk(
                    dust_classification, sender_analysis, mass_distribution, 
                    tracking_patterns, phishing_analysis
                )
                
                # 7. Determine if this constitutes a dust attack
                dust_analysis['is_dust_attack'] = dust_analysis['dust_risk_score'] > 0.6
                
                # 8. Count threats found for SecuritySensor
                if dust_analysis['is_dust_attack']:
                    dust_analysis['threats_found'] = 1
                
                # 9. Generate user warnings and recommendations
                dust_analysis['user_warnings'] = await self._generate_dust_warnings(
                    dust_analysis['dust_risk_score'], dust_analysis['dust_indicators']
                )
                
                dust_analysis['recommended_action'] = await self._get_dust_recommendation(
                    dust_analysis['dust_risk_score'], dust_analysis['dust_indicators']
                )
            
            # 10. Create analysis summary
            dust_analysis['analysis'] = self._create_analysis_summary(dust_analysis)
        
        except Exception as e:
            # Handle analysis errors gracefully
            dust_analysis['error'] = f"Dust analysis failed: {str(e)}"
            dust_analysis['analysis'] = "Dust analysis encountered an error"
            dust_analysis['threats_found'] = 0
        
        return dust_analysis
    
    def _classify_dust_amount(self, amount: float) -> Dict:
        """Classify transaction amount as different levels of dust"""
        thresholds = self.dust_patterns['solana_dust_thresholds']
        
        if amount <= thresholds['tiny_dust']:
            return {
                'is_dust': True, 
                'dust_level': 'tiny', 
                'severity': 0.9,
                'description': 'Extremely small amount typical of tracking dust'
            }
        elif amount <= thresholds['small_dust']:
            return {
                'is_dust': True, 
                'dust_level': 'small', 
                'severity': 0.7,
                'description': 'Small amount possibly used for wallet enumeration'
            }
        elif amount <= thresholds['medium_dust']:
            return {
                'is_dust': True, 
                'dust_level': 'medium', 
                'severity': 0.5,
                'description': 'Medium dust amount potentially suspicious'
            }
        elif amount <= thresholds['tracking_threshold']:
            return {
                'is_dust': True, 
                'dust_level': 'large_dust', 
                'severity': 0.3,
                'description': 'Large dust amount, may be legitimate'
            }
        else:
            return {
                'is_dust': False, 
                'dust_level': 'normal', 
                'severity': 0.0,
                'description': 'Normal transaction amount'
            }
    
    async def _analyze_sender_behavior(self, transaction_data: Dict) -> Dict:
        """Analyze sender's historical behavior for dust attack indicators"""
        sender = transaction_data.get('from_address', '')
        
        # Gather sender behavior metrics
        sender_analysis = {
            'is_new_wallet': await self._is_new_wallet(sender),
            'transaction_count': await self._get_transaction_count(sender),
            'dust_sent_count': await self._count_dust_transactions(sender),
            'target_diversity': await self._analyze_target_diversity(sender),
            'creation_time': await self._get_wallet_creation_time(sender),
            'suspicious_indicators': []
        }
        
        # Calculate sender suspicion score based on behavior
        suspicion_score = 0.0
        
        # New wallets sending dust are highly suspicious
        if sender_analysis['is_new_wallet'] and sender_analysis['dust_sent_count'] > 0:
            suspicion_score += 0.6
            sender_analysis['suspicious_indicators'].append('new_wallet_sending_dust')
        
        # High volume of dust transactions
        if sender_analysis['dust_sent_count'] > 10:
            suspicion_score += 0.4
            sender_analysis['suspicious_indicators'].append('high_dust_volume')
        
        # High target diversity (sending to many different wallets)
        if sender_analysis['target_diversity'] > 0.8:
            suspicion_score += 0.5
            sender_analysis['suspicious_indicators'].append('high_target_diversity')
        
        # Low total transaction count but high dust count ratio
        if (sender_analysis['transaction_count'] > 0 and 
            sender_analysis['dust_sent_count'] / sender_analysis['transaction_count'] > 0.7):
            suspicion_score += 0.3
            sender_analysis['suspicious_indicators'].append('high_dust_ratio')
        
        sender_analysis['suspicion_score'] = min(suspicion_score, 1.0)
        sender_analysis['is_suspicious'] = suspicion_score > 0.5
        
        return sender_analysis
    
    async def _check_mass_distribution(self, transaction_data: Dict) -> Dict:
        """Check for mass distribution patterns typical of dust attacks"""
        sender = transaction_data.get('from_address', '')
        amount = float(transaction_data.get('value', 0))
        
        mass_distribution = {
            'is_mass_sender': False,
            'recipients_count': await self._count_recent_recipients(sender),
            'identical_amounts': await self._check_identical_amounts(sender),
            'time_clustering': await self._analyze_time_clustering(sender),
            'indicators': []
        }
        
        # Check for mass sending behavior
        if mass_distribution['recipients_count'] > self.dust_patterns['suspicious_patterns']['mass_sender_threshold']:
            mass_distribution['is_mass_sender'] = True
            mass_distribution['indicators'].append('mass_sender')
        
        # Check for identical amounts (scammer signature)
        if mass_distribution['identical_amounts']:
            mass_distribution['indicators'].append('identical_amounts')
        
        # Check for time clustering (automated behavior)
        if mass_distribution['time_clustering']:
            mass_distribution['indicators'].append('time_clustering')
        
        return mass_distribution
    
    async def _detect_tracking_patterns(self, transaction_data: Dict) -> Dict:
        """Detect patterns indicating wallet tracking attempts"""
        sender = transaction_data.get('from_address', '')
        recipient = transaction_data.get('to_address', '')
        
        tracking_patterns = {
            'is_tracking': False,
            'targets_fresh_wallets': await self._targets_fresh_wallets(sender),
            'sequential_targeting': await self._shows_sequential_targeting(sender),
            'cross_exchange_tracking': await self._shows_cross_exchange_tracking(sender, recipient),
            'indicators': []
        }
        
        # Check if sender targets newly created wallets
        if tracking_patterns['targets_fresh_wallets']:
            tracking_patterns['is_tracking'] = True
            tracking_patterns['indicators'].append('targets_fresh_wallets')
        
        # Check for sequential targeting patterns
        if tracking_patterns['sequential_targeting']:
            tracking_patterns['is_tracking'] = True
            tracking_patterns['indicators'].append('sequential_targeting')
        
        # Check for cross-exchange tracking
        if tracking_patterns['cross_exchange_tracking']:
            tracking_patterns['is_tracking'] = True
            tracking_patterns['indicators'].append('cross_exchange_tracking')
        
        return tracking_patterns
    
    async def _analyze_phishing_patterns(self, transaction_data: Dict) -> Dict:
        """Analyze transaction for phishing-related patterns"""
        token_name = transaction_data.get('token_name', '').lower()
        token_symbol = transaction_data.get('token_symbol', '').lower()
        from_address = transaction_data.get('from_address', '').lower()
        
        phishing_analysis = {
            'is_phishing_attempt': False,
            'phishing_indicators': [],
            'token_analysis': {},
            'address_analysis': {}
        }
        
        # Check token name for phishing keywords
        phishing_keywords_found = [
            keyword for keyword in self.dust_patterns['phishing_keywords'] 
            if keyword in token_name or keyword in token_symbol
        ]
        
        if phishing_keywords_found:
            phishing_analysis['is_phishing_attempt'] = True
            phishing_analysis['phishing_indicators'].append('phishing_token_name')
            phishing_analysis['token_analysis']['phishing_keywords'] = phishing_keywords_found
        
        # Check for suspicious address patterns
        suspicious_address_patterns = ['dead', '0000000', '1111111']
        address_flags = [pattern for pattern in suspicious_address_patterns if pattern in from_address]
        
        if address_flags:
            phishing_analysis['is_phishing_attempt'] = True
            phishing_analysis['phishing_indicators'].append('suspicious_sender_address')
            phishing_analysis['address_analysis']['suspicious_patterns'] = address_flags
        
        # Check for fake token names mimicking popular tokens
        popular_tokens = ['usdc', 'usdt', 'sol', 'btc', 'eth']
        for popular in popular_tokens:
            if popular in token_name and token_name != popular:
                phishing_analysis['is_phishing_attempt'] = True
                phishing_analysis['phishing_indicators'].append('token_name_mimicry')
                phishing_analysis['token_analysis']['mimicked_token'] = popular
                break
        
        return phishing_analysis
    
    async def _calculate_dust_risk(self, dust_classification: Dict, sender_analysis: Dict,
                                 mass_distribution: Dict, tracking_patterns: Dict,
                                 phishing_analysis: Dict) -> float:
        """Calculate overall dust attack risk score from all analysis components"""
        risk_score = 0.0
        
        # Base risk from dust amount classification
        risk_score += dust_classification['severity'] * 0.3
        
        # Risk from sender behavior
        if sender_analysis.get('is_suspicious', False):
            risk_score += sender_analysis.get('suspicion_score', 0) * 0.3
        
        # Risk from mass distribution patterns
        if mass_distribution.get('is_mass_sender', False):
            risk_score += 0.3
        
        # Risk from tracking patterns
        if tracking_patterns.get('is_tracking', False):
            risk_score += 0.25
        
        # Risk from phishing indicators
        if phishing_analysis.get('is_phishing_attempt', False):
            risk_score += 0.35
        
        return min(risk_score, 1.0)
    
    async def _generate_dust_warnings(self, risk_score: float, indicators: List[str]) -> List[str]:
        """Generate user-friendly warnings about dust attack risks"""
        warnings = []
        
        if risk_score > 0.8:
            warnings.append("🚨 High-confidence dust attack detected - avoid interacting with this transaction")
        elif risk_score > 0.6:
            warnings.append("⚠️ Suspicious dust transaction - likely tracking attempt")
        elif risk_score > 0.4:
            warnings.append("💡 Potential dust attack - monitor for follow-up phishing attempts")
        
        # Specific warnings based on indicators
        if 'phishing_token_name' in indicators:
            warnings.append("🎣 Phishing token detected - contains suspicious keywords")
        
        if 'mass_sender' in indicators:
            warnings.append("📡 Mass distribution detected - sender targeting many wallets")
        
        if 'targets_fresh_wallets' in indicators:
            warnings.append("🎯 Wallet targeting detected - scammer focusing on new wallets")
        
        return warnings
    
    async def _get_dust_recommendation(self, risk_score: float, indicators: List[str]) -> str:
        """Get security recommendation based on dust analysis results"""
        if risk_score > 0.8:
            return 'quarantine_immediately'
        elif risk_score > 0.6:
            return 'quarantine_with_warning'
        elif risk_score > 0.3:
            return 'flag_and_monitor'
        else:
            return 'allow_but_track'
    
    def _create_analysis_summary(self, dust_analysis: Dict) -> str:
        """Create human-readable analysis summary"""
        if dust_analysis['is_dust_attack']:
            return f"Dust attack detected with {dust_analysis['dust_risk_score']:.1%} confidence. Found {len(dust_analysis['dust_indicators'])} suspicious indicators."
        elif dust_analysis['dust_type'] != 'none':
            return f"Dust transaction detected ({dust_analysis['dust_type']} level) but appears benign."
        else:
            return "Normal transaction - no dust attack indicators found."
    
    # Placeholder methods for blockchain data integration
    # Replace these with real Solana RPC calls via meta-swap-api
    
    async def _is_new_wallet(self, address: str) -> bool:
        """Check if wallet was recently created (indicates potential scammer wallet)"""
        # TODO: Integrate with Solana RPC to check wallet creation time
        return False
    
    async def _get_transaction_count(self, address: str) -> int:
        """Get total transaction count for address"""
        # TODO: Integrate with Solana RPC to get transaction history
        return 0
    
    async def _count_dust_transactions(self, address: str) -> int:
        """Count how many dust transactions this address has sent"""
        # TODO: Analyze transaction history for dust patterns
        return 0
    
    async def _analyze_target_diversity(self, address: str) -> float:
        """Analyze diversity of recipients (high diversity = suspicious)"""
        # TODO: Calculate recipient diversity from transaction history
        return 0.0
    
    async def _get_wallet_creation_time(self, address: str) -> Optional[datetime]:
        """Get wallet creation timestamp"""
        # TODO: Get wallet creation time from blockchain
        return None
    
    async def _count_recent_recipients(self, address: str) -> int:
        """Count unique recipients in recent time window"""
        # TODO: Count unique recipients in last 24 hours
        return 0
    
    async def _check_identical_amounts(self, address: str) -> bool:
        """Check if sender uses identical amounts (scammer pattern)"""
        # TODO: Analyze transaction amounts for identical patterns
        return False
    
    async def _analyze_time_clustering(self, address: str) -> bool:
        """Check for time clustering indicating automated behavior"""
        # TODO: Analyze transaction timing patterns
        return False
    
    async def _targets_fresh_wallets(self, address: str) -> bool:
        """Check if sender targets newly created wallets"""
        # TODO: Analyze recipient wallet ages
        return False
    
    async def _shows_sequential_targeting(self, address: str) -> bool:
        """Check for sequential targeting patterns"""
        # TODO: Analyze sequential patterns in targeting
        return False
    
    async def _shows_cross_exchange_tracking(self, sender: str, recipient: str) -> bool:
        """Check for cross-exchange tracking patterns"""
        # TODO: Analyze cross-exchange tracking behavior
        return False