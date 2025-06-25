"""
Scammer Dust Detection for Solana
Detects small SOL amounts sent to register wallets in transaction history
"""

import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timedelta

class DustDetector:
    """
    Detect scammer dust attacks on Solana
    """
    
    def __init__(self):
        self.dust_patterns = {
            'solana_dust_thresholds': {
                'tiny_dust': 0.00001,      # 0.00001 SOL
                'small_dust': 0.0001,      # 0.0001 SOL  
                'medium_dust': 0.001,      # 0.001 SOL
                'tracking_threshold': 0.01  # Above this = not dust
            },
            'suspicious_patterns': {
                'mass_sender_threshold': 100,    # Sent to 100+ wallets
                'timing_window_hours': 24,       # Within 24 hours
                'identical_amounts': True,       # Same amount to multiple wallets
                'new_wallet_targeting': 0.8      # 80%+ new wallets
            },
            'known_dust_programs': [
                'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',  # Token Program
                '11111111111111111111111111111111',             # System Program
                'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'   # Associated Token Program
            ]
        }
    
    async def analyze_dust_attack(self, transaction_data: Dict) -> Dict:
        """
        Analyze transaction for dust attack patterns
        """
        dust_analysis = {
            'is_dust_attack': False,
            'dust_risk_score': 0.0,
            'dust_type': 'none',
            'dust_indicators': [],
            'sender_analysis': {},
            'recommended_action': 'none'
        }
        
        try:
            # 1. Check if this is a dust amount
            amount = float(transaction_data.get('value', 0))
            dust_classification = self._classify_dust_amount(amount)
            
            if dust_classification['is_dust']:
                dust_analysis['dust_type'] = dust_classification['dust_level']
                dust_analysis['dust_indicators'].append(f"dust_amount_{dust_classification['dust_level']}")
                
                # 2. Analyze sender behavior
                sender_analysis = await self._analyze_sender_behavior(transaction_data)
                dust_analysis['sender_analysis'] = sender_analysis
                
                # 3. Check for mass distribution patterns
                mass_distribution = await self._check_mass_distribution(transaction_data)
                if mass_distribution['is_mass_sender']:
                    dust_analysis['dust_indicators'].extend(mass_distribution['indicators'])
                
                # 4. Check for tracking patterns
                tracking_patterns = await self._detect_tracking_patterns(transaction_data)
                if tracking_patterns['is_tracking']:
                    dust_analysis['dust_indicators'].extend(tracking_patterns['indicators'])
                
                # 5. Calculate dust risk score
                dust_analysis['dust_risk_score'] = await self._calculate_dust_risk(
                    dust_classification, sender_analysis, mass_distribution, tracking_patterns
                )
                
                # 6. Determine if this is a dust attack
                dust_analysis['is_dust_attack'] = dust_analysis['dust_risk_score'] > 0.6
                
                # 7. Generate recommendation
                dust_analysis['recommended_action'] = await self._get_dust_recommendation(
                    dust_analysis['dust_risk_score'], dust_analysis['dust_indicators']
                )
        
        except Exception as e:
            dust_analysis['error'] = f"Dust analysis failed: {str(e)}"
        
        return dust_analysis
    
    def _classify_dust_amount(self, amount: float) -> Dict:
        """Classify transaction amount as dust"""
        thresholds = self.dust_patterns['solana_dust_thresholds']
        
        if amount <= thresholds['tiny_dust']:
            return {'is_dust': True, 'dust_level': 'tiny', 'severity': 0.9}
        elif amount <= thresholds['small_dust']:
            return {'is_dust': True, 'dust_level': 'small', 'severity': 0.7}
        elif amount <= thresholds['medium_dust']:
            return {'is_dust': True, 'dust_level': 'medium', 'severity': 0.5}
        elif amount <= thresholds['tracking_threshold']:
            return {'is_dust': True, 'dust_level': 'large_dust', 'severity': 0.3}
        else:
            return {'is_dust': False, 'dust_level': 'normal', 'severity': 0.0}
    
    async def _analyze_sender_behavior(self, transaction_data: Dict) -> Dict:
        """Analyze sender's historical behavior"""
        sender = transaction_data.get('from_address')
        
        # In production, this would query Solana RPC for sender's history
        sender_analysis = {
            'is_new_wallet': await self._is_new_wallet(sender),
            'transaction_count': await self._get_transaction_count(sender),
            'dust_sent_count': await self._count_dust_transactions(sender),
            'target_diversity': await self._analyze_target_diversity(sender),
            'creation_time': await self._get_wallet_creation_time(sender)
        }
        
        # Calculate sender suspicion score
        suspicion_factors = []
        
        if sender_analysis['dust_sent_count'] > 50:
            suspicion_factors.append(('high_dust_volume', 0.8))
        
        if sender_analysis['target_diversity'] > 0.9:
            suspicion_factors.append(('diverse_targets', 0.7))
        
        if sender_analysis['is_new_wallet'] and sender_analysis['dust_sent_count'] > 10:
            suspicion_factors.append(('new_wallet_mass_dust', 0.9))
        
        sender_analysis['suspicion_score'] = max([score for _, score in suspicion_factors], default=0.0)
        sender_analysis['suspicion_indicators'] = [indicator for indicator, _ in suspicion_factors]
        
        return sender_analysis
    
    async def _check_mass_distribution(self, transaction_data: Dict) -> Dict:
        """Check for mass distribution patterns"""
        sender = transaction_data.get('from_address')
        
        # In production, this would analyze recent transactions from sender
        mass_distribution = {
            'is_mass_sender': False,
            'recipients_count': await self._count_recent_recipients(sender),
            'identical_amounts': await self._check_identical_amounts(sender),
            'time_clustering': await self._analyze_time_clustering(sender),
            'indicators': []
        }
        
        patterns = self.dust_patterns['suspicious_patterns']
        
        if mass_distribution['recipients_count'] > patterns['mass_sender_threshold']:
            mass_distribution['is_mass_sender'] = True
            mass_distribution['indicators'].append('mass_distribution')
        
        if mass_distribution['identical_amounts']:
            mass_distribution['indicators'].append('identical_amounts')
        
        if mass_distribution['time_clustering']:
            mass_distribution['indicators'].append('time_clustering')
        
        return mass_distribution
    
    async def _detect_tracking_patterns(self, transaction_data: Dict) -> Dict:
        """Detect wallet tracking patterns"""
        tracking_patterns = {
            'is_tracking': False,
            'tracking_indicators': [],
            'privacy_risk': 0.0
        }
        
        # Check for common tracking patterns
        sender = transaction_data.get('from_address')
        recipient = transaction_data.get('to_address', '')
        
        # Pattern 1: Targeting fresh wallets
        if await self._targets_fresh_wallets(sender):
            tracking_patterns['tracking_indicators'].append('targets_fresh_wallets')
        
        # Pattern 2: Sequential targeting
        if await self._shows_sequential_targeting(sender):
            tracking_patterns['tracking_indicators'].append('sequential_targeting')
        
        # Pattern 3: Cross-exchange tracking
        if await self._shows_cross_exchange_tracking(sender, recipient):
            tracking_patterns['tracking_indicators'].append('cross_exchange_tracking')
        
        # Determine if this is tracking
        tracking_patterns['is_tracking'] = len(tracking_patterns['tracking_indicators']) >= 2
        tracking_patterns['privacy_risk'] = len(tracking_patterns['tracking_indicators']) * 0.3
        
        return tracking_patterns
    
    async def _calculate_dust_risk(self, dust_classification: Dict, sender_analysis: Dict, 
                                 mass_distribution: Dict, tracking_patterns: Dict) -> float:
        """Calculate overall dust attack risk score"""
        risk_factors = [
            dust_classification['severity'] * 0.3,
            sender_analysis['suspicion_score'] * 0.4,
            (1.0 if mass_distribution['is_mass_sender'] else 0.0) * 0.2,
            tracking_patterns['privacy_risk'] * 0.1
        ]
        
        return min(sum(risk_factors), 1.0)
    
    async def _get_dust_recommendation(self, risk_score: float, indicators: List[str]) -> str:
        """Get recommendation based on dust analysis"""
        if risk_score > 0.8:
            return 'quarantine_immediately'
        elif risk_score > 0.6:
            return 'quarantine_with_warning'
        elif risk_score > 0.3:
            return 'flag_and_monitor'
        else:
            return 'allow_but_track'
    
    # Placeholder methods for real blockchain data
    async def _is_new_wallet(self, address: str) -> bool:
        return False  # Would check wallet age
    
    async def _get_transaction_count(self, address: str) -> int:
        return 0  # Would get from RPC
    
    async def _count_dust_transactions(self, address: str) -> int:
        return 0  # Would analyze transaction history
    
    async def _analyze_target_diversity(self, address: str) -> float:
        return 0.0  # Would check recipient diversity
    
    async def _get_wallet_creation_time(self, address: str) -> Optional[datetime]:
        return None  # Would get from blockchain
    
    async def _count_recent_recipients(self, address: str) -> int:
        return 0  # Would count recent recipients
    
    async def _check_identical_amounts(self, address: str) -> bool:
        return False  # Would check for identical amounts
    
    async def _analyze_time_clustering(self, address: str) -> bool:
        return False  # Would analyze timing patterns
    
    async def _targets_fresh_wallets(self, address: str) -> bool:
        return False  # Would check if targets new wallets
    
    async def _shows_sequential_targeting(self, address: str) -> bool:
        return False  # Would check for sequential patterns
    
    async def _shows_cross_exchange_tracking(self, sender: str, recipient: str) -> bool:
        return False  # Would check exchange patterns