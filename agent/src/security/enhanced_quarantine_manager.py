"""
Enhanced Quarantine Manager with advanced confidence scoring
"""

from typing import Dict, List, Optional
from datetime import datetime, timedelta
from enum import Enum
import json

class EnhancedQuarantineManager:
    """Enhanced quarantine system with better confidence scoring and auto-burn logic"""
    
    def __init__(self, config: Dict):
        self.config = config
        
        # Enhanced confidence thresholds
        self.confidence_thresholds = {
            'auto_burn': 0.95,        # Extremely high confidence
            'quarantine': 0.7,        # Standard quarantine threshold
            'user_review': 0.5,       # Requires user review
            'warning_only': 0.3       # Just show warning
        }
        
        # Auto-burn settings with user permission
        self.auto_burn_settings = {
            'enabled': config.get('auto_burn_enabled', True),
            'require_user_permission': True,
            'high_confidence_delay_hours': 24,    # Wait 24h for super high confidence
            'medium_confidence_delay_hours': 168, # Wait 7 days for medium confidence
            'user_notification_hours': 2          # Notify user 2 hours before auto-burn
        }
    
    async def enhanced_quarantine_decision(self, analysis_result: Dict, 
                                         transaction_data: Dict) -> Dict:
        """Enhanced quarantine decision with multiple confidence levels"""
        
        # Calculate enhanced confidence score
        enhanced_confidence = await self._calculate_enhanced_confidence(
            analysis_result, transaction_data
        )
        
        # Determine action based on confidence
        action = await self._determine_action_by_confidence(enhanced_confidence)
        
        # Set auto-burn timer if applicable
        auto_burn_timer = await self._set_auto_burn_timer(
            enhanced_confidence, action
        )
        
        return {
            'action': action['type'],
            'confidence_score': enhanced_confidence['overall_confidence'],
            'confidence_breakdown': enhanced_confidence['breakdown'],
            'quarantine_category': action['category'],
            'auto_burn_timer': auto_burn_timer,
            'user_message': action['user_message'],
            'technical_reasoning': enhanced_confidence['reasoning']
        }
    
    async def _calculate_enhanced_confidence(self, analysis_result: Dict, 
                                           transaction_data: Dict) -> Dict:
        """Calculate enhanced confidence with multiple factors"""
        
        confidence_factors = {
            'ai_analysis': 0.0,
            'community_intelligence': 0.0,
            'historical_patterns': 0.0,
            'transaction_characteristics': 0.0,
            'cross_validation': 0.0
        }
        
        # AI Analysis Confidence
        ai_confidence = analysis_result.get('confidence_score', 0.0)
        threat_categories = analysis_result.get('threat_categories', [])
        
        if 'drain_contract' in threat_categories:
            confidence_factors['ai_analysis'] = min(ai_confidence + 0.2, 1.0)
        elif 'dust_attack' in threat_categories:
            confidence_factors['ai_analysis'] = min(ai_confidence + 0.1, 1.0)
        else:
            confidence_factors['ai_analysis'] = ai_confidence
        
        # Community Intelligence Confidence
        community_data = analysis_result.get('community_intelligence', {})
        if community_data.get('blacklisted'):
            confidence_factors['community_intelligence'] = community_data.get('confidence', 0.0)
        
        # Historical Pattern Confidence
        pattern_matches = analysis_result.get('pattern_matches', [])
        if pattern_matches:
            pattern_confidence = max([p.get('confidence', 0.0) for p in pattern_matches])
            confidence_factors['historical_patterns'] = pattern_confidence
        
        # Transaction Characteristics
        characteristics_score = await self._analyze_transaction_characteristics(transaction_data)
        confidence_factors['transaction_characteristics'] = characteristics_score
        
        # Cross-validation (multiple detection methods agreeing)
        detection_methods = sum([
            1 if confidence_factors['ai_analysis'] > 0.7 else 0,
            1 if confidence_factors['community_intelligence'] > 0.7 else 0,
            1 if confidence_factors['historical_patterns'] > 0.7 else 0
        ])
        
        if detection_methods >= 2:
            confidence_factors['cross_validation'] = 0.3  # Boost for multiple confirmations
        
        # Calculate weighted overall confidence
        weights = {
            'ai_analysis': 0.4,
            'community_intelligence': 0.3,
            'historical_patterns': 0.15,
            'transaction_characteristics': 0.1,
            'cross_validation': 0.05
        }
        
        overall_confidence = sum(
            confidence_factors[factor] * weights[factor]
            for factor in confidence_factors
        )
        
        return {
            'overall_confidence': overall_confidence,
            'breakdown': confidence_factors,
            'detection_methods_count': detection_methods,
            'reasoning': self._generate_confidence_reasoning(confidence_factors, detection_methods)
        }
    
    async def _determine_action_by_confidence(self, enhanced_confidence: Dict) -> Dict:
        """Determine action based on enhanced confidence score"""
        confidence = enhanced_confidence['overall_confidence']
        
        if confidence >= self.confidence_thresholds['auto_burn']:
            return {
                'type': 'quarantine_with_auto_burn',
                'category': 'high_confidence_threat',
                'user_message': '🚨 High-confidence threat detected - will auto-delete after review period'
            }
        
        elif confidence >= self.confidence_thresholds['quarantine']:
            return {
                'type': 'quarantine',
                'category': 'suspected_threat',
                'user_message': '⚠️ Suspicious item quarantined for your review'
            }
        
        elif confidence >= self.confidence_thresholds['user_review']:
            return {
                'type': 'quarantine_with_warning',
                'category': 'potential_threat',
                'user_message': '🔍 Potentially suspicious item - please review carefully'
            }
        
        elif confidence >= self.confidence_thresholds['warning_only']:
            return {
                'type': 'allow_with_warning',
                'category': 'low_risk',
                'user_message': '💡 Minor risk detected - proceed with caution'
            }
        
        else:
            return {
                'type': 'allow',
                'category': 'safe',
                'user_message': '✅ No significant threats detected'
            }
    
    async def _set_auto_burn_timer(self, enhanced_confidence: Dict, action: Dict) -> Optional[Dict]:
        """Set auto-burn timer based on confidence and user settings"""
        
        if not self.auto_burn_settings['enabled'] or action['type'] != 'quarantine_with_auto_burn':
            return None
        
        confidence = enhanced_confidence['overall_confidence']
        
        # Determine delay based on confidence
        if confidence >= 0.98:  # Extremely high confidence
            delay_hours = self.auto_burn_settings['high_confidence_delay_hours']
        else:
            delay_hours = self.auto_burn_settings['medium_confidence_delay_hours']
        
        auto_burn_time = datetime.now() + timedelta(hours=delay_hours)
        notification_time = auto_burn_time - timedelta(
            hours=self.auto_burn_settings['user_notification_hours']
        )
        
        return {
            'auto_burn_time': auto_burn_time.isoformat(),
            'notification_time': notification_time.isoformat(),
            'delay_hours': delay_hours,
            'requires_user_permission': self.auto_burn_settings['require_user_permission'],
            'cancellation_available': True
        }
    
    async def _analyze_transaction_characteristics(self, transaction_data: Dict) -> float:
        """Analyze transaction characteristics for confidence scoring"""
        characteristics_score = 0.0
        
        # Check transaction value
        value = float(transaction_data.get('value', 0))
        if 0 < value < 0.0001:  # Very small dust amount
            characteristics_score += 0.3
        
        # Check gas price patterns
        gas_price = int(transaction_data.get('gas_price', 0))
        if gas_price > 100000000000:  # Very high gas price
            characteristics_score += 0.2
        
        # Check sender patterns
        from_address = transaction_data.get('from_address', '')
        if len(set(from_address[2:])) < 8:  # Low entropy address
            characteristics_score += 0.4
        
        return min(characteristics_score, 1.0)
    
    def _generate_confidence_reasoning(self, confidence_factors: Dict, 
                                     detection_methods: int) -> str:
        """Generate human-readable reasoning for confidence score"""
        high_factors = [
            factor for factor, score in confidence_factors.items() 
            if score > 0.7
        ]
        
        if detection_methods >= 2:
            return f"High confidence: Multiple detection methods agree ({', '.join(high_factors)})"
        elif high_factors:
            return f"Moderate confidence: Strong signal from {', '.join(high_factors)}"
        else:
            return "Low confidence: Weak or conflicting signals"
    
    async def check_auto_burn_notifications(self) -> List[Dict]:
        """Check for items that need auto-burn notifications"""
        notifications = []
        current_time = datetime.now()
        
        # This would check all quarantined items with auto-burn timers
        # and return notifications for items approaching auto-burn
        
        return notifications
    
    async def process_auto_burn_with_permission(self, item_id: str, 
                                              user_permission: bool) -> Dict:
        """Process auto-burn with user permission"""
        if not user_permission:
            return {
                'success': False,
                'action': 'auto_burn_cancelled',
                'message': 'Auto-burn cancelled by user'
            }
        
        # Proceed with auto-burn
        return {
            'success': True,
            'action': 'auto_burned',
            'message': 'Item auto-burned with user permission'
        }