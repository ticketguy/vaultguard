"""
Adaptive Community Learning System
NO HARD-CODED PROJECTS - Everything learned from community
"""

from typing import Dict, List, Optional
from datetime import datetime, timedelta
import json


class AdaptiveCommunityLearning:
    """
    Learns what's legitimate vs malicious from community feedback
    NO hard-coded projects - everything is adaptive
    """
    
    def __init__(self, rag_client):
        self.rag_client = rag_client
        
        # Dynamic learning patterns (not hard-coded projects)
        self.learning_patterns = {
            'legitimacy_indicators': {
                # These get learned from community feedback
                'metadata_quality_patterns': [],
                'sender_behavior_patterns': [],
                'community_approved_addresses': set(),
                'positive_feedback_tokens': {},
            },
            'threat_indicators': {
                # These get learned from community reports
                'reported_addresses': {},
                'scam_patterns': [],
                'negative_feedback_tokens': {},
            }
        }
        
        # Learning weights based on community consensus
        self.consensus_weights = {
            'user_feedback_weight': 0.3,
            'community_reports_weight': 0.4,
            'behavioral_analysis_weight': 0.3,
            'minimum_consensus_threshold': 3  # Need 3+ reports for consensus
        }

    async def analyze_legitimacy_from_community(self, tx_data: Dict) -> Dict:
        """
        Determine legitimacy based ONLY on community intelligence
        No hard-coded projects at all
        """
        from_address = tx_data.get('from_address', '')
        token_symbol = tx_data.get('token_symbol', '')
        token_name = tx_data.get('token_name', '')
        
        legitimacy_analysis = {
            'legitimacy_score': 0.5,  # Start neutral
            'confidence': 0.0,
            'evidence': [],
            'community_sentiment': 'unknown',
            'learning_source': []
        }
        
        # 1. Query RAG for community intelligence
        community_intel = await self._query_community_intelligence(from_address, token_symbol, token_name)
        
        # 2. Check learned patterns from user feedback
        feedback_score = await self._analyze_user_feedback_patterns(tx_data)
        
        # 3. Check community consensus
        consensus_score = await self._check_community_consensus(from_address, token_symbol)
        
        # 4. Combine all community sources
        legitimacy_analysis['legitimacy_score'] = self._calculate_adaptive_legitimacy(
            community_intel, feedback_score, consensus_score
        )
        
        legitimacy_analysis['evidence'] = [
            f"community_intel_{community_intel['sentiment']}",
            f"user_feedback_{feedback_score['sentiment']}",
            f"consensus_{consensus_score['level']}"
        ]
        
        legitimacy_analysis['learning_source'] = [
            'community_rag_intelligence',
            'user_feedback_patterns', 
            'community_consensus_data'
        ]
        
        return legitimacy_analysis

    async def _query_community_intelligence(self, address: str, symbol: str, name: str) -> Dict:
        """
        Query RAG system for what community says about this token/address
        """
        # Query RAG with natural language about legitimacy
        query = f"Is {symbol} {name} from address {address} legitimate verified project or scam threat"
        
        try:
            rag_response = await self.rag_client.query(query)
            response_text = str(rag_response).lower()
            
            # Analyze community sentiment from RAG
            sentiment_analysis = {
                'sentiment': 'unknown',
                'confidence': 0.0,
                'mentions': 0
            }
            
            # Check for positive community indicators
            positive_keywords = ['legitimate', 'verified', 'trusted', 'good', 'real', 'official']
            positive_count = sum(1 for word in positive_keywords if word in response_text)
            
            # Check for negative community indicators  
            negative_keywords = ['scam', 'fake', 'malicious', 'avoid', 'dangerous', 'reported']
            negative_count = sum(1 for word in negative_keywords if word in response_text)
            
            if positive_count > negative_count and positive_count > 0:
                sentiment_analysis['sentiment'] = 'positive'
                sentiment_analysis['confidence'] = min(positive_count * 0.2, 1.0)
            elif negative_count > positive_count and negative_count > 0:
                sentiment_analysis['sentiment'] = 'negative'  
                sentiment_analysis['confidence'] = min(negative_count * 0.2, 1.0)
            
            return sentiment_analysis
            
        except Exception as e:
            return {'sentiment': 'unknown', 'confidence': 0.0, 'error': str(e)}

    async def _analyze_user_feedback_patterns(self, tx_data: Dict) -> Dict:
        """
        Analyze patterns from previous user feedback (approve/quarantine decisions)
        """
        token_symbol = tx_data.get('token_symbol', '')
        from_address = tx_data.get('from_address', '')
        
        feedback_analysis = {
            'sentiment': 'unknown',
            'confidence': 0.0,
            'feedback_count': 0
        }
        
        # Check if users have given feedback on similar tokens/addresses
        similar_feedback = await self._get_similar_user_feedback(from_address, token_symbol)
        
        if similar_feedback['total_feedback'] > 0:
            approval_rate = similar_feedback['approvals'] / similar_feedback['total_feedback']
            
            feedback_analysis['feedback_count'] = similar_feedback['total_feedback']
            
            if approval_rate > 0.7:
                feedback_analysis['sentiment'] = 'positive'
                feedback_analysis['confidence'] = min(approval_rate, 1.0)
            elif approval_rate < 0.3:
                feedback_analysis['sentiment'] = 'negative'
                feedback_analysis['confidence'] = min(1.0 - approval_rate, 1.0)
        
        return feedback_analysis

    async def _check_community_consensus(self, address: str, symbol: str) -> Dict:
        """
        Check if there's community consensus about this address/token
        """
        consensus_analysis = {
            'level': 'none',
            'consensus_score': 0.0,
            'report_count': 0
        }
        
        # Check community reports from your database
        reports = await self._get_community_reports(address, symbol)
        
        if reports['total_reports'] >= self.consensus_weights['minimum_consensus_threshold']:
            consensus_ratio = reports['positive_reports'] / reports['total_reports']
            
            consensus_analysis['report_count'] = reports['total_reports']
            
            if consensus_ratio > 0.8:
                consensus_analysis['level'] = 'positive_consensus'
                consensus_analysis['consensus_score'] = consensus_ratio
            elif consensus_ratio < 0.2:
                consensus_analysis['level'] = 'negative_consensus'
                consensus_analysis['consensus_score'] = 1.0 - consensus_ratio
            else:
                consensus_analysis['level'] = 'mixed'
                consensus_analysis['consensus_score'] = 0.5
        
        return consensus_analysis

    def _calculate_adaptive_legitimacy(self, community_intel: Dict, feedback_score: Dict, consensus_score: Dict) -> float:
        """
        Calculate legitimacy score from community sources (no hard-coding)
        """
        score = 0.5  # Start neutral
        
        # Community intelligence from RAG
        if community_intel['sentiment'] == 'positive':
            score += community_intel['confidence'] * self.consensus_weights['community_reports_weight']
        elif community_intel['sentiment'] == 'negative':
            score -= community_intel['confidence'] * self.consensus_weights['community_reports_weight']
        
        # User feedback patterns
        if feedback_score['sentiment'] == 'positive':
            score += feedback_score['confidence'] * self.consensus_weights['user_feedback_weight']
        elif feedback_score['sentiment'] == 'negative':
            score -= feedback_score['confidence'] * self.consensus_weights['user_feedback_weight']
        
        # Community consensus
        if consensus_score['level'] == 'positive_consensus':
            score += consensus_score['consensus_score'] * self.consensus_weights['behavioral_analysis_weight']
        elif consensus_score['level'] == 'negative_consensus':
            score -= consensus_score['consensus_score'] * self.consensus_weights['behavioral_analysis_weight']
        
        return max(0.0, min(1.0, score))

    async def learn_from_user_feedback(self, feedback_data: Dict):
        """
        Learn from user decisions to improve future classifications
        """
        user_decision = feedback_data['decision']  # 'approved' or 'quarantined'
        tx_data = feedback_data['transaction_data']
        reasoning = feedback_data.get('user_reasoning', '')
        
        # Extract learning signals
        learning_signals = {
            'address': tx_data.get('from_address'),
            'token_symbol': tx_data.get('token_symbol'),
            'token_name': tx_data.get('token_name'),
            'user_decision': user_decision,
            'timestamp': datetime.now().isoformat(),
            'user_reasoning': reasoning
        }
        
        # Update learned patterns
        if user_decision == 'approved':
            await self._reinforce_positive_patterns(learning_signals)
        else:
            await self._reinforce_negative_patterns(learning_signals)
        
        # Save to RAG for future reference
        await self._save_learning_to_rag(learning_signals)
        
        print(f"📚 Learned from user feedback: {user_decision} for {tx_data.get('token_symbol')}")

    async def _reinforce_positive_patterns(self, signals: Dict):
        """
        Reinforce patterns that lead to legitimate classifications
        """
        address = signals['address']
        symbol = signals['token_symbol']
        
        # Track positive feedback
        if symbol not in self.learning_patterns['legitimacy_indicators']['positive_feedback_tokens']:
            self.learning_patterns['legitimacy_indicators']['positive_feedback_tokens'][symbol] = 0
        
        self.learning_patterns['legitimacy_indicators']['positive_feedback_tokens'][symbol] += 1
        self.learning_patterns['legitimacy_indicators']['community_approved_addresses'].add(address)

    async def _reinforce_negative_patterns(self, signals: Dict):
        """
        Reinforce patterns that lead to threat classifications
        """
        address = signals['address']
        symbol = signals['token_symbol']
        
        # Track negative feedback
        if address not in self.learning_patterns['threat_indicators']['reported_addresses']:
            self.learning_patterns['threat_indicators']['reported_addresses'][address] = 0
        
        self.learning_patterns['threat_indicators']['reported_addresses'][address] += 1

    async def _save_learning_to_rag(self, learning_signals: Dict):
        """
        Save learning signals to RAG system for future intelligence
        """
        # Create natural language context for RAG
        decision = learning_signals['user_decision']
        symbol = learning_signals['token_symbol']
        address = learning_signals['address']
        
        if decision == 'approved':
            context = f"Token {symbol} from address {address} was approved by user as legitimate. User found it to be a real airdrop or valid transaction."
        else:
            context = f"Token {symbol} from address {address} was quarantined by user as suspicious. User identified it as potential scam or unwanted spam."
        
        # Add user reasoning if provided
        if learning_signals['user_reasoning']:
            context += f" User reasoning: {learning_signals['user_reasoning']}"
        
        # Save to RAG
        await self.rag_client.save_context("user_feedback", context)

    async def get_adaptive_insights(self) -> Dict:
        """
        Get insights about what the system has learned from community
        """
        return {
            'learned_patterns': {
                'approved_tokens': len(self.learning_patterns['legitimacy_indicators']['positive_feedback_tokens']),
                'approved_addresses': len(self.learning_patterns['legitimacy_indicators']['community_approved_addresses']),
                'reported_addresses': len(self.learning_patterns['threat_indicators']['reported_addresses']),
            },
            'community_consensus': {
                'minimum_reports_required': self.consensus_weights['minimum_consensus_threshold'],
                'learning_sources': ['user_feedback', 'community_reports', 'rag_intelligence']
            },
            'adaptive_weights': self.consensus_weights
        }

    # Placeholder methods for database integration
    async def _get_similar_user_feedback(self, address: str, symbol: str) -> Dict:
        """Get similar user feedback from database"""
        # TODO: Query your database for user feedback on similar tokens/addresses
        return {'total_feedback': 0, 'approvals': 0, 'quarantines': 0}
    
    async def _get_community_reports(self, address: str, symbol: str) -> Dict:
        """Get community reports from database"""
        # TODO: Query your database for community reports
        return {'total_reports': 0, 'positive_reports': 0, 'negative_reports': 0}


class AdaptiveDustDetector:
    """
    Adaptive dust detector that learns from community - NO HARD-CODING
    """
    
    def __init__(self, rag_client):
        self.community_learning = AdaptiveCommunityLearning(rag_client)
        
        # Only basic thresholds - everything else learned from community
        self.basic_thresholds = {
            'tiny_dust': 0.00001,
            'small_dust': 0.0001,
            'medium_dust': 0.001,
            'tracking_threshold': 0.01
        }

    async def analyze_transaction(self, transaction_data: Dict) -> Dict:
        """
        Analyze transaction using ONLY community intelligence - no hard-coded projects
        """
        analysis_result = {
            'is_dust_attack': False,
            'is_legitimate_airdrop': False,
            'dust_risk_score': 0.0,
            'legitimacy_score': 0.0,
            'community_sentiment': 'unknown',
            'learning_confidence': 0.0,
            'analysis_source': 'adaptive_community_learning'
        }
        
        # 1. Basic amount classification (only objective measure)
        amount = float(transaction_data.get('value', 0))
        is_dust_amount = self._classify_dust_amount(amount)
        
        # 2. Get community intelligence (the real decision maker)
        community_analysis = await self.community_learning.analyze_legitimacy_from_community(transaction_data)
        
        analysis_result.update({
            'legitimacy_score': community_analysis['legitimacy_score'],
            'community_sentiment': community_analysis['community_sentiment'],
            'learning_confidence': community_analysis['confidence'],
            'community_evidence': community_analysis['evidence']
        })
        
        # 3. Make decision based on community intelligence + basic amount check
        if is_dust_amount and community_analysis['legitimacy_score'] < 0.3:
            analysis_result['is_dust_attack'] = True
            analysis_result['dust_risk_score'] = 0.8
        elif community_analysis['legitimacy_score'] > 0.7:
            analysis_result['is_legitimate_airdrop'] = True
            analysis_result['dust_risk_score'] = 0.1
        elif is_dust_amount:
            analysis_result['dust_risk_score'] = 0.5  # Unclear - needs more community data
        
        return analysis_result

    def _classify_dust_amount(self, amount: float) -> bool:
        """Only classify amount size - no project-specific logic"""
        return 0 < amount <= self.basic_thresholds['tracking_threshold']

    async def learn_from_feedback(self, feedback_data: Dict):
        """Pass feedback to community learning system"""
        await self.community_learning.learn_from_user_feedback(feedback_data)