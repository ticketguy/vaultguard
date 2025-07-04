
import aiohttp
import json
import re
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AdaptiveCommunityDatabase")

class AdaptiveCommunityDatabase:
    """
    Adaptive community database that learns from:
    1. User feedback (approve/quarantine decisions)
    2. Community reports
    3. RAG system intelligence
    NO HARD-CODED PROJECTS
    """
    
    def __init__(self, rag_client=None):
        self.rag_client = rag_client
        
        self.learned_data = {
            'legitimate_projects': {},
            'threat_addresses': {},
            'community_consensus': {},
            'user_feedback_patterns': {},
            'spam_patterns': {},
            'name_patterns': {},
            'sender_patterns': {},
        }
        
        self.learning_config = {
            'minimum_consensus': 3,
            'consensus_threshold': 0.7,
            'user_weight': 0.4,
            'community_weight': 0.6,
            'rag_confidence_threshold': 0.5,
        }
        
        self.threat_patterns = {
            'suspicious_keywords': [
                'winner', 'congratulations', 'urgent', 'limited',
                'exclusive', 'free', 'bonus', 'claim now', 'fake'
            ],
            'suspicious_address_patterns': [
                'dead', '1111', '0000', 'beef', 'fade', 'cafe'
            ]
        }

    async def check_legitimacy(self, address: str, token_symbol: str, token_name: str) -> Dict:
        """
        Check legitimacy using ONLY learned community intelligence
        """
        legitimacy_result = {
            'is_legitimate': False,
            'legitimacy_score': 0.5,
            'confidence': 0.0,
            'evidence': [],
            'learning_source': []
        }
        
        learned_legitimacy = await self._check_learned_legitimacy(address, token_symbol, token_name)
        rag_intelligence = await self._query_rag_intelligence(address, token_symbol, token_name)
        community_consensus = await self._check_community_consensus(address, token_symbol)
        user_patterns = await self._check_user_feedback_patterns(address, token_symbol, token_name)
        
        legitimacy_result = self._combine_legitimacy_evidence(
            learned_legitimacy, rag_intelligence, community_consensus, user_patterns
        )
        
        return legitimacy_result

    async def check_threat_intelligence(self, address: str, token_name: str = "") -> Dict:
        """
        Check threat intelligence using learned data and RAG
        """
        threat_result = {
            'is_threat': False,
            'threat_level': 'none',
            'threat_details': {},
            'evidence': [],
            'learning_source': [],
            'confidence': 0.0
        }
        
        learned_threats = await self._check_learned_threats(address, token_name)
        rag_threats = await self._query_rag_threats(address, token_name)
        pattern_threats = self._check_suspicious_patterns(address, token_name)
        
        threat_result = self._combine_threat_evidence(
            learned_threats, rag_threats, pattern_threats
        )
        
        return threat_result

    async def update_consensus_scores(self):
        """
        Update community consensus scores - called by EdgeLearningEngine
        """
        try:
            updated_count = 0
            for consensus_key, consensus_data in self.learned_data['community_consensus'].items():
                total_votes = consensus_data.get('total_votes', 0)
                if total_votes >= self.learning_config['minimum_consensus']:
                    positive_votes = consensus_data.get('positive_votes', 0)
                    negative_votes = consensus_data.get('negative_votes', 0)
                    
                    consensus_rate = positive_votes / total_votes
                    consensus_data['consensus_score'] = consensus_rate
                    consensus_data['confidence'] = min(total_votes * 0.1, 1.0)
                    consensus_data['last_updated'] = datetime.now().isoformat()
                    
                    if consensus_rate >= self.learning_config['consensus_threshold']:
                        consensus_data['consensus_level'] = 'positive'
                    elif consensus_rate <= (1.0 - self.learning_config['consensus_threshold']):
                        consensus_data['consensus_level'] = 'negative'
                    else:
                        consensus_data['consensus_level'] = 'mixed'
                    
                    updated_count += 1
            
            if updated_count > 0:
                logger.info(f"📊 Updated consensus scores for {updated_count} items")
                
        except Exception as e:
            logger.error(f"⚠️ Error updating consensus scores: {e}")

    async def check_threat_level(self, address: str, token_name: str = "") -> Dict:
        """
        Check threat level for EdgeLearningEngine compatibility
        """
        threat_result = await self.check_threat_intelligence(address, token_name)
        
        return {
            'is_threat': threat_result.get('is_threat', False),
            'threat_level': threat_result.get('threat_level', 'none'),
            'confidence': threat_result.get('confidence', 0.0),
            'threat_details': threat_result.get('threat_details', {}),
            'evidence': threat_result.get('evidence', [])
        }

    async def learn_from_user_feedback(self, feedback_data: Dict):
        """
        Learn from user decisions to improve future classifications
        """
        # Validate inputs
        address = feedback_data.get('address', '')
        if not self._is_valid_solana_address(address):
            logger.warning(f"Invalid address in feedback: {address}")
            return
        
        user_decision = feedback_data.get('user_decision')
        if user_decision not in ['approved', 'quarantined']:
            logger.warning(f"Invalid decision: {user_decision}")
            return
        
        token_symbol = feedback_data.get('token_symbol', '').upper()
        token_name = feedback_data.get('token_name', '').lower()
        user_reasoning = feedback_data.get('user_reasoning', '')
        timestamp = feedback_data.get('timestamp', datetime.now().isoformat())
        confidence = min(max(feedback_data.get('confidence', 0.8), 0.0), 1.0)
        
        learning_entry = {
            'address': address,
            'token_symbol': token_symbol,
            'token_name': token_name,
            'user_decision': user_decision,
            'user_reasoning': user_reasoning,
            'timestamp': timestamp,
            'confidence': confidence,
            'learning_weight': 1.0
        }
        
        if user_decision == 'approved':
            await self._learn_legitimate_pattern(learning_entry)
        elif user_decision == 'quarantined':
            await self._learn_threat_pattern(learning_entry)
        
        token_data = feedback_data.get('token_data', {})
        if token_data:
            await self.learn_spam_patterns_from_feedback({
                'address': address,
                'token_data': token_data,
                'decision': user_decision
            })
        
        await self._save_learning_to_rag(learning_entry)
        
        logger.info(f"📚 Learned from user: {user_decision} for {token_symbol} from {address[:8]}...")

    async def submit_community_report(self, report_data: Dict) -> Dict:
        """
        Submit community report for collective learning
        """
        report = {
            'id': f"report_{datetime.now().timestamp()}",
            'submitted_at': datetime.now().isoformat(),
            'reporter_reputation': report_data.get('reporter_reputation', 0.5),
            'report_type': report_data.get('report_type'),
            'target_address': report_data.get('address'),
            'token_info': report_data.get('token_info', {}),
            'evidence': report_data.get('evidence', []),
            'description': report_data.get('description', ''),
            'validation_status': 'pending',
            'community_votes': {'confirm': 0, 'deny': 0}
        }
        
        await self._process_community_report(report)
        await self._save_report_to_rag(report)
        
        return {
            'success': True,
            'report_id': report['id'],
            'status': 'submitted_and_processing'
        }

    async def analyze_spam_patterns(self, tx_data: Dict) -> Dict:
        """
        Analyze if transaction matches learned spam patterns from community
        """
        spam_analysis = {
            'is_spam': False,
            'spam_confidence': 0.0,
            'spam_indicators': [],
            'learning_evidence': [],
            'community_pattern_match': False
        }
        
        address = tx_data.get('from_address', '')
        token_name = tx_data.get('token_name', '').lower()
        token_symbol = tx_data.get('token_symbol', '').upper()
        amount = float(tx_data.get('value', 0))
        
        amount_spam_score = await self._check_spam_amount_patterns(amount, token_symbol)
        spam_analysis['spam_confidence'] += amount_spam_score['confidence'] * 0.3
        if amount_spam_score['is_spam_amount']:
            spam_analysis['spam_indicators'].append('learned_spam_amount_pattern')
            spam_analysis['learning_evidence'].extend(amount_spam_score['evidence'])
        
        name_spam_score = await self._check_spam_name_patterns(token_name, token_symbol)
        spam_analysis['spam_confidence'] += name_spam_score['confidence'] * 0.3
        if name_spam_score['is_spam_name']:
            spam_analysis['spam_indicators'].append('learned_spam_name_pattern')
            spam_analysis['learning_evidence'].extend(name_spam_score['evidence'])
        
        sender_reputation = await self._check_mass_sender_reputation(address)
        spam_analysis['spam_confidence'] += sender_reputation['spam_score'] * 0.4
        if sender_reputation['is_spam_sender']:
            spam_analysis['spam_indicators'].append('learned_spam_sender')
            spam_analysis['learning_evidence'].extend(sender_reputation['evidence'])
        
        spam_analysis['is_spam'] = spam_analysis['spam_confidence'] > 0.6
        spam_analysis['community_pattern_match'] = len(spam_analysis['spam_indicators']) >= 2
        
        return spam_analysis

    async def check_mass_sender_reputation(self, address: str) -> Dict:
        """
        Check sender reputation based on community learning
        """
        return await self._check_mass_sender_reputation(address)

    async def _check_learned_legitimacy(self, address: str, token_symbol: str, token_name: str) -> Dict:
        """
        Check against learned legitimate projects
        """
        legitimacy_data = {
            'score': 0.0,
            'confidence': 0.0,
            'evidence': []
        }
        
        if address in self.learned_data['legitimate_projects']:
            project_data = self.learned_data['legitimate_projects'][address]
            approval_count = project_data.get('approval_count', 0)
            total_feedback = project_data.get('total_feedback', 1)
            approval_rate = approval_count / total_feedback
            
            if approval_rate > 0.7 and total_feedback >= 3:
                legitimacy_data['score'] = approval_rate
                legitimacy_data['confidence'] = min(total_feedback * 0.2, 1.0)
                legitimacy_data['evidence'].append(f'learned_legitimate_{approval_count}_approvals')
        
        for learned_symbol, symbol_data in self.learned_data.get('user_feedback_patterns', {}).items():
            if learned_symbol.upper() == token_symbol.upper():
                if symbol_data.get('approval_rate', 0) > 0.6:
                    legitimacy_data['score'] = max(legitimacy_data['score'], symbol_data['approval_rate'] * 0.8)
                    legitimacy_data['evidence'].append(f'learned_symbol_pattern_{learned_symbol}')
        
        return legitimacy_data

    async def _query_rag_intelligence(self, address: str, token_symbol: str, token_name: str) -> Dict:
        """
        Query RAG system for community intelligence about legitimacy
        """
        if not self.rag_client:
            return {'score': 0.0, 'confidence': 0.0, 'evidence': [], 'rag_available': False}
        
        query = f"Is {token_symbol} {token_name} from address {address} legitimate verified project community sentiment"
        
        try:
            rag_response = await self.rag_client.query(query)
            response_text = str(rag_response).lower()
            
            rag_data = {
                'score': 0.0,
                'confidence': 0.0,
                'evidence': [],
                'raw_response': response_text,
                'rag_available': True
            }
            
            positive_indicators = ['legitimate', 'verified', 'trusted', 'good', 'real', 'official', 'approved']
            negative_indicators = ['scam', 'fake', 'malicious', 'avoid', 'dangerous', 'reported', 'quarantined']
            
            positive_count = sum(1 for indicator in positive_indicators if indicator in response_text)
            negative_count = sum(1 for indicator in negative_indicators if indicator in response_text)
            
            if positive_count > negative_count and positive_count > 0:
                rag_data['score'] = min(positive_count * 0.2, 1.0)
                rag_data['confidence'] = min(positive_count * 0.15, 0.8)
                rag_data['evidence'].append('rag_positive_sentiment')
            elif negative_count > positive_count and negative_count > 0:
                rag_data['score'] = max(1.0 - (negative_count * 0.2), 0.0)
                rag_data['confidence'] = min(negative_count * 0.15, 0.8)
                rag_data['evidence'].append('rag_negative_sentiment')
            
            return rag_data
            
        except Exception as e:
            logger.error(f"Failed to query RAG: {e}")
            return {'score': 0.5, 'confidence': 0.0, 'evidence': [], 'error': str(e), 'rag_available': False}

    async def _check_community_consensus(self, address: str, token_symbol: str) -> Dict:
        """
        Check community consensus data
        """
        consensus_data = {
            'score': 0.0,
            'confidence': 0.0,
            'evidence': []
        }
        
        consensus_key = f"{address}_{token_symbol}".lower()
        if consensus_key in self.learned_data['community_consensus']:
            consensus = self.learned_data['community_consensus'][consensus_key]
            total_votes = consensus.get('total_votes', 0)
            positive_votes = consensus.get('positive_votes', 0)
            
            if total_votes >= self.learning_config['minimum_consensus']:
                consensus_rate = positive_votes / total_votes
                if consensus_rate >= self.learning_config['consensus_threshold']:
                    consensus_data['score'] = consensus_rate
                    consensus_data['confidence'] = min(total_votes * 0.1, 1.0)
                    consensus_data['evidence'].append(f'community_consensus_{positive_votes}_{total_votes}')
        
        return consensus_data

    async def _check_user_feedback_patterns(self, address: str, token_symbol: str, token_name: str) -> Dict:
        """
        Check patterns from user feedback
        """
        pattern_data = {
            'score': 0.0,
            'confidence': 0.0,
            'evidence': []
        }
        
        if address in self.learned_data.get('user_feedback_patterns', {}):
            feedback = self.learned_data['user_feedback_patterns'][address]
            if feedback.get('total_interactions', 0) >= 2:
                approval_rate = feedback.get('approval_rate', 0.5)
                pattern_data['score'] = approval_rate
                pattern_data['confidence'] = min(feedback['total_interactions'] * 0.3, 0.8)
                pattern_data['evidence'].append(f'user_pattern_{feedback["total_interactions"]}_interactions')
        
        return pattern_data

    def _combine_legitimacy_evidence(self, learned_data: Dict, rag_data: Dict, 
                                   consensus_data: Dict, pattern_data: Dict) -> Dict:
        """
        Combine all legitimacy evidence sources
        """
        total_weight = 0.0
        weighted_score = 0.0
        evidence = []
        learning_sources = []
        
        sources = [
            (learned_data, 0.4, 'learned_approvals'),
            (rag_data, 0.3, 'rag_intelligence'),
            (consensus_data, 0.2, 'community_consensus'),
            (pattern_data, 0.1, 'user_patterns')
        ]
        
        for source, weight, source_name in sources:
            if source.get('confidence', 0) > 0:
                weighted_score += source['score'] * weight * source['confidence']
                total_weight += weight * source['confidence']
                evidence.extend(source.get('evidence', []))
                learning_sources.append(source_name)
        
        final_score = weighted_score / total_weight if total_weight > 0 else 0.5
        final_confidence = min(total_weight, 1.0)
        
        return {
            'is_legitimate': final_score > 0.7,
            'legitimacy_score': final_score,
            'confidence': final_confidence,
            'evidence': evidence,
            'learning_source': learning_sources
        }

    async def _learn_legitimate_pattern(self, learning_entry: Dict):
        """
        Learn from user approval decisions
        """
        address = learning_entry['address']
        token_symbol = learning_entry['token_symbol']
        
        if address not in self.learned_data['legitimate_projects']:
            self.learned_data['legitimate_projects'][address] = {
                'approval_count': 0,
                'total_feedback': 0,
                'first_approved': learning_entry['timestamp'],
                'token_symbols': set()
            }
        
        project_data = self.learned_data['legitimate_projects'][address]
        project_data['approval_count'] += 1
        project_data['total_feedback'] += 1
        project_data['token_symbols'].add(token_symbol)
        project_data['last_approved'] = learning_entry['timestamp']
        
        if address not in self.learned_data['user_feedback_patterns']:
            self.learned_data['user_feedback_patterns'][address] = {
                'total_interactions': 0,
                'approvals': 0,
                'approval_rate': 0.0
            }
        
        pattern_data = self.learned_data['user_feedback_patterns'][address]
        pattern_data['total_interactions'] += 1
        pattern_data['approvals'] += 1
        pattern_data['approval_rate'] = pattern_data['approvals'] / pattern_data['total_interactions']

    async def _learn_threat_pattern(self, learning_entry: Dict):
        """
        Learn from user quarantine decisions
        """
        address = learning_entry['address']
        
        if address not in self.learned_data['threat_addresses']:
            self.learned_data['threat_addresses'][address] = {
                'quarantine_count': 0,
                'total_feedback': 0,
                'first_quarantined': learning_entry['timestamp'],
                'threat_indicators': []
            }
        
        threat_data = self.learned_data['threat_addresses'][address]
        threat_data['quarantine_count'] += 1
        threat_data['total_feedback'] += 1
        threat_data['last_quarantined'] = learning_entry['timestamp']
        
        if address not in self.learned_data['user_feedback_patterns']:
            self.learned_data['user_feedback_patterns'][address] = {
                'total_interactions': 0,
                'approvals': 0,
                'approval_rate': 0.0
            }
        
        pattern_data = self.learned_data['user_feedback_patterns'][address]
        pattern_data['total_interactions'] += 1
        pattern_data['approval_rate'] = pattern_data['approvals'] / pattern_data['total_interactions']

    async def _save_learning_to_rag(self, learning_entry: Dict):
        """
        Save learning entry to RAG system for community intelligence
        """
        if not self.rag_client:
            return
        
        address = learning_entry['address']
        token_symbol = learning_entry['token_symbol']
        decision = learning_entry['user_decision']
        reasoning = learning_entry['user_reasoning']
        
        if decision == 'approved':
            context = f"Token {token_symbol} from address {address} was approved by user as legitimate."
            if reasoning:
                context += f" User reasoning: {reasoning}"
            context += " This indicates the token/address may be from a legitimate project."
        else:
            context = f"Token {token_symbol} from address {address} was quarantined by user as suspicious."
            if reasoning:
                context += f" User reasoning: {reasoning}"
            context += " This indicates potential threat or unwanted activity."
        
        context += f" Timestamp: {learning_entry['timestamp']}"
        
        try:
            await self.rag_client.save_context("user_feedback", context)
        except Exception as e:
            logger.error(f"⚠️ Failed to save learning to RAG: {e}")

    async def _check_learned_threats(self, address: str, token_name: str) -> Dict:
        """
        Check learned threat data
        """
        threat_data = {
            'is_threat': False,
            'threat_level': 'none',
            'confidence': 0.0,
            'evidence': []
        }
        
        if address in self.learned_data['threat_addresses']:
            threat_info = self.learned_data['threat_addresses'][address]
            quarantine_count = threat_info.get('quarantine_count', 0)
            total_feedback = threat_info.get('total_feedback', 1)
            quarantine_rate = quarantine_count / total_feedback
            
            if quarantine_rate > 0.7 and total_feedback >= 2:
                threat_data['is_threat'] = True
                threat_data['threat_level'] = 'high' if quarantine_rate > 0.9 else 'medium'
                threat_data['confidence'] = min(total_feedback * 0.3, 1.0)
                threat_data['evidence'].append(f'learned_threat_{quarantine_count}_quarantines')
        
        return threat_data

    async def _query_rag_threats(self, address: str, token_name: str) -> Dict:
        """
        Query RAG for threat intelligence
        """
        if not self.rag_client:
            return {'is_threat': False, 'threat_level': 'none', 'confidence': 0.0, 'evidence': []}
        
        query = f"Address {address} token {token_name} scam threat malicious reported quarantined"
        
        try:
            rag_response = await self.rag_client.query(query)
            response_text = str(rag_response).lower()
            
            threat_indicators = ['scam', 'malicious', 'threat', 'quarantined', 'reported', 'dangerous']
            threat_count = sum(1 for indicator in threat_indicators if indicator in response_text)
            
            if threat_count > 0:
                return {
                    'is_threat': True,
                    'threat_level': 'high' if threat_count > 2 else 'medium',
                    'confidence': min(threat_count * 0.2, 0.8),
                    'evidence': ['rag_threat_intelligence']
                }
            
        except Exception as e:
            logger.error(f"Failed to query RAG for threats: {e}")
        
        return {'is_threat': False, 'threat_level': 'none', 'confidence': 0.0, 'evidence': []}

    def _check_suspicious_patterns(self, address: str, token_name: str) -> Dict:
        """
        Check basic suspicious patterns
        """
        threat_data = {
            'is_threat': False,
            'threat_level': 'none',
            'confidence': 0.0,
            'evidence': []
        }
        
        address_lower = address.lower()
        token_name_lower = token_name.lower()
        
        for pattern in self.threat_patterns['suspicious_address_patterns']:
            if pattern in address_lower:
                threat_data['is_threat'] = True
                threat_data['threat_level'] = 'low'
                threat_data['confidence'] = 0.3
                threat_data['evidence'].append(f'suspicious_address_pattern_{pattern}')
        
        for keyword in self.threat_patterns['suspicious_keywords']:
            if keyword in token_name_lower:
                threat_data['is_threat'] = True
                threat_data['threat_level'] = 'medium' if keyword in ['fake', 'scam'] else 'low'
                threat_data['confidence'] = 0.5 if keyword in ['fake', 'scam'] else 0.3
                threat_data['evidence'].append(f'suspicious_keyword_{keyword}')
        
        return threat_data

    def _combine_threat_evidence(self, learned_threats: Dict, rag_threats: Dict, pattern_threats: Dict) -> Dict:
        """
        Combine all threat evidence
        """
        threat_levels = ['none', 'low', 'medium', 'high']
        max_level = 'none'
        total_confidence = 0.0
        all_evidence = []
        
        sources = [learned_threats, rag_threats, pattern_threats]
        for source in sources:
            if source.get('is_threat', False):
                source_level = source.get('threat_level', 'none')
                if threat_levels.index(source_level) > threat_levels.index(max_level):
                    max_level = source_level
                total_confidence += source.get('confidence', 0.0)
                all_evidence.extend(source.get('evidence', []))
        
        return {
            'is_threat': max_level != 'none',
            'threat_level': max_level,
            'threat_details': {'combined_sources': True},
            'evidence': all_evidence,
            'learning_source': ['learned_data', 'rag_intelligence', 'pattern_analysis'],
            'confidence': min(total_confidence, 1.0)
        }

    async def learn_spam_patterns_from_feedback(self, feedback_data: Dict):
        """
        Learn spam patterns from user feedback
        """
        address = feedback_data.get('address')
        token_data = feedback_data.get('token_data', {})
        amount = float(token_data.get('value', 0))
        token_name = token_data.get('token_name', '').lower()
        token_symbol = token_data.get('token_symbol', '').upper()
        user_decision = feedback_data['decision']
        
        await self._learn_amount_patterns(amount, token_symbol, user_decision)
        await self._learn_name_patterns(token_name, token_symbol, user_decision)
        await self._learn_sender_patterns(address, amount, user_decision)

    async def _learn_amount_patterns(self, amount: float, token_symbol: str, decision: str):
        """Learn from amount-based user decisions"""
        amount_range = self._categorize_amount(amount)
        pattern_key = f"amount_{amount_range}_{token_symbol}"
        
        if pattern_key not in self.learned_data['spam_patterns']:
            self.learned_data['spam_patterns'][pattern_key] = {
                'total_feedback': 0,
                'spam_feedback': 0,
                'legitimate_feedback': 0
            }
        
        pattern_data = self.learned_data['spam_patterns'][pattern_key]
        pattern_data['total_feedback'] += 1
        
        if decision == 'quarantined':
            pattern_data['spam_feedback'] += 1
        elif decision == 'approved':
            pattern_data['legitimate_feedback'] += 1

    async def _learn_name_patterns(self, token_name: str, token_symbol: str, decision: str):
        """Learn from token name-based user decisions"""
        words = token_name.lower().split()
        
        for word in words:
            if len(word) >= 3:
                word_key = f"word_{word}"
                
                if word_key not in self.learned_data['name_patterns']:
                    self.learned_data['name_patterns'][word_key] = {
                        'total_occurrences': 0,
                        'spam_occurrences': 0,
                        'legitimate_occurrences': 0
                    }
                
                word_data = self.learned_data['name_patterns'][word_key]
                word_data['total_occurrences'] += 1
                
                if decision == 'quarantined':
                    word_data['spam_occurrences'] += 1
                elif decision == 'approved':
                    word_data['legitimate_occurrences'] += 1

    async def _learn_sender_patterns(self, address: str, amount: float, decision: str):
        """Learn from sender behavior patterns"""
        sender_key = f"sender_{address}"
        
        if sender_key not in self.learned_data['sender_patterns']:
            self.learned_data['sender_patterns'][sender_key] = {
                'amounts_used': [],
                'total_interactions': 0,
                'spam_interactions': 0,
                'identical_amount_usage': 0
            }
        
        sender_data = self.learned_data['sender_patterns'][sender_key]
        sender_data['total_interactions'] += 1
        sender_data['amounts_used'].append(amount)
        
        if sender_data['amounts_used'].count(amount) > 1:
            sender_data['identical_amount_usage'] += 1
        
        if decision == 'quarantined':
            sender_data['spam_interactions'] += 1

    def _categorize_amount(self, amount: float) -> str:
        """Categorize amount into ranges for pattern analysis"""
        if amount == 0:
            return 'zero'
        elif 0 < amount <= 0.00001:
            return 'micro'
        elif 0.00001 < amount <= 0.0001:
            return 'tiny'
        elif 0.0001 < amount <= 0.001:
            return 'small'
        elif 0.001 < amount <= 0.01:
            return 'medium'
        elif 0.01 < amount <= 1:
            return 'standard'
        elif 1 < amount <= 100:
            return 'large'
        else:
            return 'very_large'

    async def _check_spam_amount_patterns(self, amount: float, token_symbol: str) -> Dict:
        """
        Check if amount matches learned spam patterns
        """
        amount_analysis = {
            'is_spam_amount': False,
            'confidence': 0.0,
            'evidence': []
        }
        
        amount_range = self._categorize_amount(amount)
        pattern_key = f"amount_{amount_range}_{token_symbol}"
        
        if pattern_key in self.learned_data['spam_patterns']:
            pattern_data = self.learned_data['spam_patterns'][pattern_key]
            total_feedback = pattern_data.get('total_feedback', 0)
            spam_feedback = pattern_data.get('spam_feedback', 0)
            
            if total_feedback >= 3:
                spam_rate = spam_feedback / total_feedback
                
                if spam_rate > 0.8:
                    amount_analysis['is_spam_amount'] = True
                    amount_analysis['confidence'] = spam_rate
                    amount_analysis['evidence'].append(f'community_spam_rate_{spam_rate:.1%}_{total_feedback}_reports')
        
        if self.rag_client:
            rag_query = f"amount {amount} {token_symbol} spam dust tracking small value"
            rag_spam_intel = await self._query_rag_amount_patterns(rag_query)
            
            if rag_spam_intel['spam_confidence'] > 0.5:
                amount_analysis['confidence'] = max(amount_analysis['confidence'], rag_spam_intel['spam_confidence'])
                amount_analysis['evidence'].append('rag_amount_spam_pattern')
        
        return amount_analysis

    async def _check_spam_name_patterns(self, token_name: str, token_symbol: str) -> Dict:
        """
        Check if token name matches learned spam patterns
        """
        name_analysis = {
            'is_spam_name': False,
            'confidence': 0.0,
            'evidence': []
        }
        
        name_words = token_name.lower().split()
        
        for word in name_words:
            word_key = f"word_{word}"
            if word_key in self.learned_data['name_patterns']:
                word_data = self.learned_data['name_patterns'][word_key]
                total_occurrences = word_data.get('total_occurrences', 0)
                spam_occurrences = word_data.get('spam_occurrences', 0)
                
                if total_occurrences >= 5:
                    spam_rate = spam_occurrences / total_occurrences
                    
                    if spam_rate > 0.7:
                        name_analysis['is_spam_name'] = True
                        name_analysis['confidence'] = max(name_analysis['confidence'], spam_rate)
                        name_analysis['evidence'].append(f'learned_spam_word_{word}_{spam_rate:.1%}')
        
        return name_analysis

    async def _check_mass_sender_reputation(self, address: str) -> Dict:
        """
        Check sender reputation based on community learning
        """
        reputation_analysis = {
            'is_spam_sender': False,
            'is_legitimate_mass_sender': False,
            'spam_score': 0.0,
            'legitimacy_score': 0.0,
            'mass_sender_type': 'unknown',
            'evidence': []
        }
        
        sender_key = f"sender_{address}"
        if sender_key in self.learned_data['sender_patterns']:
            sender_data = self.learned_data['sender_patterns'][sender_key]
            total_interactions = sender_data.get('total_interactions', 0)
            spam_interactions = sender_data.get('spam_interactions', 0)
            
            if total_interactions >= 3:
                spam_rate = spam_interactions / total_interactions
                legitimate_rate = 1.0 - spam_rate
                
                if spam_rate > 0.7:
                    reputation_analysis['is_spam_sender'] = True
                    reputation_analysis['spam_score'] = spam_rate
                    reputation_analysis['mass_sender_type'] = 'spam_mass_sender'
                    reputation_analysis['evidence'].append(f'community_spam_mass_sender_{spam_rate:.1%}')
                elif legitimate_rate > 0.7:
                    reputation_analysis['is_legitimate_mass_sender'] = True
                    reputation_analysis['legitimacy_score'] = legitimate_rate
                    reputation_analysis['mass_sender_type'] = 'legitimate_mass_sender'
                    reputation_analysis['evidence'].append(f'community_legitimate_mass_sender_{legitimate_rate:.1%}')
        
        return reputation_analysis

    async def _query_rag_amount_patterns(self, query: str) -> Dict:
        """Query RAG for amount-based spam patterns"""
        if not self.rag_client:
            return {'spam_confidence': 0.0}
        
        try:
            rag_response = await self.rag_client.query(query)
            response_text = str(rag_response).lower()
            
            spam_indicators = ['spam', 'dust', 'tracking', 'unwanted', 'fake']
            spam_count = sum(1 for indicator in spam_indicators if indicator in response_text)
            
            return {
                'spam_confidence': min(spam_count * 0.2, 1.0) if spam_count > 0 else 0.0,
                'evidence': f'rag_amount_analysis_{spam_count}_indicators'
            }
        except Exception as e:
            logger.error(f"Failed to query RAG for amount patterns: {e}")
            return {'spam_confidence': 0.0, 'error': str(e)}

    async def _process_community_report(self, report: Dict):
        """
        Process community report for immediate learning
        """
        address = report['target_address']
        token_symbol = report['token_info'].get('symbol', '')
        consensus_key = f"{address}_{token_symbol}".lower()
        
        if consensus_key not in self.learned_data['community_consensus']:
            self.learned_data['community_consensus'][consensus_key] = {
                'total_votes': 0,
                'positive_votes': 0,
                'negative_votes': 0
            }
        
        consensus = self.learned_data['community_consensus'][consensus_key]
        consensus['total_votes'] += 1
        
        if report['report_type'] == 'legitimate':
            consensus['positive_votes'] += 1
        elif report['report_type'] == 'threat':
            consensus['negative_votes'] += 1

    async def _save_report_to_rag(self, report: Dict):
        """
        Save community report to RAG system
        """
        if not self.rag_client:
            return
        
        address = report['target_address']
        report_type = report['report_type']
        description = report['description']
        
        context = f"Community report: Address {address} reported as {report_type}. {description} Reported at {report['submitted_at']}"
        
        try:
            await self.rag_client.save_context("community_reports", context)
        except Exception as e:
            logger.error(f"⚠️ Failed to save report to RAG: {e}")

    def _is_valid_solana_address(self, address: str) -> bool:
        """Validate Solana address (base58, 32-44 chars)"""
        pattern = r'^[A-HJ-NP-Z1-9]{32,44}$'
        return bool(re.match(pattern, address))

    def get_learning_stats(self) -> Dict:
        """
        Get statistics about what the system has learned
        """
        return {
            'learned_legitimate_projects': len(self.learned_data['legitimate_projects']),
            'learned_threat_addresses': len(self.learned_data['threat_addresses']),
            'community_consensus_items': len(self.learned_data['community_consensus']),
            'user_feedback_patterns': len(self.learned_data['user_feedback_patterns']),
            'spam_patterns_learned': len(self.learned_data['spam_patterns']),
            'name_patterns_learned': len(self.learned_data['name_patterns']),
            'sender_patterns_learned': len(self.learned_data['sender_patterns']),
            'learning_config': self.learning_config,
            'total_learning_entries': sum([
                len(self.learned_data['legitimate_projects']),
                len(self.learned_data['threat_addresses']),
                len(self.learned_data['community_consensus']),
                len(self.learned_data['spam_patterns']),
                len(self.learned_data['name_patterns']),
                len(self.learned_data['sender_patterns'])
            ])
        }

    def export_learned_data(self) -> Dict:
        """
        Export learned data for backup or analysis
        """
        export_data = {}
        for key, value in self.learned_data.items():
            if isinstance(value, dict):
                export_data[key] = {}
                for sub_key, sub_value in value.items():
                    if isinstance(sub_value, dict) and 'token_symbols' in sub_value:
                        export_data[key][sub_key] = {**sub_value, 'token_symbols': list(sub_value['token_symbols'])}
                    else:
                        export_data[key][sub_key] = sub_value
            else:
                export_data[key] = value
        
        return {
            'learned_data': export_data,
            'learning_config': self.learning_config,
            'export_timestamp': datetime.now().isoformat(),
            'rag_client_available': self.rag_client is not None
        }

    def set_edge_learning_engine_reference(self, edge_learning_engine):
        """
        Set EdgeLearningEngine reference for bidirectional communication
        """
        self.edge_learning_engine = edge_learning_engine
        logger.info("🔗 AdaptiveCommunityDatabase connected to EdgeLearningEngine")

    async def sync_with_external_community_db(self, api_url: str) -> Dict[str, Any]:
        """
        Sync with external community database API
        """
        try:
            sync_data = {
                'local_patterns': len(self.learned_data['user_feedback_patterns']),
                'local_consensus': self.learned_data['community_consensus'],
                'last_sync': datetime.now().isoformat()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{api_url}/sync", json=sync_data, timeout=10) as response:
                    if response.status != 200:
                        logger.warning(f"Community DB API returned status {response.status}")
                        return {'success': False, 'error': f"API error: {response.status}"}
                    
                    remote_data = await response.json()
                    
                    for key, remote_consensus in remote_data.get('consensus_data', {}).items():
                        if key in self.learned_data['community_consensus']:
                            local_consensus = self.learned_data['community_consensus'][key]
                            local_consensus['total_votes'] += remote_consensus.get('total_votes', 0)
                            local_consensus['positive_votes'] += remote_consensus.get('positive_votes', 0)
                            local_consensus['negative_votes'] += remote_consensus.get('negative_votes', 0)
                        else:
                            self.learned_data['community_consensus'][key] = remote_consensus
                    
                    logger.info(f"🌐 Synced with community DB: {len(remote_data.get('consensus_data', {}))} items")
                    return {
                        'success': True,
                        'sync_data': sync_data,
                        'remote_data': remote_data,
                        'timestamp': datetime.now().isoformat()
                    }
        except Exception as e:
            logger.error(f"❌ Community DB sync error: {e}")
            return {'success': False, 'error': str(e)}

    async def check_threat_intelligence_legacy(self, address: str, token_name: str = "") -> Dict:
        """
        Legacy method name for backward compatibility
        """
        return await self.check_threat_intelligence(address, token_name)

    async def analyze_legitimacy_from_community(self, tx_data: Dict) -> Dict:
        """
        Backward compatibility method
        """
        address = tx_data.get('from_address', '')
        token_symbol = tx_data.get('token_symbol', '')
        token_name = tx_data.get('token_name', '')
        
        legitimacy_result = await self.check_legitimacy(address, token_symbol, token_name)
        
        return {
            'legitimacy_score': legitimacy_result['legitimacy_score'],
            'confidence': legitimacy_result['confidence'],
            'evidence': legitimacy_result['evidence'],
            'community_sentiment': 'positive' if legitimacy_result['is_legitimate'] else 'negative',
            'learning_source': legitimacy_result['learning_source']
        }

class AdaptiveDustDetector:
    """
    Adaptive dust detector that learns from community
    """
    
    def __init__(self, rag_client=None):
        self.community_db = AdaptiveCommunityDatabase(rag_client)
        
        self.basic_thresholds = {
            'tiny_dust': 0.00001,
            'small_dust': 0.0001,
            'medium_dust': 0.001,
            'tracking_threshold': 0.01
        }

    async def analyze_transaction(self, transaction_data: Dict) -> Dict:
        """
        Analyze transaction using community intelligence
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
        
        spam_analysis = await self.community_db.analyze_spam_patterns(transaction_data)
        
        analysis_result['is_dust_attack'] = spam_analysis['is_spam']
        analysis_result['dust_risk_score'] = spam_analysis['spam_confidence']
        analysis_result['learning_confidence'] = spam_analysis['spam_confidence']
        
        address = transaction_data.get('from_address', '')
        token_symbol = transaction_data.get('token_symbol', '')
        token_name = transaction_data.get('token_name', '')
        
        legitimacy_result = await self.community_db.check_legitimacy(address, token_symbol, token_name)
        
        analysis_result['is_legitimate_airdrop'] = legitimacy_result['is_legitimate']
        analysis_result['legitimacy_score'] = legitimacy_result['legitimacy_score']
        
        if legitimacy_result['is_legitimate']:
            analysis_result['community_sentiment'] = 'positive'
        elif spam_analysis['is_spam']:
            analysis_result['community_sentiment'] = 'negative'
        else:
            analysis_result['community_sentiment'] = 'neutral'
        
        return analysis_result

    async def learn_from_user_decision(self, transaction_data: Dict, user_decision: str, user_reasoning: str = ""):
        """
        Learn from user feedback about dust/airdrop decisions
        """
        feedback_data = {
            'address': transaction_data.get('from_address', ''),
            'token_symbol': transaction_data.get('token_symbol', ''),
            'token_name': transaction_data.get('token_name', ''),
            'decision': user_decision,
            'user_reasoning': user_reasoning,
            'token_data': transaction_data,
            'timestamp': datetime.now().isoformat(),
            'confidence': 0.8
        }
        
        await self.community_db.learn_from_user_feedback(feedback_data)
