"""
Adaptive Community Database with Learning System
NO HARD-CODED PROJECTS - Everything learned from community
Integrates with RAG system for shared intelligence
"""

from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
import json


class AdaptiveCommunityDatabase:
    """
    Adaptive community database that learns everything from:
    1. User feedback (approve/quarantine decisions)
    2. Community reports
    3. RAG system intelligence
    NO HARD-CODED PROJECTS
    """
    
    def __init__(self, rag_client):
        self.rag_client = rag_client
        
        # Start completely empty - learn everything from community
        self.learned_data = {
            'legitimate_projects': {},      # Learned from user approvals
            'threat_addresses': {},         # Learned from user quarantines/reports
            'community_consensus': {},      # Addresses with community agreement
            'user_feedback_patterns': {},   # Patterns from user decisions
        }
        
        # Learning thresholds and weights
        self.learning_config = {
            'minimum_consensus': 3,         # Need 3+ confirmations
            'consensus_threshold': 0.7,     # 70% agreement needed
            'user_weight': 0.4,            # Weight of individual user feedback
            'community_weight': 0.6,       # Weight of community consensus
            'rag_confidence_threshold': 0.5, # Minimum RAG confidence to trust
        }
        
        # Basic threat patterns (only objective indicators, no projects)
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
            'legitimacy_score': 0.5,  # Start neutral
            'confidence': 0.0,
            'evidence': [],
            'learning_source': []
        }
        
        # 1. Check learned legitimate projects
        learned_legitimacy = await self._check_learned_legitimacy(address, token_symbol, token_name)
        
        # 2. Query RAG for community intelligence
        rag_intelligence = await self._query_rag_intelligence(address, token_symbol, token_name)
        
        # 3. Check community consensus
        community_consensus = await self._check_community_consensus(address, token_symbol)
        
        # 4. Check user feedback patterns
        user_patterns = await self._check_user_feedback_patterns(address, token_symbol, token_name)
        
        # 5. Combine all sources
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
            'learning_source': []
        }
        
        # 1. Check learned threat addresses
        learned_threats = await self._check_learned_threats(address, token_name)
        
        # 2. Query RAG for threat intelligence
        rag_threats = await self._query_rag_threats(address, token_name)
        
        # 3. Check basic suspicious patterns (only objective indicators)
        pattern_threats = self._check_suspicious_patterns(address, token_name)
        
        # 4. Combine threat evidence
        threat_result = self._combine_threat_evidence(
            learned_threats, rag_threats, pattern_threats
        )
        
        return threat_result

    async def learn_from_user_feedback(self, feedback_data: Dict):
        """
        Learn from user decisions to improve future classifications
        """
        address = feedback_data['address']
        token_symbol = feedback_data.get('token_symbol', '')
        token_name = feedback_data.get('token_name', '')
        user_decision = feedback_data['decision']  # 'approved' or 'quarantined'
        user_reasoning = feedback_data.get('reasoning', '')
        timestamp = datetime.now().isoformat()
        
        # Create learning entry
        learning_entry = {
            'address': address,
            'token_symbol': token_symbol,
            'token_name': token_name,
            'user_decision': user_decision,
            'user_reasoning': user_reasoning,
            'timestamp': timestamp,
            'learning_weight': 1.0
        }
        
        # Update learned data based on user decision
        if user_decision == 'approved':
            await self._learn_legitimate_pattern(learning_entry)
        elif user_decision == 'quarantined':
            await self._learn_threat_pattern(learning_entry)
        
        # Save learning to RAG for future reference
        await self._save_learning_to_rag(learning_entry)
        
        print(f"📚 Learned from user: {user_decision} for {token_symbol} from {address[:8]}...")

    async def submit_community_report(self, report_data: Dict) -> Dict:
        """
        Submit community report for collective learning
        """
        report = {
            'id': f"report_{datetime.now().timestamp()}",
            'submitted_at': datetime.now().isoformat(),
            'reporter_reputation': report_data.get('reporter_reputation', 0.5),
            'report_type': report_data.get('report_type'),  # 'threat' or 'legitimate'
            'target_address': report_data.get('address'),
            'token_info': report_data.get('token_info', {}),
            'evidence': report_data.get('evidence', []),
            'description': report_data.get('description', ''),
            'validation_status': 'pending',
            'community_votes': {'confirm': 0, 'deny': 0}
        }
        
        # Process report immediately for learning
        await self._process_community_report(report)
        
        # Save to RAG for community intelligence
        await self._save_report_to_rag(report)
        
        return {
            'success': True,
            'report_id': report['id'],
            'status': 'submitted_and_processing'
        }

    async def _check_learned_legitimacy(self, address: str, token_symbol: str, token_name: str) -> Dict:
        """
        Check against learned legitimate projects
        """
        legitimacy_data = {
            'score': 0.0,
            'confidence': 0.0,
            'evidence': []
        }
        
        # Check learned legitimate projects
        if address in self.learned_data['legitimate_projects']:
            project_data = self.learned_data['legitimate_projects'][address]
            approval_count = project_data.get('approval_count', 0)
            total_feedback = project_data.get('total_feedback', 1)
            approval_rate = approval_count / total_feedback
            
            if approval_rate > 0.7 and total_feedback >= 3:
                legitimacy_data['score'] = approval_rate
                legitimacy_data['confidence'] = min(total_feedback * 0.2, 1.0)
                legitimacy_data['evidence'].append(f'learned_legitimate_{approval_count}_approvals')
        
        # Check token symbol patterns
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
        query = f"Is {token_symbol} {token_name} from address {address} legitimate verified project community sentiment"
        
        try:
            rag_response = await self.rag_client.query(query)
            response_text = str(rag_response).lower()
            
            rag_data = {
                'score': 0.0,
                'confidence': 0.0,
                'evidence': [],
                'raw_response': response_text
            }
            
            # Analyze RAG response for legitimacy indicators
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
            return {'score': 0.5, 'confidence': 0.0, 'evidence': [], 'error': str(e)}

    async def _check_community_consensus(self, address: str, token_symbol: str) -> Dict:
        """
        Check community consensus data
        """
        consensus_data = {
            'score': 0.0,
            'confidence': 0.0,
            'evidence': []
        }
        
        # Check consensus data
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
        
        # Check patterns by address
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
        # Weighted average of all sources
        total_weight = 0.0
        weighted_score = 0.0
        
        sources = [
            (learned_data, 0.4, 'learned_approvals'),
            (rag_data, 0.3, 'rag_intelligence'),
            (consensus_data, 0.2, 'community_consensus'),
            (pattern_data, 0.1, 'user_patterns')
        ]
        
        evidence = []
        learning_sources = []
        
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
        
        # Update legitimate projects
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
        
        # Update user feedback patterns
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
        
        # Update threat addresses
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
        
        # Update user feedback patterns
        if address not in self.learned_data['user_feedback_patterns']:
            self.learned_data['user_feedback_patterns'][address] = {
                'total_interactions': 0,
                'approvals': 0,
                'approval_rate': 0.0
            }
        
        pattern_data = self.learned_data['user_feedback_patterns'][address]
        pattern_data['total_interactions'] += 1
        # approval_rate decreases as more quarantines happen
        pattern_data['approval_rate'] = pattern_data['approvals'] / pattern_data['total_interactions']

    async def _save_learning_to_rag(self, learning_entry: Dict):
        """
        Save learning entry to RAG system for community intelligence
        """
        address = learning_entry['address']
        token_symbol = learning_entry['token_symbol']
        decision = learning_entry['user_decision']
        reasoning = learning_entry['user_reasoning']
        
        # Create natural language context for RAG
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
        
        # Save to RAG with timestamp
        context += f" Timestamp: {learning_entry['timestamp']}"
        
        try:
            await self.rag_client.save_context("user_feedback", context)
        except Exception as e:
            print(f"⚠️ Failed to save learning to RAG: {e}")

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
        
        # Check learned threat addresses
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
            pass
        
        return {'is_threat': False, 'threat_level': 'none', 'confidence': 0.0, 'evidence': []}

    def _check_suspicious_patterns(self, address: str, token_name: str) -> Dict:
        """
        Check basic suspicious patterns (only objective indicators)
        """
        threat_data = {
            'is_threat': False,
            'threat_level': 'none',
            'confidence': 0.0,
            'evidence': []
        }
        
        address_lower = address.lower()
        token_name_lower = token_name.lower()
        
        # Check suspicious address patterns
        for pattern in self.threat_patterns['suspicious_address_patterns']:
            if pattern in address_lower:
                threat_data['is_threat'] = True
                threat_data['threat_level'] = 'low'
                threat_data['confidence'] = 0.3
                threat_data['evidence'].append(f'suspicious_address_pattern_{pattern}')
        
        # Check suspicious keywords
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
        # Take the highest threat level found
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
            'learning_source': ['learned_data', 'rag_intelligence', 'pattern_analysis']
        }

    async def _process_community_report(self, report: Dict):
        """
        Process community report for immediate learning
        """
        # Add to community consensus data
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
        address = report['target_address']
        report_type = report['report_type']
        description = report['description']
        
        context = f"Community report: Address {address} reported as {report_type}. {description} Reported at {report['submitted_at']}"
        
        try:
            await self.rag_client.save_context("community_reports", context)
        except Exception as e:
            print(f"⚠️ Failed to save report to RAG: {e}")

    def get_learning_stats(self) -> Dict:
        """
        Get statistics about what the system has learned
        """
        return {
            'learned_legitimate_projects': len(self.learned_data['legitimate_projects']),
            'learned_threat_addresses': len(self.learned_data['threat_addresses']),
            'community_consensus_items': len(self.learned_data['community_consensus']),
            'user_feedback_patterns': len(self.learned_data['user_feedback_patterns']),
            'learning_config': self.learning_config,
            'total_learning_entries': sum([
                len(self.learned_data['legitimate_projects']),
                len(self.learned_data['threat_addresses']),
                len(self.learned_data['community_consensus'])
            ])
        }

    def export_learned_data(self) -> Dict:
        """
        Export learned data for backup or analysis
        """
        # Convert sets to lists for JSON serialization
        export_data = {}
        for key, value in self.learned_data.items():
            if isinstance(value, dict):
                export_data[key] = {}
                for sub_key, sub_value in value.items():
                    if isinstance(sub_value, dict) and 'token_symbols' in sub_value:
                        # Convert set to list
                        export_data[key][sub_key] = {**sub_value, 'token_symbols': list(sub_value['token_symbols'])}
                    else:
                        export_data[key][sub_key] = sub_value
            else:
                export_data[key] = value
        
        return {
            'learned_data': export_data,
            'learning_config': self.learning_config,
            'export_timestamp': datetime.now().isoformat()
        }
        


# Add these methods to your AdaptiveCommunityDatabase class

    async def analyze_spam_patterns(self, tx_data: Dict) -> Dict:
        """
        Analyze if transaction matches learned spam patterns from community
        Replaces dust detector with community intelligence
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
        
        # 1. Check learned spam amount patterns
        amount_spam_score = await self._check_spam_amount_patterns(amount, token_symbol)
        spam_analysis['spam_confidence'] += amount_spam_score['confidence'] * 0.3
        if amount_spam_score['is_spam_amount']:
            spam_analysis['spam_indicators'].append('learned_spam_amount_pattern')
            spam_analysis['learning_evidence'].extend(amount_spam_score['evidence'])
        
        # 2. Check learned token name patterns  
        name_spam_score = await self._check_spam_name_patterns(token_name, token_symbol)
        spam_analysis['spam_confidence'] += name_spam_score['confidence'] * 0.3
        if name_spam_score['is_spam_name']:
            spam_analysis['spam_indicators'].append('learned_spam_name_pattern')
            spam_analysis['learning_evidence'].extend(name_spam_score['evidence'])
        
        # 3. Check mass sender reputation
        sender_reputation = await self._check_mass_sender_reputation(address)
        spam_analysis['spam_confidence'] += sender_reputation['spam_score'] * 0.4
        if sender_reputation['is_spam_sender']:
            spam_analysis['spam_indicators'].append('learned_spam_sender')
            spam_analysis['learning_evidence'].extend(sender_reputation['evidence'])
        
        # Final determination
        spam_analysis['is_spam'] = spam_analysis['spam_confidence'] > 0.6
        spam_analysis['community_pattern_match'] = len(spam_analysis['spam_indicators']) >= 2
        
        return spam_analysis

    async def _check_spam_amount_patterns(self, amount: float, token_symbol: str) -> Dict:
        """
        Check if amount matches patterns learned from community as spam
        """
        amount_analysis = {
            'is_spam_amount': False,
            'confidence': 0.0,
            'evidence': []
        }
        
        # Query learned patterns for this amount range
        amount_range = self._categorize_amount(amount)
        
        # Check if community has consistently marked this amount range as spam
        spam_feedback = await self._get_amount_spam_feedback(amount_range, token_symbol)
        
        if spam_feedback['total_feedback'] >= 3:  # Need minimum consensus
            spam_rate = spam_feedback['spam_count'] / spam_feedback['total_feedback']
            
            if spam_rate > 0.8:  # 80%+ of community marked as spam
                amount_analysis['is_spam_amount'] = True
                amount_analysis['confidence'] = spam_rate
                amount_analysis['evidence'].append(f'community_spam_rate_{spam_rate:.1%}_{spam_feedback["total_feedback"]}_reports')
        
        # Check RAG for amount-based spam intelligence
        rag_query = f"amount {amount} {token_symbol} spam dust tracking small value"
        rag_spam_intel = await self._query_rag_amount_patterns(rag_query)
        
        if rag_spam_intel['spam_confidence'] > 0.5:
            amount_analysis['confidence'] = max(amount_analysis['confidence'], rag_spam_intel['spam_confidence'])
            amount_analysis['evidence'].append('rag_amount_spam_pattern')
        
        return amount_analysis

    async def _check_spam_name_patterns(self, token_name: str, token_symbol: str) -> Dict:
        """
        Check if token name matches patterns learned from community as spam
        """
        name_analysis = {
            'is_spam_name': False,
            'confidence': 0.0,
            'evidence': []
        }
        
        # Extract key words from token name for pattern matching
        name_words = token_name.lower().split()
        
        # Check each word against learned spam patterns
        for word in name_words:
            word_spam_data = await self._get_word_spam_feedback(word)
            
            if word_spam_data['total_occurrences'] >= 5:  # Word appeared in 5+ tokens
                spam_rate = word_spam_data['spam_occurrences'] / word_spam_data['total_occurrences']
                
                if spam_rate > 0.7:  # 70%+ of tokens with this word were spam
                    name_analysis['is_spam_name'] = True
                    name_analysis['confidence'] = max(name_analysis['confidence'], spam_rate)
                    name_analysis['evidence'].append(f'learned_spam_word_{word}_{spam_rate:.1%}')
        
        # Check exact token symbol against learned patterns
        symbol_spam_data = await self._get_symbol_spam_feedback(token_symbol)
        if symbol_spam_data['total_feedback'] >= 3:
            symbol_spam_rate = symbol_spam_data['spam_count'] / symbol_spam_data['total_feedback']
            if symbol_spam_rate > 0.8:
                name_analysis['is_spam_name'] = True
                name_analysis['confidence'] = max(name_analysis['confidence'], symbol_spam_rate)
                name_analysis['evidence'].append(f'learned_spam_symbol_{token_symbol}')
        
        # RAG query for name patterns
        rag_query = f"token name {token_name} {token_symbol} spam fake misleading community reports"
        rag_name_intel = await self._query_rag_name_patterns(rag_query)
        
        if rag_name_intel['spam_confidence'] > 0.5:
            name_analysis['confidence'] = max(name_analysis['confidence'], rag_name_intel['spam_confidence'])
            name_analysis['evidence'].append('rag_name_spam_pattern')
        
        return name_analysis

    async def check_mass_sender_reputation(self, address: str) -> Dict:
        """
        Check sender reputation based on community learning about mass distribution
        Distinguishes between spam mass senders and legitimate airdrop senders
        """
        reputation_analysis = {
            'is_spam_sender': False,
            'is_legitimate_mass_sender': False,
            'spam_score': 0.0,
            'legitimacy_score': 0.0,
            'mass_sender_type': 'unknown',
            'evidence': []
        }
        
        # Check if this address has been reported for mass sending
        mass_sending_data = await self._get_mass_sending_feedback(address)
        
        if mass_sending_data['total_reports'] >= 3:  # Need minimum reports
            spam_rate = mass_sending_data['spam_reports'] / mass_sending_data['total_reports']
            legitimate_rate = mass_sending_data['legitimate_reports'] / mass_sending_data['total_reports']
            
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
        
        # Check learned patterns about this specific address
        address_reputation = await self._get_address_reputation_from_feedback(address)
        
        if address_reputation['total_interactions'] >= 2:
            quarantine_rate = address_reputation['quarantines'] / address_reputation['total_interactions']
            
            if quarantine_rate > 0.8:
                reputation_analysis['spam_score'] = max(reputation_analysis['spam_score'], quarantine_rate)
                reputation_analysis['evidence'].append(f'learned_address_pattern_{quarantine_rate:.1%}_quarantine_rate')
        
        # RAG query for address reputation
        rag_query = f"address {address} mass sender spam legitimate airdrop community reputation"
        rag_reputation = await self._query_rag_sender_reputation(rag_query)
        
        if rag_reputation['confidence'] > 0.5:
            if rag_reputation['sentiment'] == 'negative':
                reputation_analysis['spam_score'] = max(reputation_analysis['spam_score'], rag_reputation['confidence'])
                reputation_analysis['evidence'].append('rag_negative_sender_reputation')
            elif rag_reputation['sentiment'] == 'positive':
                reputation_analysis['legitimacy_score'] = max(reputation_analysis['legitimacy_score'], rag_reputation['confidence'])
                reputation_analysis['evidence'].append('rag_positive_sender_reputation')
        
        return reputation_analysis

    async def detect_suspicious_amounts(self, tx_data: Dict) -> Dict:
        """
        Detect suspicious amounts based on learned community patterns
        """
        amount = float(tx_data.get('value', 0))
        token_symbol = tx_data.get('token_symbol', '').upper()
        from_address = tx_data.get('from_address', '')
        
        suspicion_analysis = {
            'is_suspicious_amount': False,
            'suspicion_score': 0.0,
            'amount_category': self._categorize_amount(amount),
            'community_evidence': []
        }
        
        # 1. Check if this exact amount has been reported as spam
        exact_amount_feedback = await self._get_exact_amount_feedback(amount, token_symbol)
        
        if exact_amount_feedback['spam_reports'] > exact_amount_feedback['legitimate_reports'] and exact_amount_feedback['total_reports'] >= 2:
            suspicion_analysis['is_suspicious_amount'] = True
            suspicion_analysis['suspicion_score'] = 0.8
            suspicion_analysis['community_evidence'].append(f'exact_amount_spam_reports_{exact_amount_feedback["spam_reports"]}')
        
        # 2. Check amount range patterns
        amount_range_feedback = await self._get_amount_range_feedback(amount, token_symbol)
        
        if amount_range_feedback['total_feedback'] >= 5:
            spam_ratio = amount_range_feedback['spam_count'] / amount_range_feedback['total_feedback']
            if spam_ratio > 0.6:
                suspicion_analysis['is_suspicious_amount'] = True
                suspicion_analysis['suspicion_score'] = max(suspicion_analysis['suspicion_score'], spam_ratio)
                suspicion_analysis['community_evidence'].append(f'amount_range_spam_pattern_{spam_ratio:.1%}')
        
        # 3. Cross-reference with sender reputation
        sender_amount_patterns = await self._get_sender_amount_patterns(from_address, amount)
        
        if sender_amount_patterns['uses_identical_amounts'] and sender_amount_patterns['spam_feedback_rate'] > 0.7:
            suspicion_analysis['is_suspicious_amount'] = True
            suspicion_analysis['suspicion_score'] = max(suspicion_analysis['suspicion_score'], 0.9)
            suspicion_analysis['community_evidence'].append('sender_identical_amount_spam_pattern')
        
        return suspicion_analysis

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

    # Placeholder methods for database integration - implement with your actual database
    
    async def _get_amount_spam_feedback(self, amount_range: str, token_symbol: str) -> Dict:
        """Get community feedback about specific amount ranges"""
        # TODO: Query your database for user feedback on amounts in this range
        return {'total_feedback': 0, 'spam_count': 0, 'legitimate_count': 0}
    
    async def _get_word_spam_feedback(self, word: str) -> Dict:
        """Get feedback about how often this word appears in spam vs legitimate tokens"""
        # TODO: Query database for word occurrence patterns
        return {'total_occurrences': 0, 'spam_occurrences': 0, 'legitimate_occurrences': 0}
    
    async def _get_symbol_spam_feedback(self, symbol: str) -> Dict:
        """Get community feedback about specific token symbols"""
        # TODO: Query database for symbol feedback
        return {'total_feedback': 0, 'spam_count': 0, 'legitimate_count': 0}
    
    async def _get_mass_sending_feedback(self, address: str) -> Dict:
        """Get community reports about mass sending from this address"""
        # TODO: Query database for mass sending reports
        return {'total_reports': 0, 'spam_reports': 0, 'legitimate_reports': 0}
    
    async def _get_address_reputation_from_feedback(self, address: str) -> Dict:
        """Get address reputation from user feedback history"""
        # TODO: Query learned user feedback patterns
        return {'total_interactions': 0, 'approvals': 0, 'quarantines': 0}
    
    async def _get_exact_amount_feedback(self, amount: float, token_symbol: str) -> Dict:
        """Get feedback about this exact amount"""
        # TODO: Query database for exact amount feedback
        return {'total_reports': 0, 'spam_reports': 0, 'legitimate_reports': 0}
    
    async def _get_amount_range_feedback(self, amount: float, token_symbol: str) -> Dict:
        """Get feedback about amounts in this range"""
        amount_range = self._categorize_amount(amount)
        # TODO: Query database for amount range feedback
        return {'total_feedback': 0, 'spam_count': 0, 'legitimate_count': 0}
    
    async def _get_sender_amount_patterns(self, address: str, amount: float) -> Dict:
        """Check if sender uses identical amounts (spam pattern)"""
        # TODO: Analyze sender's transaction history for identical amounts
        return {'uses_identical_amounts': False, 'spam_feedback_rate': 0.0}
    
    # RAG query methods for pattern intelligence
    
    async def _query_rag_amount_patterns(self, query: str) -> Dict:
        """Query RAG for amount-based spam patterns"""
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
            return {'spam_confidence': 0.0, 'error': str(e)}
    
    async def _query_rag_name_patterns(self, query: str) -> Dict:
        """Query RAG for token name spam patterns"""
        try:
            rag_response = await self.rag_client.query(query)
            response_text = str(rag_response).lower()
            
            spam_indicators = ['fake', 'misleading', 'spam', 'scam', 'phishing']
            spam_count = sum(1 for indicator in spam_indicators if indicator in response_text)
            
            return {
                'spam_confidence': min(spam_count * 0.25, 1.0) if spam_count > 0 else 0.0,
                'evidence': f'rag_name_analysis_{spam_count}_indicators'
            }
        except Exception as e:
            return {'spam_confidence': 0.0, 'error': str(e)}
    
    async def _query_rag_sender_reputation(self, query: str) -> Dict:
        """Query RAG for sender reputation"""
        try:
            rag_response = await self.rag_client.query(query)
            response_text = str(rag_response).lower()
            
            negative_indicators = ['spam', 'scam', 'malicious', 'reported', 'avoid']
            positive_indicators = ['legitimate', 'verified', 'trusted', 'approved']
            
            negative_count = sum(1 for indicator in negative_indicators if indicator in response_text)
            positive_count = sum(1 for indicator in positive_indicators if indicator in response_text)
            
            if negative_count > positive_count:
                return {
                    'sentiment': 'negative',
                    'confidence': min(negative_count * 0.2, 1.0),
                    'evidence': f'rag_negative_sentiment_{negative_count}_indicators'
                }
            elif positive_count > negative_count:
                return {
                    'sentiment': 'positive', 
                    'confidence': min(positive_count * 0.2, 1.0),
                    'evidence': f'rag_positive_sentiment_{positive_count}_indicators'
                }
            else:
                return {'sentiment': 'neutral', 'confidence': 0.0, 'evidence': 'rag_neutral_sentiment'}
                
        except Exception as e:
            return {'sentiment': 'unknown', 'confidence': 0.0, 'error': str(e)}

    async def learn_spam_patterns_from_feedback(self, feedback_data: Dict):
        """
        Learn spam patterns from user feedback - extends the existing learning system
        """
        address = feedback_data['address']
        token_data = feedback_data.get('token_data', {})
        amount = float(token_data.get('value', 0))
        token_name = token_data.get('token_name', '').lower()
        token_symbol = token_data.get('token_symbol', '').upper()
        user_decision = feedback_data['decision']
        
        # Learn amount patterns
        await self._learn_amount_patterns(amount, token_symbol, user_decision)
        
        # Learn token name patterns
        await self._learn_name_patterns(token_name, token_symbol, user_decision)
        
        # Learn sender patterns
        await self._learn_sender_patterns(address, amount, user_decision)
        
        # Save spam pattern learning to RAG
        await self._save_spam_learning_to_rag(feedback_data)

    async def _learn_amount_patterns(self, amount: float, token_symbol: str, decision: str):
        """Learn from amount-based user decisions"""
        amount_range = self._categorize_amount(amount)
        pattern_key = f"amount_{amount_range}_{token_symbol}"
        
        if pattern_key not in self.learned_data.get('spam_patterns', {}):
            if 'spam_patterns' not in self.learned_data:
                self.learned_data['spam_patterns'] = {}
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
        # Learn from individual words in token name
        words = token_name.lower().split()
        
        for word in words:
            if len(word) >= 3:  # Only learn from meaningful words
                word_key = f"word_{word}"
                
                if word_key not in self.learned_data.get('name_patterns', {}):
                    if 'name_patterns' not in self.learned_data:
                        self.learned_data['name_patterns'] = {}
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
        
        if sender_key not in self.learned_data.get('sender_patterns', {}):
            if 'sender_patterns' not in self.learned_data:
                self.learned_data['sender_patterns'] = {}
            self.learned_data['sender_patterns'][sender_key] = {
                'amounts_used': [],
                'total_interactions': 0,
                'spam_interactions': 0,
                'identical_amount_usage': 0
            }
        
        sender_data = self.learned_data['sender_patterns'][sender_key]
        sender_data['total_interactions'] += 1
        sender_data['amounts_used'].append(amount)
        
        # Check for identical amount usage (spam indicator)
        if sender_data['amounts_used'].count(amount) > 1:
            sender_data['identical_amount_usage'] += 1
        
        if decision == 'quarantined':
            sender_data['spam_interactions'] += 1

    async def _save_spam_learning_to_rag(self, feedback_data: Dict):
        """Save spam pattern learning to RAG system"""
        address = feedback_data['address']
        token_data = feedback_data.get('token_data', {})
        decision = feedback_data['decision']
        amount = token_data.get('value', 0)
        token_name = token_data.get('token_name', '')
        
        # Create learning context for RAG
        if decision == 'quarantined':
            context = f"Spam pattern learned: Token {token_name} amount {amount} from address {address} was quarantined by user. "
            context += f"This indicates potential spam/unwanted token with these characteristics."
        else:
            context = f"Legitimate pattern learned: Token {token_name} amount {amount} from address {address} was approved by user. "
            context += f"This indicates legitimate token with these characteristics."
        
        context += f" Learning timestamp: {datetime.now().isoformat()}"
        
        try:
            await self.rag_client.save_context("spam_pattern_learning", context)
        except Exception as e:
            print(f"⚠️ Failed to save spam learning to RAG: {e}")