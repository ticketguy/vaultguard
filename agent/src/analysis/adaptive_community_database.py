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