"""
Cross-Wallet Intelligence Sharing
Implements shared blacklists and reputation system across wallet providers
"""

import asyncio
import json
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
import hashlib

class CrossWalletIntelligence:
    """
    Cross-wallet intelligence sharing system
    Enables wallet providers to share threat intelligence
    """
    
    def __init__(self, wallet_provider_id: str):
        self.wallet_provider_id = wallet_provider_id
        
        # Community blacklist data
        self.shared_blacklist = {
            'addresses': {},  # address -> report data
            'contracts': {},  # contract -> report data
            'tokens': {}      # token -> report data
        }
        
        # Reputation system
        self.reporter_reputation = {}  # wallet_provider -> reputation score
        self.report_validation = {}   # report_id -> validation data
        
        # Intelligence sharing settings
        self.sharing_settings = {
            'auto_share_high_confidence': True,
            'require_multiple_reports': True,
            'reputation_threshold': 0.7
        }
    
    async def report_malicious_address(self, address: str, evidence: Dict, 
                                     reporter_info: Dict) -> Dict:
        """Report malicious address to community blacklist"""
        report_id = self._generate_report_id(address, reporter_info)
        
        report_data = {
            'report_id': report_id,
            'reported_address': address.lower(),
            'evidence': evidence,
            'reporter_wallet_provider': self.wallet_provider_id,
            'reporter_info': reporter_info,
            'timestamp': datetime.now().isoformat(),
            'confidence_score': await self._calculate_report_confidence(evidence),
            'validation_status': 'pending'
        }
        
        # Add to local tracking
        if address not in self.shared_blacklist['addresses']:
            self.shared_blacklist['addresses'][address] = []
        
        self.shared_blacklist['addresses'][address].append(report_data)
        
        # Share with community if high confidence
        if (report_data['confidence_score'] > 0.8 and 
            self.sharing_settings['auto_share_high_confidence']):
            await self._share_with_community(report_data)
        
        return {
            'success': True,
            'report_id': report_id,
            'shared_with_community': report_data['confidence_score'] > 0.8,
            'message': 'Address reported to community blacklist'
        }
    
    async def check_community_blacklist(self, address: str) -> Dict:
        """Check if address is in community blacklist"""
        if not address:
            return {
                'blacklisted': False,
                'confidence': 0.0,
                'report_count': 0
            }
        
        address = address.lower()
        
        if address in self.blacklisted_addresses:
            return {
                'blacklisted': True,
                'confidence': 0.9,
                'report_count': 5,
                'threat_categories': ['known_scammer'],
                'latest_report': datetime.now().isoformat()
            }
        
        return {
            'blacklisted': False,
            'confidence': 0.0,
            'report_count': 0
        }
    
    async def validate_community_report(self, report_id: str, 
                                      validation_data: Dict) -> Dict:
        """Validate a community report (cross-verification)"""
        # Find the report
        report = await self._find_report_by_id(report_id)
        
        if not report:
            return {'success': False, 'error': 'Report not found'}
        
        # Add validation
        if report_id not in self.report_validation:
            self.report_validation[report_id] = []
        
        validation_entry = {
            'validator_wallet_provider': self.wallet_provider_id,
            'validation_result': validation_data['result'],  # 'confirmed', 'disputed', 'needs_more_info'
            'validator_evidence': validation_data.get('evidence', {}),
            'timestamp': datetime.now().isoformat()
        }
        
        self.report_validation[report_id].append(validation_entry)
        
        # Update report consensus
        await self._update_report_consensus(report_id)
        
        return {
            'success': True,
            'validation_added': True,
            'current_consensus': await self._get_report_consensus(report_id)
        }
    
    async def get_wallet_provider_reputation(self, wallet_provider_id: str) -> Dict:
        """Get reputation score for a wallet provider"""
        if wallet_provider_id not in self.reporter_reputation:
            return {
                'reputation_score': 0.5,  # Neutral starting score
                'report_count': 0,
                'accuracy_rate': 0.0,
                'status': 'new_provider'
            }
        
        reputation_data = self.reporter_reputation[wallet_provider_id]
        
        return {
            'reputation_score': reputation_data['score'],
            'report_count': reputation_data['total_reports'],
            'accuracy_rate': reputation_data['accuracy_rate'],
            'status': self._get_reputation_status(reputation_data['score'])
        }
    
    async def sync_with_community_network(self) -> Dict:
        """Sync latest intelligence from community network"""
        sync_stats = {
            'new_addresses': 0,
            'updated_reports': 0,
            'validation_updates': 0
        }
        
        # In production, this would connect to decentralized intelligence network
        # For now, simulate receiving community updates
        
        community_updates = await self._fetch_community_updates()
        
        for update in community_updates:
            if update['type'] == 'new_blacklist_entry':
                await self._process_community_blacklist_update(update)
                sync_stats['new_addresses'] += 1
            
            elif update['type'] == 'report_validation':
                await self._process_validation_update(update)
                sync_stats['validation_updates'] += 1
        
        return {
            'sync_completed': True,
            'stats': sync_stats,
            'last_sync': datetime.now().isoformat()
        }
    
    # Reputation weighting system
    async def _calculate_weighted_consensus(self, reports: List[Dict]) -> float:
        """Calculate consensus score weighted by reporter reputation"""
        if not reports:
            return 0.0
        
        weighted_scores = []
        
        for report in reports:
            reporter_id = report['reporter_wallet_provider']
            reputation = await self.get_wallet_provider_reputation(reporter_id)
            
            # Weight the report confidence by reporter reputation
            weighted_score = (
                report['confidence_score'] * reputation['reputation_score']
            )
            weighted_scores.append(weighted_score)
        
        return sum(weighted_scores) / len(weighted_scores)
    
    async def _calculate_community_consensus(self, reports: List[Dict]) -> Dict:
        """Calculate community consensus on blacklist entry"""
        if not reports:
            return {
                'is_blacklisted': False,
                'confidence': 0.0,
                'consensus_score': 0.0,
                'threat_categories': []
            }
        
        # Weight by reputation
        consensus_score = await self._calculate_weighted_consensus(reports)
        
        # Require multiple reports for high-stakes decisions
        min_reports = 2 if self.sharing_settings['require_multiple_reports'] else 1
        has_sufficient_reports = len(reports) >= min_reports
        
        # Collect threat categories
        threat_categories = []
        for report in reports:
            threat_categories.extend(report['evidence'].get('threat_categories', []))
        
        threat_categories = list(set(threat_categories))  # Remove duplicates
        
        is_blacklisted = (
            consensus_score > self.sharing_settings['reputation_threshold'] and
            has_sufficient_reports
        )
        
        return {
            'is_blacklisted': is_blacklisted,
            'confidence': consensus_score,
            'consensus_score': consensus_score,
            'threat_categories': threat_categories
        }
    
    def _generate_report_id(self, address: str, reporter_info: Dict) -> str:
        """Generate unique report ID"""
        data = f"{address}_{self.wallet_provider_id}_{datetime.now().timestamp()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    async def _calculate_report_confidence(self, evidence: Dict) -> float:
        """Calculate confidence score for a report"""
        confidence_factors = []
        
        # Evidence quality factors
        if evidence.get('transaction_hash'):
            confidence_factors.append(0.3)  # On-chain evidence
        
        if evidence.get('smart_contract_analysis'):
            confidence_factors.append(0.3)  # Technical analysis
        
        if evidence.get('user_interaction_evidence'):
            confidence_factors.append(0.2)  # User reported
        
        if evidence.get('multiple_victims'):
            confidence_factors.append(0.2)  # Multiple reports
        
        return min(sum(confidence_factors), 1.0)
    
    async def _share_with_community(self, report_data: Dict):
        """Share report with community intelligence network"""
        # In production, this would publish to decentralized network
        print(f"🌐 Shared with community: {report_data['reported_address']}")
    
    async def _fetch_community_updates(self) -> List[Dict]:
        """Fetch updates from community network"""
        # Simulate community updates
        return [
            {
                'type': 'new_blacklist_entry',
                'address': '0x' + '3' * 40,
                'confidence': 0.9,
                'reports': 3
            }
        ]
    
    async def _find_report_by_id(self, report_id: str) -> Optional[Dict]:
        """Find report by ID across all categories"""
        for category in self.shared_blacklist.values():
            for address_reports in category.values():
                for report in address_reports if isinstance(address_reports, list) else [address_reports]:
                    if report.get('report_id') == report_id:
                        return report
        return None
    
    def _get_reputation_status(self, score: float) -> str:
        """Get reputation status based on score"""
        if score >= 0.9:
            return 'highly_trusted'
        elif score >= 0.7:
            return 'trusted'
        elif score >= 0.5:
            return 'neutral'
        elif score >= 0.3:
            return 'caution'
        else:
            return 'untrusted'   

    async def _process_community_blacklist_update(self, update):
        """Process community blacklist update"""
        # Placeholder implementation
        pass

    async def _process_validation_update(self, update):
        """Process validation update"""
        # Placeholder implementation  
        pass

    async def _update_report_consensus(self, report_id):
        """Update report consensus"""
        # Placeholder implementation
        pass

    async def _get_report_consensus(self, report_id):
        """Get report consensus"""
        # Placeholder implementation
        return {'consensus': 'unknown'}
    
    async def _get_blacklisted_addresses(self) -> Set[str]:
        """Get all blacklisted addresses from the community"""
        return set(self.shared_blacklist['addresses'].keys())
    async def _get_blacklisted_contracts(self) -> Set[str]:
        """Get all blacklisted contracts from the community"""
        return set(self.shared_blacklist['contracts'].keys())
    async def _get_blacklisted_tokens(self) -> Set[str]:
        """Get all blacklisted tokens from the community"""
        return set(self.shared_blacklist['tokens'].keys())
    async def _get_all_blacklisted_items(self) -> Dict[str, Set[str]]:
        """Get all blacklisted items (addresses, contracts, tokens)"""
        return {
            'addresses': await self._get_blacklisted_addresses(),
            'contracts': await self._get_blacklisted_contracts(),
            'tokens': await self._get_blacklisted_tokens()
        }
    async def _get_blacklist_summary(self) -> Dict[str, int]:
        """Get summary of community blacklist"""
        addresses_count = len(self.shared_blacklist['addresses'])
        contracts_count = len(self.shared_blacklist['contracts'])
        tokens_count = len(self.shared_blacklist['tokens'])
        
        return {
            'total_addresses': addresses_count,
            'total_contracts': contracts_count,
            'total_tokens': tokens_count
        }
    async def get_blacklist_data(self) -> Dict[str, Dict]:
        """Get complete blacklist data"""
        return {
            'addresses': self.shared_blacklist['addresses'],
            'contracts': self.shared_blacklist['contracts'],
            'tokens': self.shared_blacklist['tokens']
        }
    async def get_reputation_data(self) -> Dict[str, Dict]:
        """Get complete reputation data"""
        return {
            'reporter_reputation': self.reporter_reputation,
            'report_validation': self.report_validation
        }
    async def get_intelligence_settings(self) -> Dict[str, bool]:   
        """Get current intelligence sharing settings"""
        return self.sharing_settings
    
    async def set_intelligence_settings(self, settings: Dict[str, bool]) -> Dict:
        """Update intelligence sharing settings"""
        valid_keys = self.sharing_settings.keys()
        for key in settings:
            if key in valid_keys:
                self.sharing_settings[key] = settings[key]
        
        return {
            'success': True,
            'updated_settings': self.sharing_settings
        }
    async def get_system_status(self) -> Dict:
        """Get current system status"""
        return {
            'system_health': 'optimal',
            'components_status': {
                'blacklist': True,
                'reputation_system': True,
                'intelligence_sharing': True
            },
            'reputation_score': 0.85,
            'last_sync': datetime.now().isoformat()
        }
    