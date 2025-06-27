"""
Enhanced Community Threat Intelligence Database
Combines threat detection with legitimate project verification
Integrates with RAG system for shared intelligence
"""

from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
import json


class EnhancedCommunityDatabase:
    """
    Enhanced community database that maintains both:
    1. Threat intelligence (scammers, malicious contracts)
    2. Legitimate project verification (real airdrops, verified tokens)
    """
    
    def __init__(self):
        # Legitimate Solana projects database
        self.legitimate_projects = {
            # DEX and Trading Projects
            'jupiter': {
                'official_addresses': [
                    'JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN',
                    'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4'
                ],
                'token_symbols': ['JUP'],
                'token_names': ['jupiter', 'jup token'],
                'official_websites': ['jup.ag', 'jupiter.ag'],
                'social_handles': ['@JupiterExchange'],
                'airdrop_history': ['2024-01-31'],  # Known airdrop dates
                'reputation_score': 1.0,
                'verification_level': 'fully_verified',
                'category': 'dex',
                'description': 'Leading Solana DEX aggregator'
            },
            'orca': {
                'official_addresses': [
                    'orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE',
                    'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc'
                ],
                'token_symbols': ['ORCA'],
                'token_names': ['orca', 'orca token'],
                'official_websites': ['orca.so'],
                'social_handles': ['@orca_so'],
                'airdrop_history': ['2021-08-18'],
                'reputation_score': 0.95,
                'verification_level': 'fully_verified',
                'category': 'dex',
                'description': 'User-friendly DEX on Solana'
            },
            'raydium': {
                'official_addresses': [
                    '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8',
                    'RayZuc5yydRzDPPJDKhJ3eqJGnXdLSqgmJKwu73ZYzh'
                ],
                'token_symbols': ['RAY'],
                'token_names': ['raydium', 'ray token'],
                'official_websites': ['raydium.io'],
                'social_handles': ['@RaydiumProtocol'],
                'airdrop_history': ['2021-02-21'],
                'reputation_score': 0.95,
                'verification_level': 'fully_verified',
                'category': 'dex',
                'description': 'Automated market maker on Solana'
            },
            
            # Lending and DeFi
            'mango_markets': {
                'official_addresses': [
                    'MangoCzJ36AjZyKwVj3VnYU4GTonjfVEnJmvvWaxLac',
                    'mv3ekLzLbnVPNxjSKvqBpU3ZeZXPQdEC3bp5MDEBG68'
                ],
                'token_symbols': ['MNGO'],
                'token_names': ['mango', 'mango markets'],
                'official_websites': ['mango.markets'],
                'social_handles': ['@mangomarkets'],
                'airdrop_history': ['2021-09-14'],
                'reputation_score': 0.9,
                'verification_level': 'verified',
                'category': 'defi',
                'description': 'Decentralized trading platform'
            },
            'solend': {
                'official_addresses': [
                    'So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo',
                    'SLNDpmoWTVADgEdndyvWzroNL7zSi1dF9PC3xHGtPwp'
                ],
                'token_symbols': ['SLND'],
                'token_names': ['solend'],
                'official_websites': ['solend.fi'],
                'social_handles': ['@solendprotocol'],
                'airdrop_history': ['2022-01-12'],
                'reputation_score': 0.9,
                'verification_level': 'verified',
                'category': 'defi',
                'description': 'Algorithmic lending protocol'
            },
            
            # Infrastructure and Core
            'solana_foundation': {
                'official_addresses': [
                    'So11111111111111111111111111111111111111112'  # Wrapped SOL
                ],
                'token_symbols': ['SOL', 'WSOL'],
                'token_names': ['solana', 'wrapped solana'],
                'official_websites': ['solana.com', 'solana.org'],
                'social_handles': ['@solana'],
                'airdrop_history': [],  # No public airdrops
                'reputation_score': 1.0,
                'verification_level': 'fully_verified',
                'category': 'infrastructure',
                'description': 'Solana blockchain native token'
            },
            'pyth_network': {
                'official_addresses': [
                    'FsJ3A3u2vn5cTVofAjvy6y5kwABJAqYWpe4975bi2epH',
                    'PythUpgradeableLoaderState1111111111111111'
                ],
                'token_symbols': ['PYTH'],
                'token_names': ['pyth', 'pyth network'],
                'official_websites': ['pyth.network'],
                'social_handles': ['@PythNetwork'],
                'airdrop_history': ['2023-11-20'],
                'reputation_score': 0.95,
                'verification_level': 'fully_verified',
                'category': 'infrastructure',
                'description': 'Oracle network providing real-time data'
            },
            
            # Gaming and NFTs
            'magic_eden': {
                'official_addresses': [
                    'MEisE1HzehtrDpAAT8PnLHjpSSkRYakotTuJRPjTpo8',
                    'M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K'
                ],
                'token_symbols': ['ME'],
                'token_names': ['magic eden'],
                'official_websites': ['magiceden.io'],
                'social_handles': ['@MagicEden'],
                'airdrop_history': ['2024-12-10'],
                'reputation_score': 0.9,
                'verification_level': 'verified',
                'category': 'nft',
                'description': 'Leading Solana NFT marketplace'
            }
        }
        
        # Known malicious patterns and addresses
        self.threat_database = {
            'known_scammer_addresses': {
                # Example malicious addresses (replace with real data)
                '9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM': {
                    'threat_type': 'dust_attacker',
                    'first_reported': '2024-01-15',
                    'report_count': 47,
                    'description': 'Mass dust attack sender targeting new wallets',
                    'evidence': ['identical_amounts', 'mass_distribution', 'fake_tokens']
                },
                'DeadBeefCafeBabe1111111111111111111111111': {
                    'threat_type': 'drain_contract',
                    'first_reported': '2024-02-01',
                    'report_count': 23,
                    'description': 'Malicious contract attempting wallet drains',
                    'evidence': ['unlimited_approvals', 'hidden_functions', 'fake_metadata']
                }
            },
            'malicious_token_patterns': {
                'fake_token_indicators': [
                    'FAKE_USDC', 'ETHEREUM_2.0', 'FREE_SOL', 'BONUS_BTC',
                    'CLAIM_NOW', 'LIMITED_AIRDROP', 'EXCLUSIVE_TOKEN'
                ],
                'scam_keywords': [
                    'winner', 'congratulations', 'urgent', 'limited',
                    'exclusive', 'free', 'bonus', 'claim now'
                ],
                'suspicious_address_patterns': [
                    'dead', '1111', '0000', 'beef', 'fade', 'cafe'
                ]
            },
            'community_reports': {
                # User-reported threats with validation
                'pending_validation': [],
                'validated_threats': [],
                'false_positives': []
            }
        }
        
        # Legitimacy verification criteria
        self.verification_criteria = {
            'fully_verified': {
                'required_score': 0.9,
                'criteria': [
                    'official_website_verified',
                    'social_media_verified',
                    'team_doxxed',
                    'audit_completed',
                    'community_recognition'
                ]
            },
            'verified': {
                'required_score': 0.7,
                'criteria': [
                    'official_website',
                    'social_media_presence',
                    'active_development',
                    'community_support'
                ]
            },
            'community_approved': {
                'required_score': 0.5,
                'criteria': [
                    'positive_community_sentiment',
                    'transparent_tokenomics',
                    'no_red_flags'
                ]
            }
        }

    def verify_project_legitimacy(self, address: str, token_symbol: str, token_name: str) -> Dict:
        """
        Verify if a project/token is legitimate based on community database
        """
        verification_result = {
            'is_legitimate': False,
            'verification_level': 'unverified',
            'project_info': None,
            'legitimacy_score': 0.0,
            'verification_evidence': []
        }
        
        # Check against known legitimate projects
        for project_id, project_data in self.legitimate_projects.items():
            # Check by address
            if address in project_data['official_addresses']:
                verification_result.update({
                    'is_legitimate': True,
                    'verification_level': project_data['verification_level'],
                    'project_info': project_data,
                    'legitimacy_score': project_data['reputation_score'],
                    'verification_evidence': ['official_address_match', f'verified_as_{project_id}']
                })
                return verification_result
            
            # Check by token symbol
            if token_symbol.upper() in project_data['token_symbols']:
                verification_result.update({
                    'is_legitimate': True,
                    'verification_level': project_data['verification_level'],
                    'project_info': project_data,
                    'legitimacy_score': project_data['reputation_score'] * 0.9,  # Slightly lower for symbol match
                    'verification_evidence': ['token_symbol_match', f'verified_as_{project_id}']
                })
                return verification_result
            
            # Check by token name patterns
            token_name_lower = token_name.lower()
            for name_pattern in project_data['token_names']:
                if name_pattern in token_name_lower:
                    verification_result.update({
                        'is_legitimate': True,
                        'verification_level': project_data['verification_level'],
                        'project_info': project_data,
                        'legitimacy_score': project_data['reputation_score'] * 0.7,  # Lower for name pattern
                        'verification_evidence': ['token_name_pattern', f'likely_{project_id}']
                    })
                    # Don't return yet, keep checking for better matches
        
        return verification_result

    def check_threat_intelligence(self, address: str, token_name: str = "") -> Dict:
        """
        Check if address or token matches known threats
        """
        threat_result = {
            'is_threat': False,
            'threat_level': 'none',
            'threat_details': None,
            'evidence': []
        }
        
        # Check known scammer addresses
        if address in self.threat_database['known_scammer_addresses']:
            threat_info = self.threat_database['known_scammer_addresses'][address]
            threat_result.update({
                'is_threat': True,
                'threat_level': 'high',
                'threat_details': threat_info,
                'evidence': ['known_malicious_address'] + threat_info.get('evidence', [])
            })
            return threat_result
        
        # Check for malicious token patterns
        token_name_lower = token_name.lower()
        
        # Check fake token indicators
        for fake_token in self.threat_database['malicious_token_patterns']['fake_token_indicators']:
            if fake_token.lower() in token_name_lower:
                threat_result.update({
                    'is_threat': True,
                    'threat_level': 'high',
                    'threat_details': {'threat_type': 'fake_token', 'pattern': fake_token},
                    'evidence': ['fake_token_pattern', f'matches_{fake_token}']
                })
                return threat_result
        
        # Check scam keywords
        for scam_keyword in self.threat_database['malicious_token_patterns']['scam_keywords']:
            if scam_keyword in token_name_lower:
                threat_result.update({
                    'is_threat': True,
                    'threat_level': 'medium',
                    'threat_details': {'threat_type': 'suspicious_keyword', 'keyword': scam_keyword},
                    'evidence': ['scam_keyword', f'contains_{scam_keyword}']
                })
                # Don't return, check for more severe threats
        
        # Check suspicious address patterns
        address_lower = address.lower()
        for pattern in self.threat_database['malicious_token_patterns']['suspicious_address_patterns']:
            if pattern in address_lower:
                current_level = threat_result['threat_level']
                if current_level == 'none':
                    threat_result.update({
                        'is_threat': True,
                        'threat_level': 'low',
                        'threat_details': {'threat_type': 'suspicious_address', 'pattern': pattern},
                        'evidence': ['suspicious_address_pattern', f'contains_{pattern}']
                    })
        
        return threat_result

    def submit_community_report(self, report_data: Dict) -> Dict:
        """
        Submit a community report for validation
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
            'validation_votes': {'confirm': 0, 'deny': 0}
        }
        
        # Add to pending validation queue
        self.threat_database['community_reports']['pending_validation'].append(report)
        
        return {
            'success': True,
            'report_id': report['id'],
            'status': 'submitted_for_validation'
        }

    def get_community_sentiment(self, project_name: str, token_symbol: str) -> Dict:
        """
        Get community sentiment about a project
        This would integrate with your RAG system for real sentiment analysis
        """
        sentiment_analysis = {
            'overall_sentiment': 'neutral',
            'confidence': 0.5,
            'positive_indicators': [],
            'negative_indicators': [],
            'community_discussions': 0,
            'recent_mentions': 0
        }
        
        # Check if it's a known legitimate project
        for project_id, project_data in self.legitimate_projects.items():
            if token_symbol.upper() in project_data['token_symbols'] or project_name.lower() in project_data['token_names']:
                sentiment_analysis.update({
                    'overall_sentiment': 'positive',
                    'confidence': project_data['reputation_score'],
                    'positive_indicators': [
                        'verified_project',
                        f'established_{project_data["category"]}_protocol',
                        'active_community'
                    ]
                })
                break
        
        # TODO: Integrate with RAG system to analyze:
        # - Social media mentions
        # - Community forum discussions  
        # - Developer activity
        # - Recent news and announcements
        
        return sentiment_analysis

    def update_project_database(self, new_projects: Dict):
        """
        Update the legitimate projects database
        """
        for project_id, project_data in new_projects.items():
            if self._validate_project_data(project_data):
                self.legitimate_projects[project_id] = project_data
                print(f"✅ Added/updated project: {project_id}")
            else:
                print(f"❌ Invalid project data for: {project_id}")

    def update_threat_database(self, new_threats: Dict):
        """
        Update the threat database with new malicious addresses/patterns
        """
        if 'addresses' in new_threats:
            self.threat_database['known_scammer_addresses'].update(new_threats['addresses'])
        
        if 'patterns' in new_threats:
            for pattern_type, patterns in new_threats['patterns'].items():
                if pattern_type in self.threat_database['malicious_token_patterns']:
                    self.threat_database['malicious_token_patterns'][pattern_type].extend(patterns)

    def export_for_rag_system(self) -> Dict:
        """
        Export data in format suitable for RAG system ingestion
        """
        rag_data = {
            'legitimate_projects_context': [],
            'threat_intelligence_context': [],
            'community_reports_context': []
        }
        
        # Format legitimate projects for RAG
        for project_id, project_data in self.legitimate_projects.items():
            context = f"""
            Legitimate Project: {project_id.upper()}
            Token Symbol: {', '.join(project_data['token_symbols'])}
            Official Addresses: {', '.join(project_data['official_addresses'])}
            Verification Level: {project_data['verification_level']}
            Category: {project_data['category']}
            Description: {project_data['description']}
            Reputation Score: {project_data['reputation_score']}
            Known for: Legitimate {project_data['category']} project on Solana
            """
            rag_data['legitimate_projects_context'].append(context)
        
        # Format threat intelligence for RAG
        for address, threat_info in self.threat_database['known_scammer_addresses'].items():
            context = f"""
            Malicious Address: {address}
            Threat Type: {threat_info['threat_type']}
            Description: {threat_info['description']}
            Report Count: {threat_info['report_count']}
            Evidence: {', '.join(threat_info['evidence'])}
            Status: Known scammer - avoid all interactions
            """
            rag_data['threat_intelligence_context'].append(context)
        
        return rag_data

    def _validate_project_data(self, project_data: Dict) -> bool:
        """
        Validate project data structure
        """
        required_fields = [
            'official_addresses', 'token_symbols', 'token_names',
            'reputation_score', 'verification_level', 'category'
        ]
        
        for field in required_fields:
            if field not in project_data:
                return False
        
        return True

    def get_stats(self) -> Dict:
        """
        Get database statistics
        """
        return {
            'legitimate_projects': len(self.legitimate_projects),
            'known_threats': len(self.threat_database['known_scammer_addresses']),
            'pending_reports': len(self.threat_database['community_reports']['pending_validation']),
            'verification_levels': {
                'fully_verified': len([p for p in self.legitimate_projects.values() if p['verification_level'] == 'fully_verified']),
                'verified': len([p for p in self.legitimate_projects.values() if p['verification_level'] == 'verified']),
                'community_approved': len([p for p in self.legitimate_projects.values() if p['verification_level'] == 'community_approved'])
            }
        }


# Integration example with RAG system
class RAGCommunityIntegration:
    """
    Integration layer between Community Database and RAG system
    """
    
    def __init__(self, community_db: EnhancedCommunityDatabase, rag_client):
        self.community_db = community_db
        self.rag_client = rag_client
        
    async def sync_community_data_to_rag(self):
        """
        Sync community database to RAG system for intelligent queries
        """
        rag_data = self.community_db.export_for_rag_system()
        
        # Upload legitimate projects context
        for context in rag_data['legitimate_projects_context']:
            await self.rag_client.save_context("legitimate_projects", context)
        
        # Upload threat intelligence context  
        for context in rag_data['threat_intelligence_context']:
            await self.rag_client.save_context("threat_intelligence", context)
        
        print("✅ Community database synced to RAG system")
    
    async def query_enhanced_intelligence(self, query: str) -> Dict:
        """
        Query RAG system with enhanced community intelligence
        """
        # First check local database for quick lookups
        if "legitimate" in query.lower() or "verified" in query.lower():
            rag_context = "legitimate_projects"
        elif "scam" in query.lower() or "threat" in query.lower():
            rag_context = "threat_intelligence"
        else:
            rag_context = "general"
        
        # Query RAG system with context
        rag_response = await self.rag_client.query_with_context(query, rag_context)
        
        return {
            'rag_response': rag_response,
            'context_used': rag_context,
            'confidence': 0.8 if rag_context != "general" else 0.5
        }