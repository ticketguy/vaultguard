"""
Scam NFT Detection for Solana
Prevents deceptive NFTs from reaching main wallet
"""

import asyncio
import re
from typing import Dict, List, Optional
import hashlib

class NFTScamDetector:
    """
    Detect scam NFTs and fraudulent collections
    """
    
    def __init__(self):
        self.nft_scam_patterns = {
            'collection_spoofing': {
                'popular_collections': [
                    'okay bears', 'degenerate ape academy', 'solana monkey business',
                    'famous fox federation', 'aurory', 'degen dojo', 'thugbirdz',
                    'catalina whale mixer', 'solanapunks', 'blocksmith labs'
                ],
                'spoofing_techniques': [
                    'character_substitution', 'extra_spaces', 'unicode_tricks',
                    'similar_names', 'extra_words', 'misspellings'
                ]
            },
            'metadata_manipulation': {
                'fake_traits': ['unrealistic_rarity', 'copied_traits', 'inflated_stats'],
                'uri_manipulation': ['ipfs_hijacking', 'metadata_switching', 'broken_links'],
                'image_theft': ['copied_artwork', 'ai_generated_copies', 'low_quality_copies']
            },
            'economic_indicators': {
                'artificial_floor': ['bot_trading', 'wash_trading', 'fake_volume'],
                'pump_schemes': ['coordinated_buying', 'fake_hype', 'influencer_manipulation'],
                'rug_pull_signs': ['creator_selling', 'liquidity_removal', 'abandoned_project']
            },
            'technical_indicators': {
                'minting_anomalies': ['rapid_minting', 'oversupply', 'preminted_collection'],
                'contract_risks': ['upgradeable_metadata', 'centralized_control', 'hidden_functions'],
                'distribution_issues': ['unfair_launch', 'insider_minting', 'bot_minting']
            }
        }
    
    async def analyze_nft_scam_risk(self, nft_data: Dict) -> Dict:
        """
        Comprehensive NFT scam risk analysis
        """
        nft_analysis = {
            'is_scam_nft': False,
            'scam_risk_score': 0.0,
            'scam_indicators': [],
            'collection_analysis': {},
            'metadata_analysis': {},
            'economic_analysis': {},
            'technical_analysis': {},
            'recommended_action': 'allow'
        }
        
        try:
            # 1. Analyze collection for spoofing
            nft_analysis['collection_analysis'] = await self._analyze_collection_spoofing(nft_data)
            
            # 2. Analyze metadata integrity
            nft_analysis['metadata_analysis'] = await self._analyze_metadata_integrity(nft_data)
            
            # 3. Analyze economic indicators
            nft_analysis['economic_analysis'] = await self._analyze_economic_indicators(nft_data)
            
            # 4. Analyze technical aspects
            nft_analysis['technical_analysis'] = await self._analyze_technical_indicators(nft_data)
            
            # 5. Calculate overall scam risk
            nft_analysis['scam_risk_score'] = await self._calculate_nft_scam_risk(
                nft_analysis['collection_analysis'],
                nft_analysis['metadata_analysis'],
                nft_analysis['economic_analysis'],
                nft_analysis['technical_analysis']
            )
            
            # 6. Determine if this is a scam NFT
            nft_analysis['is_scam_nft'] = nft_analysis['scam_risk_score'] > 0.7
            
            # 7. Generate recommendation
            nft_analysis['recommended_action'] = await self._get_nft_recommendation(
                nft_analysis['scam_risk_score']
            )
            
            # 8. Compile all scam indicators
            nft_analysis['scam_indicators'] = await self._compile_nft_scam_indicators(
                nft_analysis
            )
        
        except Exception as e:
            nft_analysis['error'] = f"NFT scam analysis failed: {str(e)}"
        
        return nft_analysis
    
    async def _analyze_collection_spoofing(self, nft_data: Dict) -> Dict:
        """Analyze collection for spoofing attempts"""
        collection_analysis = {
            'is_spoofing_attempt': False,
            'spoofing_score': 0.0,
            'spoofing_indicators': [],
            'similar_collections': []
        }
        
        collection_name = nft_data.get('collection', {}).get('name', '').lower()
        if not collection_name:
            return collection_analysis
        
        # Check against popular collections
        popular_collections = self.nft_scam_patterns['collection_spoofing']['popular_collections']
        
        for popular_collection in popular_collections:
            similarity_score = await self._calculate_name_similarity(collection_name, popular_collection)
            
            if similarity_score > 0.8:  # High similarity threshold
                collection_analysis['similar_collections'].append({
                    'original': popular_collection,
                    'similarity': similarity_score,
                    'spoofing_technique': await self._identify_spoofing_technique(
                        collection_name, popular_collection
                    )
                })
                collection_analysis['spoofing_score'] = max(
                    collection_analysis['spoofing_score'], similarity_score
                )
        
        # Check for common spoofing techniques
        spoofing_techniques = await self._detect_spoofing_techniques(collection_name)
        collection_analysis['spoofing_indicators'].extend(spoofing_techniques)
        
        # Determine if this is a spoofing attempt
        collection_analysis['is_spoofing_attempt'] = (
            collection_analysis['spoofing_score'] > 0.8 or
            len(collection_analysis['spoofing_indicators']) >= 2
        )
        
        return collection_analysis
    
    async def _analyze_metadata_integrity(self, nft_data: Dict) -> Dict:
        """Analyze NFT metadata for integrity issues"""
        metadata_analysis = {
            'integrity_score': 1.0,
            'integrity_issues': [],
            'uri_analysis': {},
            'trait_analysis': {},
            'image_analysis': {}
        }
        
        metadata = nft_data.get('metadata', {})
        
        # Analyze URI
        uri = metadata.get('uri', '')
        if uri:
            metadata_analysis['uri_analysis'] = await self._analyze_metadata_uri(uri)
            if metadata_analysis['uri_analysis'].get('is_suspicious'):
                metadata_analysis['integrity_score'] -= 0.3
        
        # Analyze traits
        attributes = metadata.get('attributes', [])
        if attributes:
            metadata_analysis['trait_analysis'] = await self._analyze_nft_traits(attributes)
            if metadata_analysis['trait_analysis'].get('has_fake_traits'):
                metadata_analysis['integrity_score'] -= 0.4
        
        # Analyze image
        image = metadata.get('image', '')
        if image:
            metadata_analysis['image_analysis'] = await self._analyze_nft_image(image)
            if metadata_analysis['image_analysis'].get('is_stolen_artwork'):
                metadata_analysis['integrity_score'] -= 0.5
        
        # Compile integrity issues
        for analysis_type in ['uri_analysis', 'trait_analysis', 'image_analysis']:
            analysis_data = metadata_analysis[analysis_type]
            if isinstance(analysis_data, dict) and analysis_data.get('issues'):
                metadata_analysis['integrity_issues'].extend(analysis_data['issues'])
        
        # Ensure score doesn't go below 0
        metadata_analysis['integrity_score'] = max(metadata_analysis['integrity_score'], 0.0)
        
        return metadata_analysis
    
    async def _analyze_economic_indicators(self, nft_data: Dict) -> Dict:
        """Analyze economic indicators for scam patterns"""
        economic_analysis = {
            'economic_risk_score': 0.0,
            'economic_indicators': [],
            'price_analysis': {},
            'volume_analysis': {},
            'trading_analysis': {}
        }
        
        # Analyze price patterns
        price_data = nft_data.get('price_data', {})
        if price_data:
            economic_analysis['price_analysis'] = await self._analyze_price_patterns(price_data)
        
        # Analyze volume patterns
        volume_data = nft_data.get('volume_data', {})
        if volume_data:
            economic_analysis['volume_analysis'] = await self._analyze_volume_patterns(volume_data)
        
        # Analyze trading patterns
        trading_data = nft_data.get('trading_data', {})
        if trading_data:
            economic_analysis['trading_analysis'] = await self._analyze_trading_patterns(trading_data)
        
        # Calculate economic risk score
        risk_factors = [
            economic_analysis['price_analysis'].get('manipulation_score', 0) * 0.4,
            economic_analysis['volume_analysis'].get('artificial_score', 0) * 0.3,
            economic_analysis['trading_analysis'].get('wash_trading_score', 0) * 0.3
        ]
        
        economic_analysis['economic_risk_score'] = sum(risk_factors)
        
        return economic_analysis
    
    async def _analyze_technical_indicators(self, nft_data: Dict) -> Dict:
        """Analyze technical indicators"""
        technical_analysis = {
            'technical_risk_score': 0.0,
            'technical_indicators': [],
            'minting_analysis': {},
            'contract_analysis': {},
            'distribution_analysis': {}
        }
        
        # Analyze minting patterns
        mint_data = nft_data.get('mint_data', {})
        if mint_data:
            technical_analysis['minting_analysis'] = await self._analyze_minting_patterns(mint_data)
        
        # Analyze contract
        contract_data = nft_data.get('contract_data', {})
        if contract_data:
            technical_analysis['contract_analysis'] = await self._analyze_nft_contract(contract_data)
        
        # Analyze distribution
        distribution_data = nft_data.get('distribution_data', {})
        if distribution_data:
            technical_analysis['distribution_analysis'] = await self._analyze_distribution(distribution_data)
        
        # Calculate technical risk score
        risk_factors = [
            technical_analysis['minting_analysis'].get('anomaly_score', 0) * 0.4,
            technical_analysis['contract_analysis'].get('risk_score', 0) * 0.3,
            technical_analysis['distribution_analysis'].get('unfairness_score', 0) * 0.3
        ]
        
        technical_analysis['technical_risk_score'] = sum(risk_factors)
        
        return technical_analysis
    
    async def _calculate_nft_scam_risk(self, collection_analysis: Dict, metadata_analysis: Dict,
                                     economic_analysis: Dict, technical_analysis: Dict) -> float:
        """Calculate overall NFT scam risk score"""
        
        # Weight different analysis types
        weights = {
            'collection_spoofing': 0.3,
            'metadata_integrity': 0.25,
            'economic_indicators': 0.25,
            'technical_indicators': 0.2
        }
        
        risk_factors = [
            collection_analysis.get('spoofing_score', 0) * weights['collection_spoofing'],
            (1.0 - metadata_analysis.get('integrity_score', 1.0)) * weights['metadata_integrity'],
            economic_analysis.get('economic_risk_score', 0) * weights['economic_indicators'],
            technical_analysis.get('technical_risk_score', 0) * weights['technical_indicators']
        ]
        
        return min(sum(risk_factors), 1.0)
    
    async def _get_nft_recommendation(self, risk_score: float) -> str:
        """Get recommendation based on NFT risk score"""
        if risk_score > 0.9:
            return 'block_scam_nft'
        elif risk_score > 0.7:
            return 'quarantine_suspicious_nft'
        elif risk_score > 0.5:
            return 'warn_potential_scam'
        elif risk_score > 0.3:
            return 'flag_for_review'
        else:
            return 'allow'
    
    # Helper methods (implementations would connect to real data sources)
    async def _calculate_name_similarity(self, name1: str, name2: str) -> float:
        """Calculate similarity between collection names"""
        # Simple implementation - would use more sophisticated algorithm
        if name1 == name2:
            return 1.0
        
        # Check for character substitution
        if len(name1) == len(name2):
            diff_count = sum(c1 != c2 for c1, c2 in zip(name1, name2))
            if diff_count <= 2:  # Allow up to 2 character differences
                return 1.0 - (diff_count / len(name1) * 0.5)
        
        # Check for extra/missing characters
        if abs(len(name1) - len(name2)) <= 2:
            longer, shorter = (name1, name2) if len(name1) > len(name2) else (name2, name1)
            if shorter in longer or longer.replace(' ', '') == shorter.replace(' ', ''):
                return 0.9
        
        return 0.0
    
    async def _identify_spoofing_technique(self, spoofed_name: str, original_name: str) -> str:
        """Identify the spoofing technique used"""
        if len(spoofed_name) != len(original_name):
            return 'length_manipulation'
        elif spoofed_name.replace(' ', '') == original_name.replace(' ', ''):
            return 'space_manipulation'
        else:
            return 'character_substitution'
    
    async def _detect_spoofing_techniques(self, collection_name: str) -> List[str]:
        """Detect common spoofing techniques"""
        techniques = []
        
        # Check for excessive spaces
        if '  ' in collection_name:
            techniques.append('excessive_spaces')
        
        # Check for unicode tricks
        if any(ord(char) > 127 for char in collection_name):
            techniques.append('unicode_characters')
        
        # Check for common misspelling patterns
        if re.search(r'[0-9]', collection_name):
            techniques.append('number_substitution')
        
        return techniques
    
    async def _analyze_metadata_uri(self, uri: str) -> Dict:
        """Analyze metadata URI for issues"""
        return {'is_suspicious': False, 'issues': []}  # Placeholder
    
    async def _analyze_nft_traits(self, attributes: List[Dict]) -> Dict:
        """Analyze NFT traits for fake/copied traits"""
        return {'has_fake_traits': False, 'issues': []}  # Placeholder
    
    async def _analyze_nft_image(self, image_uri: str) -> Dict:
        """Analyze NFT image for stolen artwork"""
        return {'is_stolen_artwork': False, 'issues': []}  # Placeholder
    
    async def _analyze_price_patterns(self, price_data: Dict) -> Dict:
        """Analyze price patterns for manipulation"""
        return {'manipulation_score': 0.0}  # Placeholder
    
    async def _analyze_volume_patterns(self, volume_data: Dict) -> Dict:
        """Analyze volume patterns for artificial inflation"""
        return {'artificial_score': 0.0}  # Placeholder
    
    async def _analyze_trading_patterns(self, trading_data: Dict) -> Dict:
        """Analyze trading patterns for wash trading"""
        return {'wash_trading_score': 0.0}  # Placeholder
    
    async def _analyze_minting_patterns(self, mint_data: Dict) -> Dict:
        """Analyze minting patterns for anomalies"""
        return {'anomaly_score': 0.0}  # Placeholder
    
    async def _analyze_nft_contract(self, contract_data: Dict) -> Dict:
        """Analyze NFT contract for risks"""
        return {'risk_score': 0.0}  # Placeholder
    
    async def _analyze_distribution(self, distribution_data: Dict) -> Dict:
        """Analyze NFT distribution for unfairness"""
        return {'unfairness_score': 0.0}  # Placeholder
    
    async def _compile_nft_scam_indicators(self, nft_analysis: Dict) -> List[str]:
        """Compile all NFT scam indicators"""
        indicators = []
        
        # Collection spoofing indicators
        if nft_analysis['collection_analysis'].get('is_spoofing_attempt'):
            indicators.append('collection_spoofing')
        
        # Metadata integrity indicators
        integrity_issues = nft_analysis['metadata_analysis'].get('integrity_issues', [])
        indicators.extend([f'metadata_{issue}' for issue in integrity_issues])
        
        # Economic indicators
        if nft_analysis['economic_analysis'].get('economic_risk_score', 0) > 0.6:
            indicators.append('economic_manipulation')
        
        # Technical indicators
        if nft_analysis['technical_analysis'].get('technical_risk_score', 0) > 0.6:
            indicators.append('technical_anomalies')
        
        return list(set(indicators))  # Remove duplicates