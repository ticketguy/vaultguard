"""
Enhanced Smart Contract Analysis for Solana Programs
Deep analysis beyond basic function detection
"""

import asyncio
import re
import json
from typing import Dict, List, Optional
from datetime import datetime

class EnhancedContractAnalyzer:
    """
    Advanced Solana program analysis with security focus
    """
    
    def __init__(self):
        self.solana_program_patterns = {
            'dangerous_programs': {
                'token_drainers': [
                    'setAuthority',
                    'closeAccount', 
                    'transferChecked',
                    'burnChecked'
                ],
                'nft_manipulators': [
                    'updateMetadata',
                    'setCollectionSize',
                    'verifyCollection',
                    'unverifyCollection'
                ],
                'defi_exploits': [
                    'flashLoan',
                    'liquidate',
                    'emergencyWithdraw',
                    'adminWithdraw'
                ]
            },
            'program_authorities': {
                'centralized_control': ['updateAuthority', 'freezeAuthority', 'mintAuthority'],
                'upgrade_risks': ['programUpgrade', 'setUpgradeAuthority'],
                'emergency_powers': ['pause', 'emergency', 'admin']
            },
            'metadata_risks': {
                'fake_metadata': ['uri manipulation', 'name spoofing', 'symbol copying'],
                'hidden_traits': ['invisible characters', 'zero-width spaces', 'unicode tricks']
            }
        }
    
    async def deep_analyze_program(self, program_data: Dict) -> Dict:
        """
        Comprehensive Solana program analysis
        """
        analysis = {
            'program_type': 'unknown',
            'authority_analysis': {},
            'instruction_analysis': {},
            'metadata_analysis': {},
            'security_risks': [],
            'trust_score': 0.0,
            'user_impact_assessment': {},
            'recommendations': []
        }
        
        try:
            # 1. Identify program type
            analysis['program_type'] = await self._identify_program_type(program_data)
            
            # 2. Analyze authority structure
            analysis['authority_analysis'] = await self._analyze_authorities(program_data)
            
            # 3. Deep instruction analysis
            analysis['instruction_analysis'] = await self._analyze_instructions(program_data)
            
            # 4. Metadata security analysis
            if program_data.get('metadata'):
                analysis['metadata_analysis'] = await self._analyze_metadata_security(program_data)
            
            # 5. Calculate trust score
            analysis['trust_score'] = await self._calculate_program_trust_score(analysis)
            
            # 6. Assess user impact
            analysis['user_impact_assessment'] = await self._assess_user_impact(analysis)
            
            # 7. Generate security recommendations
            analysis['recommendations'] = await self._generate_security_recommendations(analysis)
            
            # 8. Identify security risks
            analysis['security_risks'] = await self._identify_security_risks(analysis)
        
        except Exception as e:
            analysis['error'] = f"Enhanced contract analysis failed: {str(e)}"
        
        return analysis
    
    async def _identify_program_type(self, program_data: Dict) -> str:
        """Identify the type of Solana program"""
        program_id = program_data.get('program_id', '').lower()
        instructions = program_data.get('instructions', [])
        
        # Well-known program IDs
        known_programs = {
            'tokenkegqfezyinwajbnbgkpfxcwubvf9ss623vq5da': 'token_program',
            'atokengpvbdgvxr1b2hvzbsiqw5xwh25eftnsljaknl': 'associated_token_program',
            'metaplexdxb1hcmkv1sjtmwgsevdl1ewn6srqucs': 'metaplex_program',
            'sw1tchmxdbyfdmv19m6bfvb31vdyrs6wgf3xnm': 'switchboard_oracle',
            'jup4xgcgtctqjf1vkl1pdqk3qsxtxjkxjxtpsn3dek4': 'jupiter_aggregator'
        }
        
        if program_id in known_programs:
            return known_programs[program_id]
        
        # Analyze instructions to determine type
        instruction_types = [instr.get('type', '').lower() for instr in instructions]
        
        if any('swap' in instr or 'trade' in instr for instr in instruction_types):
            return 'dex_program'
        elif any('mint' in instr or 'token' in instr for instr in instruction_types):
            return 'token_program'
        elif any('nft' in instr or 'metadata' in instr for instr in instruction_types):
            return 'nft_program'
        elif any('lend' in instr or 'borrow' in instr for instr in instruction_types):
            return 'lending_program'
        else:
            return 'custom_program'
    
    async def _analyze_authorities(self, program_data: Dict) -> Dict:
        """Analyze program authority structure"""
        authorities = {
            'upgrade_authority': program_data.get('upgrade_authority'),
            'program_authority': program_data.get('program_authority'),
            'centralization_risk': 0.0,
            'authority_risks': []
        }
        
        # Check for centralized control
        if authorities['upgrade_authority'] and authorities['upgrade_authority'] != 'none':
            authorities['centralization_risk'] += 0.4
            authorities['authority_risks'].append('upgradeable_program')
        
        # Check for multiple authorities controlled by same entity
        if (authorities['upgrade_authority'] == authorities['program_authority'] and 
            authorities['upgrade_authority'] is not None):
            authorities['centralization_risk'] += 0.3
            authorities['authority_risks'].append('single_point_of_control')
        
        # Check for emergency powers
        instructions = program_data.get('instructions', [])
        emergency_instructions = [
            instr for instr in instructions 
            if any(emergency in instr.get('type', '').lower() 
                  for emergency in self.solana_program_patterns['program_authorities']['emergency_powers'])
        ]
        
        if emergency_instructions:
            authorities['centralization_risk'] += 0.3
            authorities['authority_risks'].append('emergency_powers')
        
        return authorities
    
    async def _analyze_instructions(self, program_data: Dict) -> Dict:
        """Deep analysis of program instructions"""
        instructions = program_data.get('instructions', [])
        
        instruction_analysis = {
            'dangerous_instructions': [],
            'permission_requirements': [],
            'user_fund_risks': [],
            'instruction_complexity': 0.0
        }
        
        dangerous_patterns = self.solana_program_patterns['dangerous_programs']
        
        for instruction in instructions:
            instr_type = instruction.get('type', '').lower()
            
            # Check for dangerous instruction patterns
            for category, patterns in dangerous_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in instr_type:
                        instruction_analysis['dangerous_instructions'].append({
                            'instruction': instr_type,
                            'category': category,
                            'risk_level': self._get_instruction_risk_level(pattern)
                        })
            
            # Analyze permission requirements
            if 'authority' in instr_type or 'admin' in instr_type:
                instruction_analysis['permission_requirements'].append(instr_type)
            
            # Check for user fund risks
            if any(risk in instr_type for risk in ['transfer', 'burn', 'close', 'drain']):
                instruction_analysis['user_fund_risks'].append(instr_type)
        
        # Calculate instruction complexity
        instruction_analysis['instruction_complexity'] = len(instructions) / 10.0  # Normalize to 0-1
        
        return instruction_analysis
    
    async def _analyze_metadata_security(self, program_data: Dict) -> Dict:
        """Analyze metadata for security issues"""
        metadata = program_data.get('metadata', {})
        
        metadata_analysis = {
            'spoofing_risks': [],
            'hidden_content': [],
            'uri_security': {},
            'content_verification': {}
        }
        
        # Check for name/symbol spoofing
        name = metadata.get('name', '')
        symbol = metadata.get('symbol', '')
        
        if await self._check_unicode_spoofing(name):
            metadata_analysis['spoofing_risks'].append('name_unicode_spoofing')
        
        if await self._check_unicode_spoofing(symbol):
            metadata_analysis['spoofing_risks'].append('symbol_unicode_spoofing')
        
        # Check URI security
        uri = metadata.get('uri', '')
        if uri:
            metadata_analysis['uri_security'] = await self._analyze_uri_security(uri)
        
        # Check for hidden content
        metadata_analysis['hidden_content'] = await self._detect_hidden_content(metadata)
        
        return metadata_analysis
    
    async def _calculate_program_trust_score(self, analysis: Dict) -> float:
        """Calculate overall program trust score"""
        trust_factors = {
            'authority_trust': 1.0 - analysis['authority_analysis'].get('centralization_risk', 0),
            'instruction_safety': 1.0 - min(len(analysis['instruction_analysis']['dangerous_instructions']) / 5.0, 1.0),
            'metadata_integrity': 1.0 - min(len(analysis['metadata_analysis'].get('spoofing_risks', [])) / 3.0, 1.0),
            'complexity_penalty': 1.0 - min(analysis['instruction_analysis']['instruction_complexity'], 0.3)
        }
        
        # Weighted average
        weights = {'authority_trust': 0.4, 'instruction_safety': 0.3, 'metadata_integrity': 0.2, 'complexity_penalty': 0.1}
        
        trust_score = sum(trust_factors[factor] * weights[factor] for factor in trust_factors)
        return max(0.0, min(trust_score, 1.0))
    
    async def _assess_user_impact(self, analysis: Dict) -> Dict:
        """Assess potential impact on user"""
        user_impact = {
            'fund_loss_risk': 'low',
            'privacy_risk': 'low', 
            'control_loss_risk': 'low',
            'worst_case_scenario': '',
            'protection_level_needed': 'standard'
        }
        
        # Assess fund loss risk
        dangerous_count = len(analysis['instruction_analysis']['dangerous_instructions'])
        if dangerous_count > 3:
            user_impact['fund_loss_risk'] = 'high'
            user_impact['protection_level_needed'] = 'maximum'
        elif dangerous_count > 1:
            user_impact['fund_loss_risk'] = 'medium'
            user_impact['protection_level_needed'] = 'enhanced'
        
        # Assess control loss risk
        authority_risk = analysis['authority_analysis'].get('centralization_risk', 0)
        if authority_risk > 0.7:
            user_impact['control_loss_risk'] = 'high'
        elif authority_risk > 0.4:
            user_impact['control_loss_risk'] = 'medium'
        
        # Generate worst case scenario
        if user_impact['fund_loss_risk'] == 'high':
            user_impact['worst_case_scenario'] = 'Complete loss of funds through malicious program execution'
        elif user_impact['control_loss_risk'] == 'high':
            user_impact['worst_case_scenario'] = 'Loss of control over tokens/NFTs through authority manipulation'
        else:
            user_impact['worst_case_scenario'] = 'Minor inconvenience or temporary loss of access'
        
        return user_impact
    
    def _get_instruction_risk_level(self, pattern: str) -> str:
        """Get risk level for instruction pattern"""
        high_risk = ['emergencyWithdraw', 'adminWithdraw', 'closeAccount']
        medium_risk = ['setAuthority', 'transferChecked', 'burnChecked']
        
        if pattern in high_risk:
            return 'high'
        elif pattern in medium_risk:
            return 'medium'
        else:
            return 'low'
    
    async def _check_unicode_spoofing(self, text: str) -> bool:
        """Check for Unicode spoofing attacks"""
        if not text:
            return False
        
        # Check for common spoofing patterns
        spoofing_patterns = [
            '\u200b',  # Zero-width space
            '\u200c',  # Zero-width non-joiner
            '\u200d',  # Zero-width joiner
            '\ufeff',  # Zero-width no-break space
        ]
        
        return any(pattern in text for pattern in spoofing_patterns)
    
    async def _analyze_uri_security(self, uri: str) -> Dict:
        """Analyze URI for security issues"""
        uri_security = {
            'scheme': 'unknown',
            'security_level': 'unknown',
            'risks': []
        }
        
        if uri.startswith('https://'):
            uri_security['scheme'] = 'https'
            uri_security['security_level'] = 'good'
        elif uri.startswith('http://'):
            uri_security['scheme'] = 'http'
            uri_security['security_level'] = 'poor'
            uri_security['risks'].append('unencrypted_connection')
        elif uri.startswith('ipfs://'):
            uri_security['scheme'] = 'ipfs'
            uri_security['security_level'] = 'good'
        else:
            uri_security['scheme'] = 'unknown'
            uri_security['security_level'] = 'poor'
            uri_security['risks'].append('unknown_scheme')
        
        return uri_security
    
    async def _detect_hidden_content(self, metadata: Dict) -> List[str]:
        """Detect hidden content in metadata"""
        hidden_content = []
        
        for key, value in metadata.items():
            if isinstance(value, str):
                if await self._check_unicode_spoofing(value):
                    hidden_content.append(f'hidden_chars_in_{key}')
        
        return hidden_content
    
    async def _identify_security_risks(self, analysis: Dict) -> List[str]:
        """Identify all security risks"""
        risks = []
        
        # Authority risks
        risks.extend(analysis['authority_analysis'].get('authority_risks', []))
        
        # Instruction risks
        dangerous_instructions = analysis['instruction_analysis']['dangerous_instructions']
        for instr in dangerous_instructions:
            if instr['risk_level'] in ['high', 'medium']:
                risks.append(f"dangerous_instruction_{instr['category']}")
        
        # Metadata risks
        risks.extend(analysis['metadata_analysis'].get('spoofing_risks', []))
        
        # Trust score risks
        if analysis['trust_score'] < 0.3:
            risks.append('very_low_trust_score')
        elif analysis['trust_score'] < 0.6:
            risks.append('low_trust_score')
        
        return list(set(risks))  # Remove duplicates
    
    async def _generate_security_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        trust_score = analysis['trust_score']
        user_impact = analysis['user_impact_assessment']
        
        if trust_score < 0.5:
            recommendations.append("⚠️ Exercise extreme caution - this program has multiple security concerns")
        
        if user_impact['fund_loss_risk'] == 'high':
            recommendations.append("💰 High fund loss risk - only interact with small amounts for testing")
        
        if user_impact['control_loss_risk'] == 'high':
            recommendations.append("🔐 Risk of losing control over your tokens - verify all permissions carefully")
        
        authority_risk = analysis['authority_analysis'].get('centralization_risk', 0)
        if authority_risk > 0.7:
            recommendations.append("👑 Highly centralized program - single entity has significant control")
        
        if analysis['metadata_analysis'].get('spoofing_risks'):
            recommendations.append("🎭 Potential name/symbol spoofing detected - verify token identity")
        
        if not recommendations:
            recommendations.append("✅ Program appears to have standard security characteristics")
        
        return recommendations