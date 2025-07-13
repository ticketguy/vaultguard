"""
Enhanced Smart Contract Analysis for Solana Programs
Deep analysis of program security with REAL Solana blockchain data
Adapted to work with SecuritySensor framework
"""

import asyncio
import re
import json
from typing import Dict, List, Optional
from datetime import datetime
from .solana_rpc_client import IntelligentSolanaRPCClient as SolanaRPCClient
from src.rpc_config import FlexibleRPCConfig


class EnhancedContractAnalyzer:
    """
    Advanced Solana program analyzer for security threats and malicious patterns.
    Now uses REAL Solana blockchain data via RPC calls.
    """
    
    def __init__(self):
        # Initialize Solana RPC client for real data
        self.solana_client = SolanaRPCClient()  # Auto-detects rpc 

        
        # Solana-specific program security patterns (unchanged)
        self.solana_program_patterns = {
            'dangerous_programs': {
                'token_drainers': [
                    'setAuthority', 'closeAccount', 'transferChecked', 'burnChecked',
                    'freezeAccount', 'thawAccount', 'revokeAuthority'
                ],
                'nft_manipulators': [
                    'updateMetadata', 'setCollectionSize', 'verifyCollection',
                    'unverifyCollection', 'updatePrimarySaleHappened'
                ],
                'defi_exploits': [
                    'flashLoan', 'liquidate', 'emergencyWithdraw', 'adminWithdraw',
                    'rescueTokens', 'drainPool', 'emergencyStop'
                ]
            },
            'program_authorities': {
                'centralized_control': ['updateAuthority', 'freezeAuthority', 'mintAuthority'],
                'upgrade_risks': ['programUpgrade', 'setUpgradeAuthority', 'bpfUpgrader'],
                'emergency_powers': ['pause', 'emergency', 'admin', 'governance']
            },
            'metadata_risks': {
                'fake_metadata': ['uri_manipulation', 'name_spoofing', 'symbol_copying'],
                'hidden_traits': ['invisible_characters', 'zero_width_spaces', 'unicode_tricks']
            },
            'known_malicious_patterns': [
                'honeypot', 'rugpull', 'backdoor', 'timebomb', 'killswitch'
            ]
        }
        
        # Known safe program IDs on Solana (unchanged)
        self.known_safe_programs = {
            'system_programs': [
                '11111111111111111111111111111111',  # System Program
                'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',  # SPL Token
                'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'   # Associated Token
            ],
            'verified_dexes': [
                'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4',   # Jupiter
                '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8',   # Raydium
                'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc'    # Orca
            ],
            'verified_protocols': [
                'So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo',   # Solend
                '4MangoMjqJ2firMokCjjGgoK8d4MXcrgL7XJaL3w6fVg',   # Mango
                'JD3bq9hGdy38PuWQ4h2YJpELmHVGPPfFSuFkpzAd9zfu',   # Drift
                'CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK'    # Raydium CPMM
            ]
        }
    
    async def analyze_contract_for_drain_risk(self, contract_data: Dict) -> Dict:
        """
        Analyze Solana program for drain contract risks using REAL blockchain data.
        Primary method called by SecuritySensor for program analysis.
        """
        program_address = contract_data.get('address', '').strip()
        
        # Initialize analysis result for framework compatibility
        analysis_result = {
            'is_drain_contract': False,        # SecuritySensor expects this field
            'drain_risk_score': 0.0,
            'drain_warnings': [],
            'safe_contract': False,
            'permission_risks': [],
            'upgrade_risks': [],
            'threats_found': 0,               # SecuritySensor expects this field
            'analysis': "",                   # SecuritySensor expects analysis description
            'technical_details': {}           # Detailed technical analysis
        }
        
        if not program_address:
            analysis_result['analysis'] = "No program address provided"
            return analysis_result
        
        try:
            # Check if program is in known safe list
            if self._is_known_safe_program(program_address):
                analysis_result['safe_contract'] = True
                analysis_result['drain_risk_score'] = 0.0
                analysis_result['analysis'] = f"Verified safe program: {program_address}"
                return analysis_result
            
            # Use Solana RPC client to get REAL program data
            async with self.solana_client as client:
                # Get real program account info
                account_info = await client.get_program_account_info(program_address)
                
                if not account_info.get('exists'):
                    analysis_result['analysis'] = "Program does not exist on Solana blockchain"
                    analysis_result['drain_risk_score'] = 0.0
                    return analysis_result
                
                # Get real program bytecode
                bytecode = await client.get_program_bytecode(program_address)
                
                # Get real program instructions from transaction history
                instructions = await client.get_program_instructions(program_address)
                
                # Get real program metadata
                metadata = await client.get_program_metadata(program_address)
                
                # Get real authority information
                authority_info = await client.check_program_authorities(program_address)
                
                # Perform comprehensive program analysis with real data
                program_analysis = await self.deep_analyze_program({
                    'program_id': program_address,
                    'bytecode': bytecode,
                    'instructions': instructions,
                    'metadata': metadata,
                    'account_info': account_info,
                    'authority_info': authority_info
                })
            
            # Extract drain risk information from deep analysis
            analysis_result['technical_details'] = program_analysis
            analysis_result['drain_risk_score'] = program_analysis.get('security_risk_score', 0.0)
            
            # Determine if this is a drain contract
            if analysis_result['drain_risk_score'] > 0.7:
                analysis_result['is_drain_contract'] = True
                analysis_result['threats_found'] = 1
            
            # Extract security warnings
            analysis_result['drain_warnings'] = program_analysis.get('security_warnings', [])
            analysis_result['permission_risks'] = program_analysis.get('authority_risks', [])
            analysis_result['upgrade_risks'] = program_analysis.get('upgrade_risks', [])
            
            # Create analysis summary
            analysis_result['analysis'] = self._create_contract_analysis_summary(analysis_result)
        
        except Exception as e:
            # Handle analysis errors gracefully
            analysis_result['error'] = f"Contract analysis failed: {str(e)}"
            analysis_result['analysis'] = f"Contract analysis encountered an error: {str(e)}"
            analysis_result['drain_risk_score'] = 0.5  # Default to moderate risk on error
        
        return analysis_result
    
    async def deep_analyze_program(self, program_data: Dict) -> Dict:
        """
        Comprehensive Solana program security analysis using REAL blockchain data.
        Analyzes program structure, authorities, instructions, and potential risks.
        """
        analysis = {
            'program_type': 'unknown',
            'authority_analysis': {},
            'instruction_analysis': {},
            'metadata_analysis': {},
            'security_risks': [],
            'security_risk_score': 0.0,
            'security_warnings': [],
            'authority_risks': [],
            'upgrade_risks': [],
            'trust_score': 0.0,
            'user_impact_assessment': {},
            'recommendations': []
        }
        
        try:
            program_id = program_data.get('program_id', '')
            bytecode = program_data.get('bytecode', '')
            instructions = program_data.get('instructions', [])
            metadata = program_data.get('metadata', {})
            account_info = program_data.get('account_info', {})
            authority_info = program_data.get('authority_info', {})
            
            # 1. Identify program type using real data
            analysis['program_type'] = await self._identify_program_type_real(program_data)
            
            # 2. Analyze authority structure with real authority data
            authority_analysis = await self._analyze_authorities_real(authority_info, instructions)
            analysis['authority_analysis'] = authority_analysis
            
            # 3. Deep instruction analysis using real instruction history
            instruction_analysis = await self._analyze_instructions_real(instructions, program_id)
            analysis['instruction_analysis'] = instruction_analysis
            
            # 4. Metadata security analysis with real metadata
            if metadata:
                metadata_analysis = await self._analyze_metadata_security_real(metadata)
                analysis['metadata_analysis'] = metadata_analysis
            
            # 5. Check for known malicious patterns in real bytecode
            malicious_patterns = await self._detect_malicious_patterns_real(bytecode, instructions)
            analysis['malicious_patterns'] = malicious_patterns
            
            # 6. Calculate overall security risk score
            analysis['security_risk_score'] = await self._calculate_security_risk_score(analysis)
            
            # 7. Generate security warnings and risks
            analysis['security_warnings'] = await self._generate_security_warnings(analysis)
            analysis['authority_risks'] = authority_analysis.get('risks', [])
            analysis['upgrade_risks'] = authority_analysis.get('upgrade_risks', [])
            
            # 8. Calculate trust score
            analysis['trust_score'] = await self._calculate_program_trust_score(analysis)
            
            # 9. Assess potential user impact
            analysis['user_impact_assessment'] = await self._assess_user_impact(analysis)
            
            # 10. Generate security recommendations
            analysis['recommendations'] = await self._generate_security_recommendations(analysis)
            
        except Exception as e:
            analysis['error'] = f"Deep program analysis failed: {str(e)}"
            analysis['security_risk_score'] = 0.5
        
        return analysis
    
    async def _identify_program_type_real(self, program_data: Dict) -> str:
        """Identify program type using real blockchain data"""
        program_id = program_data.get('program_id', '')
        instructions = program_data.get('instructions', [])
        account_info = program_data.get('account_info', {})
        
        # Check against known program types first
        if program_id in self.known_safe_programs['system_programs']:
            return 'system_program'
        elif program_id in self.known_safe_programs['verified_dexes']:
            return 'verified_dex'
        elif program_id in self.known_safe_programs['verified_protocols']:
            return 'verified_defi_protocol'
        
        # Use real instruction patterns to determine type
        instruction_str = ' '.join(instructions).lower()
        
        # Analyze real instruction patterns
        if any(token_term in instruction_str for token_term in ['transfer', 'mint', 'burn', 'approve']):
            return 'token_program'
        elif any(nft_term in instruction_str for nft_term in ['metadata', 'collection', 'nft', 'create_metadata_accounts']):
            return 'nft_program'
        elif any(defi_term in instruction_str for defi_term in ['swap', 'pool', 'liquidity', 'deposit', 'withdraw']):
            return 'defi_program'
        elif any(game_term in instruction_str for game_term in ['game', 'play', 'reward', 'battle']):
            return 'gaming_program'
        
        # Check if it's executable (real program vs data account)
        if account_info.get('executable'):
            return 'custom_program'
        else:
            return 'data_account'
    
    async def _analyze_authorities_real(self, authority_info: Dict, instructions: List[str]) -> Dict:
        """Analyze program authority structure using real authority data"""
        authority_analysis = {
            'centralization_risk': 0.0,
            'upgrade_risk': 0.0,
            'authority_functions': [],
            'risks': [],
            'upgrade_risks': [],
            'emergency_controls': []
        }
        
        # Use real authority information
        if authority_info.get('is_upgradeable'):
            authority_analysis['upgrade_risk'] = 0.8
            authority_analysis['upgrade_risks'].append("Program is upgradeable - code can be changed")
            
            upgrade_authority = authority_info.get('upgrade_authority')
            if upgrade_authority:
                authority_analysis['upgrade_risks'].append(f"Upgrade authority: {upgrade_authority}")
        
        # Analyze real instruction patterns for authority functions
        centralized_functions = []
        for instruction in instructions:
            for control_type, functions in self.solana_program_patterns['program_authorities'].items():
                if any(func.lower() in instruction.lower() for func in functions):
                    centralized_functions.append(instruction)
                    if control_type == 'centralized_control':
                        authority_analysis['centralization_risk'] += 0.3
                    elif control_type == 'emergency_powers':
                        authority_analysis['emergency_controls'].append(instruction)
        
        authority_analysis['authority_functions'] = centralized_functions
        
        # Generate authority risk warnings based on real data
        if authority_analysis['centralization_risk'] > 0.5:
            authority_analysis['risks'].append("High centralization risk detected in program instructions")
        
        if authority_analysis['upgrade_risk'] > 0.3:
            authority_analysis['risks'].append("Program upgrade capability detected")
        
        if authority_analysis['emergency_controls']:
            authority_analysis['risks'].append(f"Emergency controls found: {', '.join(authority_analysis['emergency_controls'][:3])}")
        
        return authority_analysis
    
    async def _analyze_instructions_real(self, instructions: List[str], program_id: str) -> Dict:
        """Deep analysis of real program instructions for malicious patterns"""
        instruction_analysis = {
            'dangerous_instructions': [],
            'drain_risk_instructions': [],
            'token_manipulation': [],
            'nft_manipulation': [],
            'defi_exploits': [],
            'instruction_risk_score': 0.0,
            'real_usage_patterns': {}
        }
        
        # Analyze real instruction usage patterns
        instruction_counts = {}
        for instruction in instructions:
            instruction_counts[instruction] = instruction_counts.get(instruction, 0) + 1
        
        instruction_analysis['real_usage_patterns'] = instruction_counts
        
        # Check for dangerous instruction patterns in real data
        for instruction in instructions:
            instruction_lower = instruction.lower()
            
            # Check token drainer patterns
            for drain_func in self.solana_program_patterns['dangerous_programs']['token_drainers']:
                if drain_func.lower() in instruction_lower:
                    instruction_analysis['drain_risk_instructions'].append(instruction)
                    instruction_analysis['token_manipulation'].append(instruction)
                    instruction_analysis['instruction_risk_score'] += 0.4
            
            # Check NFT manipulation patterns
            for nft_func in self.solana_program_patterns['dangerous_programs']['nft_manipulators']:
                if nft_func.lower() in instruction_lower:
                    instruction_analysis['nft_manipulation'].append(instruction)
                    instruction_analysis['instruction_risk_score'] += 0.3
            
            # Check DeFi exploit patterns
            for defi_func in self.solana_program_patterns['dangerous_programs']['defi_exploits']:
                if defi_func.lower() in instruction_lower:
                    instruction_analysis['defi_exploits'].append(instruction)
                    instruction_analysis['instruction_risk_score'] += 0.5
        
        # Compile all dangerous instructions
        instruction_analysis['dangerous_instructions'] = list(set(
            instruction_analysis['drain_risk_instructions'] + 
            instruction_analysis['nft_manipulation'] + 
            instruction_analysis['defi_exploits']
        ))
        
        instruction_analysis['instruction_risk_score'] = min(instruction_analysis['instruction_risk_score'], 1.0)
        
        return instruction_analysis
    
    async def _analyze_metadata_security_real(self, metadata: Dict) -> Dict:
        """Analyze real program metadata for security risks"""
        metadata_analysis = {
            'metadata_risks': [],
            'spoofing_risk': 0.0,
            'deception_indicators': [],
            'uri_analysis': {},
            'real_metadata_found': bool(metadata)
        }
        
        if not metadata:
            metadata_analysis['metadata_risks'].append("No metadata found for program")
            return metadata_analysis
        
        # Check real metadata for spoofing
        name = metadata.get('name', '').lower()
        symbol = metadata.get('symbol', '').lower()
        uri = metadata.get('uri', '')
        
        # Check for popular token/project name spoofing using real data
        popular_tokens = ['usdc', 'usdt', 'sol', 'btc', 'eth', 'bnb', 'matic', 'jupiter', 'raydium']
        for token in popular_tokens:
            if token in name and name != token:
                metadata_analysis['spoofing_risk'] += 0.6
                metadata_analysis['deception_indicators'].append(f"Name spoofing detected: '{name}' mimics '{token}'")
        
        # Analyze real URI patterns
        if uri:
            metadata_analysis['uri_analysis']['uri'] = uri
            if any(suspicious in uri.lower() for suspicious in ['bit.ly', 'tinyurl', 'shortened']):
                metadata_analysis['metadata_risks'].append("Suspicious shortened URI detected")
                metadata_analysis['spoofing_risk'] += 0.3
            
            if uri.startswith('ipfs://'):
                metadata_analysis['metadata_risks'].append("IPFS URI detected - content may be mutable")
                metadata_analysis['spoofing_risk'] += 0.1
        
        # Check for unicode tricks in real metadata
        if any(ord(char) > 127 for char in name + symbol):
            metadata_analysis['deception_indicators'].append("Unicode characters detected - potential visual spoofing")
            metadata_analysis['spoofing_risk'] += 0.4
        
        return metadata_analysis
    
    async def _detect_malicious_patterns_real(self, bytecode: str, instructions: List[str]) -> Dict:
        """Detect known malicious patterns in real program code"""
        malicious_analysis = {
            'known_patterns': [],
            'pattern_risk_score': 0.0,
            'malicious_indicators': [],
            'bytecode_analysis': {},
            'instruction_patterns': {}
        }
        
        # Analyze real bytecode if available
        if bytecode:
            malicious_analysis['bytecode_analysis']['size'] = len(bytecode)
            malicious_analysis['bytecode_analysis']['has_bytecode'] = True
            
            # Check for known malicious patterns in real bytecode
            bytecode_lower = bytecode.lower()
            for pattern in self.solana_program_patterns['known_malicious_patterns']:
                if pattern in bytecode_lower:
                    malicious_analysis['known_patterns'].append(pattern)
                    malicious_analysis['malicious_indicators'].append(f"Malicious pattern in bytecode: {pattern}")
                    malicious_analysis['pattern_risk_score'] += 0.8
        
        # Analyze real instruction patterns
        if instructions:
            instruction_str = ' '.join(instructions).lower()
            malicious_analysis['instruction_patterns']['total_instructions'] = len(instructions)
            malicious_analysis['instruction_patterns']['unique_instructions'] = len(set(instructions))
            
            for pattern in self.solana_program_patterns['known_malicious_patterns']:
                if pattern in instruction_str:
                    malicious_analysis['known_patterns'].append(pattern)
                    malicious_analysis['malicious_indicators'].append(f"Malicious pattern in instructions: {pattern}")
                    malicious_analysis['pattern_risk_score'] += 0.6
        
        malicious_analysis['pattern_risk_score'] = min(malicious_analysis['pattern_risk_score'], 1.0)
        
        return malicious_analysis
    
    # Keep all the other methods unchanged (they don't have TODO placeholders)
    def _is_known_safe_program(self, program_id: str) -> bool:
        """Check if program ID is in known safe programs list"""
        for category in self.known_safe_programs.values():
            if program_id in category:
                return True
        return False
    
    async def _calculate_security_risk_score(self, analysis: Dict) -> float:
        """Calculate overall security risk score from all analysis components"""
        risk_score = 0.0
        
        # Authority risks
        authority_risk = analysis.get('authority_analysis', {}).get('centralization_risk', 0)
        upgrade_risk = analysis.get('authority_analysis', {}).get('upgrade_risk', 0)
        risk_score += (authority_risk * 0.25) + (upgrade_risk * 0.2)
        
        # Instruction risks
        instruction_risk = analysis.get('instruction_analysis', {}).get('instruction_risk_score', 0)
        risk_score += instruction_risk * 0.3
        
        # Metadata risks
        metadata_risk = analysis.get('metadata_analysis', {}).get('spoofing_risk', 0)
        risk_score += metadata_risk * 0.15
        
        # Malicious pattern risks
        pattern_risk = analysis.get('malicious_patterns', {}).get('pattern_risk_score', 0)
        risk_score += pattern_risk * 0.1
        
        return min(risk_score, 1.0)
    
    async def _generate_security_warnings(self, analysis: Dict) -> List[str]:
        """Generate user-friendly security warnings"""
        warnings = []
        
        # Authority warnings
        authority_risks = analysis.get('authority_analysis', {}).get('risks', [])
        warnings.extend([f"🔒 {risk}" for risk in authority_risks])
        
        # Instruction warnings
        dangerous_instructions = analysis.get('instruction_analysis', {}).get('dangerous_instructions', [])
        if dangerous_instructions:
            warnings.append(f"⚠️ Dangerous instructions detected: {', '.join(dangerous_instructions[:3])}")
        
        # Metadata warnings
        deception_indicators = analysis.get('metadata_analysis', {}).get('deception_indicators', [])
        warnings.extend([f"🎭 {indicator}" for indicator in deception_indicators])
        
        # Malicious pattern warnings
        malicious_indicators = analysis.get('malicious_patterns', {}).get('malicious_indicators', [])
        warnings.extend([f"🚨 {indicator}" for indicator in malicious_indicators])
        
        return warnings
    
    async def _calculate_program_trust_score(self, analysis: Dict) -> float:
        """Calculate program trust score (inverse of risk score)"""
        security_risk = analysis.get('security_risk_score', 0.5)
        trust_score = 1.0 - security_risk
        
        # Bonus for verified programs
        program_type = analysis.get('program_type', '')
        if 'verified' in program_type:
            trust_score = min(trust_score + 0.2, 1.0)
        
        return trust_score
    
    async def _assess_user_impact(self, analysis: Dict) -> Dict:
        """Assess potential impact on users"""
        security_risk = analysis.get('security_risk_score', 0)
        
        if security_risk > 0.8:
            impact = "critical"
            description = "High risk of token/NFT theft or manipulation"
        elif security_risk > 0.6:
            impact = "high"
            description = "Potential for financial loss or unauthorized actions"
        elif security_risk > 0.4:
            impact = "medium"
            description = "Some risk of unexpected behavior or loss of control"
        elif security_risk > 0.2:
            impact = "low"
            description = "Minor risks or centralization concerns"
        else:
            impact = "minimal"
            description = "Low risk, appears to be safe"
        
        return {
            'impact_level': impact,
            'description': description,
            'risk_score': security_risk
        }
    
    async def _generate_security_recommendations(self, analysis: Dict) -> List[str]:
        """Generate actionable security recommendations"""
        recommendations = []
        security_risk = analysis.get('security_risk_score', 0)
        
        if security_risk > 0.7:
            recommendations.extend([
                "🚫 Do not interact with this program",
                "⚠️ High risk of token/fund loss",
                "🔍 Verify program legitimacy before proceeding"
            ])
        elif security_risk > 0.5:
            recommendations.extend([
                "⚠️ Exercise extreme caution",
                "💰 Limit exposure and transaction amounts",
                "🔍 Research program thoroughly before use"
            ])
        elif security_risk > 0.3:
            recommendations.extend([
                "📋 Review program permissions carefully",
                "💡 Consider alternatives if available",
                "👀 Monitor for any unexpected behavior"
            ])
        
        # Specific recommendations based on real data analysis
        if analysis.get('authority_analysis', {}).get('upgrade_risk', 0) > 0.3:
            recommendations.append("🔄 Program can be upgraded - code may change")
        
        if analysis.get('instruction_analysis', {}).get('drain_risk_instructions'):
            recommendations.append("🔐 Program can manipulate your tokens - revoke approvals after use")
        
        return recommendations
    
    def _create_contract_analysis_summary(self, analysis_result: Dict) -> str:
        """Create human-readable analysis summary"""
        if analysis_result['is_drain_contract']:
            return f"Drain contract detected with {analysis_result['drain_risk_score']:.1%} risk score. Found {len(analysis_result['drain_warnings'])} security warnings."
        elif analysis_result['safe_contract']:
            return "Verified safe program - no security concerns detected."
        elif analysis_result['drain_risk_score'] > 0.4:
            return f"Elevated security risk ({analysis_result['drain_risk_score']:.1%}) - review program carefully before interaction."
        else:
            return f"Program appears safe with low risk score ({analysis_result['drain_risk_score']:.1%})."