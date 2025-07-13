"""
HOW THE SECURITY MODULES USE RPC 
====================================================

This shows how different parts of the security system use the RPC client
to get information from the Solana blockchain.

Think of it like different apps on your phone all using the same internet connection.
"""

# =============================================================================
# 1. BEHAVIOR ANALYZER - Watches wallet transaction patterns
# =============================================================================

class BehaviorAnalyzer:
    """
    Analyzes wallet behavior to detect suspicious patterns
    
    Simple explanation: Like a security guard watching how people normally
    behave, then noticing when someone acts weird.
    """
    
    def __init__(self):
        # 🎯 AUTO-DETECTION: Just create the RPC client, it finds the best setup automatically!
        self.solana_client = SolanaRPCClient()  # No parameters needed!
        
        # Set up behavior patterns to look for
        self.behavior_patterns = {
            'normal_user': {
                'avg_transaction_value': 50.0,        # Normal people spend ~$50 per transaction
                'transactions_per_day': 3.0,          # Normal people make ~3 transactions per day
                'common_time_hours': [9, 12, 15, 18, 21],  # Normal activity hours
                'preferred_tokens': ['SOL', 'USDC', 'USDT'],
                'typical_gas_usage': 0.001,
                'interaction_diversity': 0.3
            },
            'suspicious_patterns': {
                'rapid_transactions': 20,              # 20+ transactions per hour is suspicious
                'unusual_hours': [1, 2, 3, 4, 5],     # Activity at 1-5 AM is unusual
                'high_value_threshold': 10000,        # Transactions over $10,000
                'micro_transaction_count': 50,        # Many tiny transactions
                'new_wallet_age_days': 1              # Very new wallets are suspicious
            }
        }
    
    async def analyze_wallet_behavior(self, wallet_address: str) -> Dict:
        """
        Main function: Analyze how a wallet normally behaves
        
        Simple explanation: "Look at this wallet's transaction history and tell me
        if anything looks weird compared to normal user behavior."
        
        Steps:
        1. Get the wallet's transaction history from blockchain
        2. Analyze patterns (when do they transact, how much, etc.)
        3. Compare to normal behavior patterns
        4. Flag anything suspicious
        """
        
        # Use the RPC client to get real transaction data from blockchain
        try:
            # This calls get_wallet_transaction_history() which we added
            async with self.solana_client as client:
                transactions = await client.get_wallet_transaction_history(wallet_address, limit=50)
                
                if not transactions:
                    return {
                        'has_anomalies': False,
                        'anomaly_score': 0.0,
                        'analysis': 'No transaction history found'
                    }
                
                # Analyze the real transaction data
                analysis = self._analyze_transaction_patterns(transactions, wallet_address)
                return analysis
                
        except Exception as e:
            return {
                'has_anomalies': False,
                'anomaly_score': 0.0,
                'analysis': f'Analysis failed: {str(e)}'
            }
    
    def _analyze_transaction_patterns(self, transactions: List[Dict], wallet_address: str) -> Dict:
        """
        Analyze real transaction patterns for suspicious behavior
        
        Simple explanation: Look through all the transactions and check:
        - Are they making transactions at weird times?
        - Are the amounts normal or suspicious?
        - How often are they transacting?
        """
        
        anomaly_score = 0.0
        anomalies_found = []
        
        # Check transaction timing patterns
        unusual_hours = 0
        for tx in transactions:
            hour = tx['timestamp'].hour
            if hour in self.behavior_patterns['suspicious_patterns']['unusual_hours']:
                unusual_hours += 1
        
        if unusual_hours > len(transactions) * 0.3:  # More than 30% at unusual hours
            anomaly_score += 0.4
            anomalies_found.append(f"Unusual timing: {unusual_hours} transactions at 1-5 AM")
        
        # Check transaction values
        values = [tx.get('value', 0) for tx in transactions if tx.get('value', 0) > 0]
        if values:
            avg_value = sum(values) / len(values)
            max_value = max(values)
            
            # Check for value spikes
            if max_value > avg_value * 10:  # 10x spike
                anomaly_score += 0.3
                anomalies_found.append(f"Large value spike: ${max_value:.2f} vs avg ${avg_value:.2f}")
        
        # Check transaction frequency
        if len(transactions) > 20:  # More than 20 transactions in recent history
            anomaly_score += 0.2
            anomalies_found.append(f"High frequency: {len(transactions)} recent transactions")
        
        return {
            'has_anomalies': anomaly_score > 0.3,
            'anomaly_score': min(anomaly_score, 1.0),
            'anomalies_found': len(anomalies_found),
            'analysis': f"Behavior analysis complete. Found {len(anomalies_found)} potential issues.",
            'details': anomalies_found
        }


# =============================================================================
# 2. CONTRACT ANALYZER - Examines smart contracts for security risks
# =============================================================================

class EnhancedContractAnalyzer:
    """
    Analyzes Solana programs (smart contracts) for security risks
    
    Simple explanation: Like a building inspector checking if a house
    is safe before you buy it.
    """
    
    def __init__(self):
        # 🎯 AUTO-DETECTION: Just create the RPC client, it finds the best setup automatically!
        self.solana_client = SolanaRPCClient()  # No parameters needed!
        
        # Known dangerous patterns to look for in smart contracts
        self.dangerous_patterns = {
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
        }
        
        # Known safe programs we trust
        self.known_safe_programs = {
            '11111111111111111111111111111111': 'System Program',
            'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA': 'SPL Token Program',
            'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4': 'Jupiter DEX',
            '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8': 'Raydium DEX'
        }
    
    async def analyze_contract_for_drain_risk(self, contract_data: Dict) -> Dict:
        """
        Main function: Check if a smart contract is safe to interact with
        
        Simple explanation: "Look at this smart contract and tell me:
        - Can it steal my tokens?
        - Does it have suspicious code?
        - Can the owner change the rules later?"
        
        Steps:
        1. Get the contract's code from blockchain
        2. Check if it's a known safe contract
        3. Look for dangerous patterns in the code
        4. Check who controls the contract
        """
        
        program_address = contract_data.get('address', '').strip()
        
        if not program_address:
            return {
                'is_drain_contract': False,
                'drain_risk_score': 0.0,
                'analysis': 'No program address provided'
            }
        
        # Check if it's a known safe program first
        if program_address in self.known_safe_programs:
            return {
                'is_drain_contract': False,
                'drain_risk_score': 0.0,
                'safe_contract': True,
                'analysis': f"Known safe program: {self.known_safe_programs[program_address]}"
            }
        
        try:
            # Use RPC client to get real contract data from blockchain
            async with self.solana_client as client:
                # Get basic program info
                account_info = await client.get_program_account_info(program_address)
                
                if not account_info.get('exists'):
                    return {
                        'is_drain_contract': False,
                        'drain_risk_score': 0.0,
                        'analysis': 'Program does not exist on blockchain'
                    }
                
                # Get program bytecode for analysis
                bytecode = await client.get_program_bytecode(program_address)
                
                # Get recent instructions to see how it's been used
                instructions = await client.get_program_instructions(program_address)
                
                # Get metadata and authority info
                metadata = await client.get_program_metadata(program_address)
                authority_info = await client.check_program_authorities(program_address)
                
                # Analyze all this data for risks
                risk_analysis = self._analyze_program_risks({
                    'bytecode': bytecode,
                    'instructions': instructions,
                    'metadata': metadata,
                    'authority_info': authority_info
                })
                
                return risk_analysis
                
        except Exception as e:
            return {
                'is_drain_contract': False,
                'drain_risk_score': 0.5,  # Moderate risk if we can't analyze
                'analysis': f'Contract analysis failed: {str(e)}'
            }
    
    def _analyze_program_risks(self, program_data: Dict) -> Dict:
        """
        Analyze program data for security risks
        
        Simple explanation: Look through the contract's code and behavior
        to find red flags that might indicate it's dangerous.
        """
        
        risk_score = 0.0
        warnings = []
        
        # Check bytecode for dangerous patterns
        bytecode = program_data.get('bytecode', '')
        if bytecode:
            for pattern_type, patterns in self.dangerous_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in bytecode.lower():
                        risk_score += 0.3
                        warnings.append(f"Dangerous pattern found: {pattern} ({pattern_type})")
        
        # Check if program is upgradeable (can be changed by owner)
        authority_info = program_data.get('authority_info', {})
        if authority_info.get('is_upgradeable'):
            risk_score += 0.2
            warnings.append("Program is upgradeable - owner can change the code")
        
        # Check instruction patterns
        instructions = program_data.get('instructions', [])
        dangerous_instructions = []
        for instruction in instructions:
            for pattern_type, patterns in self.dangerous_patterns.items():
                if any(pattern.lower() in instruction.lower() for pattern in patterns):
                    dangerous_instructions.append(instruction)
        
        if dangerous_instructions:
            risk_score += 0.4
            warnings.append(f"Dangerous instructions found: {', '.join(dangerous_instructions[:3])}")
        
        # Determine final risk assessment
        is_drain_contract = risk_score > 0.7
        
        return {
            'is_drain_contract': is_drain_contract,
            'drain_risk_score': min(risk_score, 1.0),
            'drain_warnings': warnings,
            'safe_contract': risk_score < 0.2,
            'analysis': self._create_risk_summary(risk_score, len(warnings))
        }
    
    def _create_risk_summary(self, risk_score: float, warning_count: int) -> str:
        """Create human-readable risk summary"""
        if risk_score > 0.7:
            return f"HIGH RISK: Multiple security concerns detected ({warning_count} warnings)"
        elif risk_score > 0.4:
            return f"MEDIUM RISK: Some security concerns found ({warning_count} warnings)"
        elif risk_score > 0.2:
            return f"LOW RISK: Minor concerns detected ({warning_count} warnings)"
        else:
            return "SAFE: No significant security risks detected"


# =============================================================================
# 3. HOW SECURITY SENSOR COORDINATES EVERYTHING
# =============================================================================

class SecuritySensor:
    """
    Main coordinator that uses all the analysis modules
    
    Simple explanation: Like a security guard desk that coordinates
    all the different security systems (cameras, alarms, etc.)
    """
    
    def __init__(self, wallet_addresses: List[str], solana_rpc_url: str, rpc_api_key: str = "", rpc_provider_name: str = "Unknown", rag_client=None):
        # Store connection info
        self.wallet_addresses = wallet_addresses
        self.solana_rpc_url = solana_rpc_url
        self.rpc_api_key = rpc_api_key
        self.rpc_provider_name = rpc_provider_name
        
        # Initialize all the analysis modules
        # 🎯 NOW THEY ALL AUTO-DETECT THE BEST RPC!
        try:
            self.behavior_analyzer = BehaviorAnalyzer()  # No parameters needed!
            print("✅ BehaviorAnalyzer initialized with auto-detection")
        except Exception as e:
            self.behavior_analyzer = None
            print(f"❌ BehaviorAnalyzer failed: {e}")
        
        try:
            self.contract_analyzer = EnhancedContractAnalyzer()  # No parameters needed!
            print("✅ EnhancedContractAnalyzer initialized with auto-detection")
        except Exception as e:
            self.contract_analyzer = None
            print(f"❌ EnhancedContractAnalyzer failed: {e}")
        
        # Create our own RPC client for general use
        self.solana_client = SolanaRPCClient()  # Auto-detects best RPC
        
        print(f"🛡️ SecuritySensor initialized for {len(wallet_addresses)} wallets")
    
    async def analyze_transaction_security(self, transaction_data: Dict) -> Dict:
        """
        Main security analysis function
        
        Simple explanation: "Look at this transaction and tell me if it's safe"
        
        Uses multiple analysis modules:
        1. Behavior analysis - "Is this person acting normally?"
        2. Contract analysis - "Is this smart contract safe?"
        3. Other analyses as needed
        """
        
        security_analysis = {
            'overall_risk_score': 0.0,
            'warnings': [],
            'recommendations': [],
            'analyses_performed': []
        }
        
        # 1. Analyze wallet behavior if we have the module
        if self.behavior_analyzer:
            try:
                wallet_address = transaction_data.get('from_address', '')
                if wallet_address:
                    behavior_result = await self.behavior_analyzer.analyze_wallet_behavior(wallet_address)
                    security_analysis['behavior_analysis'] = behavior_result
                    security_analysis['overall_risk_score'] += behavior_result.get('anomaly_score', 0) * 0.3
                    security_analysis['analyses_performed'].append('behavior_analysis')
                    
                    if behavior_result.get('has_anomalies'):
                        security_analysis['warnings'].append("Unusual wallet behavior detected")
            except Exception as e:
                print(f"❌ Behavior analysis failed: {e}")
        
        # 2. Analyze smart contract if we have the module and contract address
        if self.contract_analyzer:
            try:
                program_id = transaction_data.get('program_id', '')
                if program_id:
                    contract_result = await self.contract_analyzer.analyze_contract_for_drain_risk({
                        'address': program_id
                    })
                    security_analysis['contract_analysis'] = contract_result
                    security_analysis['overall_risk_score'] += contract_result.get('drain_risk_score', 0) * 0.5
                    security_analysis['analyses_performed'].append('contract_analysis')
                    
                    if contract_result.get('is_drain_contract'):
                        security_analysis['warnings'].append("Contract has drain risk patterns")
                    
                    security_analysis['warnings'].extend(contract_result.get('drain_warnings', []))
            except Exception as e:
                print(f"❌ Contract analysis failed: {e}")
        
        # 3. Generate overall assessment and recommendations
        risk_score = min(security_analysis['overall_risk_score'], 1.0)
        
        if risk_score > 0.7:
            security_analysis['risk_level'] = 'HIGH'
            security_analysis['recommendations'].extend([
                "❌ DO NOT PROCEED with this transaction",
                "🚨 Multiple security risks detected",
                "🔍 Consider getting a second opinion"
            ])
        elif risk_score > 0.4:
            security_analysis['risk_level'] = 'MEDIUM'
            security_analysis['recommendations'].extend([
                "⚠️ PROCEED WITH CAUTION",
                "🔍 Review the warnings carefully",
                "💰 Consider reducing transaction amount"
            ])
        elif risk_score > 0.2:
            security_analysis['risk_level'] = 'LOW'
            security_analysis['recommendations'].extend([
                "✅ Generally safe to proceed",
                "👁️ Monitor for any unusual behavior"
            ])
        else:
            security_analysis['risk_level'] = 'SAFE'
            security_analysis['recommendations'].append("✅ No significant security risks detected")
        
        # 4. Create human-readable summary
        warnings_count = len(security_analysis['warnings'])
        analyses_count = len(security_analysis['analyses_performed'])
        
        security_analysis['summary'] = (
            f"Security analysis complete. "
            f"Risk level: {security_analysis['risk_level']} "
            f"({risk_score:.1%} risk score). "
            f"Performed {analyses_count} analyses, found {warnings_count} warnings."
        )
        
        return security_analysis


# =============================================================================
# 4. SIMPLE USAGE EXAMPLES
# =============================================================================

async def example_usage():
    """
    Examples of how to use the auto-detecting RPC system
    
    Simple explanation: "Here's how easy it is to use now!"
    """
    
    print("🎯 EXAMPLE: Auto-detecting RPC usage")
    print("=" * 50)
    
    # 1. Create analysis modules - they auto-detect the best RPC!
    print("1. Creating analysis modules...")
    
    behavior_analyzer = BehaviorAnalyzer()  # No parameters needed!
    contract_analyzer = EnhancedContractAnalyzer()  # No parameters needed!
    
    print("✅ All modules created with auto-detection")
    
    # 2. Analyze wallet behavior
    print("\n2. Analyzing wallet behavior...")
    
    wallet_address = "SomeWalletAddressHere123456789"
    behavior_result = await behavior_analyzer.analyze_wallet_behavior(wallet_address)
    
    print(f"   Result: {behavior_result['analysis']}")
    print(f"   Risk Score: {behavior_result['anomaly_score']:.1%}")
    
    # 3. Analyze smart contract
    print("\n3. Analyzing smart contract...")
    
    contract_address = "SomeProgramAddressHere123456789"
    contract_result = await contract_analyzer.analyze_contract_for_drain_risk({
        'address': contract_address
    })
    
    print(f"   Result: {contract_result['analysis']}")
    print(f"   Risk Score: {contract_result['drain_risk_score']:.1%}")
    
    # 4. Full security analysis
    print("\n4. Full transaction security analysis...")
    
    security_sensor = SecuritySensor(
        wallet_addresses=[wallet_address],
        solana_rpc_url="",  # Will be auto-detected
        rpc_api_key="",     # Will be auto-detected
        rpc_provider_name=""  # Will be auto-detected
    )
    
    transaction_data = {
        'from_address': wallet_address,
        'program_id': contract_address,
        'value': 100.0,
        'token_symbol': 'SOL'
    }
    
    security_result = await security_sensor.analyze_transaction_security(transaction_data)
    
    print(f"   Summary: {security_result['summary']}")
    print(f"   Risk Level: {security_result['risk_level']}")
    
    if security_result['warnings']:
        print("   Warnings:")
        for warning in security_result['warnings']:
            print(f"     - {warning}")
    
    if security_result['recommendations']:
        print("   Recommendations:")
        for rec in security_result['recommendations']:
            print(f"     - {rec}")


# =============================================================================
# 5. ENVIRONMENT VARIABLE EXAMPLES
# =============================================================================

def show_environment_examples():
    """
    Show how users can configure their RPC settings
    
    Simple explanation: "Here's how to set up your .env file for different scenarios"
    """
    
    print("🔧 ENVIRONMENT CONFIGURATION EXAMPLES")
    print("=" * 50)
    
    print("\n1. AUTO-DETECTION (Recommended):")
    print("   Just set your API keys, system picks the best one:")
    print("   ```")
    print("   HELIUS_API_KEY=your_helius_key_here")
    print("   QUICKNODE_API_KEY=your_quicknode_key_here")
    print("   QUICKNODE_ENDPOINT=your_endpoint_name")
    print("   ```")
    print("   → System will use Helius (first detected)")
    
    print("\n2. CUSTOM RPC OVERRIDE:")
    print("   Force use of a specific RPC:")
    print("   ```")
    print("   CUSTOM_SOLANA_RPC_URL=https://my-custom-rpc.com/api")
    print("   CUSTOM_SOLANA_API_KEY=my_custom_key")
    print("   ```")
    print("   → System will use your custom RPC even if others are available")
    
    print("\n3. EXPLICIT RPC URL:")
    print("   Use a specific RPC without API key:")
    print("   ```")
    print("   SOLANA_RPC_URL=https://another-provider.com/rpc")
    print("   ```")
    print("   → System will use this RPC (no API key)")
    
    print("\n4. PUBLIC RPC FALLBACK:")
    print("   Don't set any API keys:")
    print("   ```")
    print("   # No RPC variables set")
    print("   ```")
    print("   → System will use free public RPCs")
    
    print("\n🎯 PRIORITY ORDER:")
    print("   1. CUSTOM_SOLANA_RPC_URL (highest priority)")
    print("   2. SOLANA_RPC_URL (if not default)")
    print("   3. Auto-detected providers (Helius, QuickNode, etc.)")
    print("   4. Public RPCs (lowest priority)")


# =============================================================================
# 6. WHAT HAPPENS IN THE LOGS
# =============================================================================

def explain_log_output():
    """
    Explain what you'll see in the logs
    
    Simple explanation: "Here's what all those log messages mean"
    """
    
    print("📋 LOG OUTPUT EXPLAINED")
    print("=" * 50)
    
    print("\n✅ GOOD LOGS (What you want to see):")
    print("   🎯 Auto-detected: Helius (with API key)")
    print("   🔄 Initialized RPC client with 5 endpoints")
    print("   PRIMARY: Helius (with API key)")
    print("   FALLBACK-1: Solana_Public (public)")
    print("   → This means auto-detection worked perfectly!")
    
    print("\n⚠️ WARNING LOGS (Still works, but not optimal):")
    print("   ⚠️ Auto-detection failed, using single fallback")
    print("   📡 Primary RPC: Emergency_Fallback")
    print("   → Auto-detection failed, using basic public RPC")
    
    print("\n🔧 MANUAL OVERRIDE LOGS:")
    print("   🔧 Using custom Solana RPC: https://my-rpc.com...")
    print("   🔧 Manual config: Custom")
    print("   → User specified a custom RPC, system respects it")
    
    print("\n📊 DURING OPERATION:")
    print("   📡 Helius: getAccountInfo")
    print("   → Making RPC call to get account info")
    print("   ")
    print("   🔄 Retrying with different endpoint (attempt 2)")
    print("   → First RPC failed, trying backup automatically")
    print("   ")
    print("   🚫 Helius rate limited, reset in 60s")
    print("   → Hit rate limit, switching to backup RPC")
    print("   ")
    print("   ✅ Helius endpoint recovered")
    print("   → Primary RPC is working again")


if __name__ == "__main__":
    """
    If you run this file directly, it shows examples
    """
    print("🚀 RPC SYSTEM EXPLANATION AND EXAMPLES")
    print("=" * 60)
    
    show_environment_examples()
    print("\n")
    explain_log_output()
    
    print("\n🎯 TO USE IN YOUR CODE:")
    print("   # OLD WAY (complicated):")
    print("   rpc_config = FlexibleRPCConfig()")
    print("   url, provider, endpoints, key = rpc_config.detect_and_configure_rpc()")
    print("   client = SolanaRPCClient(rpc_api_key=key, primary_rpc_url=url, rpc_provider_name=provider)")
    print()
    print("   # NEW WAY (simple):")
    print("   client = SolanaRPCClient()  # Auto-detects everything!")
    print()
    print("   # Same for analysis modules:")
    print("   analyzer = BehaviorAnalyzer()  # No parameters needed!")
    print("   contract_checker = EnhancedContractAnalyzer()  # Auto-detects RPC!")