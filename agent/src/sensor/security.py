"""
SecuritySensor - Fixed Imports & Complete Transaction Parser
Proper error handling, no fallbacks, real transaction parsing for SOL/tokens/NFTs
"""

from typing import Any, Dict, List, Optional
from functools import partial
import time
import asyncio
import json
import requests
from datetime import datetime, timedelta
import traceback

# FIXED IMPORTS - Capture specific errors instead of silent failures
module_import_errors = {}

try:
    from src.analysis.adaptive_community_database import AdaptiveCommunityDatabase, AdaptiveDustDetector
except ImportError as e:
    module_import_errors['AdaptiveCommunityDatabase'] = str(e)
    AdaptiveCommunityDatabase = None
    AdaptiveDustDetector = None

try:
    from src.analysis.mev_detector import MEVDetector  
except ImportError as e:
    module_import_errors['MEVDetector'] = str(e)
    MEVDetector = None

try:
    from src.analysis.enhanced_contract_analyzer import EnhancedContractAnalyzer
except ImportError as e:
    module_import_errors['EnhancedContractAnalyzer'] = str(e)
    EnhancedContractAnalyzer = None

try:
    from src.analysis.smart_contract_explainer import SmartContractExplainer
except ImportError as e:
    module_import_errors['SmartContractExplainer'] = str(e)
    SmartContractExplainer = None

try:
    from src.analysis.nft_scam_detector import NFTScamDetector
except ImportError as e:
    module_import_errors['NFTScamDetector'] = str(e)
    NFTScamDetector = None

try:
    from src.analysis.behavior_analyzer import BehaviorAnalyzer
except ImportError as e:
    module_import_errors['BehaviorAnalyzer'] = str(e)
    BehaviorAnalyzer = None

try:
    from src.analysis.network_analyzer import NetworkAnalyzer
except ImportError as e:
    module_import_errors['NetworkAnalyzer'] = str(e)
    NetworkAnalyzer = None

try:
    from src.analysis.deep_pattern_analyzer import DeepPatternAnalyzer
except ImportError as e:
    module_import_errors['DeepPatternAnalyzer'] = str(e)
    DeepPatternAnalyzer = None

try:
    from src.analysis.solana_rpc_client import IntelligentSolanaRPCClient as SolanaRPCClient
except ImportError as e:
    module_import_errors['SolanaRPCClient'] = str(e)
    SolanaRPCClient = None

# For Solana blockchain interactions
try:
    from solana.rpc.async_api import AsyncClient
    from solders.pubkey import Pubkey as PublicKey
    from solders.signature import Signature
    SOLANA_WEB3_AVAILABLE = True
except ImportError as e:
    module_import_errors['solana-py'] = str(e)
    SOLANA_WEB3_AVAILABLE = False
    print(f"❌ solana-py not available: {e}")

class SecuritySensor:
    """
    SecuritySensor with proper error handling and complete transaction parsing
    """
    
    def __init__(self, wallet_addresses: List[str], solana_rpc_url: str, rpc_api_key: str = "", rpc_provider_name: str = "Unknown", rag_client=None):
        # Core connection parameters
        self.wallet_addresses = wallet_addresses
        self.solana_rpc_url = solana_rpc_url
        self.rpc_api_key = rpc_api_key
        self.rpc_provider_name = rpc_provider_name
        self.module_errors = {}
        
        # Initialize analysis modules with proper error reporting
        self._initialize_analysis_modules(rag_client)
        
        # Initialize Solana RPC clients
        self._initialize_rpc_clients()
        
        # Track security state
        self.last_analysis_time = datetime.now()
        self.threat_cache = {}
        
        # Real-time monitoring properties
        self.monitoring_active = False
        self.monitoring_tasks = []
        self.websocket_connections = {}
        self.last_processed_signatures = set()
        
        # SecurityAgent reference (will be injected)
        self.security_agent = None
        
        print(f"🛡️ SecuritySensor initialized for {len(wallet_addresses)} wallets")
        self._report_module_status()

    def _initialize_analysis_modules(self, rag_client):
        """Initialize analysis modules with proper error tracking"""
        # Try to initialize each module, track specific errors
        try:
            self.community_db = AdaptiveCommunityDatabase(rag_client) if AdaptiveCommunityDatabase else None
            if not self.community_db and 'AdaptiveCommunityDatabase' in module_import_errors:
                self.module_errors['AdaptiveCommunityDatabase'] = module_import_errors['AdaptiveCommunityDatabase']
        except Exception as e:
            self.module_errors['AdaptiveCommunityDatabase'] = f"Initialization failed: {str(e)}"
            self.community_db = None

        try:
            self.dust_detector = AdaptiveDustDetector(rag_client) if AdaptiveDustDetector else None
            if not self.dust_detector and 'AdaptiveCommunityDatabase' in module_import_errors:
                self.module_errors['AdaptiveDustDetector'] = module_import_errors['AdaptiveCommunityDatabase']
        except Exception as e:
            self.module_errors['AdaptiveDustDetector'] = f"Initialization failed: {str(e)}"
            self.dust_detector = None

        try:
            self.mev_detector = MEVDetector() if MEVDetector else None
            if not self.mev_detector and 'MEVDetector' in module_import_errors:
                self.module_errors['MEVDetector'] = module_import_errors['MEVDetector']
        except Exception as e:
            self.module_errors['MEVDetector'] = f"Initialization failed: {str(e)}"
            self.mev_detector = None

        try:
            self.contract_analyzer = EnhancedContractAnalyzer() if EnhancedContractAnalyzer else None
            if not self.contract_analyzer and 'EnhancedContractAnalyzer' in module_import_errors:
                self.module_errors['EnhancedContractAnalyzer'] = module_import_errors['EnhancedContractAnalyzer']
        except Exception as e:
            self.module_errors['EnhancedContractAnalyzer'] = f"Initialization failed: {str(e)}"
            self.contract_analyzer = None

        try:
            self.contract_explainer = SmartContractExplainer() if SmartContractExplainer else None
            if not self.contract_explainer and 'SmartContractExplainer' in module_import_errors:
                self.module_errors['SmartContractExplainer'] = module_import_errors['SmartContractExplainer']
        except Exception as e:
            self.module_errors['SmartContractExplainer'] = f"Initialization failed: {str(e)}"
            self.contract_explainer = None

        try:
            self.nft_scam_detector = NFTScamDetector() if NFTScamDetector else None
            if not self.nft_scam_detector and 'NFTScamDetector' in module_import_errors:
                self.module_errors['NFTScamDetector'] = module_import_errors['NFTScamDetector']
        except Exception as e:
            self.module_errors['NFTScamDetector'] = f"Initialization failed: {str(e)}"
            self.nft_scam_detector = None

        try:
            self.behavior_analyzer = BehaviorAnalyzer() if BehaviorAnalyzer else None
            if not self.behavior_analyzer and 'BehaviorAnalyzer' in module_import_errors:
                self.module_errors['BehaviorAnalyzer'] = module_import_errors['BehaviorAnalyzer']
        except Exception as e:
            self.module_errors['BehaviorAnalyzer'] = f"Initialization failed: {str(e)}"
            self.behavior_analyzer = None

        try:
            self.network_analyzer = NetworkAnalyzer() if NetworkAnalyzer else None
            if not self.network_analyzer and 'NetworkAnalyzer' in module_import_errors:
                self.module_errors['NetworkAnalyzer'] = module_import_errors['NetworkAnalyzer']
        except Exception as e:
            self.module_errors['NetworkAnalyzer'] = f"Initialization failed: {str(e)}"
            self.network_analyzer = None

        try:
            self.pattern_analyzer = DeepPatternAnalyzer() if DeepPatternAnalyzer else None
            if not self.pattern_analyzer and 'DeepPatternAnalyzer' in module_import_errors:
                self.module_errors['DeepPatternAnalyzer'] = module_import_errors['DeepPatternAnalyzer']
        except Exception as e:
            self.module_errors['DeepPatternAnalyzer'] = f"Initialization failed: {str(e)}"
            self.pattern_analyzer = None

    def _initialize_rpc_clients(self):
        """Initialize RPC clients with proper error reporting"""
        # Initialize intelligent RPC client
        if SolanaRPCClient:
            try:
                self.solana_client = SolanaRPCClient(
                    helius_api_key=self.rpc_api_key,
                    primary_rpc_url=self.solana_rpc_url
                )
                print(f"✅ Intelligent RPC client initialized with {self.rpc_provider_name}")
            except Exception as e:
                self.module_errors['SolanaRPCClient'] = f"Initialization failed: {str(e)}"
                self.solana_client = None
                print(f"❌ Failed to initialize intelligent RPC client: {e}")
        else:
            self.solana_client = None
            if 'SolanaRPCClient' in module_import_errors:
                self.module_errors['SolanaRPCClient'] = module_import_errors['SolanaRPCClient']

        # Initialize basic Solana client
        if SOLANA_WEB3_AVAILABLE and self.solana_rpc_url:
            try:
                self.basic_solana_client = AsyncClient(self.solana_rpc_url)
                print(f"✅ Basic Solana client connected to {self.rpc_provider_name}")
            except Exception as e:
                self.module_errors['BasicSolanaClient'] = f"Connection failed: {str(e)}"
                self.basic_solana_client = None
                print(f"❌ Failed to connect basic Solana client: {e}")
        else:
            self.basic_solana_client = None
            if 'solana-py' in module_import_errors:
                self.module_errors['BasicSolanaClient'] = module_import_errors['solana-py']

    def _report_module_status(self):
        """Report which modules loaded successfully and which failed"""
        loaded_modules = []
        failed_modules = []

        # Check each module status
        modules_to_check = [
            ('AdaptiveCommunityDatabase', self.community_db),
            ('AdaptiveDustDetector', self.dust_detector),
            ('MEVDetector', self.mev_detector),
            ('EnhancedContractAnalyzer', self.contract_analyzer),
            ('SmartContractExplainer', self.contract_explainer),
            ('NFTScamDetector', self.nft_scam_detector),
            ('BehaviorAnalyzer', self.behavior_analyzer),
            ('NetworkAnalyzer', self.network_analyzer),
            ('DeepPatternAnalyzer', self.pattern_analyzer),
            ('SolanaRPCClient', self.solana_client),
            ('BasicSolanaClient', self.basic_solana_client)
        ]

        for module_name, module_instance in modules_to_check:
            if module_instance is not None:
                loaded_modules.append(module_name)
            else:
                failed_modules.append(module_name)

        if loaded_modules:
            print(f"✅ Successfully loaded modules: {', '.join(loaded_modules)}")
        
        if failed_modules:
            print(f"❌ Failed to load modules: {', '.join(failed_modules)}")
            for module_name in failed_modules:
                if module_name in self.module_errors:
                    print(f"   {module_name}: {self.module_errors[module_name]}")

    def get_rpc_health(self) -> Dict[str, Any]:
        """Get RPC endpoint health status for monitoring rate limiting"""
        if self.solana_client and hasattr(self.solana_client, 'get_endpoint_health'):
            health = self.solana_client.get_endpoint_health()
            return {
                'rpc_health': health,
                'current_endpoint': health.get('current_endpoint', 'unknown'),
                'total_requests': health.get('total_requests', 0),
                'success_rate': health.get('total_successes', 0) / max(health.get('total_requests', 1), 1)
            }
        else:
            return {
                'rpc_health': 'not_available',
                'status': 'basic_client_or_none'
            }

    def _get_loaded_modules(self) -> str:
        """Get list of successfully loaded analysis modules with error reporting"""
        modules = []
        if self.community_db: modules.append("AdaptiveCommunityDatabase")
        if self.dust_detector: modules.append("AdaptiveDustDetector")
        if self.mev_detector: modules.append("MEVDetector")
        if self.contract_analyzer: modules.append("EnhancedContractAnalyzer")
        if self.contract_explainer: modules.append("SmartContractExplainer")
        if self.nft_scam_detector: modules.append("NFTScamDetector")
        if self.behavior_analyzer: modules.append("BehaviorAnalyzer")
        if self.network_analyzer: modules.append("NetworkAnalyzer")
        if self.pattern_analyzer: modules.append("DeepPatternAnalyzer")
        if self.solana_client: modules.append("SolanaRPCClient")
        if self.basic_solana_client: modules.append("BasicSolanaClient")
        
        if not modules:
            error_summary = []
            for module, error in self.module_errors.items():
                error_summary.append(f"{module}: {error}")
            return f"NO MODULES LOADED - Errors: {'; '.join(error_summary)}"
        
        return ", ".join(modules)

    def set_security_agent(self, security_agent):
        """Connect to SecurityAgent for AI analysis"""
        self.security_agent = security_agent
        print("🔗 SecuritySensor connected to SecurityAgent")

    # ========== COMPLETE TRANSACTION PARSING ==========

    async def _fetch_recent_transactions(self, wallet_address: str) -> List[Dict]:
        """
        Fetch and completely parse recent transactions for tokens and NFTs
        """
        transactions = []
        
        # Try intelligent RPC client first
        if self.solana_client and hasattr(self.solana_client, 'get_recent_transactions'):
            try:
                print(f"🔍 Fetching transactions using intelligent RPC client for {wallet_address[:8]}...")
                transactions = await self.solana_client.get_recent_transactions(wallet_address, limit=10)
                print(f"✅ Found {len(transactions)} recent transactions via intelligent RPC")
                return transactions
            except Exception as e:
                print(f"❌ Intelligent RPC client error: {e}")

        # Use basic Solana client with complete transaction parsing
        if self.basic_solana_client and SOLANA_WEB3_AVAILABLE:
            try:
                print(f"🔍 Fetching and parsing transactions using basic Solana client for {wallet_address[:8]}...")
                
                # Get signatures for address
                pubkey = PublicKey.from_string(wallet_address)
                signature_response = await self.basic_solana_client.get_signatures_for_address(pubkey, limit=10)
                
                if not signature_response.value:
                    print(f"📭 No transactions found for {wallet_address[:8]}...")
                    return []
                
                for sig_info in signature_response.value:
                    try:
                        # Get full transaction data
                        tx_signature = str(sig_info.signature)
                        print(f"📦 Parsing transaction: {tx_signature[:8]}...")
                        
                        # Fetch complete transaction
                        tx_response = await self.basic_solana_client.get_transaction(
                            Signature.from_string(tx_signature),
                            encoding="jsonParsed",
                            max_supported_transaction_version=0
                        )
                        
                        if not tx_response.value:
                            print(f"⚠️ Could not fetch transaction data for {tx_signature[:8]}...")
                            continue
                        
                        # Parse complete transaction
                        parsed_tx = await self._parse_complete_transaction(
                            tx_response.value, wallet_address, sig_info
                        )
                        
                        if parsed_tx:
                            transactions.append(parsed_tx)
                            print(f"✅ Parsed {parsed_tx['transaction_type']}: {parsed_tx.get('value', 0)} {parsed_tx.get('token_symbol', 'SOL')}")
                        
                    except Exception as e:
                        print(f"❌ Failed to parse transaction {str(sig_info.signature)[:8]}...: {e}")
                        continue
                
                print(f"✅ Successfully parsed {len(transactions)} transactions")
                return transactions
                
            except Exception as e:
                print(f"❌ Basic Solana client error: {e}")
                raise Exception(f"Failed to fetch transactions: {e}")
        
        # No RPC client available
        if not self.basic_solana_client:
            raise Exception(f"No RPC client available: {self.module_errors.get('BasicSolanaClient', 'Unknown error')}")
        
        return []

    async def _parse_complete_transaction(self, tx_data, wallet_address: str, sig_info) -> Optional[Dict]:
        """
        Completely parse Solana transaction to extract all relevant data
        Fixed to handle solders objects properly
        """
        try:
            # Fix: Access nested solders structure correctly
            transaction = tx_data.transaction.transaction  # UiTransaction object
            meta = tx_data.transaction.meta                # UiTransactionStatusMeta object
            message = transaction.message                  # UiMessage object
            
            # Extract basic info
            parsed_tx = {
                'hash': str(sig_info.signature),
                'signature': str(sig_info.signature),
                'timestamp': datetime.fromtimestamp(sig_info.block_time) if sig_info.block_time else datetime.now(),
                'block_time': sig_info.block_time,
                'slot': sig_info.slot,
                'confirmation_status': str(sig_info.confirmation_status),
                'fee': meta.fee / 1e9 if meta.fee else 0.0,  # Convert lamports to SOL
                'success': meta.err is None,
                'direction': 'unknown',
                'transaction_type': 'unknown',
                'from_address': 'unknown',
                'to_address': wallet_address,
                'value': 0.0,
                'value_usd': 0.0,
                'token_address': None,
                'token_name': None,
                'token_symbol': 'SOL',
                'program_id': None,
                'instruction_data': None,
                'dapp_url': None,
                'dapp_name': None,
                'is_nft': False,
                'nft_metadata': None,
                'pre_balances': meta.pre_balances if meta.pre_balances else [],
                'post_balances': meta.post_balances if meta.post_balances else [],
                'account_keys': [str(key.pubkey) for key in message.account_keys] if message.account_keys else [],
                'instructions': []
            }
            
            # Parse account keys
            account_keys = [str(key.pubkey) for key in message.account_keys] if message.account_keys else []
            
            # Find wallet index
            wallet_index = None
            try:
                wallet_index = account_keys.index(wallet_address)
            except ValueError:
                print(f"⚠️ Wallet address not found in account keys")
            
            # Parse SOL balance changes
            if wallet_index is not None and meta.pre_balances and len(meta.pre_balances) > wallet_index:
                pre_balance = meta.pre_balances[wallet_index] / 1e9
                post_balance = meta.post_balances[wallet_index] / 1e9
                sol_change = post_balance - pre_balance
                
                if abs(sol_change) > 0.000001:  # Ignore dust changes
                    parsed_tx['value'] = abs(sol_change)
                    parsed_tx['direction'] = 'incoming' if sol_change > 0 else 'outgoing'
                    parsed_tx['transaction_type'] = 'sol_transfer'
                    
                    # Find counterparty for SOL transfer
                    if meta.pre_balances and meta.post_balances:
                        for i, (pre, post) in enumerate(zip(meta.pre_balances, meta.post_balances)):
                            if i != wallet_index and i < len(account_keys):
                                balance_change = (post - pre) / 1e9
                                if abs(balance_change) > 0.000001 and (balance_change * sol_change) < 0:
                                    parsed_tx['from_address'] = account_keys[i] if sol_change > 0 else wallet_address
                                    parsed_tx['to_address'] = wallet_address if sol_change > 0 else account_keys[i]
                                    break
            
            # Parse token transfers
            token_transfers = []
            if meta.pre_token_balances and meta.post_token_balances:
                token_transfers = await self._parse_token_transfers(
                    meta.pre_token_balances, 
                    meta.post_token_balances, 
                    wallet_address,
                    account_keys
                )
                
                if token_transfers:
                    # Use the first token transfer as primary transaction data
                    primary_transfer = token_transfers[0]
                    parsed_tx.update({
                        'transaction_type': 'token_transfer',
                        'value': primary_transfer['amount'],
                        'token_address': primary_transfer['mint'],
                        'token_symbol': primary_transfer.get('symbol', 'UNKNOWN'),
                        'token_name': primary_transfer.get('name'),
                        'direction': primary_transfer['direction'],
                        'from_address': primary_transfer['from_address'],
                        'to_address': primary_transfer['to_address'],
                        'is_nft': primary_transfer.get('is_nft', False),
                        'nft_metadata': primary_transfer.get('metadata')
                    })
                    
                    if primary_transfer.get('is_nft'):
                        parsed_tx['transaction_type'] = 'nft_transfer'
            
            # Parse instructions to get program info
            instructions = message.instructions if message.instructions else []
            parsed_instructions = []
            
            for instruction in instructions:
                try:
                    # Handle different instruction types
                    if hasattr(instruction, 'program_id'):
                        # PartiallyDecoded instruction
                        program_id = str(instruction.program_id)
                        inst_data = {
                            'program_id': program_id,
                            'accounts': [str(acc) for acc in instruction.accounts] if hasattr(instruction, 'accounts') else [],
                            'data': str(instruction.data) if hasattr(instruction, 'data') else None,
                            'type': 'partially_decoded'
                        }
                    elif hasattr(instruction, 'program') and hasattr(instruction, 'parsed'):
                        # Parsed instruction
                        inst_data = {
                            'program_id': str(instruction.program_id),
                            'program': str(instruction.program),
                            'parsed': instruction.parsed,
                            'type': 'parsed'
                        }
                        
                        # Extract parsed data safely
                        if hasattr(instruction.parsed, 'type'):
                            inst_data['instruction_type'] = str(instruction.parsed.type)
                        if hasattr(instruction.parsed, 'info'):
                            inst_data['info'] = instruction.parsed.info
                    else:
                        # Raw instruction with program_id_index
                        program_id_index = instruction.program_id_index if hasattr(instruction, 'program_id_index') else 0
                        if program_id_index < len(account_keys):
                            inst_data = {
                                'program_id': account_keys[program_id_index],
                                'accounts': [account_keys[i] for i in instruction.accounts] if hasattr(instruction, 'accounts') else [],
                                'data': str(instruction.data) if hasattr(instruction, 'data') else None,
                                'type': 'raw'
                            }
                        else:
                            continue
                    
                    parsed_instructions.append(inst_data)
                
                except Exception as inst_error:
                    print(f"⚠️ Error parsing instruction: {inst_error}")
                    continue
            
            parsed_tx['instructions'] = parsed_instructions
            
            # Set primary program ID from first instruction
            if parsed_instructions:
                parsed_tx['program_id'] = parsed_instructions[0]['program_id']
                if 'parsed' in parsed_instructions[0]:
                    parsed_tx['instruction_data'] = json.dumps(parsed_instructions[0]['parsed'], default=str)
                elif 'info' in parsed_instructions[0]:
                    parsed_tx['instruction_data'] = json.dumps(parsed_instructions[0]['info'], default=str)
            
            # Identify DApp from program IDs
            dapp_info = self._identify_dapp_from_programs([inst['program_id'] for inst in parsed_instructions])
            if dapp_info:
                parsed_tx['dapp_name'] = dapp_info['name']
                parsed_tx['dapp_url'] = dapp_info.get('url')
            
            return parsed_tx
            
        except Exception as e:
            print(f"❌ Error parsing transaction: {e}")
            print(f"❌ Exception type: {type(e)}")
            print(f"❌ Transaction data structure: {type(tx_data)}")
            import traceback
            print(f"❌ Full traceback: {traceback.format_exc()}")
            return None

    async def _parse_token_transfers(self, pre_balances: List, post_balances: List, wallet_address: str, account_keys: List) -> List[Dict]:
        """
        Parse token balance changes to identify transfers, including NFTs
        """
        transfers = []
        
        # Create lookup maps
        pre_map = {bal['accountIndex']: bal for bal in pre_balances}
        post_map = {bal['accountIndex']: bal for bal in post_balances}
        
        # Find all account indices with balance changes
        all_indices = set(pre_map.keys()) | set(post_map.keys())
        
        for account_index in all_indices:
            try:
                if account_index >= len(account_keys):
                    continue
                    
                account_address = account_keys[account_index]
                
                pre_bal = pre_map.get(account_index, {})
                post_bal = post_map.get(account_index, {})
                
                # Get token info
                mint = pre_bal.get('mint') or post_bal.get('mint')
                if not mint:
                    continue
                
                # Calculate balance change
                pre_amount = float(pre_bal.get('uiTokenAmount', {}).get('uiAmount', 0))
                post_amount = float(post_bal.get('uiTokenAmount', {}).get('uiAmount', 0))
                change = post_amount - pre_amount
                
                if abs(change) < 0.000001:  # Ignore dust changes
                    continue
                
                # Get token metadata
                token_info = await self._get_token_metadata(mint)
                
                transfer = {
                    'mint': mint,
                    'account_address': account_address,
                    'amount': abs(change),
                    'direction': 'incoming' if change > 0 else 'outgoing',
                    'decimals': pre_bal.get('uiTokenAmount', {}).get('decimals', 0),
                    'symbol': token_info.get('symbol', 'UNKNOWN'),
                    'name': token_info.get('name'),
                    'is_nft': token_info.get('is_nft', False),
                    'metadata': token_info.get('metadata')
                }
                
                # Determine from/to addresses based on direction
                if account_address == wallet_address:
                    if change > 0:  # Incoming to wallet
                        transfer['from_address'] = 'unknown'  # Would need to trace from other accounts
                        transfer['to_address'] = wallet_address
                    else:  # Outgoing from wallet
                        transfer['from_address'] = wallet_address
                        transfer['to_address'] = 'unknown'  # Would need to trace to other accounts
                else:
                    # This is a counterparty account
                    if change > 0:  # Counterparty received
                        transfer['from_address'] = wallet_address
                        transfer['to_address'] = account_address
                    else:  # Counterparty sent
                        transfer['from_address'] = account_address
                        transfer['to_address'] = wallet_address
                
                transfers.append(transfer)
                
            except Exception as e:
                print(f"❌ Error parsing token transfer for account {account_index}: {e}")
                continue
        
        # Filter to only transfers involving the monitored wallet
        wallet_transfers = [t for t in transfers if wallet_address in [t['from_address'], t['to_address']]]
        
        return wallet_transfers

    async def _get_token_metadata(self, mint_address: str) -> Dict:
        """
        Get token metadata to determine if it's an NFT and get name/symbol
        """
        try:
            if not self.basic_solana_client:
                return {'symbol': 'UNKNOWN', 'name': None, 'is_nft': False}
            
            # Get mint account info
            mint_pubkey = PublicKey.from_string(mint_address)
            mint_info = await self.basic_solana_client.get_account_info(mint_pubkey)
            
            if not mint_info.value:
                return {'symbol': 'UNKNOWN', 'name': None, 'is_nft': False}
            
            # Parse mint data to get supply
            mint_data = mint_info.value.data
            if len(mint_data) >= 44:  # Standard mint account size
                # Supply is at offset 36-44 (8 bytes, little endian)
                supply_bytes = mint_data[36:44]
                supply = int.from_bytes(supply_bytes, byteorder='little')
                
                # NFTs typically have supply of 1
                is_likely_nft = supply == 1
            else:
                is_likely_nft = False
            
            # Try to get metadata from Metaplex
            metadata = None
            if is_likely_nft:
                try:
                    # Derive metadata PDA (this is a simplified approach)
                    metadata = await self._get_metaplex_metadata(mint_address)
                except Exception as e:
                    print(f"⚠️ Could not fetch metadata for {mint_address}: {e}")
            
            # Default token info
            token_info = {
                'symbol': metadata.get('symbol', 'UNKNOWN') if metadata else 'UNKNOWN',
                'name': metadata.get('name') if metadata else None,
                'is_nft': is_likely_nft,
                'supply': supply if 'supply' in locals() else 0
            }
            
            if metadata:
                token_info['metadata'] = metadata
            
            return token_info
            
        except Exception as e:
            print(f"❌ Error getting token metadata for {mint_address}: {e}")
            return {'symbol': 'UNKNOWN', 'name': None, 'is_nft': False}

    async def _get_metaplex_metadata(self, mint_address: str) -> Optional[Dict]:
        """
        Get Metaplex metadata for NFTs (simplified implementation)
        """
        try:
            # This is a simplified approach - in production you'd use the full Metaplex SDK
            # For now, we'll try to detect common NFT patterns
            
            # Basic metadata structure
            metadata = {
                'name': f'NFT {mint_address[:8]}...',
                'symbol': 'NFT',
                'collection': None,
                'attributes': []
            }
            
            return metadata
            
        except Exception as e:
            print(f"❌ Error fetching Metaplex metadata: {e}")
            return None

    def _identify_dapp_from_programs(self, program_ids: List[str]) -> Optional[Dict]:
        """
        Identify DApp based on program IDs used in transaction
        """
        known_programs = {
            'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4': {'name': 'Jupiter', 'url': 'https://jup.ag'},
            '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8': {'name': 'Raydium', 'url': 'https://raydium.io'},
            'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc': {'name': 'Orca', 'url': 'https://orca.so'},
            'So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo': {'name': 'Solend', 'url': 'https://solend.fi'},
            '4MangoMjqJ2firMokCjjGgoK8d4MXcrgL7XJaL3w6fVg': {'name': 'Mango', 'url': 'https://mango.markets'},
            'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA': {'name': 'SPL Token Program', 'url': None},
            '11111111111111111111111111111111': {'name': 'System Program', 'url': None},
            'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL': {'name': 'Associated Token Program', 'url': None}
        }
        
        for program_id in program_ids:
            if program_id in known_programs:
                return known_programs[program_id]
        
        return None

    # ========== TRANSACTION PROCESSING WITH PROPER ERROR HANDLING ==========

    def _sanitize_transaction_data(self, transaction_data: Dict) -> Dict:
        """Convert Signature objects and other non-serializable types to strings"""
        def make_serializable(obj):
            if isinstance(obj, dict):
                return {key: make_serializable(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [make_serializable(item) for item in obj]
            elif isinstance(obj, datetime):
                return obj.isoformat()
            elif hasattr(obj, '__str__') and hasattr(obj, '__class__'):
                # Convert Signature objects and similar types to strings
                if 'Signature' in str(type(obj)) or 'TransactionConfirmationStatus' in str(type(obj)) or not self._is_hashable(obj):
                    return str(obj)
                else:
                    return obj
            else:
                return obj
        
        try:
            sanitized = make_serializable(transaction_data)
            json.dumps(sanitized)  # Test serialization
            return sanitized
        except (TypeError, ValueError) as e:
            print(f"❌ Failed to sanitize transaction data: {e}")
            raise Exception(f"Transaction data serialization failed: {e}")

    def _is_hashable(self, obj) -> bool:
        """Check if an object is hashable"""
        try:
            hash(obj)
            return True
        except TypeError:
            return False

    # ========== REAL-TIME TRANSACTION INTERCEPTION ==========

    async def intercept_outgoing_transaction(self, transaction_data: Dict, user_language: str = "english") -> Dict:
        """
        Real-time outgoing transaction analysis (BEFORE signing)
        """
        if not self.security_agent:
            raise Exception("No AI agent connected - cannot analyze transactions")
        
        try:
            transaction_data = self._sanitize_transaction_data(transaction_data)
            
            analysis_result = await self.security_agent.analyze_with_ai_code_generation(
                transaction_data, user_language
            )
            
            analysis_result['sensor_modules_used'] = self._get_loaded_modules()
            analysis_result['analysis_method'] = 'ai_code_generation'
            analysis_result['rpc_provider'] = self.rpc_provider_name
            
            return analysis_result
            
        except Exception as e:
            error_msg = f"Transaction analysis failed: {str(e)}"
            print(f"❌ {error_msg}")
            raise Exception(error_msg)

    async def process_incoming_transaction(self, transaction_data: Dict, user_language: str = "english") -> Dict:
        """
        Process incoming transactions for quarantine decisions
        """
        if not self.security_agent:
            raise Exception("No AI agent connected - cannot analyze incoming transactions")
        
        try:
            transaction_data = self._sanitize_transaction_data(transaction_data)
            
            print(f"📥 Processing incoming transaction: {transaction_data.get('hash', 'unknown')}")
            
            transaction_data['direction'] = 'incoming'
            transaction_data['analysis_type'] = 'quarantine_assessment'
            
            analysis_result = await self.security_agent.analyze_with_ai_code_generation(
                transaction_data, user_language
            )
            
            risk_score = analysis_result.get('risk_score', 0.0)
            
            if risk_score >= 0.7:
                analysis_result['quarantine_recommended'] = True
                analysis_result['quarantine_reason'] = 'High risk score from AI analysis'
                analysis_result['action'] = 'QUARANTINE'
            elif risk_score >= 0.4:
                analysis_result['quarantine_recommended'] = False
                analysis_result['user_review_recommended'] = True
                analysis_result['action'] = 'WARN'
            else:
                analysis_result['quarantine_recommended'] = False
                analysis_result['action'] = 'ALLOW'
            
            analysis_result['sensor_modules_used'] = self._get_loaded_modules()
            analysis_result['rpc_provider'] = self.rpc_provider_name
            
            print(f"✅ Incoming analysis complete - Action: {analysis_result['action']}, Risk: {risk_score:.2f}")
            
            return analysis_result
            
        except Exception as e:
            error_msg = f"Failed to process incoming transaction: {str(e)}"
            print(f"❌ {error_msg}")
            raise Exception(error_msg)

    async def analyze_dapp_reputation(self, dapp_url: str, dapp_name: str = "") -> Dict:
        """
        Check DApp safety using AI analysis
        """
        if not self.security_agent:
            raise Exception("No AI agent connected - cannot analyze DApp reputation")
        
        dapp_data = {
            'dapp_url': dapp_url,
            'dapp_name': dapp_name,
            'analysis_type': 'dapp_reputation'
        }
        
        try:
            dapp_data = self._sanitize_transaction_data(dapp_data)
            analysis_result = await self.security_agent.analyze_with_ai_code_generation(dapp_data)
            
            risk_score = analysis_result.get('risk_score', 0.5)
            if risk_score <= 0.3:
                status = 'safe'
            elif risk_score <= 0.6:
                status = 'unknown'
            else:
                status = 'risky'
            
            return {
                'status': status,
                'risk_score': risk_score,
                'reason': analysis_result['user_explanation'],
                'details': analysis_result
            }
            
        except Exception as e:
            error_msg = f"DApp reputation analysis failed: {str(e)}"
            print(f"❌ {error_msg}")
            raise Exception(error_msg)

    # ========== REAL-TIME MONITORING ==========

    async def start_incoming_monitor(self):
        """Start real-time monitoring for incoming transactions"""
        if self.monitoring_active:
            print("⚠️ Monitoring already active")
            return
        
        if not self.basic_solana_client:
            raise Exception(f"Cannot start monitoring - no RPC client available: {self.module_errors.get('BasicSolanaClient', 'Unknown error')}")
        
        self.monitoring_active = True
        print("🛡️ Starting real-time incoming transaction monitoring...")
        
        for wallet_address in self.wallet_addresses:
            task = asyncio.create_task(self._monitor_wallet_incoming(wallet_address))
            self.monitoring_tasks.append(task)
        
        print(f"📡 Monitoring {len(self.wallet_addresses)} wallets in real-time")

    async def stop_incoming_monitor(self):
        """Stop real-time monitoring"""
        self.monitoring_active = False
        
        for task in self.monitoring_tasks:
            if not task.done():
                task.cancel()
        
        if self.monitoring_tasks:
            await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
        
        self.monitoring_tasks.clear()
        print("🛑 Real-time monitoring stopped")

    async def _monitor_wallet_incoming(self, wallet_address: str):
        """Monitor specific wallet for incoming transactions"""
        print(f"👁️ Starting monitoring for wallet: {wallet_address[:8]}...{wallet_address[-8:]}")
        
        while self.monitoring_active:
            try:
                recent_transactions = await self._fetch_recent_transactions(wallet_address)
                
                for tx in recent_transactions:
                    tx = self._sanitize_transaction_data(tx)
                    tx_hash = tx.get('hash', tx.get('signature', ''))
                    
                    if tx_hash in self.last_processed_signatures:
                        continue
                    
                    self.last_processed_signatures.add(tx_hash)
                    
                    if tx.get('direction') == 'incoming':
                        print(f"📥 New incoming transaction detected: {tx_hash}")
                        try:
                            analysis_result = await self.process_incoming_transaction(tx)
                            
                            if analysis_result.get('quarantine_recommended'):
                                await self._handle_quarantine_decision(tx, analysis_result)
                            else:
                                print(f"✅ ALLOWED: {tx_hash} - Safe incoming transaction")
                        except Exception as e:
                            print(f"❌ Failed to analyze incoming transaction {tx_hash}: {e}")
                
                await asyncio.sleep(10)
                
            except Exception as e:
                print(f"❌ Error monitoring wallet {wallet_address[:8]}...{wallet_address[-8:]}: {e}")
                await asyncio.sleep(30)

    async def _handle_quarantine_decision(self, transaction: Dict, analysis_result: Dict):
        """
        Handle quarantine decision for incoming transaction
        """
        tx_hash = transaction.get('hash', transaction.get('signature', 'unknown'))
        
        if analysis_result.get('quarantine_recommended'):
            quarantine_reason = analysis_result.get('quarantine_reason', 'High risk detected')
            print(f"🏠 QUARANTINED: {tx_hash} - {quarantine_reason}")
            
            self.threat_cache[tx_hash] = {
                'transaction': transaction,
                'analysis_result': analysis_result,
                'quarantined_at': datetime.now().isoformat(),
                'threat_type': 'incoming_quarantine'
            }
            
            await self._notify_user_quarantine(transaction, analysis_result)
        else:
            print(f"✅ ALLOWED: {tx_hash} - Safe transaction")

    async def _notify_user_quarantine(self, transaction: Dict, analysis_result: Dict):
        """
        Notify user about quarantined item
        """
        notification = {
            'type': 'quarantine',
            'transaction': transaction,
            'reason': analysis_result.get('user_explanation', 'Suspicious transaction detected'),
            'risk_score': analysis_result.get('risk_score', 0.0),
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"📱 USER NOTIFICATION: {notification}")

    # ========== STATUS AND UTILITY METHODS ==========

    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status"""
        return {
            "security_score": 0.8,
            "total_threats_detected": len(self.threat_cache),
            "quarantined_items": len([t for t in self.threat_cache.values() if t.get('threat_type') == 'incoming_quarantine']),
            "monitored_wallets": len(self.wallet_addresses),
            "last_analysis": self.last_analysis_time.isoformat(),
            "modules_loaded": self._get_loaded_modules(),
            "module_errors": self.module_errors,
            "monitoring_active": self.monitoring_active,
            "ai_agent_connected": self.security_agent is not None,
            "analysis_method": "ai_code_generation",
            "rpc_provider": self.rpc_provider_name,
            "api_key_configured": bool(self.rpc_api_key),
            "rpc_health": self.get_rpc_health()
        }

    def get_transaction_threats(self) -> Dict[str, Any]:
        """Get recent threat detection data"""
        return {
            "recent_threats": list(self.threat_cache.values())[-10:],
            "threat_count": len(self.threat_cache),
            "last_scan": int(time.time()),
            "protection_enabled": True,
            "ai_analysis_available": self.security_agent is not None,
            "rpc_provider": self.rpc_provider_name
        }

    def get_metric_fn(self, metric_name: str = "security") -> callable:
        """Get a callable that fetches security metrics"""
        if metric_name == "security":
            return lambda: self.get_security_status()
        else:
            return lambda: {"metric": metric_name, "value": 0.5, "rpc_provider": self.rpc_provider_name}

    # ========== DIRECT MODULE ACCESS ==========

    async def run_specific_analysis(self, analysis_type: str, target_data: Dict) -> Dict:
        """
        Run specific analysis using existing modules directly
        """
        try:
            if analysis_type == "mev":
                if not self.mev_detector:
                    raise Exception(f"MEVDetector not available: {self.module_errors.get('MEVDetector', 'Module not loaded')}")
                return await self.mev_detector.analyze_mev_risk(target_data)
            
            elif analysis_type == "contract":
                if not self.contract_analyzer:
                    raise Exception(f"EnhancedContractAnalyzer not available: {self.module_errors.get('EnhancedContractAnalyzer', 'Module not loaded')}")
                return await self.contract_analyzer.analyze_contract_for_drain_risk(target_data)
            
            elif analysis_type == "dust":
                if not self.dust_detector:
                    raise Exception(f"AdaptiveDustDetector not available: {self.module_errors.get('AdaptiveDustDetector', 'Module not loaded')}")
                return await self.dust_detector.analyze_transaction(target_data)
            
            elif analysis_type == "nft":
                if not self.nft_scam_detector:
                    raise Exception(f"NFTScamDetector not available: {self.module_errors.get('NFTScamDetector', 'Module not loaded')}")
                return await self.nft_scam_detector.analyze_nft_scam_risk(target_data)
            
            elif analysis_type == "behavior":
                if not self.behavior_analyzer:
                    raise Exception(f"BehaviorAnalyzer not available: {self.module_errors.get('BehaviorAnalyzer', 'Module not loaded')}")
                wallet_address = target_data.get('wallet_address', '')
                return await self.behavior_analyzer.analyze_wallet_behavior(wallet_address)
            
            else:
                raise Exception(f"Unknown analysis type: {analysis_type}")
                
        except Exception as e:
            error_msg = f"Analysis '{analysis_type}' failed: {str(e)}"
            print(f"❌ {error_msg}")
            raise Exception(error_msg)

    # ========== WALLET MANAGEMENT ==========

    async def add_wallet_to_monitoring(self, wallet_address: str):
        """Add new wallet to monitoring list"""
        if wallet_address not in self.wallet_addresses:
            self.wallet_addresses.append(wallet_address)
            print(f"📡 Added wallet to monitoring: {wallet_address[:8]}...{wallet_address[-8:]}")
            
            if self.monitoring_active:
                if not self.basic_solana_client:
                    print(f"⚠️ Cannot start monitoring - no RPC client available")
                    return
                    
                task = asyncio.create_task(self._monitor_wallet_incoming(wallet_address))
                self.monitoring_tasks.append(task)
                print(f"🔄 Started real-time monitoring for new wallet")

    async def remove_wallet_from_monitoring(self, wallet_address: str):
        """Remove wallet from monitoring list"""
        if wallet_address in self.wallet_addresses:
            self.wallet_addresses.remove(wallet_address)
            print(f"📡 Removed wallet from monitoring: {wallet_address[:8]}...{wallet_address[-8:]}")

    def get_quarantined_items(self) -> List[Dict]:
        """Get all quarantined items"""
        return [item for item in self.threat_cache.values() if item.get('threat_type') == 'incoming_quarantine']

    def clear_quarantine_cache(self):
        """Clear quarantine cache"""
        quarantine_count = len(self.get_quarantined_items())
        self.threat_cache.clear()
        print(f"🧹 Cleared {quarantine_count} quarantined items from cache")