"""
Solana RPC Client for Security Analysis
Provides real blockchain data for security modules
"""

import asyncio
import aiohttp
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import base64
import base58


class SolanaRPCClient:
    """
    Solana RPC client for fetching real blockchain data for security analysis.
    Integrates with meta-swap-api and direct Solana RPC calls.
    """
    
    def __init__(self, rpc_url: str = "https://api.mainnet-beta.solana.com", meta_swap_api_url: str = "http://localhost:9009"):
        self.rpc_url = rpc_url
        self.meta_swap_api_url = meta_swap_api_url
        self.session = None
        
        # Common Solana program addresses for reference
        self.known_programs = {
            'system': '11111111111111111111111111111111',
            'spl_token': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
            'associated_token': 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
            'metadata': 'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s',
            'memo': 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def _make_rpc_call(self, method: str, params: List[Any]) -> Dict:
        """Make a direct Solana RPC call"""
        if not self.session:
            self.session = aiohttp.ClientSession()
        
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }
        
        try:
            async with self.session.post(self.rpc_url, json=payload) as response:
                data = await response.json()
                return data.get('result', {})
        except Exception as e:
            print(f"RPC call failed: {e}")
            return {}
    
    async def get_program_account_info(self, program_id: str) -> Dict:
        """Get detailed program account information"""
        try:
            result = await self._make_rpc_call("getAccountInfo", [
                program_id,
                {
                    "encoding": "base64",
                    "commitment": "confirmed"
                }
            ])
            
            if result and result.get('value'):
                account_data = result['value']
                return {
                    'exists': True,
                    'executable': account_data.get('executable', False),
                    'owner': account_data.get('owner', ''),
                    'lamports': account_data.get('lamports', 0),
                    'data': account_data.get('data', ['', 'base64']),
                    'rent_epoch': account_data.get('rentEpoch', 0)
                }
            else:
                return {'exists': False}
        except Exception as e:
            print(f"Failed to get program account info: {e}")
            return {'exists': False, 'error': str(e)}
    
    async def get_program_bytecode(self, program_id: str) -> str:
        """Extract program bytecode for analysis"""
        try:
            account_info = await self.get_program_account_info(program_id)
            
            if account_info.get('exists') and account_info.get('executable'):
                # For executable programs, the bytecode is in the data field
                data = account_info.get('data', ['', 'base64'])
                if len(data) >= 1:
                    bytecode_b64 = data[0]
                    bytecode_bytes = base64.b64decode(bytecode_b64)
                    return bytecode_bytes.hex()
            
            return ""
        except Exception as e:
            print(f"Failed to get program bytecode: {e}")
            return ""
    
    async def get_program_instructions(self, program_id: str) -> List[str]:
        """Analyze program to extract instruction patterns"""
        try:
            # Get recent transactions involving this program
            signatures = await self._make_rpc_call("getConfirmedSignaturesForAddress2", [
                program_id,
                {
                    "limit": 50,
                    "commitment": "confirmed"
                }
            ])
            
            instructions = []
            
            # Analyze recent transactions to understand program instructions
            for sig_info in signatures[:10]:  # Analyze first 10 transactions
                tx_data = await self._make_rpc_call("getConfirmedTransaction", [
                    sig_info['signature'],
                    {
                        "encoding": "jsonParsed",
                        "commitment": "confirmed"
                    }
                ])
                
                if tx_data and tx_data.get('transaction'):
                    tx_instructions = tx_data['transaction'].get('message', {}).get('instructions', [])
                    
                    for instruction in tx_instructions:
                        if instruction.get('programId') == program_id:
                            # Extract instruction type/method if available
                            if 'parsed' in instruction:
                                inst_type = instruction['parsed'].get('type', 'unknown')
                                instructions.append(inst_type)
                            elif 'data' in instruction:
                                # Try to decode instruction data for patterns
                                data = instruction['data']
                                if data:
                                    instructions.append(f"data_instruction_{data[:8]}")
            
            return list(set(instructions))  # Remove duplicates
            
        except Exception as e:
            print(f"Failed to get program instructions: {e}")
            return []
    
    async def get_program_metadata(self, program_id: str) -> Dict:
        """Get program metadata if available"""
        try:
            # Try to get metadata from Metaplex metadata program
            metadata_result = {}
            
            # For SPL tokens, try to get token metadata
            if await self._is_spl_token_program(program_id):
                token_metadata = await self._get_spl_token_metadata(program_id)
                metadata_result.update(token_metadata)
            
            # Try to get program upgrade authority
            account_info = await self.get_program_account_info(program_id)
            if account_info.get('executable'):
                # Executable programs might have upgrade authority
                metadata_result['is_upgradeable'] = True
                metadata_result['owner'] = account_info.get('owner', '')
            
            return metadata_result
            
        except Exception as e:
            print(f"Failed to get program metadata: {e}")
            return {}
    
    async def get_wallet_transaction_history(self, wallet_address: str, limit: int = 100) -> List[Dict]:
        """Get transaction history for behavioral analysis"""
        try:
            # Get confirmed signatures for the address
            signatures = await self._make_rpc_call("getConfirmedSignaturesForAddress2", [
                wallet_address,
                {
                    "limit": limit,
                    "commitment": "confirmed"
                }
            ])
            
            transactions = []
            
            # Get detailed transaction data
            for sig_info in signatures:
                tx_data = await self._make_rpc_call("getConfirmedTransaction", [
                    sig_info['signature'],
                    {
                        "encoding": "jsonParsed",
                        "commitment": "confirmed"
                    }
                ])
                
                if tx_data:
                    parsed_tx = await self._parse_transaction_for_analysis(tx_data, wallet_address)
                    if parsed_tx:
                        transactions.append(parsed_tx)
            
            return transactions
            
        except Exception as e:
            print(f"Failed to get transaction history: {e}")
            return []
    
    async def check_program_authorities(self, program_id: str) -> Dict:
        """Check program authority structure"""
        try:
            account_info = await self.get_program_account_info(program_id)
            
            authority_info = {
                'owner': account_info.get('owner', ''),
                'executable': account_info.get('executable', False),
                'is_upgradeable': False,
                'upgrade_authority': None,
                'authority_risks': []
            }
            
            # Check if program is owned by BPF loader (upgradeable)
            if account_info.get('owner') == 'BPFLoaderUpgradeab1e11111111111111111111111':
                authority_info['is_upgradeable'] = True
                authority_info['authority_risks'].append('Program can be upgraded')
                
                # Try to get upgrade authority
                try:
                    upgrade_authority = await self._get_program_upgrade_authority(program_id)
                    authority_info['upgrade_authority'] = upgrade_authority
                except:
                    pass
            
            return authority_info
            
        except Exception as e:
            print(f"Failed to check program authorities: {e}")
            return {}
    
    async def get_token_account_info(self, token_address: str) -> Dict:
        """Get token account information for analysis"""
        try:
            # Get token mint info
            mint_info = await self._make_rpc_call("getAccountInfo", [
                token_address,
                {
                    "encoding": "jsonParsed",
                    "commitment": "confirmed"
                }
            ])
            
            if mint_info and mint_info.get('value'):
                parsed_data = mint_info['value'].get('data', {})
                if parsed_data.get('program') == 'spl-token' and parsed_data.get('parsed'):
                    token_data = parsed_data['parsed']['info']
                    return {
                        'is_token': True,
                        'decimals': token_data.get('decimals', 0),
                        'supply': token_data.get('supply', '0'),
                        'mint_authority': token_data.get('mintAuthority'),
                        'freeze_authority': token_data.get('freezeAuthority'),
                        'is_initialized': token_data.get('isInitialized', False)
                    }
            
            return {'is_token': False}
            
        except Exception as e:
            print(f"Failed to get token account info: {e}")
            return {'is_token': False, 'error': str(e)}
    
    async def _is_spl_token_program(self, program_id: str) -> bool:
        """Check if program is SPL token related"""
        token_programs = [
            'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',  # SPL Token
            'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'   # Token 2022
        ]
        return program_id in token_programs
    
    async def _get_spl_token_metadata(self, token_mint: str) -> Dict:
        """Get SPL token metadata"""
        try:
            # Try to get Metaplex metadata
            metadata_seeds = ['metadata', 'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s', token_mint]
            # This would require proper PDA derivation in a full implementation
            return {
                'name': 'Unknown Token',
                'symbol': 'UNK',
                'uri': '',
                'metadata_source': 'spl_token'
            }
        except:
            return {}
    
    async def _get_program_upgrade_authority(self, program_id: str) -> Optional[str]:
        """Get program upgrade authority if upgradeable"""
        try:
            # This would require proper program data parsing
            # For now, return placeholder
            return None
        except:
            return None
    
    async def _parse_transaction_for_analysis(self, tx_data: Dict, wallet_address: str) -> Optional[Dict]:
        """Parse transaction data for security analysis"""
        try:
            if not tx_data.get('transaction'):
                return None
            
            transaction = tx_data['transaction']
            block_time = tx_data.get('blockTime')
            
            # Extract basic transaction info
            parsed_tx = {
                'signature': transaction.get('signatures', [''])[0],
                'timestamp': datetime.fromtimestamp(block_time) if block_time else datetime.now(),
                'slot': tx_data.get('slot', 0),
                'fee': tx_data.get('meta', {}).get('fee', 0),
                'success': tx_data.get('meta', {}).get('err') is None,
                'instructions': [],
                'token_transfers': [],
                'sol_transfers': []
            }
            
            # Parse instructions
            instructions = transaction.get('message', {}).get('instructions', [])
            for instruction in instructions:
                inst_info = {
                    'program_id': instruction.get('programId', ''),
                    'type': 'unknown'
                }
                
                if 'parsed' in instruction:
                    inst_info['type'] = instruction['parsed'].get('type', 'unknown')
                    inst_info['info'] = instruction['parsed'].get('info', {})
                
                parsed_tx['instructions'].append(inst_info)
            
            # Parse token transfers from meta
            meta = tx_data.get('meta', {})
            if 'preTokenBalances' in meta and 'postTokenBalances' in meta:
                # Calculate token balance changes
                pre_balances = {tb['accountIndex']: tb for tb in meta['preTokenBalances']}
                post_balances = {tb['accountIndex']: tb for tb in meta['postTokenBalances']}
                
                for acc_idx, post_balance in post_balances.items():
                    pre_balance = pre_balances.get(acc_idx, {})
                    
                    pre_amount = int(pre_balance.get('uiTokenAmount', {}).get('amount', '0'))
                    post_amount = int(post_balance.get('uiTokenAmount', {}).get('amount', '0'))
                    
                    if pre_amount != post_amount:
                        parsed_tx['token_transfers'].append({
                            'mint': post_balance.get('mint', ''),
                            'amount_change': post_amount - pre_amount,
                            'decimals': post_balance.get('uiTokenAmount', {}).get('decimals', 0)
                        })
            
            return parsed_tx
            
        except Exception as e:
            print(f"Failed to parse transaction: {e}")
            return None