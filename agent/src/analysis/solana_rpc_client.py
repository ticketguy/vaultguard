"""
IntelligentSolanaRPCClient 
=====================================================

What this does:
- Makes actual calls to the Solana blockchain
- Automatically switches to backup RPCs if one fails
- Handles rate limiting (don't call too fast)
- Retries failed requests with smart delays
- Now auto-detects the best RPC to use!

Think of it like:
- A smart phone that automatically dials backup numbers if the first one is busy
- Waits between calls so you don't annoy the person you're calling
- Tries calling again if the line drops
- Automatically picks the best phone service provider
"""

import asyncio
import aiohttp
import json
import time
import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class RPCStatus(Enum):
    """
    Status of each RPC endpoint - like checking if a phone line is working
    """
    HEALTHY = "healthy"        # Working fine
    RATE_LIMITED = "rate_limited"  # Too many calls, need to slow down
    ERROR = "error"           # Something's wrong, avoid for a while
    TIMEOUT = "timeout"       # Takes too long to answer

@dataclass
class RPCEndpoint:
    """
    Information about one RPC endpoint
    
    Simple explanation: Like a contact in your phone book
    - url: The phone number (RPC URL)
    - name: The contact name (provider name)
    - api_key: VIP access code (optional)
    - status: Is this contact available right now?
    - Various tracking info for smart switching
    """
    url: str
    name: str
    api_key: Optional[str] = None
    status: RPCStatus = RPCStatus.HEALTHY
    last_error_time: Optional[datetime] = None
    consecutive_errors: int = 0
    rate_limit_reset_time: Optional[datetime] = None
    request_count: int = 0
    success_count: int = 0

class IntelligentSolanaRPCClient:
    """
    Smart RPC client that automatically finds the best connection and handles failures
    
    Simple explanation: This is like a super smart phone that:
    1. Automatically picks the best phone service
    2. Keeps backup numbers ready
    3. Doesn't call too fast (rate limiting)
    4. Tries again if calls fail
    5. Switches to backup numbers when needed
    """
    
    def __init__(self, rpc_api_key: Optional[str] = None, primary_rpc_url: Optional[str] = None, rpc_provider_name: Optional[str] = None):
        """
        Set up the RPC client
        
        🎯 NEW: AUTO-DETECTION!
        If you don't provide any parameters, it will automatically:
        1. Check your environment variables for API keys
        2. Pick the best RPC provider you have access to
        3. Set up fallback RPCs in case the main one fails
        """
        
        # 🎯 AUTO-DETECTION: If no parameters provided, detect from environment
        if not rpc_api_key and not primary_rpc_url:
            try:
                # Import the configuration system
                from src.rpc_config import FlexibleRPCConfig
                rpc_config = FlexibleRPCConfig()
                
                # Ask the config system: "What's the best RPC setup?"
                primary_rpc_url, rpc_provider_name, all_endpoints, rpc_api_key = rpc_config.detect_and_configure_rpc()
                logger.info(f"🎯 Auto-detected: {rpc_provider_name} ({'with API key' if rpc_api_key else 'public RPC'})")
                
                # 🔥 USE THE CONFIG'S ENDPOINTS DIRECTLY - no duplication!
                # The config system already figured out the best setup, so just use it
                self.endpoints = []
                for endpoint in all_endpoints:
                    self.endpoints.append(RPCEndpoint(
                        url=endpoint['url'],
                        name=endpoint['name'],
                        # Only the primary endpoint gets the API key
                        api_key=rpc_api_key if endpoint['name'] == rpc_provider_name else None
                    ))
                
            except Exception as e:
                logger.warning(f"⚠️ Auto-detection failed, using single fallback: {e}")
                # Emergency fallback if auto-detection fails
                self.endpoints = [RPCEndpoint(
                    url="https://api.mainnet-beta.solana.com", 
                    name="Emergency_Fallback"
                )]
                rpc_provider_name = "Emergency_Fallback"
                rpc_api_key = None
        else:
            # Manual configuration - user provided specific parameters
            self.endpoints = [RPCEndpoint(
                url=primary_rpc_url,
                name=rpc_provider_name or "Manual",
                api_key=rpc_api_key
            )]
            logger.info(f"🔧 Manual config: {rpc_provider_name or 'Manual'}")
        
        # Store basic info
        self.rpc_provider_name = rpc_provider_name or "Unknown"
        self.rpc_api_key = rpc_api_key
        self.session = None  # HTTP session for making requests
        self.current_endpoint_index = 0  # Which endpoint we're currently using
        
        # Rate limiting configuration - don't call too fast!
        self.max_requests_per_second = 10  # Max 10 calls per second
        self.max_burst_requests = 20      # Can burst up to 20 calls
        self.request_timestamps = []      # Track when we made calls
        
        # Retry configuration - how to handle failures
        self.max_retries = 3              # Try up to 3 times
        self.base_delay = 1.0             # Start with 1 second delay
        self.max_delay = 60.0             # Max 60 second delay
        self.backoff_multiplier = 2.0     # Double delay each retry
        
        # Circuit breaker configuration - when to stop trying an endpoint
        self.circuit_breaker_threshold = 5  # After 5 errors in a row
        self.circuit_breaker_reset_time = 300  # Wait 5 minutes before trying again
        
        logger.info(f"🔄 Initialized RPC client with {len(self.endpoints)} endpoints")
        
        # Show user what endpoints we're using (for transparency)
        for i, ep in enumerate(self.endpoints):
            priority = "PRIMARY" if i == 0 else f"FALLBACK-{i}"
            api_status = "with API key" if ep.api_key else "public"
            logger.info(f"   {priority}: {ep.name} ({api_status})")
    
    async def __aenter__(self):
        """
        Async context manager entry - sets up the HTTP session
        
        Simple explanation: Like picking up the phone to start making calls
        """
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30, connect=10)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        Async context manager exit - cleans up the HTTP session
        
        Simple explanation: Like hanging up the phone when done
        """
        if self.session:
            await self.session.close()
    
    def _get_healthy_endpoint(self) -> Optional[RPCEndpoint]:
        """
        Find the next healthy endpoint to use
        
        Simple explanation: "Which phone number should I try next?"
        - Checks if endpoints have recovered from problems
        - Uses round-robin (tries each one in turn)
        - Avoids endpoints that are currently having issues
        """
        now = datetime.now()
        
        # Try to find a healthy endpoint starting from where we left off
        for i in range(len(self.endpoints)):
            endpoint_index = (self.current_endpoint_index + i) % len(self.endpoints)
            endpoint = self.endpoints[endpoint_index]
            
            # Check if endpoint has recovered from rate limiting
            if (endpoint.status == RPCStatus.RATE_LIMITED and 
                endpoint.rate_limit_reset_time and 
                now > endpoint.rate_limit_reset_time):
                endpoint.status = RPCStatus.HEALTHY
                endpoint.consecutive_errors = 0
                logger.info(f"🟢 {endpoint.name} recovered from rate limiting")
            
            # Check if endpoint has recovered from circuit breaker
            if (endpoint.status == RPCStatus.ERROR and 
                endpoint.last_error_time and 
                now - endpoint.last_error_time > timedelta(seconds=self.circuit_breaker_reset_time)):
                endpoint.status = RPCStatus.HEALTHY
                endpoint.consecutive_errors = 0
                logger.info(f"🔄 {endpoint.name} circuit breaker reset")
            
            # Use this endpoint if it's healthy
            if endpoint.status == RPCStatus.HEALTHY:
                self.current_endpoint_index = endpoint_index
                return endpoint
        
        # If no healthy endpoints, use the one with the least recent error
        best_endpoint = min(self.endpoints, 
                          key=lambda e: e.last_error_time or datetime.min)
        logger.warning(f"⚠️ No healthy endpoints, falling back to {best_endpoint.name}")
        return best_endpoint
    
    async def _wait_for_rate_limit(self):
        """
        Smart rate limiting - don't call too fast
        
        Simple explanation: "Am I calling too fast? If so, wait a bit."
        Tracks how many calls we've made in the last second and slows down if needed.
        """
        now = time.time()
        
        # Remove old timestamps (older than 1 second)
        self.request_timestamps = [ts for ts in self.request_timestamps if now - ts < 1.0]
        
        # Check if we need to wait
        if len(self.request_timestamps) >= self.max_requests_per_second:
            # We're calling too fast! Calculate how long to wait
            sleep_time = 1.0 - (now - self.request_timestamps[0])
            if sleep_time > 0:
                logger.debug(f"🕒 Rate limiting: waiting {sleep_time:.2f}s")
                await asyncio.sleep(sleep_time)
        
        # Add current request timestamp
        self.request_timestamps.append(now)
    
    async def _make_rpc_call_with_retry(self, method: str, params: List[Any], retry_count: int = 0) -> Dict:
        """
        Make an RPC call with smart retry logic
        
        Simple explanation: "Call the blockchain, and if it fails, try again smartly"
        
        Process:
        1. Pick a healthy endpoint
        2. Wait if we're calling too fast (rate limiting)
        3. Make the actual HTTP request
        4. Handle different types of errors:
           - Rate limiting (429): Try different endpoint immediately
           - Other HTTP errors: Wait and retry
           - Timeouts: Wait and retry
           - Success: Return the result
        """
        # Step 1: Get a healthy endpoint to use
        endpoint = self._get_healthy_endpoint()
        if not endpoint:
            raise Exception("No available RPC endpoints")
        
        # Step 2: Wait if we're calling too fast
        await self._wait_for_rate_limit()
        
        # Step 3: Set up HTTP session if needed
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30, connect=10)
            )
        
        # Step 4: Prepare the RPC request
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,      # Like "getAccountInfo"
            "params": params       # Parameters for the method
        }
        
        try:
            logger.debug(f"📡 {endpoint.name}: {method}")
            
            # Step 5: Make the HTTP request
            async with self.session.post(endpoint.url, json=payload) as response:
                endpoint.request_count += 1
                
                # Handle rate limiting (429 Too Many Requests)
                if response.status == 429:
                    await self._handle_rate_limit(endpoint, response)
                    
                    # Try with a different endpoint immediately
                    if retry_count < self.max_retries:
                        logger.info(f"🔄 Retrying with different endpoint (attempt {retry_count + 1})")
                        self.current_endpoint_index = (self.current_endpoint_index + 1) % len(self.endpoints)
                        return await self._make_rpc_call_with_retry(method, params, retry_count + 1)
                    else:
                        raise Exception(f"Rate limited on all endpoints for {method}")
                
                # Handle other HTTP errors
                if response.status != 200:
                    await self._handle_http_error(endpoint, response)
                    
                    if retry_count < self.max_retries:
                        delay = min(self.base_delay * (self.backoff_multiplier ** retry_count), self.max_delay)
                        delay += random.uniform(0, delay * 0.1)  # Add some randomness
                        logger.info(f"⏱️ HTTP {response.status}: retrying in {delay:.1f}s")
                        await asyncio.sleep(delay)
                        return await self._make_rpc_call_with_retry(method, params, retry_count + 1)
                    else:
                        raise Exception(f"HTTP {response.status} after {self.max_retries} retries")
                
                # Step 6: Parse the response
                data = await response.json()
                
                # Handle JSON-RPC errors (blockchain-level errors)
                if 'error' in data:
                    await self._handle_rpc_error(endpoint, data['error'])
                    
                    if retry_count < self.max_retries:
                        delay = min(self.base_delay * (self.backoff_multiplier ** retry_count), self.max_delay)
                        logger.info(f"🔄 RPC error: retrying in {delay:.1f}s")
                        await asyncio.sleep(delay)
                        return await self._make_rpc_call_with_retry(method, params, retry_count + 1)
                    else:
                        raise Exception(f"RPC error: {data['error']}")
                
                # Success! Update endpoint status and return result
                endpoint.success_count += 1
                endpoint.consecutive_errors = 0
                if endpoint.status != RPCStatus.HEALTHY:
                    endpoint.status = RPCStatus.HEALTHY
                    logger.info(f"✅ {endpoint.name} endpoint recovered")
                
                return data.get('result', {})
        
        except asyncio.TimeoutError:
            # Handle timeout errors
            await self._handle_timeout(endpoint)
            if retry_count < self.max_retries:
                delay = min(self.base_delay * (self.backoff_multiplier ** retry_count), self.max_delay)
                logger.info(f"⏱️ Timeout: retrying in {delay:.1f}s")
                await asyncio.sleep(delay)
                return await self._make_rpc_call_with_retry(method, params, retry_count + 1)
            else:
                raise Exception(f"Timeout after {self.max_retries} retries")
        
        except Exception as e:
            # Handle general errors
            await self._handle_general_error(endpoint, e)
            if retry_count < self.max_retries:
                delay = min(self.base_delay * (self.backoff_multiplier ** retry_count), self.max_delay)
                logger.info(f"🔄 Error: {e} - retrying in {delay:.1f}s")
                await asyncio.sleep(delay)
                return await self._make_rpc_call_with_retry(method, params, retry_count + 1)
            else:
                raise
    
    async def _handle_rate_limit(self, endpoint: RPCEndpoint, response):
        """
        Handle rate limiting response from RPC
        
        Simple explanation: "The RPC said we're calling too fast, mark it as busy"
        """
        endpoint.status = RPCStatus.RATE_LIMITED
        endpoint.consecutive_errors += 1
        
        # Try to get rate limit reset time from headers
        retry_after = response.headers.get('Retry-After')
        if retry_after:
            try:
                reset_seconds = int(retry_after)
                endpoint.rate_limit_reset_time = datetime.now() + timedelta(seconds=reset_seconds)
                logger.warning(f"🚫 {endpoint.name} rate limited, reset in {reset_seconds}s")
            except ValueError:
                # If Retry-After is not a number, wait 60 seconds
                endpoint.rate_limit_reset_time = datetime.now() + timedelta(seconds=60)
                logger.warning(f"🚫 {endpoint.name} rate limited, reset in 60s")
        else:
            # No reset time provided, assume 60 seconds
            endpoint.rate_limit_reset_time = datetime.now() + timedelta(seconds=60)
            logger.warning(f"🚫 {endpoint.name} rate limited, reset in 60s")
    
    async def _handle_http_error(self, endpoint: RPCEndpoint, response):
        """
        Handle HTTP errors (404, 500, etc.)
        
        Simple explanation: "The server had a problem, note it down"
        """
        endpoint.consecutive_errors += 1
        endpoint.last_error_time = datetime.now()
        
        if endpoint.consecutive_errors >= self.circuit_breaker_threshold:
            endpoint.status = RPCStatus.ERROR
            logger.error(f"💥 {endpoint.name} circuit breaker triggered: HTTP {response.status}")
        else:
            logger.warning(f"⚠️ {endpoint.name} HTTP error: {response.status}")
    
    async def _handle_rpc_error(self, endpoint: RPCEndpoint, error: Dict):
        """
        Handle RPC-level errors (blockchain errors)
        
        Simple explanation: "The blockchain request failed, but the connection is OK"
        """
        error_code = error.get('code', 'unknown')
        error_message = error.get('message', 'Unknown error')
        
        # Some RPC errors are not the endpoint's fault (like invalid account)
        if error_code in [-32602, -32603]:  # Invalid params or internal error
            logger.warning(f"⚠️ {endpoint.name} RPC error {error_code}: {error_message}")
        else:
            logger.error(f"❌ {endpoint.name} RPC error {error_code}: {error_message}")
    
    async def _handle_timeout(self, endpoint: RPCEndpoint):
        """
        Handle timeout errors
        
        Simple explanation: "The call took too long, mark it as slow"
        """
        endpoint.status = RPCStatus.TIMEOUT
        endpoint.consecutive_errors += 1
        endpoint.last_error_time = datetime.now()
        logger.warning(f"⏱️ {endpoint.name} timeout")
    
    async def _handle_general_error(self, endpoint: RPCEndpoint, error: Exception):
        """
        Handle other general errors
        
        Simple explanation: "Something unexpected went wrong"
        """
        endpoint.consecutive_errors += 1
        endpoint.last_error_time = datetime.now()
        
        if endpoint.consecutive_errors >= self.circuit_breaker_threshold:
            endpoint.status = RPCStatus.ERROR
            logger.error(f"💥 {endpoint.name} circuit breaker triggered: {error}")
        else:
            logger.warning(f"⚠️ {endpoint.name} error: {error}")
    
    def get_endpoint_health(self) -> Dict[str, Any]:
        """
        Get health status of all endpoints
        
        Simple explanation: "Show me how all my phone numbers are doing"
        Returns info about success rates, errors, etc. for monitoring.
        """
        return {
            'endpoints': [
                {
                    'name': ep.name,
                    'status': ep.status.value,
                    'success_rate': ep.success_count / max(ep.request_count, 1),
                    'consecutive_errors': ep.consecutive_errors,
                    'last_error': ep.last_error_time.isoformat() if ep.last_error_time else None,
                    'rate_limit_reset': ep.rate_limit_reset_time.isoformat() if ep.rate_limit_reset_time else None
                }
                for ep in self.endpoints
            ],
            'current_endpoint': self.endpoints[self.current_endpoint_index].name,
            'primary_provider': self.rpc_provider_name,
            'api_key_configured': bool(self.rpc_api_key),
            'total_requests': sum(ep.request_count for ep in self.endpoints),
            'total_successes': sum(ep.success_count for ep in self.endpoints)
        }
    
    # Public API methods (unchanged interface)
    async def get_program_account_info(self, program_id: str) -> Dict:
        """Get detailed program account information"""
        try:
            result = await self._make_rpc_call_with_retry("getAccountInfo", [
                program_id,
                {"encoding": "base64", "commitment": "confirmed"}
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
            logger.error(f"Failed to get program account info: {e}")
            return {'exists': False, 'error': str(e)}
    
    async def get_recent_transactions(self, wallet_address: str, limit: int = 10) -> List[Dict]:
        """Get recent transactions for wallet with intelligent retry"""
        try:
            signatures = await self._make_rpc_call_with_retry("getSignaturesForAddress", [
                wallet_address,
                {"limit": limit, "commitment": "confirmed"}
            ])
            
            transactions = []
            for sig_info in signatures[:limit]:  # Respect limit
                try:
                    tx_signature = sig_info.get('signature', '')
                    if tx_signature:
                        tx_data = await self._make_rpc_call_with_retry("getTransaction", [
                            tx_signature,
                            {"encoding": "json", "commitment": "confirmed"}
                        ])
                        
                        if tx_data:
                            parsed_tx = self._parse_transaction_data(tx_data)
                            if parsed_tx:
                                transactions.append(parsed_tx)
                        
                        # Small delay between transaction fetches to avoid rate limits
                        await asyncio.sleep(0.1)
                        
                except Exception as e:
                    logger.warning(f"Failed to fetch transaction {sig_info}: {e}")
                    continue
            
            return transactions
            
        except Exception as e:
            logger.error(f"Failed to get recent transactions: {e}")
            return []

    async def get_wallet_transaction_history(self, wallet_address: str, limit: int = 50) -> List[Dict]:
            """Get comprehensive transaction history for a wallet with full parsing"""
            try:
                # Get transaction signatures first
                signatures_result = await self._make_rpc_call_with_retry("getSignaturesForAddress", [
                    wallet_address,
                    {"limit": limit, "commitment": "confirmed"}
                ])
                
                if not signatures_result:
                    return []
                
                transactions = []
                for sig_info in signatures_result[:limit]:
                    try:
                        signature = sig_info.get('signature', '')
                        if not signature:
                            continue
                        
                        # Get full transaction data
                        tx_data = await self._make_rpc_call_with_retry("getTransaction", [
                            signature,
                            {
                                "encoding": "jsonParsed",
                                "commitment": "confirmed",
                                "maxSupportedTransactionVersion": 0
                            }
                        ])
                        
                        if tx_data:
                            parsed_tx = self._parse_transaction_comprehensive(tx_data, wallet_address, sig_info)
                            if parsed_tx:
                                transactions.append(parsed_tx)
                        
                        # Small delay to avoid rate limits
                        await asyncio.sleep(0.05)
                        
                    except Exception as e:
                        logger.warning(f"Failed to fetch transaction {sig_info}: {e}")
                        continue
                
                logger.info(f"✅ Retrieved {len(transactions)} transactions for {wallet_address[:8]}...")
                return transactions
                
            except Exception as e:
                logger.error(f"Failed to get wallet transaction history: {e}")
                return []

    def _parse_transaction_comprehensive(self, tx_data: Dict, wallet_address: str, sig_info: Dict) -> Optional[Dict]:
        """Comprehensive transaction parsing for SecuritySensor compatibility"""
        try:
            transaction = tx_data.get('transaction', {})
            meta = tx_data.get('meta', {})
            message = transaction.get('message', {})
            
            # Basic transaction info
            parsed_tx = {
                'hash': sig_info.get('signature', ''),
                'signature': sig_info.get('signature', ''),
                'timestamp': datetime.fromtimestamp(sig_info.get('blockTime', time.time())),
                'block_time': sig_info.get('blockTime'),
                'slot': sig_info.get('slot', 0),
                'confirmation_status': sig_info.get('confirmationStatus', 'confirmed'),
                'fee': (meta.get('fee', 0)) / 1e9,  # Convert to SOL
                'success': meta.get('err') is None,
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
                'instructions': [],
                'token_transfers': []
            }
            
            # Parse account keys
            account_keys = message.get('accountKeys', [])
            if isinstance(account_keys[0], str):
                # Already strings
                account_keys_str = account_keys
            else:
                # Convert pubkey objects to strings
                account_keys_str = [str(key) if hasattr(key, 'pubkey') else str(key) for key in account_keys]
            
            # Find wallet position
            wallet_index = None
            try:
                wallet_index = account_keys_str.index(wallet_address)
            except ValueError:
                pass
            
            # Parse SOL balance changes
            pre_balances = meta.get('preBalances', [])
            post_balances = meta.get('postBalances', [])
            
            if wallet_index is not None and len(pre_balances) > wallet_index and len(post_balances) > wallet_index:
                pre_balance = pre_balances[wallet_index] / 1e9
                post_balance = post_balances[wallet_index] / 1e9
                sol_change = post_balance - pre_balance
                
                if abs(sol_change) > 0.000001:  # Ignore dust
                    parsed_tx['value'] = abs(sol_change)
                    parsed_tx['direction'] = 'incoming' if sol_change > 0 else 'outgoing'
                    parsed_tx['transaction_type'] = 'sol_transfer'
                    
                    # Find counterparty
                    for i, (pre, post) in enumerate(zip(pre_balances, post_balances)):
                        if i != wallet_index and i < len(account_keys_str):
                            balance_change = (post - pre) / 1e9
                            if abs(balance_change) > 0.000001 and (balance_change * sol_change) < 0:
                                if sol_change > 0:
                                    parsed_tx['from_address'] = account_keys_str[i]
                                    parsed_tx['to_address'] = wallet_address
                                else:
                                    parsed_tx['from_address'] = wallet_address
                                    parsed_tx['to_address'] = account_keys_str[i]
                                break
            
            # Parse token transfers
            pre_token_balances = meta.get('preTokenBalances', [])
            post_token_balances = meta.get('postTokenBalances', [])
            
            if pre_token_balances or post_token_balances:
                token_transfers = self._parse_token_balance_changes(
                    pre_token_balances, post_token_balances, wallet_address, account_keys_str
                )
                parsed_tx['token_transfers'] = token_transfers
                
                # Use primary token transfer data
                if token_transfers:
                    primary = token_transfers[0]
                    parsed_tx.update({
                        'transaction_type': 'nft_transfer' if primary.get('is_nft') else 'token_transfer',
                        'value': primary.get('amount', 0),
                        'token_address': primary.get('mint'),
                        'token_symbol': primary.get('symbol', 'UNKNOWN'),
                        'token_name': primary.get('name'),
                        'direction': primary.get('direction', 'unknown'),
                        'is_nft': primary.get('is_nft', False),
                        'nft_metadata': primary.get('metadata')
                    })
            
            # Parse instructions
            instructions = message.get('instructions', [])
            parsed_instructions = []
            
            for instruction in instructions:
                try:
                    inst_data = {}
                    
                    if 'parsed' in instruction:
                        # Parsed instruction
                        inst_data = {
                            'program_id': instruction.get('programId', ''),
                            'program': instruction.get('program', ''),
                            'type': instruction.get('parsed', {}).get('type', 'unknown'),
                            'info': instruction.get('parsed', {}).get('info', {}),
                            'parsed': True
                        }
                    else:
                        # Raw instruction
                        program_id_index = instruction.get('programIdIndex', 0)
                        if program_id_index < len(account_keys_str):
                            inst_data = {
                                'program_id': account_keys_str[program_id_index],
                                'accounts': [account_keys_str[i] for i in instruction.get('accounts', []) if i < len(account_keys_str)],
                                'data': instruction.get('data', ''),
                                'parsed': False
                            }
                    
                    if inst_data:
                        parsed_instructions.append(inst_data)
                
                except Exception as e:
                    logger.warning(f"Failed to parse instruction: {e}")
                    continue
            
            parsed_tx['instructions'] = parsed_instructions
            
            # Set primary program ID
            if parsed_instructions:
                parsed_tx['program_id'] = parsed_instructions[0].get('program_id', '')
                if parsed_instructions[0].get('parsed') and 'info' in parsed_instructions[0]:
                    parsed_tx['instruction_data'] = json.dumps(parsed_instructions[0]['info'], default=str)
            
            # Identify DApp
            program_ids = [inst.get('program_id', '') for inst in parsed_instructions]
            dapp_info = self._identify_dapp_from_programs(program_ids)
            if dapp_info:
                parsed_tx['dapp_name'] = dapp_info['name']
                parsed_tx['dapp_url'] = dapp_info.get('url')
            
            return parsed_tx
            
        except Exception as e:
            logger.error(f"Failed to parse transaction comprehensively: {e}")
            return None

    def _parse_token_balance_changes(self, pre_balances: List, post_balances: List, wallet_address: str, account_keys: List) -> List[Dict]:
        """Parse token balance changes into transfer objects"""
        transfers = []
        
        # Create lookup maps
        pre_map = {bal['accountIndex']: bal for bal in pre_balances}
        post_map = {bal['accountIndex']: bal for bal in post_balances}
        
        # Find all account indices with changes
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
                
                # Calculate change
                pre_amount = float(pre_bal.get('uiTokenAmount', {}).get('uiAmount', 0) or 0)
                post_amount = float(post_bal.get('uiTokenAmount', {}).get('uiAmount', 0) or 0)
                change = post_amount - pre_amount
                
                if abs(change) < 0.000001:
                    continue
                
                # Check if it's an NFT (supply = 1, decimals = 0)
                decimals = pre_bal.get('uiTokenAmount', {}).get('decimals', 0)
                is_nft = decimals == 0 and abs(change) == 1
                
                transfer = {
                    'mint': mint,
                    'account_address': account_address,
                    'amount': abs(change),
                    'direction': 'incoming' if change > 0 else 'outgoing',
                    'decimals': decimals,
                    'symbol': 'UNKNOWN',  # Would need token metadata lookup
                    'name': None,
                    'is_nft': is_nft,
                    'metadata': None
                }
                
                # Set from/to addresses
                if account_address == wallet_address:
                    if change > 0:
                        transfer['from_address'] = 'unknown'
                        transfer['to_address'] = wallet_address
                    else:
                        transfer['from_address'] = wallet_address
                        transfer['to_address'] = 'unknown'
                
                transfers.append(transfer)
                
            except Exception as e:
                logger.warning(f"Failed to parse token transfer for account {account_index}: {e}")
                continue
        
        # Filter to wallet-related transfers only
        wallet_transfers = [t for t in transfers if wallet_address in [t.get('from_address'), t.get('to_address'), t.get('account_address')]]
        return wallet_transfers

    def _identify_dapp_from_programs(self, program_ids: List[str]) -> Optional[Dict]:
        """Identify DApp from program IDs"""
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

    async def get_program_bytecode(self, program_id: str) -> str:
        """Get program bytecode for analysis"""
        try:
            result = await self._make_rpc_call_with_retry("getAccountInfo", [
                program_id,
                {"encoding": "base64", "commitment": "confirmed"}
            ])
            
            if result and result.get('value') and result['value'].get('data'):
                # Data is returned as [data, encoding] format
                data_info = result['value']['data']
                if isinstance(data_info, list) and len(data_info) >= 1:
                    return data_info[0]  # Base64 encoded bytecode
            
            return ""
            
        except Exception as e:
            logger.error(f"Failed to get program bytecode: {e}")
            return ""

    async def get_program_instructions(self, program_id: str, limit: int = 100) -> List[str]:
        """Get recent instructions for a program"""
        try:
            # Get recent transactions involving this program
            signatures = await self._make_rpc_call_with_retry("getSignaturesForAddress", [
                program_id,
                {"limit": limit, "commitment": "confirmed"}
            ])
            
            instructions = []
            for sig_info in signatures[:20]:  # Limit to prevent rate limiting
                try:
                    signature = sig_info.get('signature', '')
                    if not signature:
                        continue
                    
                    tx_data = await self._make_rpc_call_with_retry("getTransaction", [
                        signature,
                        {"encoding": "jsonParsed", "commitment": "confirmed"}
                    ])
                    
                    if tx_data and tx_data.get('transaction'):
                        tx_instructions = tx_data['transaction'].get('message', {}).get('instructions', [])
                        for instruction in tx_instructions:
                            if instruction.get('programId') == program_id:
                                if 'parsed' in instruction:
                                    inst_type = instruction['parsed'].get('type', 'unknown')
                                    instructions.append(inst_type)
                                else:
                                    instructions.append('raw_instruction')
                    
                    await asyncio.sleep(0.1)  # Rate limiting
                    
                except Exception as e:
                    logger.warning(f"Failed to fetch instruction data: {e}")
                    continue
            
            # Return unique instructions
            return list(set(instructions))
            
        except Exception as e:
            logger.error(f"Failed to get program instructions: {e}")
            return []

    async def get_program_metadata(self, program_id: str) -> Dict:
        """Get program metadata if available"""
        try:
            # Get basic account info
            account_info = await self.get_program_account_info(program_id)
            
            metadata = {
                'program_id': program_id,
                'executable': account_info.get('executable', False),
                'owner': account_info.get('owner', ''),
                'lamports': account_info.get('lamports', 0),
                'data_size': 0,
                'is_known_program': False,
                'program_type': 'unknown'
            }
            
            # Calculate data size
            if account_info.get('data') and isinstance(account_info['data'], list):
                try:
                    import base64
                    data_bytes = base64.b64decode(account_info['data'][0])
                    metadata['data_size'] = len(data_bytes)
                except Exception:
                    pass
            
            # Check if it's a known program
            known_programs = {
                'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4': {'name': 'Jupiter', 'type': 'dex'},
                '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8': {'name': 'Raydium', 'type': 'dex'},
                'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc': {'name': 'Orca', 'type': 'dex'},
                'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA': {'name': 'SPL Token Program', 'type': 'system'},
                '11111111111111111111111111111111': {'name': 'System Program', 'type': 'system'}
            }
            
            if program_id in known_programs:
                program_info = known_programs[program_id]
                metadata.update({
                    'is_known_program': True,
                    'name': program_info['name'],
                    'program_type': program_info['type']
                })
            
            return metadata
            
        except Exception as e:
            logger.error(f"Failed to get program metadata: {e}")
            return {'program_id': program_id, 'error': str(e)}

    async def check_program_authorities(self, program_id: str) -> Dict:
        """Check program upgrade authority and other control mechanisms"""
        try:
            # Get account info to check if upgradeable
            account_info = await self.get_program_account_info(program_id)
            
            authority_info = {
                'program_id': program_id,
                'is_upgradeable': False,
                'upgrade_authority': None,
                'is_immutable': False,
                'authority_analysis': {}
            }
            
            if not account_info.get('exists'):
                authority_info['error'] = 'Program does not exist'
                return authority_info
            
            # Check if program is executable
            if not account_info.get('executable'):
                authority_info['error'] = 'Not an executable program'
                return authority_info
            
            # For Solana programs, check if they're upgradeable by looking at the owner
            owner = account_info.get('owner', '')
            
            # BPF Loader programs can be upgradeable
            bpf_loaders = [
                'BPFLoaderUpgradeab1e11111111111111111111111',  # Upgradeable BPF Loader
                'BPFLoader2111111111111111111111111111111111',  # BPF Loader v2
                'BPFLoader1111111111111111111111111111111111'   # BPF Loader v1
            ]
            
            if owner in bpf_loaders:
                authority_info['is_upgradeable'] = True
                
                # Try to get upgrade authority for upgradeable programs
                if owner == 'BPFLoaderUpgradeab1e11111111111111111111111':
                    try:
                        # Derive program data account
                        program_data_seeds = [program_id.encode()[:32]]
                        # This is simplified - in reality you'd need proper PDA derivation
                        authority_info['upgrade_authority'] = 'Could not determine - requires PDA derivation'
                    except Exception:
                        authority_info['upgrade_authority'] = 'Unknown'
                else:
                    authority_info['upgrade_authority'] = 'Legacy loader - may be immutable'
            else:
                authority_info['is_immutable'] = True
                authority_info['upgrade_authority'] = 'Program is immutable'
            
            # Add analysis based on program type
            authority_info['authority_analysis'] = {
                'control_risk': 'high' if authority_info['is_upgradeable'] else 'low',
                'immutability': 'mutable' if authority_info['is_upgradeable'] else 'immutable',
                'loader_type': owner
            }
            
            return authority_info
            
        except Exception as e:
            logger.error(f"Failed to check program authorities: {e}")
            return {
                'program_id': program_id,
                'error': str(e),
                'is_upgradeable': False,
                'is_immutable': False
            }

    
    def _parse_transaction_data(self, tx_data: Dict) -> Optional[Dict]:
        """Parse transaction data into standard format"""
        try:
            transaction = tx_data.get('transaction', {})
            meta = tx_data.get('meta', {})
            block_time = tx_data.get('blockTime')
            
            parsed_tx = {
                'signature': transaction.get('signatures', [''])[0],
                'timestamp': datetime.fromtimestamp(block_time) if block_time else datetime.now(),
                'slot': tx_data.get('slot', 0),
                'fee': meta.get('fee', 0),
                'success': meta.get('err') is None,
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
            
            return parsed_tx
            
        except Exception as e:
            logger.error(f"Failed to parse transaction: {e}")
            return None