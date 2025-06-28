"""
Enhanced Solana RPC Client with Intelligent Rate Limiting
Automatically handles 429 errors, implements exponential backoff, and provides fallback RPCs
Works with any RPC provider - Helius, QuickNode, Alchemy, Custom RPCs
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
    HEALTHY = "healthy"
    RATE_LIMITED = "rate_limited" 
    ERROR = "error"
    TIMEOUT = "timeout"

@dataclass
class RPCEndpoint:
    """RPC endpoint with health tracking"""
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
    Enhanced Solana RPC client with automatic rate limiting, fallbacks, and self-healing
    Works with any RPC provider - generic API key support
    """
    
    def __init__(self, rpc_api_key: Optional[str] = None, primary_rpc_url: str = "https://api.mainnet-beta.solana.com", rpc_provider_name: str = "Unknown"):
        # Set up multiple RPC endpoints for redundancy
        self.endpoints = []
        self.rpc_provider_name = rpc_provider_name
        self.rpc_api_key = rpc_api_key
        
        # Primary endpoint (highest priority if API key provided)
        if rpc_api_key and primary_rpc_url:
            # Smart URL construction based on provider type
            primary_endpoint_url = self._construct_api_url(primary_rpc_url, rpc_api_key, rpc_provider_name)
            self.endpoints.append(RPCEndpoint(
                url=primary_endpoint_url,
                name=rpc_provider_name,
                api_key=rpc_api_key
            ))
            logger.info(f"🚀 Primary RPC: {rpc_provider_name} with API key")
        elif primary_rpc_url:
            # Use primary URL without API key
            self.endpoints.append(RPCEndpoint(
                url=primary_rpc_url,
                name=rpc_provider_name or "Primary"
            ))
            logger.info(f"📡 Primary RPC: {rpc_provider_name or 'Primary'} (no API key)")
        
        # Public RPC endpoints as fallbacks
        fallback_endpoints = [
            RPCEndpoint(url="https://api.mainnet-beta.solana.com", name="Solana_Public"),
            RPCEndpoint(url="https://solana-api.projectserum.com", name="Serum"),
            RPCEndpoint(url="https://rpc.ankr.com/solana", name="Ankr"),
            RPCEndpoint(url="https://solana-mainnet.phantom.app/YBPpkkN4g91xDiAnTE9r0R7tbaWrQk3muennlvPhRgRs", name="Phantom"),
        ]
        
        # Add fallbacks that aren't duplicates of primary
        for fallback in fallback_endpoints:
            if not any(ep.url == fallback.url for ep in self.endpoints):
                self.endpoints.append(fallback)
        
        self.session = None
        self.current_endpoint_index = 0
        
        # Rate limiting configuration
        self.max_requests_per_second = 10
        self.max_burst_requests = 20
        self.request_timestamps = []
        
        # Retry configuration
        self.max_retries = 3
        self.base_delay = 1.0  # seconds
        self.max_delay = 60.0  # seconds
        self.backoff_multiplier = 2.0
        
        # Circuit breaker configuration
        self.circuit_breaker_threshold = 5  # consecutive errors
        self.circuit_breaker_reset_time = 300  # 5 minutes
        
        logger.info(f"🔄 Initialized RPC client with {len(self.endpoints)} endpoints")
    
    def _construct_api_url(self, base_url: str, api_key: str, provider_name: str) -> str:
        """Smart URL construction based on provider patterns"""
        base_url_lower = base_url.lower()
        provider_lower = provider_name.lower()
        
        # If URL already contains API key, return as-is
        if 'api-key=' in base_url_lower or '/v2/' in base_url_lower or api_key in base_url:
            return base_url
        
        # Provider-specific URL patterns
        if 'helius' in base_url_lower or 'helius' in provider_lower:
            if '?' in base_url:
                return f"{base_url}&api-key={api_key}"
            else:
                return f"{base_url}?api-key={api_key}"
        
        elif 'alchemy' in base_url_lower or 'alchemy' in provider_lower:
            # Alchemy uses /v2/{api_key} pattern
            if base_url.endswith('/'):
                return f"{base_url}v2/{api_key}"
            else:
                return f"{base_url}/v2/{api_key}"
        
        elif 'quicknode' in base_url_lower or 'quicknode' in provider_lower:
            # QuickNode usually has API key in path
            if api_key not in base_url:
                return f"{base_url.rstrip('/')}/{api_key}/"
            return base_url
        
        elif 'ankr' in base_url_lower or 'ankr' in provider_lower:
            # Ankr uses /{api_key} pattern for premium
            return f"{base_url.rstrip('/')}/{api_key}"
        
        elif 'triton' in base_url_lower or 'triton' in provider_lower:
            # Triton uses /rpc/{api_key} pattern
            return f"{base_url.rstrip('/')}/{api_key}"
        
        else:
            # Generic: try query parameter first
            if '?' in base_url:
                return f"{base_url}&api-key={api_key}"
            else:
                return f"{base_url}?api-key={api_key}"
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30, connect=10)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def _get_healthy_endpoint(self) -> Optional[RPCEndpoint]:
        """Get the next healthy endpoint using round-robin with health checks"""
        now = datetime.now()
        
        # Try to find a healthy endpoint starting from current index
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
        """Implement intelligent rate limiting"""
        now = time.time()
        
        # Remove old timestamps (older than 1 second)
        self.request_timestamps = [ts for ts in self.request_timestamps if now - ts < 1.0]
        
        # Check if we need to wait
        if len(self.request_timestamps) >= self.max_requests_per_second:
            sleep_time = 1.0 - (now - self.request_timestamps[0])
            if sleep_time > 0:
                logger.debug(f"🕒 Rate limiting: waiting {sleep_time:.2f}s")
                await asyncio.sleep(sleep_time)
        
        # Add current request timestamp
        self.request_timestamps.append(now)
    
    async def _make_rpc_call_with_retry(self, method: str, params: List[Any], retry_count: int = 0) -> Dict:
        """Make RPC call with automatic retry and fallback logic"""
        endpoint = self._get_healthy_endpoint()
        if not endpoint:
            raise Exception("No available RPC endpoints")
        
        await self._wait_for_rate_limit()
        
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30, connect=10)
            )
        
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }
        
        try:
            logger.debug(f"📡 {endpoint.name}: {method}")
            
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
                        delay += random.uniform(0, delay * 0.1)  # Add jitter
                        logger.info(f"⏱️ HTTP {response.status}: retrying in {delay:.1f}s")
                        await asyncio.sleep(delay)
                        return await self._make_rpc_call_with_retry(method, params, retry_count + 1)
                    else:
                        raise Exception(f"HTTP {response.status} after {self.max_retries} retries")
                
                # Parse successful response
                data = await response.json()
                
                # Handle JSON-RPC errors
                if 'error' in data:
                    await self._handle_rpc_error(endpoint, data['error'])
                    
                    if retry_count < self.max_retries:
                        delay = min(self.base_delay * (self.backoff_multiplier ** retry_count), self.max_delay)
                        logger.info(f"🔄 RPC error: retrying in {delay:.1f}s")
                        await asyncio.sleep(delay)
                        return await self._make_rpc_call_with_retry(method, params, retry_count + 1)
                    else:
                        raise Exception(f"RPC error: {data['error']}")
                
                # Success!
                endpoint.success_count += 1
                endpoint.consecutive_errors = 0
                if endpoint.status != RPCStatus.HEALTHY:
                    endpoint.status = RPCStatus.HEALTHY
                    logger.info(f"✅ {endpoint.name} endpoint recovered")
                
                return data.get('result', {})
        
        except asyncio.TimeoutError:
            await self._handle_timeout(endpoint)
            if retry_count < self.max_retries:
                delay = min(self.base_delay * (self.backoff_multiplier ** retry_count), self.max_delay)
                logger.info(f"⏱️ Timeout: retrying in {delay:.1f}s")
                await asyncio.sleep(delay)
                return await self._make_rpc_call_with_retry(method, params, retry_count + 1)
            else:
                raise Exception(f"Timeout after {self.max_retries} retries")
        
        except Exception as e:
            await self._handle_general_error(endpoint, e)
            if retry_count < self.max_retries:
                delay = min(self.base_delay * (self.backoff_multiplier ** retry_count), self.max_delay)
                logger.info(f"🔄 Error: {e} - retrying in {delay:.1f}s")
                await asyncio.sleep(delay)
                return await self._make_rpc_call_with_retry(method, params, retry_count + 1)
            else:
                raise
    
    async def _handle_rate_limit(self, endpoint: RPCEndpoint, response):
        """Handle 429 rate limit response"""
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
                logger.warning(f"🚫 {endpoint.name} rate limited, reset in 60s (default)")
        else:
            # No Retry-After header, estimate based on endpoint type/provider
            provider_lower = endpoint.name.lower()
            if "helius" in provider_lower:
                reset_time = 60  # Helius typically resets every minute
            elif "alchemy" in provider_lower:
                reset_time = 60  # Alchemy similar to Helius
            elif "quicknode" in provider_lower:
                reset_time = 30  # QuickNode might be faster
            else:
                reset_time = 120  # Public RPCs might have longer windows
            
            endpoint.rate_limit_reset_time = datetime.now() + timedelta(seconds=reset_time)
            logger.warning(f"🚫 {endpoint.name} rate limited, estimated reset in {reset_time}s")
    
    async def _handle_http_error(self, endpoint: RPCEndpoint, response):
        """Handle HTTP errors"""
        endpoint.consecutive_errors += 1
        endpoint.last_error_time = datetime.now()
        
        if endpoint.consecutive_errors >= self.circuit_breaker_threshold:
            endpoint.status = RPCStatus.ERROR
            logger.error(f"💥 {endpoint.name} circuit breaker triggered after {endpoint.consecutive_errors} errors")
        
        logger.warning(f"⚠️ {endpoint.name} HTTP {response.status}: {await response.text()}")
    
    async def _handle_rpc_error(self, endpoint: RPCEndpoint, error_data):
        """Handle JSON-RPC errors"""
        error_code = error_data.get('code', 0)
        error_message = error_data.get('message', 'Unknown RPC error')
        
        # Some RPC errors are retryable, others are not
        retryable_codes = [-32603, -32005, -32002]  # Internal error, rate limit, transaction not found
        
        if error_code in retryable_codes:
            endpoint.consecutive_errors += 1
            logger.warning(f"⚠️ {endpoint.name} retryable RPC error {error_code}: {error_message}")
        else:
            logger.error(f"❌ {endpoint.name} RPC error {error_code}: {error_message}")
    
    async def _handle_timeout(self, endpoint: RPCEndpoint):
        """Handle timeout errors"""
        endpoint.status = RPCStatus.TIMEOUT
        endpoint.consecutive_errors += 1
        endpoint.last_error_time = datetime.now()
        logger.warning(f"⏱️ {endpoint.name} timeout")
    
    async def _handle_general_error(self, endpoint: RPCEndpoint, error: Exception):
        """Handle general errors"""
        endpoint.consecutive_errors += 1
        endpoint.last_error_time = datetime.now()
        
        if endpoint.consecutive_errors >= self.circuit_breaker_threshold:
            endpoint.status = RPCStatus.ERROR
            logger.error(f"💥 {endpoint.name} circuit breaker triggered: {error}")
        else:
            logger.warning(f"⚠️ {endpoint.name} error: {error}")
    
    def get_endpoint_health(self) -> Dict[str, Any]:
        """Get health status of all endpoints"""
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