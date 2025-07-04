
import aiohttp
from typing import Dict, Optional
from datetime import datetime, timedelta
from loguru import logger

class JupiterConnector:
    """Connector for Jupiter API to fetch token swap routes and market data."""
    
    def __init__(self, api_url: str, api_key: str, rate_limit: int = 30, timeout: int = 10):
        """
        Initialize Jupiter connector with API configuration.
        
        Args:
            api_url (str): Base URL for Jupiter API
            api_key (str): API key for authentication
            rate_limit (int): Maximum requests per minute
            timeout (int): Request timeout in seconds
        """
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.last_requests = []
    
    async def fetch_popular_routes(self, params: Dict) -> Optional[Dict]:
        """
        Fetch popular swap routes from Jupiter API.
        
        Args:
            params (Dict): Query parameters (e.g., inputMint, outputMint, amount)
        
        Returns:
            Optional[Dict]: Route data or None if request fails
        """
        try:
            self._enforce_rate_limit()
            async with aiohttp.ClientSession() as session:
                headers = {'Authorization': f"Bearer {self.api_key}"}
                async with session.get(f"{self.api_url}/v6/quote", params=params, headers=headers, timeout=self.timeout) as response:
                    if response.status != 200:
                        logger.warning(f"Jupiter API returned status {response.status}")
                        return None
                    data = await response.json()
                    self.last_requests.append(datetime.now())
                    return {
                        'routes': data.get('data', []),
                        'source': 'jupiter_api',
                        'timestamp': datetime.now().isoformat()
                    }
        except Exception as e:
            logger.error(f"Jupiter API fetch error: {e}")
            return None
    
    def _enforce_rate_limit(self):
        """Enforce rate limiting for API requests."""
        now = datetime.now()
        cutoff = now - timedelta(minutes=1)
        self.last_requests = [t for t in self.last_requests if t > cutoff]
        if len(self.last_requests) >= self.rate_limit:
            logger.warning(f"Jupiter API rate limit exceeded ({self.rate_limit} requests/min)")
            raise Exception("Rate limit exceeded")
