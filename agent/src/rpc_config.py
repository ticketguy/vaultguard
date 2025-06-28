"""
Flexible RPC Configuration System
Supports any RPC provider with auto-URL generation and custom URLs
Uses generic parameters for consistent naming across the system
"""

import os
from typing import Dict, List, Optional, Tuple
from loguru import logger

class FlexibleRPCConfig:
    """
    Smart RPC configuration that supports multiple providers and auto-generates URLs
    """
    
    def __init__(self):
        # Known RPC provider patterns
        self.provider_patterns = {
            'helius': {
                'url_pattern': 'https://mainnet.helius-rpc.com/?api-key={api_key}',
                'env_keys': ['HELIUS_API_KEY'],
                'name': 'Helius',
                'rate_limits': {'free': 100, 'premium': 1000}  # requests per minute
            },
            'quicknode': {
                'url_pattern': 'https://{endpoint}.solana-mainnet.quiknode.pro/{api_key}/',
                'env_keys': ['QUICKNODE_API_KEY', 'QUICKNODE_ENDPOINT'],
                'name': 'QuickNode',
                'rate_limits': {'free': 300, 'premium': 3000}
            },
            'alchemy': {
                'url_pattern': 'https://solana-mainnet.g.alchemy.com/v2/{api_key}',
                'env_keys': ['ALCHEMY_API_KEY'],
                'name': 'Alchemy',
                'rate_limits': {'free': 200, 'premium': 2000}
            },
            'triton': {
                'url_pattern': 'https://api.triton.one/rpc/{api_key}',
                'env_keys': ['TRITON_API_KEY'],
                'name': 'Triton One',
                'rate_limits': {'premium': 5000}
            },
            'ankr': {
                'url_pattern': 'https://rpc.ankr.com/solana/{api_key}',
                'env_keys': ['ANKR_API_KEY'],
                'name': 'Ankr',
                'rate_limits': {'free': 100, 'premium': 1000}
            },
            'getblock': {
                'url_pattern': 'https://sol.getblock.io/{api_key}/mainnet/',
                'env_keys': ['GETBLOCK_API_KEY'],
                'name': 'GetBlock',
                'rate_limits': {'free': 40000, 'premium': 100000}
            },
            'syndica': {
                'url_pattern': 'https://solana-api.syndica.io/access-token/{api_key}/rpc',
                'env_keys': ['SYNDICA_API_KEY'],
                'name': 'Syndica',
                'rate_limits': {'premium': 2000}
            }
        }
        
        # Fallback public RPCs (no API key needed)
        self.public_rpcs = [
            {'url': 'https://api.mainnet-beta.solana.com', 'name': 'Solana_Public'},
            {'url': 'https://solana-api.projectserum.com', 'name': 'Serum'},
            {'url': 'https://rpc.ankr.com/solana', 'name': 'Ankr_Public'},
            {'url': 'https://solana-mainnet.phantom.app/YBPpkkN4g91xDiAnTE9r0R7tbaWrQk3muennlvPhRgRs', 'name': 'Phantom'}
        ]
    
    def detect_and_configure_rpc(self) -> Tuple[str, str, List[Dict], str]:
        """
        Detect available RPC configuration and return primary URL, provider name, all endpoints, and API key
        
        Returns:
            Tuple[primary_url, provider_name, all_endpoints, api_key]
        """
        # Check for custom URL first (highest priority)
        custom_url = os.getenv('CUSTOM_SOLANA_RPC_URL')
        custom_api_key = os.getenv('CUSTOM_SOLANA_API_KEY', '')
        
        if custom_url:
            # Handle custom URL with optional API key
            final_url = self._apply_custom_api_key(custom_url, custom_api_key)
            logger.info(f"🔧 Using custom Solana RPC: {final_url[:50]}...")
            return final_url, "Custom", self._build_endpoint_list(final_url, "Custom"), custom_api_key
        
        # Check for explicit SOLANA_RPC_URL (second priority)
        explicit_url = os.getenv('SOLANA_RPC_URL')
        if explicit_url and not explicit_url == 'https://api.mainnet-beta.solana.com':
            logger.info(f"🔧 Using configured Solana RPC: {explicit_url[:50]}...")
            return explicit_url, "Configured", self._build_endpoint_list(explicit_url, "Configured"), ""
        
        # Auto-detect provider based on available API keys (third priority)
        detected_provider = self._detect_provider()
        if detected_provider:
            provider_name, primary_url, api_key = detected_provider
            logger.info(f"🚀 Auto-detected {provider_name} with API key")
            return primary_url, provider_name, self._build_endpoint_list(primary_url, provider_name), api_key
        
        # Fall back to public RPC (lowest priority)
        public_url = self.public_rpcs[0]['url']
        logger.info(f"📡 Using public Solana RPC (no API keys detected)")
        return public_url, "Public", self._build_public_endpoint_list(), ""
    
    def _apply_custom_api_key(self, url: str, api_key: str) -> str:
        """Apply API key to custom URL if provided"""
        if not api_key:
            return url
        
        # If URL already contains an API key pattern, don't modify
        if any(pattern in url.lower() for pattern in ['api-key=', '/v2/', 'access-token']):
            return url
        
        # Apply API key using query parameter (most common)
        if '?' in url:
            return f"{url}&api-key={api_key}"
        else:
            return f"{url}?api-key={api_key}"
    
    def _detect_provider(self) -> Optional[Tuple[str, str, str]]:
        """Detect which RPC provider is configured based on environment variables"""
        
        for provider_key, provider_config in self.provider_patterns.items():
            # Check if all required environment variables are present
            required_keys = provider_config['env_keys']
            env_values = {}
            
            all_keys_present = True
            for env_key in required_keys:
                value = os.getenv(env_key)
                if not value:
                    all_keys_present = False
                    break
                env_values[env_key.lower().replace('_api_key', '').replace('_endpoint', '')] = value
            
            if all_keys_present:
                # Generate URL using the pattern
                url = self._generate_provider_url(provider_config, env_values)
                if url:
                    # Return provider name, URL, and primary API key
                    primary_api_key = next(iter(env_values.values()))  # Get first API key
                    return provider_config['name'], url, primary_api_key
        
        return None
    
    def _generate_provider_url(self, provider_config: Dict, env_values: Dict) -> Optional[str]:
        """Generate RPC URL based on provider pattern and environment values"""
        try:
            url_pattern = provider_config['url_pattern']
            
            # Handle different substitution patterns
            if 'helius' in url_pattern:
                api_key = env_values.get('helius', '')
                return url_pattern.format(api_key=api_key)
            
            elif 'quicknode' in url_pattern:
                api_key = env_values.get('quicknode', '')
                endpoint = env_values.get('quicknode', '')  # QuickNode provides endpoint in API key
                return url_pattern.format(api_key=api_key, endpoint=endpoint)
            
            elif 'alchemy' in url_pattern:
                api_key = env_values.get('alchemy', '')
                return url_pattern.format(api_key=api_key)
            
            elif 'triton' in url_pattern:
                api_key = env_values.get('triton', '')
                return url_pattern.format(api_key=api_key)
            
            elif 'ankr' in url_pattern:
                api_key = env_values.get('ankr', '')
                return url_pattern.format(api_key=api_key)
            
            elif 'getblock' in url_pattern:
                api_key = env_values.get('getblock', '')
                return url_pattern.format(api_key=api_key)
            
            elif 'syndica' in url_pattern:
                api_key = env_values.get('syndica', '')
                return url_pattern.format(api_key=api_key)
            
            else:
                # Generic pattern - use first available API key
                first_key = list(env_values.values())[0] if env_values else ''
                return url_pattern.format(api_key=first_key)
                
        except Exception as e:
            logger.warning(f"⚠️ Failed to generate URL for provider: {e}")
            return None
    
    def _build_endpoint_list(self, primary_url: str, provider_name: str) -> List[Dict]:
        """Build list of endpoints with primary first, then fallbacks"""
        endpoints = [{'url': primary_url, 'name': provider_name}]
        
        # Add public RPCs as fallbacks
        for public_rpc in self.public_rpcs:
            if public_rpc['url'] != primary_url:  # Avoid duplicates
                endpoints.append(public_rpc)
        
        return endpoints
    
    def _build_public_endpoint_list(self) -> List[Dict]:
        """Build list starting with public RPCs"""
        return self.public_rpcs.copy()
    
    def get_provider_info(self, provider_name: str) -> Optional[Dict]:
        """Get information about a specific provider"""
        for provider_config in self.provider_patterns.values():
            if provider_config['name'].lower() == provider_name.lower():
                return provider_config
        return None
    
    def validate_custom_url(self, url: str) -> bool:
        """Validate if a custom URL is properly formatted"""
        import re
        # Basic URL validation
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return url_pattern.match(url) is not None
    
    def get_configuration_summary(self) -> Dict:
        """Get a summary of current RPC configuration"""
        primary_url, provider_name, all_endpoints, api_key = self.detect_and_configure_rpc()
        
        return {
            'primary_rpc': {
                'url': primary_url,
                'provider': provider_name
            },
            'fallback_rpcs': [ep for ep in all_endpoints[1:]],  # Skip primary
            'total_endpoints': len(all_endpoints),
            'detected_providers': self._get_detected_providers(),
            'configuration_method': self._get_config_method(),
            'api_key_configured': bool(api_key)
        }
    
    def _get_detected_providers(self) -> List[str]:
        """Get list of providers with available API keys"""
        detected = []
        for provider_key, provider_config in self.provider_patterns.items():
            if all(os.getenv(key) for key in provider_config['env_keys']):
                detected.append(provider_config['name'])
        return detected
    
    def _get_config_method(self) -> str:
        """Determine how RPC was configured"""
        if os.getenv('CUSTOM_SOLANA_RPC_URL'):
            return 'custom_url'
        elif os.getenv('SOLANA_RPC_URL') and os.getenv('SOLANA_RPC_URL') != 'https://api.mainnet-beta.solana.com':
            return 'explicit_url'
        elif self._detect_provider():
            return 'auto_detected'
        else:
            return 'public_fallback'


# Updated SecuritySensor setup function with generic parameters
def setup_flexible_security_sensor():
    """Setup SecuritySensor with flexible RPC configuration using generic parameters"""
    
    # Initialize RPC configuration
    rpc_config = FlexibleRPCConfig()
    
    # Get optimal RPC configuration (now returns API key too)
    primary_url, provider_name, all_endpoints, api_key = rpc_config.detect_and_configure_rpc()
    
    # Get monitored wallets
    monitored_wallets = []
    wallet_env_vars = [key for key in os.environ.keys() if key.startswith("MONITOR_WALLET_")]
    for wallet_var in wallet_env_vars:
        wallet_address = os.environ[wallet_var]
        if wallet_address:
            monitored_wallets.append(wallet_address)
    
    # Default to demo wallets if none specified
    if not monitored_wallets:
        monitored_wallets = [
            "7xKs1aTF7YbL8C9s3mZNbGKPFXCWuBvf9Ss623VQ5DA",
            "9mNp2bK8fG3cCd4sVhMnBkLpQrTt5RwXyZ7nE8hS1kL"
        ]
    
    logger.info(f"🛡️ Setting up SecuritySensor for {len(monitored_wallets)} wallets:")
    for wallet in monitored_wallets:
        logger.info(f"   📡 Monitoring: {wallet[:8]}...{wallet[-8:]}")
    
    logger.info(f"🚀 Primary RPC: {provider_name}")
    if api_key:
        logger.info(f"🔑 API key configured for enhanced rate limits")
    logger.info(f"🔄 Total endpoints available: {len(all_endpoints)}")
    
    # Import SecuritySensor here to avoid circular imports
    from src.sensor.security import SecuritySensor
    
    # Create SecuritySensor with generic configuration (updated to match new SecuritySensor interface)
    sensor = SecuritySensor(
        wallet_addresses=monitored_wallets,
        solana_rpc_url=primary_url,
        rpc_api_key=api_key,  # Generic API key parameter - works with any provider
        rpc_provider_name=provider_name,  # Clear provider name
    )
    
    # Print configuration summary
    config_summary = rpc_config.get_configuration_summary()
    logger.info(f"📊 RPC Configuration Summary:")
    logger.info(f"   🎯 Method: {config_summary['configuration_method']}")
    logger.info(f"   🔑 Detected providers: {', '.join(config_summary['detected_providers']) if config_summary['detected_providers'] else 'None'}")
    logger.info(f"   🔐 API key status: {'Configured' if config_summary['api_key_configured'] else 'Not configured'}")
    logger.info(f"   🔄 Fallback endpoints: {len(config_summary['fallback_rpcs'])}")
    
    return sensor


# Helper function for backward compatibility
def setup_security_sensor_with_provider(provider_name: str, api_key: str, monitored_wallets: List[str] = None):
    """
    Setup SecuritySensor with specific provider configuration
    Useful for programmatic setup or testing with specific providers
    """
    rpc_config = FlexibleRPCConfig()
    
    # Get provider info
    provider_info = rpc_config.get_provider_info(provider_name)
    if not provider_info:
        raise ValueError(f"Unknown provider: {provider_name}")
    
    # Generate URL for this provider
    try:
        url_pattern = provider_info['url_pattern']
        primary_url = url_pattern.format(api_key=api_key)
    except Exception as e:
        raise ValueError(f"Failed to generate URL for {provider_name}: {e}")
    
    # Default wallets if none provided
    if not monitored_wallets:
        monitored_wallets = [
            "7xKs1aTF7YbL8C9s3mZNbGKPFXCWuBvf9Ss623VQ5DA",
            "9mNp2bK8fG3cCd4sVhMnBkLpQrTt5RwXyZ7nE8hS1kL"
        ]
    
    logger.info(f"🛡️ Setting up SecuritySensor with {provider_name}")
    logger.info(f"🚀 Primary RPC: {primary_url[:50]}...")
    
    # Import SecuritySensor here to avoid circular imports
    from src.sensor.security import SecuritySensor
    
    sensor = SecuritySensor(
        wallet_addresses=monitored_wallets,
        solana_rpc_url=primary_url,
        rpc_api_key=api_key,
        rpc_provider_name=provider_name,
    )
    
    return sensor


# Utility function to test RPC configuration
def test_rpc_configuration():
    """Test current RPC configuration and display results"""
    rpc_config = FlexibleRPCConfig()
    
    logger.info("🔍 Testing RPC Configuration...")
    
    # Test detection
    primary_url, provider_name, all_endpoints, api_key = rpc_config.detect_and_configure_rpc()
    
    logger.info(f"✅ Primary: {provider_name} - {primary_url[:50]}...")
    logger.info(f"🔑 API Key: {'Configured' if api_key else 'Not configured'}")
    logger.info(f"🔄 Fallbacks: {len(all_endpoints) - 1} endpoints")
    
    # Test configuration summary
    summary = rpc_config.get_configuration_summary()
    logger.info(f"📊 Configuration Summary:")
    for key, value in summary.items():
        if key != 'fallback_rpcs':  # Skip detailed fallback list
            logger.info(f"   {key}: {value}")
    
    # Test detected providers
    detected = rpc_config._get_detected_providers()
    if detected:
        logger.info(f"🚀 Detected providers: {', '.join(detected)}")
    else:
        logger.info(f"📡 No provider API keys detected, using public RPCs")
    
    return summary


if __name__ == "__main__":
    # Test the configuration
    test_rpc_configuration()