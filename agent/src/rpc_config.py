"""
Flexible RPC Configuration System
==============================================================

What this does:
- Finds the best Solana RPC (Remote Procedure Call) to connect to the blockchain
- Automatically detects which RPC providers you have API keys for
- Sets up fallback RPCs in case the main one fails
- Handles different URL formats for different providers

Think of it like:
- You want to call someone (the blockchain)
- This system finds the best phone number to use (RPC URL)
- If that number is busy, it tries backup numbers (fallbacks)
- Some numbers are premium (with API keys), some are free (public RPCs)
"""

import os
from typing import Dict, List, Optional, Tuple
from loguru import logger

class FlexibleRPCConfig:
    """
    Smart RPC configuration that supports multiple providers and auto-generates URLs
    
    Simple explanation: This is like a smart phone book that:
    1. Looks through your contacts (environment variables) 
    2. Finds the best phone number to call (RPC URL)
    3. Keeps backup numbers ready (fallback RPCs)
    """
    
    def __init__(self):
        # Known RPC provider patterns - like a phone book with templates
        # Each provider has different URL formats, so we store the patterns here
        self.provider_patterns = {
            'helius': {
                # Template: "https://mainnet.helius-rpc.com/?api-key=YOUR_KEY"
                'url_pattern': 'https://mainnet.helius-rpc.com/?api-key={api_key}',
                'env_keys': ['HELIUS_API_KEY'],  # What environment variable to look for
                'name': 'Helius',
                'rate_limits': {'free': 100, 'premium': 1000}  # How many requests per minute
            },
            'quicknode': {
                # Template: "https://neat-quiet-pine.solana-mainnet.quiknode.pro/YOUR_KEY/"
                'url_pattern': 'https://{endpoint}.solana-mainnet.quiknode.pro/{api_key}/',
                'env_keys': ['QUICKNODE_API_KEY', 'QUICKNODE_ENDPOINT'],  # Needs both key and endpoint
                'name': 'QuickNode',
                'rate_limits': {'free': 300, 'premium': 3000}
            },
            'alchemy': {
                # Template: "https://solana-mainnet.g.alchemy.com/v2/YOUR_KEY"
                'url_pattern': 'https://solana-mainnet.g.alchemy.com/v2/{api_key}',
                'env_keys': ['ALCHEMY_API_KEY'],
                'name': 'Alchemy',
                'rate_limits': {'free': 200, 'premium': 2000}
            },
            # More providers... each has their own URL format
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
        
        # Fallback public RPCs - free phone numbers anyone can use
        # These work without API keys but have stricter limits
        self.public_rpcs = [
            {'url': 'https://api.mainnet-beta.solana.com', 'name': 'Solana_Public'},
            {'url': 'https://solana-api.projectserum.com', 'name': 'Serum'},
            {'url': 'https://rpc.ankr.com/solana', 'name': 'Ankr_Public'},
            {'url': 'https://solana-mainnet.phantom.app/YBPpkkN4g91xDiAnTE9r0R7tbaWrQk3muennlvPhRgRs', 'name': 'Phantom'}
        ]
    
    def detect_and_configure_rpc(self) -> Tuple[str, str, List[Dict], str]:
        """
        Main function: Find the best RPC to use
        
        Simple explanation: This is like asking "Who should I call?"
        It checks in order:
        1. Did the user give me a custom number? (CUSTOM_SOLANA_RPC_URL)
        2. Did the user specify a particular number? (SOLANA_RPC_URL) 
        3. Do I have any premium numbers? (API keys for Helius, QuickNode, etc.)
        4. Fall back to free numbers (public RPCs)
        
        Returns: (best_url, provider_name, all_backup_urls, api_key)
        """
        
        # PRIORITY 1: Check for custom URL first (highest priority)
        # User said "Use this specific RPC no matter what"
        custom_url = os.getenv('CUSTOM_SOLANA_RPC_URL')
        custom_api_key = os.getenv('CUSTOM_SOLANA_API_KEY', '')
        
        if custom_url:
            # User wants to use their own custom RPC
            final_url = self._apply_custom_api_key(custom_url, custom_api_key)
            logger.info(f"🔧 Using custom Solana RPC: {final_url[:50]}...")
            return final_url, "Custom", self._build_endpoint_list(final_url, "Custom"), custom_api_key
        
        # PRIORITY 2: Check for explicit SOLANA_RPC_URL (second priority)
        # User said "Use this RPC URL instead of auto-detection"
        explicit_url = os.getenv('SOLANA_RPC_URL')
        if explicit_url and not explicit_url == 'https://api.mainnet-beta.solana.com':
            logger.info(f"🔧 Using configured Solana RPC: {explicit_url[:50]}...")
            return explicit_url, "Configured", self._build_endpoint_list(explicit_url, "Configured"), ""
        
        # PRIORITY 3: Auto-detect provider based on available API keys (third priority)
        # "Let me check what premium services you have access to"
        detected_provider = self._detect_provider()
        if detected_provider:
            provider_name, primary_url, api_key = detected_provider
            logger.info(f"🚀 Auto-detected {provider_name} with API key")
            return primary_url, provider_name, self._build_endpoint_list(primary_url, provider_name), api_key
        
        # PRIORITY 4: Fall back to public RPC (lowest priority)
        # "No premium services found, using free public RPC"
        public_url = self.public_rpcs[0]['url']
        logger.info(f"📡 Using public Solana RPC (no API keys detected)")
        return public_url, "Public", self._build_public_endpoint_list(), ""
    
    def _apply_custom_api_key(self, url: str, api_key: str) -> str:
        """
        Add API key to custom URL if provided
        
        Simple explanation: If user gives us a URL and an API key,
        we need to combine them properly. Different RPCs want the key in different places.
        """
        if not api_key:
            return url  # No API key to add
        
        # If URL already has an API key in it, don't add another one
        if any(pattern in url.lower() for pattern in ['api-key=', '/v2/', 'access-token']):
            return url
        
        # Add API key as a URL parameter (most common way)
        if '?' in url:
            # URL already has parameters: "https://rpc.com/api?param=1" -> "https://rpc.com/api?param=1&api-key=KEY"
            return f"{url}&api-key={api_key}"
        else:
            # URL has no parameters: "https://rpc.com/api" -> "https://rpc.com/api?api-key=KEY"
            return f"{url}?api-key={api_key}"
    
    def _detect_provider(self) -> Optional[Tuple[str, str, str]]:
        """
        Look through all known providers and see which ones we have API keys for
        
        Simple explanation: Go through our list of RPC providers and check:
        "Do I have all the credentials needed for this service?"
        """
        
        # Check each provider in our list
        for provider_key, provider_config in self.provider_patterns.items():
            # Check if all required environment variables are present
            required_keys = provider_config['env_keys']  # What env vars does this provider need?
            env_values = {}  # Store the actual values we find
            
            all_keys_present = True
            # Check each required environment variable
            for env_key in required_keys:
                value = os.getenv(env_key)  # Look for this env var
                if not value:
                    all_keys_present = False  # Missing a required key
                    break
                # Store the value (remove _API_KEY and _ENDPOINT from the key name)
                env_values[env_key.lower().replace('_api_key', '').replace('_endpoint', '')] = value
            
            if all_keys_present:
                # We have all required credentials for this provider!
                url = self._generate_provider_url(provider_config, env_values)
                if url:
                    # Return: provider name, complete URL, and the API key
                    primary_api_key = next(iter(env_values.values()))  # Get the first API key
                    return provider_config['name'], url, primary_api_key
        
        return None  # Didn't find any providers with complete credentials
    
    def _generate_provider_url(self, provider_config: Dict, env_values: Dict) -> Optional[str]:
        """
        Build the actual URL for a specific provider using their template
        
        Simple explanation: Each provider wants their URL formatted differently.
        This takes their template and fills in your API key(s) to make the final URL.
        """
        try:
            url_pattern = provider_config['url_pattern']  # Get the template
            
            # Handle different providers' URL patterns
            if 'helius' in url_pattern:
                # Helius: "https://mainnet.helius-rpc.com/?api-key=YOUR_KEY"
                api_key = env_values.get('helius', '')
                return url_pattern.format(api_key=api_key)
            
            elif 'quicknode' in url_pattern:
                # QuickNode: "https://YOUR_ENDPOINT.solana-mainnet.quiknode.pro/YOUR_KEY/"
                # Needs both an endpoint name AND an API key
                api_key = env_values.get('quicknode', '')
                endpoint = env_values.get('quicknode', '')  # QuickNode gives you an endpoint name
                return url_pattern.format(api_key=api_key, endpoint=endpoint)
            
            elif 'alchemy' in url_pattern:
                # Alchemy: "https://solana-mainnet.g.alchemy.com/v2/YOUR_KEY"
                api_key = env_values.get('alchemy', '')
                return url_pattern.format(api_key=api_key)
            
            elif 'triton' in url_pattern:
                # Triton: "https://api.triton.one/rpc/YOUR_KEY"
                api_key = env_values.get('triton', '')
                return url_pattern.format(api_key=api_key)
            
            elif 'ankr' in url_pattern:
                # Ankr: "https://rpc.ankr.com/solana/YOUR_KEY"
                api_key = env_values.get('ankr', '')
                return url_pattern.format(api_key=api_key)
            
            elif 'getblock' in url_pattern:
                # GetBlock: "https://sol.getblock.io/YOUR_KEY/mainnet/"
                api_key = env_values.get('getblock', '')
                return url_pattern.format(api_key=api_key)
            
            elif 'syndica' in url_pattern:
                # Syndica: "https://solana-api.syndica.io/access-token/YOUR_KEY/rpc"
                api_key = env_values.get('syndica', '')
                return url_pattern.format(api_key=api_key)
            
            else:
                # Generic pattern - just use the first API key we have
                first_key = list(env_values.values())[0] if env_values else ''
                return url_pattern.format(api_key=first_key)
                
        except Exception as e:
            logger.warning(f"⚠️ Failed to generate URL for provider: {e}")
            return None
    
    def _build_endpoint_list(self, primary_url: str, provider_name: str) -> List[Dict]:
        """
        Create a list of all RPCs to try, with the main one first
        
        Simple explanation: Make a list like:
        1. Your main RPC (premium with API key)
        2. Backup RPC #1 (free public)
        3. Backup RPC #2 (free public)
        4. etc.
        """
        # Start with the main RPC
        endpoints = [{'url': primary_url, 'name': provider_name}]
        
        # Add public RPCs as backups (but don't duplicate the main one)
        for public_rpc in self.public_rpcs:
            if public_rpc['url'] != primary_url:  # Don't add the same URL twice
                endpoints.append(public_rpc)
        
        return endpoints
    
    def _build_public_endpoint_list(self) -> List[Dict]:
        """
        Create a list of just the free public RPCs
        
        Simple explanation: When we don't have any premium RPCs,
        just use the free ones in order of preference.
        """
        return self.public_rpcs.copy()
    
    def get_provider_info(self, provider_name: str) -> Optional[Dict]:
        """
        Get information about a specific provider by name
        
        Simple explanation: "Tell me everything you know about Helius"
        Returns the provider's URL pattern, rate limits, etc.
        """
        for provider_config in self.provider_patterns.values():
            if provider_config['name'].lower() == provider_name.lower():
                return provider_config
        return None
    
    def validate_custom_url(self, url: str) -> bool:
        """
        Check if a custom URL looks valid
        
        Simple explanation: Basic check to see if the URL format is correct
        (starts with http/https, has a domain name, etc.)
        """
        import re
        # Pattern that matches valid URLs
        url_pattern = re.compile(
            r'^https?://'  # Must start with http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # Domain name
            r'localhost|'  # Or localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # Or IP address
            r'(?::\d+)?'  # Optional port number
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)  # Optional path
        return url_pattern.match(url) is not None
    
    def get_configuration_summary(self) -> Dict:
        """
        Get a summary of the current RPC setup
        
        Simple explanation: "Show me what RPC configuration we ended up with"
        Useful for debugging and logging.
        """
        primary_url, provider_name, all_endpoints, api_key = self.detect_and_configure_rpc()
        
        return {
            'primary_rpc': {
                'url': primary_url,
                'provider': provider_name
            },
            'fallback_rpcs': [ep for ep in all_endpoints[1:]],  # All except the first one
            'total_endpoints': len(all_endpoints),
            'detected_providers': self._get_detected_providers(),
            'configuration_method': self._get_config_method(),
            'api_key_configured': bool(api_key)
        }
    
    def _get_detected_providers(self) -> List[str]:
        """
        Get list of all providers that we have complete credentials for
        
        Simple explanation: "Which premium RPC services can I use?"
        """
        detected = []
        for provider_key, provider_config in self.provider_patterns.items():
            # Check if we have all required environment variables for this provider
            if all(os.getenv(key) for key in provider_config['env_keys']):
                detected.append(provider_config['name'])
        return detected
    
    def _get_config_method(self) -> str:
        """
        Figure out how the RPC was configured
        
        Simple explanation: "How did we decide which RPC to use?"
        """
        if os.getenv('CUSTOM_SOLANA_RPC_URL'):
            return 'custom_url'  # User specified a custom URL
        elif os.getenv('SOLANA_RPC_URL') and os.getenv('SOLANA_RPC_URL') != 'https://api.mainnet-beta.solana.com':
            return 'explicit_url'  # User set a specific URL
        elif self._detect_provider():
            return 'auto_detected'  # We found a provider automatically
        else:
            return 'public_fallback'  # Using free public RPCs


# HELPER FUNCTIONS FOR SETTING UP THE SECURITY SYSTEM

def setup_flexible_security_sensor():
    """
    Set up the security system with the best available RPC
    
    Simple explanation: This function:
    1. Finds the best RPC to use
    2. Gets list of wallets to monitor
    3. Creates the SecuritySensor with the right settings
    """
    
    # Step 1: Find the best RPC configuration
    rpc_config = FlexibleRPCConfig()
    primary_url, provider_name, all_endpoints, api_key = rpc_config.detect_and_configure_rpc()
    
    # Step 2: Get list of wallets to monitor from environment variables
    monitored_wallets = []
    # Look for environment variables like MONITOR_WALLET_1, MONITOR_WALLET_2, etc.
    wallet_env_vars = [key for key in os.environ.keys() if key.startswith("MONITOR_WALLET_")]
    for wallet_var in wallet_env_vars:
        wallet_address = os.environ[wallet_var]
        if wallet_address:
            monitored_wallets.append(wallet_address)
    
    # If no wallets specified, use placeholder values
    if not monitored_wallets:
        monitored_wallets = ["N/A", "N/A"]
    
    # Log what we're setting up
    logger.info(f"🛡️ Setting up SecuritySensor for {len(monitored_wallets)} wallets:")
    for wallet in monitored_wallets:
        logger.info(f"   📡 Monitoring: {wallet[:8]}...{wallet[-8:]}")
    
    logger.info(f"🚀 Primary RPC: {provider_name}")
    if api_key:
        logger.info(f"🔑 API key configured for enhanced rate limits")
    logger.info(f"🔄 Total endpoints available: {len(all_endpoints)}")
    
    # Step 3: Create the SecuritySensor
    from src.sensor.security import SecuritySensor
    
    sensor = SecuritySensor(
        wallet_addresses=monitored_wallets,
        solana_rpc_url=primary_url,
        rpc_api_key=api_key,
        rpc_provider_name=provider_name,
    )
    
    # Print summary of what we set up
    config_summary = rpc_config.get_configuration_summary()
    logger.info(f"📊 RPC Configuration Summary:")
    logger.info(f"   🎯 Method: {config_summary['configuration_method']}")
    logger.info(f"   🔑 Detected providers: {', '.join(config_summary['detected_providers']) if config_summary['detected_providers'] else 'None'}")
    logger.info(f"   🔐 API key status: {'Configured' if config_summary['api_key_configured'] else 'Not configured'}")
    logger.info(f"   🔄 Fallback endpoints: {len(config_summary['fallback_rpcs'])}")
    
    return sensor


def setup_security_sensor_with_provider(provider_name: str, api_key: str, monitored_wallets: List[str] = None):
    """
    Set up SecuritySensor with a specific provider (for testing or manual setup)
    
    Simple explanation: "I want to use Helius specifically, not auto-detection"
    """
    rpc_config = FlexibleRPCConfig()
    
    # Get the provider information
    provider_info = rpc_config.get_provider_info(provider_name)
    if not provider_info:
        raise ValueError(f"Unknown provider: {provider_name}")
    
    # Generate the URL for this specific provider
    try:
        url_pattern = provider_info['url_pattern']
        primary_url = url_pattern.format(api_key=api_key)
    except Exception as e:
        raise ValueError(f"Failed to generate URL for {provider_name}: {e}")
    
    # Default wallets if none provided
    if not monitored_wallets:
        monitored_wallets = ["N/A", "N/A"]
    
    logger.info(f"🛡️ Setting up SecuritySensor with {provider_name}")
    logger.info(f"🚀 Primary RPC: {primary_url[:50]}...")
    
    # Create the SecuritySensor
    from src.sensor.security import SecuritySensor
    
    sensor = SecuritySensor(
        wallet_addresses=monitored_wallets,
        solana_rpc_url=primary_url,
        rpc_api_key=api_key,
        rpc_provider_name=provider_name,
    )
    
    return sensor


def test_rpc_configuration():
    """
    Test the RPC configuration and show what it would use
    
    Simple explanation: "Show me what RPC setup we would get with current settings"
    Useful for debugging environment variable issues.
    """
    rpc_config = FlexibleRPCConfig()
    
    logger.info("🔍 Testing RPC Configuration...")
    
    # Test the detection process
    primary_url, provider_name, all_endpoints, api_key = rpc_config.detect_and_configure_rpc()
    
    logger.info(f"✅ Primary: {provider_name} - {primary_url[:50]}...")
    logger.info(f"🔑 API Key: {'Configured' if api_key else 'Not configured'}")
    logger.info(f"🔄 Fallbacks: {len(all_endpoints) - 1} endpoints")
    
    # Show detailed summary
    summary = rpc_config.get_configuration_summary()
    logger.info(f"📊 Configuration Summary:")
    for key, value in summary.items():
        if key != 'fallback_rpcs':  # Don't show the long list of fallbacks
            logger.info(f"   {key}: {value}")
    
    # Show which providers we could use
    detected = rpc_config._get_detected_providers()
    if detected:
        logger.info(f"🚀 Detected providers: {', '.join(detected)}")
    else:
        logger.info(f"📡 No provider API keys detected, using public RPCs")
    
    return summary


if __name__ == "__main__":
    # If you run this file directly, test the configuration
    test_rpc_configuration()