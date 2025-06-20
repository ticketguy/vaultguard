"""
Security Intelligence Engine
Adapts the RAG system for threat intelligence storage and retrieval
"""

import asyncio
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import logging
import aiohttp
from pathlib import Path

class SecurityIntelligence:
    """
    Main security intelligence engine that adapts RAG capabilities
    for threat detection and analysis
    """
    
    def __init__(self, config_path: str = "config/security_intel_config.json"):
        self.config = self.load_config(config_path)
        
        # Threat intelligence sources
        self.threat_sources = {
            'twitter_security': [],
            'exploit_databases': [],
            'scammer_reports': [],
            'contract_analysis': [],
            'community_reports': []
        }
        
        # Intelligence storage
        self.threat_patterns = {}
        self.scammer_addresses = set()
        self.malicious_contracts = {}
        self.exploit_signatures = {}
        
        # Performance tracking
        self.intelligence_metrics = {
            'patterns_loaded': 0,
            'addresses_tracked': 0,
            'exploits_cataloged': 0,
            'last_update': None
        }
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("SecurityIntelligence")
    
    def load_config(self, config_path: str) -> Dict:
        """Load security intelligence configuration"""
        default_config = {
            "update_interval_hours": 6,
            "max_patterns": 10000,
            "confidence_threshold": 0.8,
            "sources": {
                "enable_twitter_monitoring": True,
                "enable_exploit_db": True,
                "enable_community_reports": True
            }
        }
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                return {**default_config, **config}
        except FileNotFoundError:
            self.logger.warning(f"Config file not found: {config_path}, using defaults")
            return default_config
    
    async def initialize(self):
        """Initialize the security intelligence system"""
        self.logger.info("🧠 Initializing Security Intelligence Engine")
        
        # Load existing threat data
        await self.load_threat_patterns()
        await self.load_scammer_addresses()
        await self.load_exploit_signatures()
        
        # Start intelligence gathering
        await self.start_intelligence_gathering()
        
        self.logger.info("✅ Security Intelligence Engine initialized")
    
    async def load_threat_patterns(self):
        """Load known threat patterns from storage"""
        patterns_file = Path("data/threat_patterns.json")
        
        if patterns_file.exists():
            try:
                with open(patterns_file, 'r') as f:
                    self.threat_patterns = json.load(f)
                self.intelligence_metrics['patterns_loaded'] = len(self.threat_patterns)
                self.logger.info(f"📋 Loaded {len(self.threat_patterns)} threat patterns")
            except Exception as e:
                self.logger.error(f"Error loading threat patterns: {e}")
        else:
            # Initialize with basic patterns
            self.threat_patterns = {
                'dust_attacks': {
                    'pattern': 'small_value_transactions',
                    'threshold': 0.001,
                    'confidence': 0.9
                },
                'fake_tokens': {
                    'pattern': 'name_impersonation',
                    'keywords': ['usdc', 'ethereum', 'bitcoin'],
                    'confidence': 0.85
                },
                'drain_contracts': {
                    'pattern': 'excessive_permissions',
                    'permissions': ['approve', 'transferFrom'],
                    'confidence': 0.95
                }
            }
            await self.save_threat_patterns()
    
    async def load_scammer_addresses(self):
        """Load known scammer addresses"""
        addresses_file = Path("data/scammer_addresses.json")
        
        if addresses_file.exists():
            try:
                with open(addresses_file, 'r') as f:
                    data = json.load(f)
                    self.scammer_addresses = set(data.get('addresses', []))
                self.intelligence_metrics['addresses_tracked'] = len(self.scammer_addresses)
                self.logger.info(f"🚫 Loaded {len(self.scammer_addresses)} known scammer addresses")
            except Exception as e:
                self.logger.error(f"Error loading scammer addresses: {e}")
        else:
            # Initialize with basic known scammers
            self.scammer_addresses = {
                '0x000000000000000000000000000000000000dead',
                '0x1111111111111111111111111111111111111111',
                '0x0000000000000000000000000000000000000000'
            }
            await self.save_scammer_addresses()
    
    async def load_exploit_signatures(self):
        """Load exploit signatures from various sources"""
        exploits_file = Path("data/exploit_signatures.json")
        
        if exploits_file.exists():
            try:
                with open(exploits_file, 'r') as f:
                    self.exploit_signatures = json.load(f)
                self.intelligence_metrics['exploits_cataloged'] = len(self.exploit_signatures)
                self.logger.info(f"🔍 Loaded {len(self.exploit_signatures)} exploit signatures")
            except Exception as e:
                self.logger.error(f"Error loading exploit signatures: {e}")
        else:
            # Initialize with basic exploit patterns
            self.exploit_signatures = {
                'reentrancy': {
                    'pattern': 'recursive_call',
                    'signature': 'call_before_state_change',
                    'severity': 'high'
                },
                'integer_overflow': {
                    'pattern': 'unchecked_math',
                    'signature': 'arithmetic_without_safeguards',
                    'severity': 'medium'
                }
            }
            await self.save_exploit_signatures()
    
    async def start_intelligence_gathering(self):
        """Start gathering threat intelligence from various sources"""
        self.logger.info("🕵️ Starting threat intelligence gathering")
        
        # Schedule regular updates
        asyncio.create_task(self.intelligence_update_loop())
        
        # Initialize specific intelligence sources
        if self.config['sources']['enable_twitter_monitoring']:
            asyncio.create_task(self.monitor_security_twitter())
        
        if self.config['sources']['enable_exploit_db']:
            asyncio.create_task(self.monitor_exploit_databases())
        
        if self.config['sources']['enable_community_reports']:
            asyncio.create_task(self.process_community_reports())
    
    async def intelligence_update_loop(self):
        """Main intelligence update loop"""
        while True:
            try:
                self.logger.info("🔄 Updating threat intelligence")
                
                # Update threat patterns
                await self.update_threat_patterns()
                
                # Update scammer database
                await self.update_scammer_database()
                
                # Update exploit signatures
                await self.update_exploit_signatures()
                
                self.intelligence_metrics['last_update'] = datetime.now().isoformat()
                
                # Wait for next update
                update_interval = self.config['update_interval_hours'] * 3600
                await asyncio.sleep(update_interval)
                
            except Exception as e:
                self.logger.error(f"Error in intelligence update loop: {e}")
                await asyncio.sleep(3600)  # Wait 1 hour before retry
    
    async def monitor_security_twitter(self):
        """Monitor security-focused Twitter accounts for threat intelligence"""
        # This would integrate with Twitter API in production
        # For now, simulate intelligence gathering
        
        while True:
            try:
                # Simulate discovering new threats from Twitter
                new_threats = await self.simulate_twitter_intelligence()
                
                for threat in new_threats:
                    await self.process_new_threat_intel(threat)
                
                await asyncio.sleep(3600)  # Check hourly
                
            except Exception as e:
                self.logger.error(f"Error monitoring Twitter: {e}")
                await asyncio.sleep(3600)
    
    async def monitor_exploit_databases(self):
        """Monitor exploit databases for new vulnerabilities"""
        # This would integrate with actual exploit databases
        # For now, simulate exploit monitoring
        
        while True:
            try:
                # Simulate discovering new exploits
                new_exploits = await self.simulate_exploit_discovery()
                
                for exploit in new_exploits:
                    await self.process_new_exploit(exploit)
                
                await asyncio.sleep(7200)  # Check every 2 hours
                
            except Exception as e:
                self.logger.error(f"Error monitoring exploit databases: {e}")
                await asyncio.sleep(3600)
    
    async def process_community_reports(self):
        """Process community-submitted threat reports"""
        while True:
            try:
                # This would integrate with community reporting system
                # For now, simulate processing reports
                
                reports = await self.get_pending_community_reports()
                
                for report in reports:
                    await self.validate_and_process_report(report)
                
                await asyncio.sleep(1800)  # Check every 30 minutes
                
            except Exception as e:
                self.logger.error(f"Error processing community reports: {e}")
                await asyncio.sleep(1800)
    
    async def query_threat_intelligence(self, query_data: Dict) -> Dict:
        """
        Query threat intelligence for a specific transaction or address
        This is the main interface used by the security agent
        """
        address = query_data.get('address', '').lower()
        token_name = query_data.get('token_name', '').lower()
        contract_data = query_data.get('contract_data', {})
        
        intelligence_result = {
            'address_intelligence': await self.check_address_intelligence(address),
            'token_intelligence': await self.check_token_intelligence(token_name),
            'contract_intelligence': await self.check_contract_intelligence(contract_data),
            'pattern_matches': await self.check_pattern_matches(query_data),
            'confidence_score': 0.0,
            'threat_level': 'unknown'
        }
        
        # Calculate overall confidence and threat level
        intelligence_result['confidence_score'] = await self.calculate_intelligence_confidence(intelligence_result)
        intelligence_result['threat_level'] = await self.determine_threat_level(intelligence_result)
        
        return intelligence_result
    
    async def check_address_intelligence(self, address: str) -> Dict:
        """Check intelligence on a specific address"""
        if address in self.scammer_addresses:
            return {
                'status': 'known_scammer',
                'confidence': 1.0,
                'source': 'scammer_database',
                'details': 'Address found in known scammer database'
            }
        
        # Check for address patterns
        if self.is_suspicious_address_pattern(address):
            return {
                'status': 'suspicious_pattern',
                'confidence': 0.7,
                'source': 'pattern_analysis',
                'details': 'Address matches suspicious pattern'
            }
        
        return {
            'status': 'unknown',
            'confidence': 0.0,
            'source': 'no_data',
            'details': 'No intelligence available for this address'
        }
    
    async def check_token_intelligence(self, token_name: str) -> Dict:
        """Check intelligence on a specific token"""
        # Check against fake token patterns
        for pattern_name, pattern_data in self.threat_patterns.items():
            if pattern_name == 'fake_tokens':
                keywords = pattern_data.get('keywords', [])
                for keyword in keywords:
                    if keyword in token_name:
                        return {
                            'status': 'potential_fake',
                            'confidence': pattern_data.get('confidence', 0.8),
                            'source': 'threat_patterns',
                            'details': f'Token name contains suspicious keyword: {keyword}'
                        }
        
        return {
            'status': 'unknown',
            'confidence': 0.0,
            'source': 'no_data',
            'details': 'No intelligence available for this token'
        }
    
    async def check_contract_intelligence(self, contract_data: Dict) -> Dict:
        """Check intelligence on smart contract"""
        contract_address = contract_data.get('address', '')
        
        if contract_address in self.malicious_contracts:
            contract_info = self.malicious_contracts[contract_address]
            return {
                'status': 'known_malicious',
                'confidence': 1.0,
                'source': 'malicious_contracts_db',
                'details': contract_info.get('reason', 'Known malicious contract')
            }
        
        # Check for exploit signatures
        for exploit_name, exploit_data in self.exploit_signatures.items():
            if await self.contract_matches_exploit_pattern(contract_data, exploit_data):
                return {
                    'status': 'potential_exploit',
                    'confidence': 0.8,
                    'source': 'exploit_signatures',
                    'details': f'Contract matches {exploit_name} pattern'
                }
        
        return {
            'status': 'unknown',
            'confidence': 0.0,
            'source': 'no_data',
            'details': 'No intelligence available for this contract'
        }
    
    async def check_pattern_matches(self, query_data: Dict) -> List[Dict]:
        """Check for matches against known threat patterns"""
        matches = []
        
        for pattern_name, pattern_data in self.threat_patterns.items():
            if await self.matches_threat_pattern(query_data, pattern_data):
                matches.append({
                    'pattern': pattern_name,
                    'confidence': pattern_data.get('confidence', 0.5),
                    'details': f'Transaction matches {pattern_name} pattern'
                })
        
        return matches
    
    async def calculate_intelligence_confidence(self, intelligence_result: Dict) -> float:
        """Calculate overall confidence score from intelligence results"""
        confidence_scores = []
        
        # Collect confidence scores from each intelligence check
        for key, value in intelligence_result.items():
            if isinstance(value, dict) and 'confidence' in value:
                confidence_scores.append(value['confidence'])
            elif isinstance(value, list):  # pattern_matches
                for item in value:
                    if 'confidence' in item:
                        confidence_scores.append(item['confidence'])
        
        if not confidence_scores:
            return 0.0
        
        # Return weighted average (max confidence gets higher weight)
        max_confidence = max(confidence_scores)
        avg_confidence = sum(confidence_scores) / len(confidence_scores)
        
        return (max_confidence * 0.7) + (avg_confidence * 0.3)
    
    async def determine_threat_level(self, intelligence_result: Dict) -> str:
        """Determine threat level based on intelligence"""
        confidence = intelligence_result['confidence_score']
        
        if confidence >= 0.9:
            return 'critical'
        elif confidence >= 0.7:
            return 'high'
        elif confidence >= 0.5:
            return 'medium'
        elif confidence >= 0.3:
            return 'low'
        else:
            return 'minimal'
    
    # Helper methods
    def is_suspicious_address_pattern(self, address: str) -> bool:
        """Check if address follows suspicious patterns"""
        if len(set(address[2:])) < 8:  # Very few unique characters
            return True
        
        suspicious_patterns = ['dead', 'beef', '1111', '0000', 'face', 'fade']
        for pattern in suspicious_patterns:
            if pattern in address.lower():
                return True
        
        return False
    
    async def contract_matches_exploit_pattern(self, contract_data: Dict, exploit_data: Dict) -> bool:
        """Check if contract matches exploit pattern"""
        # Simplified pattern matching - would be more sophisticated in production
        pattern = exploit_data.get('pattern', '')
        
        if pattern == 'recursive_call':
            # Check if contract has potential for reentrancy
            return 'call' in str(contract_data).lower()
        elif pattern == 'unchecked_math':
            # Check for potential overflow issues
            return 'math' in str(contract_data).lower()
        
        return False
    
    async def matches_threat_pattern(self, query_data: Dict, pattern_data: Dict) -> bool:
        """Check if query data matches a threat pattern"""
        pattern = pattern_data.get('pattern', '')
        
        if pattern == 'small_value_transactions':
            value = float(query_data.get('value', 0))
            threshold = pattern_data.get('threshold', 0.001)
            return 0 < value < threshold
        
        elif pattern == 'name_impersonation':
            token_name = query_data.get('token_name', '').lower()
            keywords = pattern_data.get('keywords', [])
            return any(keyword in token_name for keyword in keywords)
        
        return False
    
    # Simulation methods (replace with real implementations)
    async def simulate_twitter_intelligence(self) -> List[Dict]:
        """Simulate Twitter intelligence gathering"""
        return [
            {
                'type': 'new_scammer',
                'address': '0x' + '2' * 40,
                'source': 'twitter_security_alert',
                'confidence': 0.8
            }
        ]
    
    async def simulate_exploit_discovery(self) -> List[Dict]:
        """Simulate exploit discovery"""
        return [
            {
                'type': 'new_exploit',
                'name': 'flash_loan_attack',
                'signature': 'rapid_borrowing_pattern',
                'severity': 'high'
            }
        ]
    
    async def get_pending_community_reports(self) -> List[Dict]:
        """Get pending community reports"""
        return []  # Placeholder
    
    async def process_new_threat_intel(self, threat: Dict):
        """Process new threat intelligence"""
        if threat['type'] == 'new_scammer':
            self.scammer_addresses.add(threat['address'])
            await self.save_scammer_addresses()
            self.logger.info(f"🚨 Added new scammer address: {threat['address']}")
    
    async def process_new_exploit(self, exploit: Dict):
        """Process new exploit information"""
        exploit_name = exploit['name']
        self.exploit_signatures[exploit_name] = exploit
        await self.save_exploit_signatures()
        self.logger.info(f"🔍 Added new exploit signature: {exploit_name}")
    
    async def validate_and_process_report(self, report: Dict):
        """Validate and process community report"""
        # Placeholder for community report processing
        pass
    
    # Data persistence methods
    async def save_threat_patterns(self):
        """Save threat patterns to storage"""
        Path("data").mkdir(exist_ok=True)
        with open("data/threat_patterns.json", 'w') as f:
            json.dump(self.threat_patterns, f, indent=2)
    
    async def save_scammer_addresses(self):
        """Save scammer addresses to storage"""
        Path("data").mkdir(exist_ok=True)
        data = {'addresses': list(self.scammer_addresses)}
        with open("data/scammer_addresses.json", 'w') as f:
            json.dump(data, f, indent=2)
    
    async def save_exploit_signatures(self):
        """Save exploit signatures to storage"""
        Path("data").mkdir(exist_ok=True)
        with open("data/exploit_signatures.json", 'w') as f:
            json.dump(self.exploit_signatures, f, indent=2)
    
    async def update_threat_patterns(self):
        """Update threat patterns from intelligence sources"""
        # This would connect to real intelligence sources
        pass
    
    async def update_scammer_database(self):
        """Update scammer database from various sources"""
        # This would connect to real threat feeds
        pass
    
    async def update_exploit_signatures(self):
        """Update exploit signatures from security databases"""
        # This would connect to exploit databases
        pass

# Example usage
if __name__ == "__main__":
    async def test_security_intelligence():
        intel = SecurityIntelligence()
        await intel.initialize()
        
        # Test query
        test_query = {
            'address': '0x000000000000000000000000000000000000dead',
            'token_name': 'FakeUSDC',
            'value': '0.0001'
        }
        
        result = await intel.query_threat_intelligence(test_query)
        print(f"Intelligence result: {json.dumps(result, indent=2)}")
    
    asyncio.run(test_security_intelligence())