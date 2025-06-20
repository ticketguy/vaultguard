"""
Security-focused blockchain monitoring service
Adapts the notification service for security monitoring
"""

import asyncio
import json
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import logging
from pathlib import Path

class SecurityMonitor:
    """
    Real-time blockchain security monitoring service
    Adapts the notification service for security-specific monitoring
    """
    
    def __init__(self, config_path: str = "config/security_monitor_config.json"):
        self.config = self.load_config(config_path)
        
        # Monitoring targets
        self.monitored_addresses = set()
        self.monitored_contracts = set()
        self.monitored_tokens = set()
        
        # Alert thresholds
        self.alert_thresholds = {
            'large_transfer': 100000,  # USD
            'high_gas': 100,  # gwei
            'new_contract_interactions': 10,  # per hour
            'suspicious_patterns': 5  # per hour
        }
        
        # Monitoring state
        self.last_block_processed = 0
        self.alert_queue = asyncio.Queue()
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("SecurityMonitor")
    
    def load_config(self, config_path: str) -> Dict:
        """Load security monitoring configuration"""
        default_config = {
            "networks": {
                "ethereum": {
                    "rpc_url": "https://mainnet.infura.io/v3/YOUR_PROJECT_ID",
                    "enabled": True,
                    "poll_interval": 12
                },
                "polygon": {
                    "rpc_url": "https://polygon-rpc.com",
                    "enabled": True,
                    "poll_interval": 2
                },
                "bsc": {
                    "rpc_url": "https://bsc-dataseed.binance.org",
                    "enabled": True,
                    "poll_interval": 3
                }
            },
            "monitoring": {
                "monitor_new_contracts": True,
                "monitor_large_transfers": True,
                "monitor_suspicious_patterns": True,
                "monitor_governance_changes": True
            }
        }
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                return {**default_config, **config}
        except FileNotFoundError:
            self.logger.warning(f"Config file not found: {config_path}, using defaults")
            return default_config
    
    async def start_monitoring(self):
        """Start the security monitoring service"""
        self.logger.info("🔍 Starting Security Monitoring Service")
        
        # Start monitoring tasks for each enabled network
        monitoring_tasks = []
        
        for network_name, network_config in self.config['networks'].items():
            if network_config.get('enabled', False):
                task = asyncio.create_task(
                    self.monitor_network(network_name, network_config)
                )
                monitoring_tasks.append(task)
                self.logger.info(f"📡 Started monitoring {network_name}")
        
        # Start alert processing
        alert_task = asyncio.create_task(self.process_alerts())
        monitoring_tasks.append(alert_task)
        
        # Wait for all monitoring tasks
        await asyncio.gather(*monitoring_tasks)
    
    async def monitor_network(self, network_name: str, network_config: Dict):
        """Monitor a specific blockchain network"""
        rpc_url = network_config['rpc_url']
        poll_interval = network_config.get('poll_interval', 12)
        
        self.logger.info(f"🌐 Monitoring {network_name} network")
        
        while True:
            try:
                # Get latest block
                latest_block = await self.get_latest_block(rpc_url)
                
                if latest_block and latest_block['number'] > self.last_block_processed:
                    # Process new blocks
                    for block_num in range(self.last_block_processed + 1, latest_block['number'] + 1):
                        await self.process_block(network_name, rpc_url, block_num)
                    
                    self.last_block_processed = latest_block['number']
                
                await asyncio.sleep(poll_interval)
                
            except Exception as e:
                self.logger.error(f"Error monitoring {network_name}: {e}")
                await asyncio.sleep(poll_interval * 2)  # Wait longer on error
    
    async def get_latest_block(self, rpc_url: str) -> Optional[Dict]:
        """Get the latest block from blockchain"""
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(rpc_url, json=payload) as response:
                    result = await response.json()
                    
                    if 'result' in result:
                        block_number = int(result['result'], 16)
                        return {'number': block_number}
                    
        except Exception as e:
            self.logger.error(f"Error getting latest block: {e}")
        
        return None
    
    async def process_block(self, network_name: str, rpc_url: str, block_number: int):
        """Process a specific block for security events"""
        block_data = await self.get_block_with_transactions(rpc_url, block_number)
        
        if not block_data or 'transactions' not in block_data:
            return
        
        for tx in block_data['transactions']:
            await self.analyze_transaction_for_security(network_name, tx)
    
    async def get_block_with_transactions(self, rpc_url: str, block_number: int) -> Optional[Dict]:
        """Get block data with all transactions"""
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [hex(block_number), True],  # True to include full transaction objects
            "id": 1
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(rpc_url, json=payload) as response:
                    result = await response.json()
                    return result.get('result')
                    
        except Exception as e:
            self.logger.error(f"Error getting block {block_number}: {e}")
        
        return None
    
    async def analyze_transaction_for_security(self, network_name: str, tx: Dict):
        """Analyze individual transaction for security threats"""
        # Extract transaction details
        tx_data = {
            'network': network_name,
            'hash': tx.get('hash'),
            'from_address': tx.get('from'),
            'to_address': tx.get('to'),
            'value': int(tx.get('value', '0x0'), 16) / 10**18,  # Convert from wei to ETH
            'gas_price': int(tx.get('gasPrice', '0x0'), 16),
            'gas_limit': int(tx.get('gas', '0x0'), 16),
            'input_data': tx.get('input', '0x'),
            'timestamp': datetime.now().isoformat()
        }
        
        # Security checks
        await self.check_large_transfers(tx_data)
        await self.check_suspicious_contracts(tx_data)
        await self.check_unusual_gas_patterns(tx_data)
        await self.check_new_contract_deployments(tx_data)
        await self.check_monitored_addresses(tx_data)
    
    async def check_large_transfers(self, tx_data: Dict):
        """Check for unusually large transfers"""
        value_usd = tx_data['value'] * 2000  # Approximate ETH price
        
        if value_usd > self.alert_thresholds['large_transfer']:
            alert = {
                'type': 'large_transfer',
                'severity': 'medium',
                'transaction': tx_data,
                'details': f"Large transfer detected: ${value_usd:,.2f}",
                'timestamp': datetime.now().isoformat()
            }
            await self.alert_queue.put(alert)
    
    async def check_suspicious_contracts(self, tx_data: Dict):
        """Check for interactions with suspicious contracts"""
        to_address = tx_data.get('to_address')
        
        if to_address and to_address.lower() in self.monitored_contracts:
            alert = {
                'type': 'suspicious_contract_interaction',
                'severity': 'high',
                'transaction': tx_data,
                'details': f"Interaction with monitored contract: {to_address}",
                'timestamp': datetime.now().isoformat()
            }
            await self.alert_queue.put(alert)
    
    async def check_unusual_gas_patterns(self, tx_data: Dict):
        """Check for unusual gas usage patterns"""
        gas_price_gwei = tx_data['gas_price'] / 10**9
        
        if gas_price_gwei > self.alert_thresholds['high_gas']:
            alert = {
                'type': 'high_gas_price',
                'severity': 'low',
                'transaction': tx_data,
                'details': f"High gas price detected: {gas_price_gwei:.2f} gwei",
                'timestamp': datetime.now().isoformat()
            }
            await self.alert_queue.put(alert)
    
    async def check_new_contract_deployments(self, tx_data: Dict):
        """Check for new contract deployments"""
        if tx_data.get('to_address') is None and len(tx_data.get('input_data', '0x')) > 2:
            # This is likely a contract deployment
            alert = {
                'type': 'new_contract_deployment',
                'severity': 'medium',
                'transaction': tx_data,
                'details': "New contract deployment detected",
                'timestamp': datetime.now().isoformat()
            }
            await self.alert_queue.put(alert)
    
    async def check_monitored_addresses(self, tx_data: Dict):
        """Check for transactions involving monitored addresses"""
        from_address = tx_data.get('from_address', '').lower()
        to_address = tx_data.get('to_address', '').lower()
        
        if from_address in self.monitored_addresses or to_address in self.monitored_addresses:
            alert = {
                'type': 'monitored_address_activity',
                'severity': 'medium',
                'transaction': tx_data,
                'details': f"Activity from/to monitored address",
                'timestamp': datetime.now().isoformat()
            }
            await self.alert_queue.put(alert)
    
    async def process_alerts(self):
        """Process security alerts from the queue"""
        while True:
            try:
                alert = await self.alert_queue.get()
                await self.handle_security_alert(alert)
                self.alert_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Error processing alert: {e}")
    
    async def handle_security_alert(self, alert: Dict):
        """Handle a security alert"""
        alert_type = alert['type']
        severity = alert['severity']
        
        # Log the alert
        self.logger.warning(f"🚨 Security Alert [{severity.upper()}]: {alert_type}")
        self.logger.warning(f"   Details: {alert['details']}")
        self.logger.warning(f"   Transaction: {alert['transaction']['hash']}")
        
        # Send to security agent (Phase 2 integration)
        await self.send_alert_to_security_agent(alert)
        
        # Store alert for analysis
        await self.store_alert(alert)
    
    async def send_alert_to_security_agent(self, alert: Dict):
        """Send alert to the security agent for analysis"""
        try:
            # This would integrate with your security agent API
            # For now, just simulate the integration
            
            security_agent_url = "http://localhost:8001/analyze"
            
            payload = {
                'type': 'real_time_alert',
                'alert_data': alert,
                'priority': alert['severity']
            }
            
            # In production, this would make an actual HTTP request
            self.logger.info(f"📤 Sent alert to security agent: {alert['type']}")
            
        except Exception as e:
            self.logger.error(f"Error sending alert to security agent: {e}")
    
    async def store_alert(self, alert: Dict):
        """Store alert for historical analysis"""
        alerts_dir = Path("data/alerts")
        alerts_dir.mkdir(exist_ok=True)
        
        date_str = datetime.now().strftime("%Y-%m-%d")
        alerts_file = alerts_dir / f"alerts_{date_str}.json"
        
        try:
            # Load existing alerts
            alerts = []
            if alerts_file.exists():
                with open(alerts_file, 'r') as f:
                    alerts = json.load(f)
            
            # Add new alert
            alerts.append(alert)
            
            # Save back to file
            with open(alerts_file, 'w') as f:
                json.dump(alerts, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error storing alert: {e}")
    
    def add_monitored_address(self, address: str):
        """Add an address to monitoring list"""
        self.monitored_addresses.add(address.lower())
        self.logger.info(f"📍 Added address to monitoring: {address}")
    
    def add_monitored_contract(self, contract_address: str):
        """Add a contract to monitoring list"""
        self.monitored_contracts.add(contract_address.lower())
        self.logger.info(f"📜 Added contract to monitoring: {contract_address}")
    
    def remove_monitored_address(self, address: str):
        """Remove an address from monitoring"""
        self.monitored_addresses.discard(address.lower())
        self.logger.info(f"📍 Removed address from monitoring: {address}")

# Configuration file
async def create_monitor_config():
    """Create default monitoring configuration"""
    config = {
        "networks": {
            "ethereum": {
                "rpc_url": "https://mainnet.infura.io/v3/YOUR_PROJECT_ID",
                "enabled": True,
                "poll_interval": 12
            },
            "polygon": {
                "rpc_url": "https://polygon-rpc.com",
                "enabled": False,  # Disabled by default for testing
                "poll_interval": 2
            }
        },
        "monitoring": {
            "monitor_new_contracts": True,
            "monitor_large_transfers": True,
            "monitor_suspicious_patterns": True,
            "monitor_governance_changes": True
        },
        "alert_thresholds": {
            "large_transfer_usd": 100000,
            "high_gas_gwei": 100,
            "new_contract_interactions_per_hour": 10,
            "suspicious_patterns_per_hour": 5
        }
    }
    
    config_path = Path("config/security_monitor_config.json")
    config_path.parent.mkdir(exist_ok=True)
    
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"✅ Created monitoring configuration: {config_path}")

# Example usage
if __name__ == "__main__":
    async def test_security_monitor():
        # Create config if it doesn't exist
        await create_monitor_config()
        
        # Initialize and start monitoring
        monitor = SecurityMonitor()
        
        # Add some test addresses to monitor
        monitor.add_monitored_address("0x000000000000000000000000000000000000dead")
        
        # Start monitoring (this would run indefinitely in production)
        try:
            await monitor.start_monitoring()
        except KeyboardInterrupt:
            print("\n🛑 Stopping security monitoring")
    
    asyncio.run(test_security_monitor())