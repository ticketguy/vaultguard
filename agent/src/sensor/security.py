"""
SecuritySensor - Fixed Imports & Simplified Orchestrator
Integrates with your existing analysis modules and calls SecurityAgent for AI analysis
"""

from typing import Any, Dict, List, Optional
from functools import partial
import time
import asyncio
import json
import requests
from datetime import datetime, timedelta

# FIXED IMPORTS - Using your actual analysis modules
try:
    from analysis.adaptive_community_database import AdaptiveCommunityDatabase, AdaptiveDustDetector
except ImportError:
    AdaptiveCommunityDatabase = None
    AdaptiveDustDetector = None

try:
    from analysis.mev_detector import MEVDetector  
except ImportError:
    MEVDetector = None

try:
    from analysis.enhanced_contract_analyzer import EnhancedContractAnalyzer
except ImportError:
    EnhancedContractAnalyzer = None

try:
    from analysis.smart_contract_explainer import SmartContractExplainer
except ImportError:
    SmartContractExplainer = None

try:
    from analysis.nft_scam_detector import NFTScamDetector
except ImportError:
    NFTScamDetector = None

try:
    from analysis.behavior_analyzer import BehaviorAnalyzer
except ImportError:
    BehaviorAnalyzer = None

try:
    from analysis.network_analyzer import NetworkAnalyzer
except ImportError:
    NetworkAnalyzer = None

try:
    from analysis.deep_pattern_analyzer import DeepPatternAnalyzer
except ImportError:
    DeepPatternAnalyzer = None

try:
    from analysis.solana_rpc_client import IntelligentSolanaRPCClient as SolanaRPCClient
except ImportError:
    SolanaRPCClient = None

# For Solana blockchain interactions
try:
    from solana.rpc.async_api import AsyncClient
    from solders.pubkey import Pubkey as PublicKey  # ✅ CORRECT IMPORT PATH
    SOLANA_WEB3_AVAILABLE = True
except ImportError:
    SOLANA_WEB3_AVAILABLE = False
    print("⚠️ solana-py not installed - using mock transaction data")

class SecuritySensor:
    """
    Simplified SecuritySensor that orchestrates your existing analysis modules
    and coordinates with SecurityAgent for AI-driven analysis
    """
    
    def __init__(self, wallet_addresses: List[str], solana_rpc_url: str, rpc_api_key: str = "", rpc_provider_name: str = "Unknown", rag_client=None):
        # Core connection parameters
        self.wallet_addresses = wallet_addresses
        self.solana_rpc_url = solana_rpc_url
        self.rpc_api_key = rpc_api_key  # Generic API key for any RPC provider
        self.rpc_provider_name = rpc_provider_name  # Name of the RPC provider
        
        # Initialize your existing analysis modules with correct imports
        self.community_db = AdaptiveCommunityDatabase(rag_client) if AdaptiveCommunityDatabase else None

        self.dust_detector = AdaptiveDustDetector(rag_client) if AdaptiveDustDetector else None

        self.mev_detector = MEVDetector() if MEVDetector else None
        self.contract_analyzer = EnhancedContractAnalyzer() if EnhancedContractAnalyzer else None
        self.contract_explainer = SmartContractExplainer() if SmartContractExplainer else None
        self.nft_scam_detector = NFTScamDetector() if NFTScamDetector else None
        self.behavior_analyzer = BehaviorAnalyzer() if BehaviorAnalyzer else None
        self.network_analyzer = NetworkAnalyzer() if NetworkAnalyzer else None
        self.pattern_analyzer = DeepPatternAnalyzer() if DeepPatternAnalyzer else None
        
        # Initialize Solana RPC client
        if SolanaRPCClient:
            self.solana_client = SolanaRPCClient(
                helius_api_key=self.rpc_api_key,  # Pass any provider's API key (parameter name is legacy)
                primary_rpc_url=self.solana_rpc_url
            )
            print(f"🔄 Intelligent RPC client initialized with {len(self.solana_client.endpoints) if hasattr(self.solana_client, 'endpoints') else 'multiple'} endpoints")
            print(f"🚀 Primary RPC provider: {self.rpc_provider_name}")
        else:
            self.solana_client = None
        
        # Initialize basic Solana client for transaction fetching
        if SOLANA_WEB3_AVAILABLE and solana_rpc_url:
            try:
                self.basic_solana_client = AsyncClient(solana_rpc_url)
                print(f"✅ Basic Solana client connected to {self.rpc_provider_name}")
            except Exception as e:
                print(f"⚠️ Failed to connect basic Solana client: {e}")
                self.basic_solana_client = None
        else:
            self.basic_solana_client = None
        
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
        print(f"📊 Analysis modules loaded: {self._get_loaded_modules()}")

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
        """Get list of successfully loaded analysis modules"""
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
        return ", ".join(modules)

    def set_security_agent(self, security_agent):
        """Connect to SecurityAgent for AI analysis"""
        self.security_agent = security_agent
        print("🔗 SecuritySensor connected to SecurityAgent")

    # ========== REAL-TIME TRANSACTION INTERCEPTION ==========

    async def intercept_outgoing_transaction(self, transaction_data: Dict, user_language: str = "english") -> Dict:
        """
        Real-time outgoing transaction analysis (BEFORE signing)
        Main method called by transaction interceptor
        """
        if not self.security_agent:
            return self._fallback_analysis(transaction_data, "No AI agent connected")
        
        try:
            # Use SecurityAgent's AI code generation for analysis
            analysis_result = await self.security_agent.analyze_with_ai_code_generation(
                transaction_data, user_language
            )
            
            # Add sensor-specific context
            analysis_result['sensor_modules_used'] = self._get_loaded_modules()
            analysis_result['analysis_method'] = 'ai_code_generation'
            analysis_result['rpc_provider'] = self.rpc_provider_name
            
            return analysis_result
            
        except Exception as e:
            return self._fallback_analysis(transaction_data, f"AI analysis failed: {str(e)}")

    async def process_incoming_transaction(self, transaction_data: Dict, user_language: str = "english") -> Dict:
        """
        FIXED: Process incoming transactions for quarantine decisions
        """
        if not self.security_agent:
            return self._fallback_analysis(transaction_data, "No AI agent connected")
        
        try:
            print(f"📥 Processing incoming transaction: {transaction_data.get('hash', 'unknown')}")
            
            # Mark as incoming transaction
            transaction_data['direction'] = 'incoming'
            transaction_data['analysis_type'] = 'quarantine_assessment'
            
            # Use SecurityAgent's AI analysis
            analysis_result = await self.security_agent.analyze_with_ai_code_generation(
                transaction_data, user_language
            )
            
            # Add quarantine recommendation based on risk score
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
            
            # Add sensor context
            analysis_result['sensor_modules_used'] = self._get_loaded_modules()
            analysis_result['rpc_provider'] = self.rpc_provider_name
            
            print(f"✅ Incoming analysis complete - Action: {analysis_result['action']}, Risk: {risk_score:.2f}")
            
            return analysis_result
            
        except Exception as e:
            print(f"❌ Error processing incoming transaction: {e}")
            # Default to quarantine on error for safety
            return {
                'action': 'QUARANTINE',
                'risk_score': 0.8,
                'quarantine_recommended': True,
                'quarantine_reason': f'Analysis error: {str(e)}',
                'user_explanation': 'Unable to analyze transaction - quarantined for safety',
                'chain_of_thought': [f'Error in analysis: {str(e)}', 'Defaulting to quarantine for safety'],
                'error': str(e),
                'analysis_method': 'error_fallback'
            }

    async def analyze_dapp_reputation(self, dapp_url: str, dapp_name: str = "") -> Dict:
        """
        Check DApp safety using AI analysis
        """
        if not self.security_agent:
            return {'status': 'unknown', 'reason': 'No AI agent available'}
        
        dapp_data = {
            'dapp_url': dapp_url,
            'dapp_name': dapp_name,
            'analysis_type': 'dapp_reputation'
        }
        
        try:
            analysis_result = await self.security_agent.analyze_with_ai_code_generation(dapp_data)
            
            # Convert to simple status
            if analysis_result['risk_score'] <= 0.3:
                status = 'safe'
            elif analysis_result['risk_score'] <= 0.6:
                status = 'unknown'
            else:
                status = 'risky'
            
            return {
                'status': status,
                'risk_score': analysis_result['risk_score'],
                'reason': analysis_result['user_explanation'],
                'details': analysis_result
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'risk_score': 0.5,
                'reason': f'Analysis failed: {str(e)}',
                'error': str(e)
            }

    # ========== REAL-TIME MONITORING ==========

    async def start_incoming_monitor(self):
        """Start real-time monitoring for incoming transactions"""
        if self.monitoring_active:
            print("⚠️ Monitoring already active")
            return
        
        self.monitoring_active = True
        print("🛡️ Starting real-time incoming transaction monitoring...")
        
        # Start monitoring tasks for each wallet
        for wallet_address in self.wallet_addresses:
            task = asyncio.create_task(self._monitor_wallet_incoming(wallet_address))
            self.monitoring_tasks.append(task)
        
        print(f"📡 Monitoring {len(self.wallet_addresses)} wallets in real-time")

    async def stop_incoming_monitor(self):
        """Stop real-time monitoring"""
        self.monitoring_active = False
        
        # Cancel all monitoring tasks
        for task in self.monitoring_tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to complete cancellation
        if self.monitoring_tasks:
            await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
        
        self.monitoring_tasks.clear()
        print("🛑 Real-time monitoring stopped")

    async def _monitor_wallet_incoming(self, wallet_address: str):
        """Monitor specific wallet for incoming transactions"""
        print(f"👁️ Starting monitoring for wallet: {wallet_address[:8]}...{wallet_address[-8:]}")
        
        while self.monitoring_active:
            try:
                # Get recent transactions for this wallet
                recent_transactions = await self._fetch_recent_transactions(wallet_address)
                
                for tx in recent_transactions:
                    tx_hash = tx.get('hash', tx.get('signature', ''))
                    
                    # Skip if already processed
                    if tx_hash in self.last_processed_signatures:
                        continue
                    
                    # Mark as processed
                    self.last_processed_signatures.add(tx_hash)
                    
                    # Process incoming transaction
                    if tx.get('to_address') == wallet_address:  # Incoming
                        print(f"📥 New incoming transaction detected: {tx_hash}")
                        analysis_result = await self.process_incoming_transaction(tx)
                        
                        # Handle quarantine decision
                        if analysis_result.get('quarantine_recommended'):
                            await self._handle_quarantine_decision(tx, analysis_result)
                        else:
                            print(f"✅ ALLOWED: {tx_hash} - Safe incoming transaction")
                
                # Wait before next check
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                print(f"⚠️ Error monitoring wallet {wallet_address[:8]}...{wallet_address[-8:]}: {e}")
                await asyncio.sleep(30)  # Wait longer on error

    async def _fetch_recent_transactions(self, wallet_address: str) -> List[Dict]:
        """
        FIXED: Fetch recent transactions for wallet using real Solana RPC
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
                print(f"⚠️ Intelligent RPC client error: {e}, trying basic client...")
        
        # Try basic Solana client
        if self.basic_solana_client and SOLANA_WEB3_AVAILABLE:
            try:
                print(f"🔍 Fetching transactions using basic Solana client for {wallet_address[:8]}...")
                
                # Get signatures for address
                pubkey = PublicKey.from_string(wallet_address)

                signature_response = await self.basic_solana_client.get_signatures_for_address(pubkey, limit=10)
                
                if signature_response.value:
                    for sig_info in signature_response.value:
                        # Convert to our transaction format
                        tx_data = {
                            'hash': sig_info.signature,
                            'signature': sig_info.signature,
                            'to_address': wallet_address,  # This is an approximation
                            'from_address': 'unknown',  # Would need full transaction parsing
                            'value': 0.0,  # Would need full transaction parsing
                            'timestamp': datetime.fromtimestamp(sig_info.block_time) if sig_info.block_time else datetime.now(),
                            'token_symbol': 'SOL',
                            'block_time': sig_info.block_time,
                            'slot': sig_info.slot,
                            'confirmation_status': sig_info.confirmation_status
                        }
                        transactions.append(tx_data)
                
                print(f"✅ Found {len(transactions)} recent transactions via basic RPC")
                return transactions
                
            except Exception as e:
                print(f"⚠️ Basic Solana client error: {e}")
        
        # NO FALLBACK - Return empty list if no RPC available
        print(f"❌ No RPC client available for fetching transactions from {wallet_address[:8]}...")
        print("🛑 Real-time monitoring requires a working Solana RPC connection")
        return []

    async def _handle_quarantine_decision(self, transaction: Dict, analysis_result: Dict):
        """
        FIXED: Handle quarantine decision for incoming transaction
        """
        tx_hash = transaction.get('hash', transaction.get('signature', 'unknown'))
        
        if analysis_result.get('quarantine_recommended'):
            quarantine_reason = analysis_result.get('quarantine_reason', 'High risk detected')
            print(f"🏠 QUARANTINED: {tx_hash} - {quarantine_reason}")
            
            # Store in threat cache
            self.threat_cache[tx_hash] = {
                'transaction': transaction,
                'analysis_result': analysis_result,
                'quarantined_at': datetime.now().isoformat(),
                'threat_type': 'incoming_quarantine'
            }
            
            # Notify user about quarantine
            await self._notify_user_quarantine(transaction, analysis_result)
        else:
            print(f"✅ ALLOWED: {tx_hash} - Safe transaction")

    async def _notify_user_quarantine(self, transaction: Dict, analysis_result: Dict):
        """
        FIXED: Notify user about quarantined item
        """
        # This would integrate with wallet UI notification system
        notification = {
            'type': 'quarantine',
            'transaction': transaction,
            'reason': analysis_result.get('user_explanation', 'Suspicious transaction detected'),
            'risk_score': analysis_result.get('risk_score', 0.0),
            'timestamp': datetime.now().isoformat()
        }
        
        # Log for now - in production would send to wallet UI
        print(f"📱 USER NOTIFICATION: {notification}")
        
        # In a real implementation, this would:
        # 1. Send notification to wallet UI
        # 2. Store in quarantine database
        # 3. Update user dashboard
        # 4. Send email/push notification if configured

    # ========== FALLBACK METHODS ==========

    def _fallback_analysis(self, transaction_data: Dict, error_reason: str) -> Dict:
        """Fallback analysis when AI agent unavailable"""
        print(f"🔄 Using fallback analysis: {error_reason}")
        
        # Basic rule-based analysis as last resort
        risk_score = 0.0
        threats = []
        
        # Check for dust attack patterns
        value = transaction_data.get('value', transaction_data.get('amount', 0))
        if isinstance(value, (int, float)) and 0 < value < 0.001:
            risk_score += 0.6
            threats.append('potential_dust_attack')
        
        # Check for suspicious token names
        token_name = transaction_data.get('token_name', '').lower()
        if token_name and any(word in token_name for word in ['free', 'airdrop', 'bonus', 'gift']):
            risk_score += 0.7
            threats.append('suspicious_token_name')
        
        # Check for suspicious addresses (simple pattern matching)
        from_addr = str(transaction_data.get('from_address', ''))
        if len(from_addr) > 10 and ('1111' in from_addr or '0000' in from_addr):
            risk_score += 0.5
            threats.append('suspicious_address_pattern')
        
        # Determine action
        if risk_score >= 0.7:
            action = 'QUARANTINE'
        elif risk_score >= 0.4:
            action = 'WARN'
        else:
            action = 'ALLOW'
        
        return {
            'action': action,
            'risk_score': min(risk_score, 1.0),
            'user_explanation': f'Basic analysis only: {error_reason}. Transaction flagged for manual review.',
            'chain_of_thought': [
                f'⚠️ Fallback analysis: {error_reason}',
                f'Detected threats: {threats}' if threats else 'No obvious threats detected',
                f'Risk score: {risk_score:.2f}',
                f'Recommended action: {action}'
            ],
            'threat_categories': threats,
            'analysis_method': 'fallback',
            'quarantine_recommended': risk_score >= 0.7,
            'rpc_provider': self.rpc_provider_name,
            'confidence': 0.3  # Low confidence for fallback analysis
        }

    # ========== LEGACY COMPATIBILITY METHODS ==========

    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status - compatible with existing framework"""
        base_status = {
            "security_score": 0.8,
            "total_threats_detected": len(self.threat_cache),
            "quarantined_items": len([t for t in self.threat_cache.values() if t.get('threat_type') == 'incoming_quarantine']),
            "monitored_wallets": len(self.wallet_addresses),
            "last_analysis": self.last_analysis_time.isoformat(),
            "modules_loaded": self._get_loaded_modules(),
            "monitoring_active": self.monitoring_active,
            "ai_agent_connected": self.security_agent is not None,
            "analysis_method": "ai_code_generation",
            "rpc_provider": self.rpc_provider_name,
            "api_key_configured": bool(self.rpc_api_key)
        }
        
        # Add RPC health info
        rpc_health = self.get_rpc_health()
        base_status.update({
            "rpc_status": rpc_health.get('current_endpoint', 'unknown'),
            "rpc_success_rate": f"{rpc_health.get('success_rate', 0):.1%}",
            "total_rpc_requests": rpc_health.get('total_requests', 0)
        })
        
        return base_status

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

    # ========== DIRECT MODULE ACCESS (For specific analysis) ==========

    async def run_specific_analysis(self, analysis_type: str, target_data: Dict) -> Dict:
        """
        Run specific analysis using your existing modules directly
        Useful for debugging or when AI agent isn't available
        """
        try:
            if analysis_type == "mev" and self.mev_detector:
                return await self.mev_detector.analyze_mev_risk(target_data)
            
            elif analysis_type == "contract" and self.contract_analyzer:
                return await self.contract_analyzer.analyze_contract_for_drain_risk(target_data)
            
            elif analysis_type == "dust" and self.dust_detector:
                return await self.dust_detector.analyze_transaction(target_data)
            
            elif analysis_type == "nft" and self.nft_scam_detector:
                return await self.nft_scam_detector.analyze_nft_scam_risk(target_data)
            
            elif analysis_type == "behavior" and self.behavior_analyzer:
                wallet_address = target_data.get('wallet_address', '')
                return await self.behavior_analyzer.analyze_wallet_behavior(wallet_address)
            
            else:
                return {"error": f"Analysis type '{analysis_type}' not available or module not loaded"}
                
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}", "analysis_type": analysis_type}

    # ========== UTILITY METHODS ==========

    async def add_wallet_to_monitoring(self, wallet_address: str):
        """Add new wallet to monitoring list"""
        if wallet_address not in self.wallet_addresses:
            self.wallet_addresses.append(wallet_address)
            print(f"📡 Added wallet to monitoring: {wallet_address[:8]}...{wallet_address[-8:]}")
            
            # If monitoring is active, start monitoring this wallet
            if self.monitoring_active:
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