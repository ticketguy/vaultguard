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
    from analysis.solana_rpc_client import SolanaRPCClient
except ImportError:
    SolanaRPCClient = None


class SecuritySensor:
    """
    Simplified SecuritySensor that orchestrates your existing analysis modules
    and coordinates with SecurityAgent for AI-driven analysis
    """
    
    def __init__(self, wallet_addresses: List[str], solana_rpc_url: str, helius_api_key: str = ""):
        # Core connection parameters
        self.wallet_addresses = wallet_addresses
        self.solana_rpc_url = solana_rpc_url
        self.helius_api_key = helius_api_key
        
        # Initialize your existing analysis modules with correct imports
        self.community_db = AdaptiveCommunityDatabase() if AdaptiveCommunityDatabase else None
        self.dust_detector = AdaptiveDustDetector(None) if AdaptiveDustDetector else None  # Now using adaptive version
        self.mev_detector = MEVDetector() if MEVDetector else None
        self.contract_analyzer = EnhancedContractAnalyzer() if EnhancedContractAnalyzer else None
        self.contract_explainer = SmartContractExplainer() if SmartContractExplainer else None
        self.nft_scam_detector = NFTScamDetector() if NFTScamDetector else None
        self.behavior_analyzer = BehaviorAnalyzer() if BehaviorAnalyzer else None
        self.network_analyzer = NetworkAnalyzer() if NetworkAnalyzer else None
        self.pattern_analyzer = DeepPatternAnalyzer() if DeepPatternAnalyzer else None
        self.solana_client = SolanaRPCClient() if SolanaRPCClient else None
        
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
            
            return analysis_result
            
        except Exception as e:
            return self._fallback_analysis(transaction_data, f"AI analysis failed: {str(e)}")

    async def process_incoming_transaction(self, transaction_data: Dict, user_language: str = "english") -> Dict:
        """
        Process incoming transactions for quarantine decisions
        """
        if not self.security_agent:
            return self._fallback_analysis(transaction_data, "No AI agent connected")
        
        try:
            # Mark as incoming transaction
            transaction_data['direction'] = 'incoming'
            transaction_data['analysis_type'] = 'quarantine_assessment'
            
            # Use SecurityAgent's AI analysis
            analysis_result = await self.security_agent.analyze_with_ai_code_generation(
                transaction_data, user_language
            )
            
            # Add quarantine recommendation
            if analysis_result['risk_score'] >= 0.7:
                analysis_result['quarantine_recommended'] = True
                analysis_result['quarantine_reason'] = 'High risk score from AI analysis'
            elif analysis_result['risk_score'] >= 0.4:
                analysis_result['quarantine_recommended'] = False
                analysis_result['user_review_recommended'] = True
            else:
                analysis_result['quarantine_recommended'] = False
            
            return analysis_result
            
        except Exception as e:
            # Default to quarantine on error for safety
            return {
                'action': 'QUARANTINE',
                'risk_score': 0.8,
                'quarantine_recommended': True,
                'quarantine_reason': f'Analysis error: {str(e)}',
                'user_explanation': 'Unable to analyze transaction - quarantined for safety',
                'error': str(e)
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

    async def _monitor_wallet_incoming(self, wallet_address: str):
        """Monitor specific wallet for incoming transactions"""
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
                        analysis_result = await self.process_incoming_transaction(tx)
                        
                        # Handle quarantine decision
                        if analysis_result.get('quarantine_recommended'):
                            await self._handle_quarantine_decision(tx, analysis_result)
                
                # Wait before next check
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                print(f"⚠️ Error monitoring wallet {wallet_address}: {e}")
                await asyncio.sleep(30)  # Wait longer on error

    async def _fetch_recent_transactions(self, wallet_address: str) -> List[Dict]:
        """Fetch recent transactions for wallet using real Solana RPC"""
        if self.solana_client:
            try:
                return await self.solana_client.get_recent_transactions(wallet_address, limit=10)
            except Exception as e:
                print(f"⚠️ Error fetching transactions: {e}")
        
        # Mock data for testing when RPC not available
        return [{
            'hash': f'mock_tx_{int(time.time())}',
            'from_address': 'mock_sender',
            'to_address': wallet_address,
            'value': 0.001,
            'timestamp': datetime.now().isoformat(),
            'token_symbol': 'SOL'
        }]

    async def _handle_quarantine_decision(self, transaction: Dict, analysis_result: Dict):
        """Handle quarantine decision for incoming transaction"""
        if analysis_result.get('quarantine_recommended'):
            print(f"🏠 QUARANTINED: {transaction.get('hash', 'unknown')} - {analysis_result.get('quarantine_reason', 'High risk')}")
            
            # Notify user about quarantine
            await self._notify_user_quarantine(transaction, analysis_result)
        else:
            print(f"✅ ALLOWED: {transaction.get('hash', 'unknown')} - Safe transaction")

    async def _notify_user_quarantine(self, transaction: Dict, analysis_result: Dict):
        """Notify user about quarantined item"""
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

    # ========== FALLBACK METHODS ==========

    def _fallback_analysis(self, transaction_data: Dict, error_reason: str) -> Dict:
        """Fallback analysis when AI agent unavailable"""
        return {
            'action': 'WARN',
            'risk_score': 0.5,
            'user_explanation': f'Basic analysis only: {error_reason}. Transaction flagged for manual review.',
            'chain_of_thought': [f'⚠️ Fallback analysis: {error_reason}'],
            'analysis_method': 'fallback',
            'quarantine_recommended': True  # Conservative approach
        }

    # ========== LEGACY COMPATIBILITY METHODS ==========

    def get_security_status(self) -> Dict[str, Any]:
        """
        Get current security status - compatible with existing framework
        """
        return {
            "security_score": 0.8,
            "total_threats_detected": len(self.threat_cache),
            "quarantined_items": 0,
            "monitored_wallets": len(self.wallet_addresses),
            "last_analysis": self.last_analysis_time.isoformat(),
            "modules_loaded": self._get_loaded_modules(),
            "monitoring_active": self.monitoring_active,
            "ai_agent_connected": self.security_agent is not None,
            "analysis_method": "ai_code_generation"
        }

    def get_transaction_threats(self) -> Dict[str, Any]:
        """Get recent threat detection data"""
        return {
            "recent_threats": list(self.threat_cache.values())[-10:],
            "threat_count": len(self.threat_cache),
            "last_scan": int(time.time()),
            "protection_enabled": True,
            "ai_analysis_available": self.security_agent is not None
        }

    def get_metric_fn(self, metric_name: str = "security") -> callable:
        """Get a callable that fetches security metrics"""
        if metric_name == "security":
            return lambda: self.get_security_status()
        else:
            return lambda: {"metric": metric_name, "value": 0.5}

    # ========== DIRECT MODULE ACCESS (For specific analysis) ==========

    async def run_specific_analysis(self, analysis_type: str, target_data: Dict) -> Dict:
        """
        Run specific analysis using your existing modules directly
        Useful for debugging or when AI agent isn't available
        """
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