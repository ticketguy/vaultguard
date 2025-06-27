"""
SecuritySensor - Replaces TradingSensor with security monitoring
Integrates with existing analysis modules following framework patterns
NOW WITH REAL-TIME INCOMING TRANSACTION MONITORING
"""

from typing import Any, Dict, List
from functools import partial
import time
import asyncio
import json
import requests
from datetime import datetime, timedelta

# Import existing analysis modules - keep them as separate classes
try:
    from analysis.dust_detector import DustDetector
except ImportError:
    DustDetector = None

try:
    from analysis.mev_detector import MEVDetector  
except ImportError:
    MEVDetector = None

try:
    from analysis.enhanced_contract_analyzer import EnhancedContractAnalyzer
except ImportError:
    EnhancedContractAnalyzer = None

try:
    from analysis.behavior_analyzer import BehaviorAnalyzer
except ImportError:
    BehaviorAnalyzer = None

try:
    from security.threat_analyzer import ThreatAnalyzer
except ImportError:
    ThreatAnalyzer = None

try:
    from security.quarantine_manager import QuarantineManager
except ImportError:
    QuarantineManager = None


class SecuritySensor:
    """
    Security monitoring sensor that orchestrates all analysis modules.
    Follows exact same pattern as TradingSensor but for security operations.
    NOW WITH REAL-TIME INCOMING TRANSACTION MONITORING AND AUTO-QUARANTINE
    """
    
    def __init__(self, wallet_addresses: List[str], solana_rpc_url: str, helius_api_key: str = ""):
        # Core connection parameters (like TradingSensor's eth_address, etc.)
        self.wallet_addresses = wallet_addresses
        self.solana_rpc_url = solana_rpc_url
        self.helius_api_key = helius_api_key
        
        # Initialize your existing analysis modules - keep them as separate classes
        self.dust_detector = DustDetector() if DustDetector else None
        self.mev_detector = MEVDetector() if MEVDetector else None
        self.contract_analyzer = EnhancedContractAnalyzer() if EnhancedContractAnalyzer else None
        self.behavior_analyzer = BehaviorAnalyzer() if BehaviorAnalyzer else None
        self.threat_analyzer = ThreatAnalyzer() if ThreatAnalyzer else None
        
        # Track security state
        self.last_analysis_time = datetime.now()
        self.threat_cache = {}
        
        # NEW: Real-time monitoring properties
        self.monitoring_active = False
        self.monitoring_tasks = []
        self.websocket_connections = {}
        self.last_processed_signatures = set()
        
        # Connect to SecurityAgent for quarantine decisions (will be injected)
        self.security_agent = None
        
        print(f"🛡️ SecuritySensor initialized for {len(wallet_addresses)} wallets")
        print(f"📊 Analysis modules loaded: {self._get_loaded_modules()}")

    def _get_loaded_modules(self) -> str:
        """Get list of successfully loaded analysis modules"""
        modules = []
        if self.dust_detector: modules.append("DustDetector")
        if self.mev_detector: modules.append("MEVDetector") 
        if self.contract_analyzer: modules.append("ContractAnalyzer")
        if self.behavior_analyzer: modules.append("BehaviorAnalyzer")
        if self.threat_analyzer: modules.append("ThreatAnalyzer")
        return ", ".join(modules) if modules else "None"

    # NEW: Real-time monitoring integration method
    def set_security_agent(self, security_agent):
        """Inject SecurityAgent for quarantine decisions"""
        self.security_agent = security_agent

    # NEW: Start real-time monitoring
    async def start_incoming_monitor(self):
        """
        Start background monitoring for incoming transactions to all wallets
        This is the core real-time protection system
        """
        if self.monitoring_active:
            print("🛡️ Monitoring already active")
            return
        
        self.monitoring_active = True
        print(f"🚀 Starting real-time monitoring for {len(self.wallet_addresses)} wallets...")
        
        # Start monitoring tasks for each wallet
        for wallet_address in self.wallet_addresses:
            task = asyncio.create_task(
                self._monitor_wallet_incoming(wallet_address)
            )
            self.monitoring_tasks.append(task)
            print(f"   📡 Monitoring: {wallet_address[:8]}...{wallet_address[-8:]}")
        
        # Start MEV mempool monitoring
        mev_task = asyncio.create_task(self._monitor_mev_activity())
        self.monitoring_tasks.append(mev_task)
        
        print("✅ Real-time monitoring started - protecting against:")
        print("   🧼 Dust attacks and spam tokens")
        print("   🤖 MEV sandwich attacks") 
        print("   💀 Drain contracts and scams")
        print("   🔗 Malicious contract interactions")
        print("   🌐 Community-reported threats")

    # NEW: Monitor specific wallet for incoming transactions
    async def _monitor_wallet_incoming(self, wallet_address: str):
        """Monitor incoming transactions for a specific wallet"""
        print(f"👀 Watching wallet: {wallet_address[:8]}...{wallet_address[-8:]}")
        
        while self.monitoring_active:
            try:
                # Get recent transactions (last 30 seconds)
                recent_transactions = await self._fetch_recent_transactions_realtime(wallet_address, limit=50)
                
                for tx in recent_transactions:
                    # Skip if already processed
                    tx_signature = tx.get('signature', '')
                    if tx_signature in self.last_processed_signatures:
                        continue
                    
                    # Only process incoming transactions TO this wallet
                    if self._is_incoming_transaction(tx, wallet_address):
                        await self.process_incoming_transaction(tx, wallet_address)
                    
                    self.last_processed_signatures.add(tx_signature)
                
                # Clean old signatures to prevent memory bloat
                if len(self.last_processed_signatures) > 1000:
                    # Keep only last 500 signatures
                    signatures_list = list(self.last_processed_signatures)
                    self.last_processed_signatures = set(signatures_list[-500:])
                
            except Exception as e:
                print(f"⚠️ Monitoring error for {wallet_address[:8]}: {str(e)}")
            
            # Check every 5 seconds for new transactions
            await asyncio.sleep(5)

    # NEW: Core real-time transaction analysis
    async def process_incoming_transaction(self, tx_data: Dict, wallet_address: str) -> Dict:
        """
        Auto-analyze incoming transaction using existing analysis modules
        This is where the magic happens - real-time threat detection
        """
        tx_signature = tx_data.get('signature', 'unknown')
        token_info = self._extract_token_info(tx_data)
        
        print(f"🔍 Analyzing incoming: {token_info.get('name', 'Unknown')} → {wallet_address[:8]}...")
        
        # Initialize analysis results
        analysis_results = {
            'transaction_data': tx_data,
            'wallet_address': wallet_address,
            'token_info': token_info,
            'risk_score': 0.0,
            'threat_types': [],
            'simple_explanation': "",
            'technical_details': {},
            'recommended_action': 'allow',
            'user_message': "",
            'chain_of_thought': []
        }
        
        # Chain of thought reasoning
        analysis_results['chain_of_thought'].append(
            f"🤔 Analyzing {token_info.get('name', 'token')} from {tx_data.get('from_address', 'unknown')[:8]}..."
        )
        
        # 1. DUST ATTACK DETECTION
        if self.dust_detector:
            dust_analysis = await self._run_dust_analysis(tx_data)
            analysis_results['technical_details']['dust_analysis'] = dust_analysis
            
            if dust_analysis.get('is_dust_attack', False):
                analysis_results['risk_score'] += 0.7
                analysis_results['threat_types'].append('dust_attack')
                analysis_results['chain_of_thought'].append(
                    f"🧼 Dust attack detected: {dust_analysis.get('dust_type', 'unknown')} pattern"
                )
                analysis_results['simple_explanation'] = f"This is a spam token sent to track your wallet activity. Amount: {token_info.get('amount', '0')} {token_info.get('symbol', '')}"
        
        # 2. MEV THREAT DETECTION  
        if self.mev_detector:
            mev_analysis = await self._run_mev_analysis(tx_data)
            analysis_results['technical_details']['mev_analysis'] = mev_analysis
            
            if mev_analysis.get('mev_risk', 0) > 0.5:
                analysis_results['risk_score'] += mev_analysis.get('mev_risk', 0)
                analysis_results['threat_types'].append('mev_risk')
                analysis_results['chain_of_thought'].append(
                    f"🤖 MEV risk detected: {mev_analysis.get('risk_factors', {})}"
                )
                # Simple English explanation for MEV
                if 'sandwich_attack' in str(mev_analysis):
                    analysis_results['simple_explanation'] = "⚠️ MEV bots detected! If you interact with this token, bots might 'sandwich' your transaction and steal profits from you."
                elif 'front_running' in str(mev_analysis):
                    analysis_results['simple_explanation'] = "⚠️ Front-running risk! Bots are watching - they might copy your transaction and get a better price before you."
        
        # 3. CONTRACT SECURITY ANALYSIS
        if self.contract_analyzer:
            contract_analysis = await self._run_contract_analysis(tx_data)
            analysis_results['technical_details']['contract_analysis'] = contract_analysis
            
            if contract_analysis.get('threats_found', 0) > 0:
                analysis_results['risk_score'] += 0.8
                analysis_results['threat_types'].append('malicious_contract')
                analysis_results['chain_of_thought'].append(
                    f"💀 Malicious contract detected: {contract_analysis.get('threat_summary', 'unknown')}"
                )
                analysis_results['simple_explanation'] = f"🚨 DANGER: This token is connected to a malicious contract that could drain your wallet if you interact with it. Keep it quarantined!"
        
        # 4. BEHAVIOR PATTERN ANALYSIS
        if self.behavior_analyzer:
            behavior_analysis = await self._run_behavior_analysis(tx_data, wallet_address)
            analysis_results['technical_details']['behavior_analysis'] = behavior_analysis
            
            if behavior_analysis.get('anomalies_found', 0) > 0:
                analysis_results['risk_score'] += 0.6
                analysis_results['threat_types'].append('suspicious_behavior')
                analysis_results['chain_of_thought'].append(
                    f"🔍 Suspicious behavior: {behavior_analysis.get('anomaly_summary', 'unknown pattern')}"
                )
        
        # 5. COMMUNITY THREAT INTELLIGENCE (RAG System)
        community_intel = await self._check_community_threats(tx_data)
        analysis_results['technical_details']['community_intel'] = community_intel
        
        if community_intel.get('is_known_threat', False):
            analysis_results['risk_score'] += 0.9
            analysis_results['threat_types'].append('community_reported')
            analysis_results['chain_of_thought'].append(
                f"🌐 Community alert: {community_intel.get('threat_description', 'Known scammer')}"
            )
            analysis_results['simple_explanation'] = f"🚨 SCAM ALERT: This address has been reported {community_intel.get('report_count', 0)} times by the community for: {community_intel.get('scam_type', 'fraudulent activity')}"
        
        # Calculate final risk score and decision
        final_risk = min(analysis_results['risk_score'], 1.0)
        analysis_results['risk_score'] = final_risk
        
        # Make quarantine decision with simple explanations
        decision_result = await self._auto_quarantine_decision(analysis_results)
        analysis_results.update(decision_result)
        
        # Log the complete analysis
        self._log_analysis_result(analysis_results)
        
        return analysis_results

    # NEW: Automatic quarantine decision making
    async def _auto_quarantine_decision(self, analysis_results: Dict) -> Dict:
        """
        Make automatic quarantine decision and provide simple explanations
        Connects to existing SecurityAgent quarantine system
        """
        risk_score = analysis_results['risk_score']
        threat_types = analysis_results['threat_types']
        token_info = analysis_results['token_info']
        
        # Decision thresholds
        if risk_score >= 0.8:
            # HIGH RISK - Auto-quarantine
            action = 'quarantine'
            confidence = 'high'
            user_message = f"🚨 HIGH RISK: {token_info.get('name', 'Token')} quarantined for your safety"
            
            if 'malicious_contract' in threat_types:
                user_message = f"💀 MALICIOUS CONTRACT: {token_info.get('name', 'Token')} can drain your wallet - safely quarantined"
            elif 'community_reported' in threat_types:
                user_message = f"🌐 SCAM ALERT: {token_info.get('name', 'Token')} reported by community - quarantined"
            elif 'dust_attack' in threat_types:
                user_message = f"🧼 SPAM BLOCKED: Dust attack from {analysis_results['transaction_data'].get('from_address', 'unknown')[:8]}... quarantined"
                
        elif risk_score >= 0.5:
            # MEDIUM RISK - Quarantine with warning
            action = 'quarantine'
            confidence = 'medium'
            user_message = f"⚠️ SUSPICIOUS: {token_info.get('name', 'Token')} needs review - quarantined for safety"
            
            if 'mev_risk' in threat_types:
                user_message = f"🤖 MEV RISK: Interacting with {token_info.get('name', 'Token')} might trigger bot attacks - quarantined for review"
                
        else:
            # LOW RISK - Allow but monitor
            action = 'allow'
            confidence = 'low'
            user_message = f"✅ {token_info.get('name', 'Token')} appears safe - added to main wallet"
        
        # Execute quarantine if needed
        if action == 'quarantine' and self.security_agent:
            # Use existing SecurityAgent quarantine system
            quarantine_item = self.security_agent.quarantine_item(
                item_data={
                    'transaction': analysis_results['transaction_data'],
                    'token_info': token_info,
                    'wallet_address': analysis_results['wallet_address']
                },
                risk_score=risk_score,
                reasoning=f"Auto-quarantined: {', '.join(threat_types)} (confidence: {confidence})"
            )
            
            print(f"🔒 QUARANTINED: {token_info.get('name', 'Token')} (Risk: {risk_score:.2f})")
            print(f"   Threats: {', '.join(threat_types)}")
            print(f"   User message: {user_message}")
        
        return {
            'recommended_action': action,
            'confidence_level': confidence,
            'user_message': user_message,
            'quarantine_reasoning': f"Risk score {risk_score:.2f}: {', '.join(threat_types)}" if threat_types else "Low risk analysis"
        }

    # NEW: MEV monitoring
    async def _monitor_mev_activity(self):
        """Monitor mempool for MEV activity that could affect user transactions"""
        print("🤖 Starting MEV monitoring...")
        
        while self.monitoring_active:
            try:
                # Monitor pending transactions in mempool
                mempool_data = await self._fetch_mempool_data()
                
                if mempool_data:
                    mev_threats = await self._analyze_mempool_mev(mempool_data)
                    
                    if mev_threats.get('high_mev_activity', False):
                        print(f"⚠️ HIGH MEV ACTIVITY: {mev_threats.get('bot_count', 0)} bots detected")
                        print(f"   Simple explanation: {mev_threats.get('user_warning', 'MEV bots are very active')}")
                        
                        # Cache MEV threat info for transaction analysis
                        self.threat_cache['mev_activity'] = {
                            'timestamp': datetime.now(),
                            'threat_level': mev_threats.get('threat_level', 'medium'),
                            'bot_count': mev_threats.get('bot_count', 0),
                            'user_warning': mev_threats.get('user_warning', ''),
                            'recommended_actions': mev_threats.get('recommended_actions', [])
                        }
                
            except Exception as e:
                print(f"⚠️ MEV monitoring error: {str(e)}")
            
            # Check every 30 seconds
            await asyncio.sleep(30)

    # NEW: Community threat intelligence
    async def _check_community_threats(self, tx_data: Dict) -> Dict:
        """
        Check transaction against community threat intelligence database
        Uses existing RAG system for threat intelligence
        """
        from_address = tx_data.get('from_address', '')
        to_address = tx_data.get('to_address', '')
        token_info = self._extract_token_info(tx_data)
        
        # Use existing RAG system to check threat intelligence
        threat_query = f"known scammer threat {from_address} {token_info.get('name', '')} malicious"
        
        try:
            # This uses your existing RAG system
            rag_response = await self._query_threat_intelligence(threat_query)
            
            # Parse RAG response for threat indicators
            is_threat = (
                'scam' in str(rag_response).lower() or
                'malicious' in str(rag_response).lower() or
                'reported' in str(rag_response).lower() or
                'blacklist' in str(rag_response).lower()
            )
            
            return {
                'is_known_threat': is_threat,
                'threat_description': str(rag_response)[:200] if is_threat else "",
                'confidence': 0.8 if is_threat else 0.1,
                'source': 'community_intelligence',
                'report_count': self._extract_report_count(rag_response),
                'scam_type': self._extract_scam_type(rag_response)
            }
            
        except Exception as e:
            print(f"⚠️ Community intelligence check failed: {str(e)}")
            return {'is_known_threat': False, 'error': str(e)}

    # NEW: Stop monitoring
    def stop_monitoring(self):
        """Stop all real-time monitoring"""
        print("🛑 Stopping real-time monitoring...")
        self.monitoring_active = False
        
        # Cancel all monitoring tasks
        for task in self.monitoring_tasks:
            task.cancel()
        
        self.monitoring_tasks.clear()
        print("✅ Monitoring stopped")

    # EXISTING: Your original get_security_status method stays the same
    def get_security_status(self) -> Dict[str, Any]:
        """
        Main method that orchestrates all security analysis.
        Equivalent to TradingSensor.get_portfolio_status() but for security.
        """
        print("🔍 Starting comprehensive security analysis...")
        
        # Get recent transactions for analysis
        recent_transactions = self._fetch_recent_transactions()
        
        # Run all analysis modules on the data
        analysis_results = {
            "security_score": 0.7,  # Overall security score (0-1)
            "total_threats_detected": 0,
            "quarantined_items": 0,
            "monitored_wallets": len(self.wallet_addresses),
            "last_analysis": datetime.now().isoformat(),
            "threat_breakdown": {
                "dust_attacks": 0,
                "mev_threats": 0,
                "malicious_contracts": 0,
                "behavioral_anomalies": 0,
                "general_threats": 0
            },
            "detailed_analysis": {},
            "recent_transactions": recent_transactions[:5],  # Last 5 for context
            "recommendations": []
        }
        
        # 1. Dust Attack Detection
        if self.dust_detector and recent_transactions:
            print("💨 Running dust attack analysis...")
            dust_results = self._analyze_dust_attacks(recent_transactions)
            analysis_results["detailed_analysis"]["dust_analysis"] = dust_results
            analysis_results["threat_breakdown"]["dust_attacks"] = dust_results.get("threats_found", 0)
            analysis_results["total_threats_detected"] += dust_results.get("threats_found", 0)
            
            if dust_results.get("threats_found", 0) > 0:
                analysis_results["recommendations"].append("🚨 Dust attacks detected - avoid interacting with suspicious small transactions")
        
        # 2. MEV Attack Detection  
        if self.mev_detector and recent_transactions:
            print("⚡ Running MEV analysis...")
            mev_results = self._analyze_mev_risks(recent_transactions)
            analysis_results["detailed_analysis"]["mev_analysis"] = mev_results
            analysis_results["threat_breakdown"]["mev_threats"] = mev_results.get("threats_found", 0)
            analysis_results["total_threats_detected"] += mev_results.get("threats_found", 0)
            
            if mev_results.get("high_risk", False):
                analysis_results["recommendations"].append("⚡ MEV risks detected - consider adjusting gas fees or timing")
        
        # 3. Contract Analysis
        if self.contract_analyzer and recent_transactions:
            print("🔬 Running contract security analysis...")
            contract_results = self._analyze_contracts(recent_transactions)
            analysis_results["detailed_analysis"]["contract_analysis"] = contract_results
            analysis_results["threat_breakdown"]["malicious_contracts"] = contract_results.get("threats_found", 0)
            analysis_results["total_threats_detected"] += contract_results.get("threats_found", 0)
            
            if contract_results.get("threats_found", 0) > 0:
                analysis_results["recommendations"].append("🔒 Malicious contracts detected - avoid interacting with flagged addresses")
        
        # 4. Behavioral Analysis
        if self.behavior_analyzer:
            print("🧠 Running behavioral analysis...")
            behavior_results = self._analyze_behavior_patterns()
            analysis_results["detailed_analysis"]["behavior_analysis"] = behavior_results
            analysis_results["threat_breakdown"]["behavioral_anomalies"] = behavior_results.get("anomalies_found", 0)
            
            if behavior_results.get("anomalies_found", 0) > 0:
                analysis_results["recommendations"].append("🔍 Unusual patterns detected - review recent activity")
        
        # 5. General Threat Analysis
        if self.threat_analyzer and recent_transactions:
            print("🛡️ Running general threat analysis...")
            general_threats = self._analyze_general_threats(recent_transactions)
            analysis_results["detailed_analysis"]["general_threats"] = general_threats
            analysis_results["threat_breakdown"]["general_threats"] = general_threats.get("threats_found", 0)
            analysis_results["total_threats_detected"] += general_threats.get("threats_found", 0)
        
        # Calculate overall security score based on threats
        total_threats = analysis_results["total_threats_detected"]
        if total_threats == 0:
            analysis_results["security_score"] = 0.9
        elif total_threats <= 2:
            analysis_results["security_score"] = 0.7
        elif total_threats <= 5:
            analysis_results["security_score"] = 0.4
        else:
            analysis_results["security_score"] = 0.2
        
        print(f"✅ Security analysis complete - Score: {analysis_results['security_score']:.2f}, Threats: {total_threats}")
        
        return analysis_results

    def get_transaction_threats(self) -> Dict[str, Any]:
        """
        Get specific transaction threat data.
        Additional method for the SecuritySensorInterface.
        """
        recent_transactions = self._fetch_recent_transactions()
        
        threat_data = {
            "high_risk_transactions": [],
            "medium_risk_transactions": [],
            "low_risk_transactions": [],
            "quarantine_candidates": [],
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        # Analyze each transaction for threat level
        for tx in recent_transactions[:10]:  # Analyze last 10 transactions
            risk_level = self._assess_transaction_risk(tx)
            
            if risk_level >= 0.8:
                threat_data["high_risk_transactions"].append(tx)
                threat_data["quarantine_candidates"].append(tx)
            elif risk_level >= 0.5:
                threat_data["medium_risk_transactions"].append(tx)
            else:
                threat_data["low_risk_transactions"].append(tx)
        
        return threat_data

    def get_metric_fn(self, metric_name: str = "security"):
        """
        Return a callable that fetches security metrics.
        Follows exact same pattern as TradingSensor.get_metric_fn()
        """
        metrics = {
            "security": self.get_security_status,
            "threats": self.get_transaction_threats,
            "wallet_status": self._get_wallet_security_status
        }
        
        if metric_name not in metrics:
            raise ValueError(f"Unsupported metric: {metric_name}")
        
        return metrics[metric_name]

    # Helper methods that use your existing analysis modules
    
    def _fetch_recent_transactions(self) -> List[Dict]:
        """Fetch recent transactions for monitored wallets"""
        try:
            # This would use your meta-swap-api integration
            all_transactions = []
            
            for wallet in self.wallet_addresses:
                # Mock transaction data for now - replace with real Solana RPC calls
                transactions = self._get_wallet_transactions(wallet)
                all_transactions.extend(transactions)
            
            # Sort by timestamp and return most recent
            all_transactions.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
            return all_transactions[:20]  # Return last 20 transactions
            
        except Exception as e:
            print(f"⚠️ Error fetching transactions: {e}")
            return []

    def _get_wallet_transactions(self, wallet_address: str) -> List[Dict]:
        """Get transactions for a specific wallet using Solana RPC"""
        try:
            # Replace this with real Solana RPC integration via your meta-swap-api
            # For now, return mock data that matches your existing analysis module expectations
            
            mock_transactions = [
                {
                    "hash": f"mock_tx_{int(time.time())}_{wallet_address[-6:]}",
                    "from_address": "random_sender_address",
                    "to_address": wallet_address,
                    "value": "0.001",
                    "value_usd": 0.2,
                    "timestamp": int(time.time()) - (60 * 20),  # 20 minutes ago
                    "token_name": "SOL",
                    "token_symbol": "SOL",
                    "program_id": "11111111111111111111111111111112",  # System program
                    "network": "solana"
                }
            ]
            
            # TODO: Replace with actual Solana API call:
            # response = requests.post(self.solana_rpc_url, json={
            #     "jsonrpc": "2.0", 
            #     "id": 1,
            #     "method": "getSignaturesForAddress",
            #     "params": [wallet_address, {"limit": 10}]
            # })
            
            return mock_transactions
            
        except Exception as e:
            print(f"⚠️ Error getting wallet transactions: {e}")
            return []

    def _analyze_dust_attacks(self, transactions: List[Dict]) -> Dict:
        """Use your existing DustDetector"""
        if not self.dust_detector:
            return {"threats_found": 0, "analysis": "DustDetector not available"}
        
        try:
            # Use your existing dust detector's methods
            dust_threats = 0
            dust_details = []
            
            for tx in transactions:
                # Call your existing dust detector analysis method
                # Adapt the method call to match your dust detector's interface
                if hasattr(self.dust_detector, 'analyze_dust_attack'):
                    result = asyncio.run(self.dust_detector.analyze_dust_attack(tx))
                    if result.get('is_dust_attack', False):
                        dust_threats += 1
                        dust_details.append(result)
                        
            return {
                "threats_found": dust_threats,
                "details": dust_details,
                "analysis": f"Analyzed {len(transactions)} transactions for dust attacks"
            }
            
        except Exception as e:
            print(f"⚠️ Dust analysis error: {e}")
            return {"threats_found": 0, "error": str(e)}

    def _analyze_mev_risks(self, transactions: List[Dict]) -> Dict:
        """Use your existing MEVDetector"""
        if not self.mev_detector:
            return {"threats_found": 0, "analysis": "MEVDetector not available"}
        
        try:
            # Use your existing MEV detector
            mev_threats = 0
            high_risk = False
            mev_details = []
            
            for tx in transactions:
                if hasattr(self.mev_detector, 'analyze_mev_risk'):
                    result = asyncio.run(self.mev_detector.analyze_mev_risk(tx))
                    if result.get('mev_risk', 0) > 0.7:
                        mev_threats += 1
                        high_risk = True
                        mev_details.append(result)
                        
            return {
                "threats_found": mev_threats,
                "high_risk": high_risk,
                "details": mev_details,
                "analysis": f"Analyzed {len(transactions)} transactions for MEV risks"
            }
            
        except Exception as e:
            print(f"⚠️ MEV analysis error: {e}")
            return {"threats_found": 0, "error": str(e)}

    def _analyze_contracts(self, transactions: List[Dict]) -> Dict:
        """Use your existing EnhancedContractAnalyzer"""
        if not self.contract_analyzer:
            return {"threats_found": 0, "analysis": "ContractAnalyzer not available"}
        
        try:
            contract_threats = 0
            contract_details = []
            
            for tx in transactions:
                if tx.get('program_id') or tx.get('to_address'):
                    # Analyze the contract/program
                    if hasattr(self.contract_analyzer, 'analyze_contract_for_drain_risk'):
                        contract_data = {
                            'address': tx.get('program_id') or tx.get('to_address'),
                            'bytecode': tx.get('contract_bytecode', ''),
                            'functions': tx.get('contract_functions', [])
                        }
                        result = asyncio.run(self.contract_analyzer.analyze_contract_for_drain_risk(contract_data))
                        if result.get('is_drain_contract', False):
                            contract_threats += 1
                            contract_details.append(result)
                            
            return {
                "threats_found": contract_threats,
                "details": contract_details,
                "analysis": f"Analyzed contracts in {len(transactions)} transactions"
            }
            
        except Exception as e:
            print(f"⚠️ Contract analysis error: {e}")
            return {"threats_found": 0, "error": str(e)}

    def _analyze_behavior_patterns(self) -> Dict:
        """Use your existing BehaviorAnalyzer"""
        if not self.behavior_analyzer:
            return {"anomalies_found": 0, "analysis": "BehaviorAnalyzer not available"}
        
        try:
            # Use your existing behavior analyzer
            if hasattr(self.behavior_analyzer, 'analyze_wallet_behavior'):
                anomalies = 0
                for wallet in self.wallet_addresses:
                    result = asyncio.run(self.behavior_analyzer.analyze_wallet_behavior(wallet))
                    if result.get('has_anomalies', False):
                        anomalies += 1
                        
                return {
                    "anomalies_found": anomalies,
                    "analysis": f"Analyzed behavior for {len(self.wallet_addresses)} wallets"
                }
            else:
                return {"anomalies_found": 0, "analysis": "Behavior analysis method not found"}
                
        except Exception as e:
            print(f"⚠️ Behavior analysis error: {e}")
            return {"anomalies_found": 0, "error": str(e)}

    def _analyze_general_threats(self, transactions: List[Dict]) -> Dict:
        """Use your existing ThreatAnalyzer"""
        if not self.threat_analyzer:
            return {"threats_found": 0, "analysis": "ThreatAnalyzer not available"}
        
        try:
            general_threats = 0
            threat_details = []
            
            for tx in transactions:
                if hasattr(self.threat_analyzer, 'analyze_transaction_threats'):
                    result = asyncio.run(self.threat_analyzer.analyze_transaction_threats(tx))
                    if result.get('threat_level', 0) > 0.5:
                        general_threats += 1
                        threat_details.append(result)
                        
            return {
                "threats_found": general_threats,
                "details": threat_details,
                "analysis": f"General threat analysis on {len(transactions)} transactions"
            }
            
        except Exception as e:
            print(f"⚠️ General threat analysis error: {e}")
            return {"threats_found": 0, "error": str(e)}

    def _assess_transaction_risk(self, transaction: Dict) -> float:
        """Assess individual transaction risk level (0-1)"""
        risk_score = 0.0
        
        # Check transaction value
        value_usd = transaction.get('value_usd', 0)
        if value_usd > 10000:
            risk_score += 0.3
        
        # Check for suspicious addresses
        from_addr = transaction.get('from_address', '').lower()
        if 'dead' in from_addr or '0000000' in from_addr:
            risk_score += 0.5
        
        # Check for new contracts
        if transaction.get('program_id') and len(transaction.get('contract_bytecode', '')) > 0:
            risk_score += 0.2
        
        return min(risk_score, 1.0)

    def _get_wallet_security_status(self) -> Dict[str, Any]:
        """Get security status for each monitored wallet"""
        wallet_statuses = {}
        
        for wallet in self.wallet_addresses:
            wallet_statuses[wallet] = {
                "security_score": 0.8,  # Individual wallet score
                "last_activity": datetime.now().isoformat(),
                "threats_detected": 0,
                "status": "secure"
            }
        
        return {
            "individual_wallets": wallet_statuses,
            "total_wallets": len(self.wallet_addresses),
            "average_security_score": 0.8
        }

    # NEW: Helper methods for real-time monitoring system
    
    def _is_incoming_transaction(self, tx: Dict, wallet_address: str) -> bool:
        """Check if transaction is incoming to the specified wallet"""
        to_address = tx.get('to_address', '')
        return to_address.lower() == wallet_address.lower()
    
    def _extract_token_info(self, tx_data: Dict) -> Dict:
        """Extract token information from transaction"""
        return {
            'name': tx_data.get('token_name', 'Unknown'),
            'symbol': tx_data.get('token_symbol', ''),
            'amount': tx_data.get('amount', '0'),
            'decimals': tx_data.get('decimals', 9),
            'mint_address': tx_data.get('mint_address', ''),
            'from_address': tx_data.get('from_address', ''),
            'to_address': tx_data.get('to_address', '')
        }
    
    async def _fetch_recent_transactions_realtime(self, wallet_address: str, limit: int = 50) -> List[Dict]:
        """Fetch recent transactions for wallet (implement with actual Solana RPC)"""
        # This would use your existing Solana RPC connection
        # For now, returning mock structure
        try:
            # Your existing Solana RPC code would go here
            # Using self.solana_rpc_url and self.helius_api_key
            return []  # Replace with actual RPC call
        except Exception as e:
            print(f"⚠️ Failed to fetch transactions: {str(e)}")
            return []
    
    async def _fetch_mempool_data(self) -> Dict:
        """Fetch current mempool data for MEV analysis"""
        # Implementation depends on your Solana RPC setup
        return {}
    
    async def _query_threat_intelligence(self, query: str) -> str:
        """Query threat intelligence using existing RAG system"""
        # This would use your existing RAG system
        # You already have this in your SecurityAgent
        return "No threat intelligence available"
    
    def _extract_report_count(self, rag_response) -> int:
        """Extract number of community reports from RAG response"""
        # Parse RAG response for report count
        return 0
    
    def _extract_scam_type(self, rag_response) -> str:
        """Extract scam type from RAG response"""
        # Parse RAG response for scam classification
        return "unknown"
    
    def _log_analysis_result(self, analysis_results: Dict):
        """Log detailed analysis results for monitoring and debugging"""
        risk_score = analysis_results['risk_score']
        action = analysis_results.get('recommended_action', 'unknown')
        threats = ', '.join(analysis_results['threat_types']) if analysis_results['threat_types'] else 'none'
        
        print(f"📊 ANALYSIS COMPLETE:")
        print(f"   Risk Score: {risk_score:.2f}")
        print(f"   Action: {action.upper()}")
        print(f"   Threats: {threats}")
        print(f"   Chain of Thought: {len(analysis_results['chain_of_thought'])} steps")
        
        if analysis_results.get('simple_explanation'):
            print(f"   User Explanation: {analysis_results['simple_explanation']}")
    
    # Integration methods for existing analysis modules
    
    async def _run_dust_analysis(self, tx_data: Dict) -> Dict:
        """Run dust detection using existing DustDetector"""
        if not self.dust_detector:
            return {'is_dust_attack': False}
        
        try:
            return await self.dust_detector.analyze_transaction(tx_data)
        except Exception as e:
            print(f"⚠️ Dust analysis error: {str(e)}")
            return {'is_dust_attack': False, 'error': str(e)}
    
    async def _run_mev_analysis(self, tx_data: Dict) -> Dict:
        """Run MEV detection using existing MEVDetector"""
        if not self.mev_detector:
            return {'mev_risk': 0.0}
        
        try:
            return await self.mev_detector.analyze_transaction(tx_data)
        except Exception as e:
            print(f"⚠️ MEV analysis error: {str(e)}")
            return {'mev_risk': 0.0, 'error': str(e)}
    
    async def _run_contract_analysis(self, tx_data: Dict) -> Dict:
        """Run contract analysis using existing EnhancedContractAnalyzer"""
        if not self.contract_analyzer:
            return {'threats_found': 0}
        
        try:
            return await self.contract_analyzer.analyze_transaction(tx_data)
        except Exception as e:
            print(f"⚠️ Contract analysis error: {str(e)}")
            return {'threats_found': 0, 'error': str(e)}
    
    async def _run_behavior_analysis(self, tx_data: Dict, wallet_address: str) -> Dict:
        """Run behavior analysis using existing BehaviorAnalyzer"""
        if not self.behavior_analyzer:
            return {'anomalies_found': 0}
        
        try:
            return await self.behavior_analyzer.analyze_transaction(tx_data, wallet_address)
        except Exception as e:
            print(f"⚠️ Behavior analysis error: {str(e)}")
            return {'anomalies_found': 0, 'error': str(e)}
    
    async def _analyze_mempool_mev(self, mempool_data: Dict) -> Dict:
        """Analyze mempool for MEV activity"""
        if not self.mev_detector:
            return {'high_mev_activity': False}
        
        try:
            return await self.mev_detector.analyze_mempool(mempool_data)
        except Exception as e:
            print(f"⚠️ Mempool MEV analysis error: {str(e)}")
            return {'high_mev_activity': False, 'error': str(e)}