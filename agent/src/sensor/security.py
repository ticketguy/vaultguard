"""
SecuritySensor - Replaces TradingSensor with security monitoring
Integrates with existing analysis modules following framework patterns
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