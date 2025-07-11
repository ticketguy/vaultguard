"""
Wallet Security SDK for Wallet Providers (Python)
Simple decision service - wallets handle hiding/showing with existing mechanisms
"""

import asyncio
import json
import aiohttp
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from enum import Enum
import logging

class SecurityDecision:
    """Simple security decision for wallets"""
    def __init__(self, action: str, risk_score: float, confidence: float, 
                 reasoning: str, user_explanation: str, threat_categories: List[str],
                 chain_of_thought: List[str], technical_details: Dict = None,
                 analysis_time_ms: int = 0):
        self.action = action  # 'allow', 'hide', 'warn', 'block'
        self.risk_score = risk_score
        self.confidence = confidence
        self.reasoning = reasoning
        self.user_explanation = user_explanation
        self.threat_categories = threat_categories
        self.chain_of_thought = chain_of_thought
        self.technical_details = technical_details or {}
        self.analysis_time_ms = analysis_time_ms

class WalletSecuritySDK:
    """
    SDK for wallet providers to integrate AI security agent
    Simple decision service - no quarantine storage
    """
    
    def __init__(self, wallet_provider_id: str, config: Dict = None):
        self.wallet_provider_id = wallet_provider_id
        self.config = config or {}
        self.agent_url = self.config.get('agent_url', 'http://localhost:8001')
        
        # HTTP session for API calls
        self.session = None
        
        # Callbacks for notifications
        self.callbacks = {
            'on_threat_detected': None,
            'on_analysis_complete': None
        }
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(f"WalletSDK-{wallet_provider_id}")
    
    async def initialize(self):
        """Initialize the wallet security SDK"""
        self.logger.info(f"🔌 Initializing Wallet Security SDK for {self.wallet_provider_id}")
        
        # Create HTTP session
        self.session = aiohttp.ClientSession()
        
        # Test connection to security agent
        await self.connect_to_security_agent()
        
        self.logger.info("✅ Wallet Security SDK initialized")
    
    async def close(self):
        """Clean up resources"""
        if self.session:
            await self.session.close()
    
    async def connect_to_security_agent(self):
        """Connect to the AI security agent"""
        try:
            if not self.session:
                raise Exception("HTTP session not initialized")
            
            async with self.session.get(f"{self.agent_url}/health") as response:
                if response.status == 200:
                    self.logger.info(f"🤖 Connected to AI Security Agent at {self.agent_url}")
                    return True
                else:
                    self.logger.warning(f"⚠️ Security agent responded with status {response.status}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"❌ Failed to connect to security agent: {e}")
            self.logger.info("🔄 Will attempt to connect on first transaction")
            return False
    
    # ========== CORE API FOR WALLET PROVIDERS ==========
    
    async def analyze_incoming_transaction(self, transaction_data: Dict) -> SecurityDecision:
        """
        Analyze incoming transaction - returns decision to hide/show
        Wallet uses existing spam filtering mechanisms
        """
        self.logger.info(f"🔍 Analyzing incoming transaction: {transaction_data.get('hash', 'unknown')}")
        
        enhanced_data = {
            **transaction_data,
            'transaction_type': 'incoming',
            'additional_data': {
                **transaction_data.get('additional_data', {}),
                'analysis_type': 'incoming_transaction',
                'wallet_provider': self.wallet_provider_id
            }
        }
        
        analysis_result = await self.analyze_with_ai_agent(enhanced_data)
        return self._convert_to_wallet_decision(analysis_result, 'incoming')
    
    async def analyze_outgoing_transaction(self, transaction_data: Dict) -> SecurityDecision:
        """
        Analyze outgoing transaction before signing - returns allow/warn/block
        """
        self.logger.info(f"🚀 Analyzing outgoing transaction to: {transaction_data.get('to_address', 'unknown')}")
        
        enhanced_data = {
            **transaction_data,
            'transaction_type': 'outgoing',
            'additional_data': {
                **transaction_data.get('additional_data', {}),
                'analysis_type': 'outgoing_transaction',
                'wallet_provider': self.wallet_provider_id
            }
        }
        
        analysis_result = await self.analyze_with_ai_agent(enhanced_data)
        return self._convert_to_wallet_decision(analysis_result, 'outgoing')
    
    async def analyze_token(self, token_data: Dict) -> SecurityDecision:
        """
        Analyze token for spam/scam detection - returns decision to hide/show
        """
        self.logger.info(f"🪙 Analyzing token: {token_data.get('token_name', 'unknown')}")
        
        enhanced_data = {
            **token_data,
            'transaction_type': 'token_analysis',
            'additional_data': {
                **token_data.get('additional_data', {}),
                'analysis_type': 'token_analysis',
                'wallet_provider': self.wallet_provider_id
            }
        }
        
        analysis_result = await self.analyze_with_ai_agent(enhanced_data)
        return self._convert_to_wallet_decision(analysis_result, 'token')
    
    async def analyze_dapp(self, dapp_url: str, dapp_name: str = None) -> SecurityDecision:
        """
        Analyze DApp safety
        """
        self.logger.info(f"🌐 Analyzing DApp: {dapp_name or dapp_url}")
        
        dapp_data = {
            'dapp_url': dapp_url,
            'dapp_name': dapp_name,
            'transaction_type': 'dapp_analysis',
            'additional_data': {
                'analysis_type': 'dapp_analysis',
                'wallet_provider': self.wallet_provider_id
            }
        }
        
        analysis_result = await self.analyze_with_ai_agent(dapp_data)
        return self._convert_to_wallet_decision(analysis_result, 'dapp')
    
    # ========== DECISION CONVERSION ==========
    
    def _convert_to_wallet_decision(self, analysis_result: Dict, analysis_type: str) -> SecurityDecision:
        """Convert AI analysis to simple wallet decision"""
        risk_score = analysis_result.get('risk_score', 0)
        confidence = analysis_result.get('confidence', 0)
        threat_categories = analysis_result.get('threat_categories', [])
        
        # Determine action based on type and risk
        if analysis_type == 'incoming':
            # For incoming transactions/tokens - hide risky items
            if risk_score > 0.7:
                action = 'hide'
            elif risk_score > 0.4:
                action = 'warn'  # Wallet can choose to show with warning
            else:
                action = 'allow'
        elif analysis_type == 'outgoing':
            # For outgoing transactions - block dangerous ones
            if risk_score > 0.8 and confidence > 0.7:
                action = 'block'
            elif risk_score > 0.4:
                action = 'warn'
            else:
                action = 'allow'
        else:
            # General analysis
            if risk_score > 0.8:
                action = 'hide'
            elif risk_score > 0.5:
                action = 'warn'
            else:
                action = 'allow'
        
        decision = SecurityDecision(
            action=action,
            risk_score=risk_score,
            confidence=confidence,
            reasoning=analysis_result.get('reasoning', ''),
            user_explanation=analysis_result.get('user_explanation', ''),
            threat_categories=threat_categories,
            chain_of_thought=analysis_result.get('chain_of_thought', []),
            technical_details=analysis_result.get('technical_details', {}),
            analysis_time_ms=analysis_result.get('analysis_time_ms', 0)
        )
        
        # Notify callback if threat detected
        if action != 'allow' and self.callbacks.get('on_threat_detected'):
            asyncio.create_task(self.callbacks['on_threat_detected']({
                'action': action,
                'risk_score': risk_score,
                'threat_categories': threat_categories,
                'reasoning': analysis_result.get('reasoning', '')
            }))
        
        return decision
    
    # ========== REAL AI AGENT CONNECTION ==========
    
    async def analyze_with_ai_agent(self, transaction_data: Dict) -> Dict:
        """Send transaction to REAL AI agent for analysis"""
        try:
            if not self.session:
                raise Exception("SDK not initialized - call initialize() first")
            
            # Prepare request payload
            payload = {
                "transaction_hash": transaction_data.get('hash'),
                "from_address": transaction_data.get('from_address'),
                "to_address": transaction_data.get('to_address'),
                "amount": transaction_data.get('amount') or transaction_data.get('value'),
                "value_usd": transaction_data.get('value_usd'),
                "token_address": transaction_data.get('token_address'),
                "token_name": transaction_data.get('token_name'),
                "program_id": transaction_data.get('program_id'),
                "instruction_data": transaction_data.get('instruction_data'),
                "transaction_type": transaction_data.get('transaction_type', 'transfer'),
                "dapp_url": transaction_data.get('dapp_url'),
                "dapp_name": transaction_data.get('dapp_name'),
                "user_id": transaction_data.get('user_id'),
                "wallet_provider": self.wallet_provider_id,
                "user_language": transaction_data.get('user_language', 'english'),
                "additional_data": transaction_data.get('additional_data', {})
            }
            
            headers = {
                'Content-Type': 'application/json',
                'X-Wallet-Provider': self.wallet_provider_id,
                'X-API-Key': self.config.get('api_key', '')
            }
            
            self.logger.info(f"🤖 Sending to AI agent: {self.agent_url}/api/v1/analyze-transaction")
            
            # Make REAL API call
            async with self.session.post(
                f"{self.agent_url}/api/v1/analyze-transaction",
                json=payload,
                headers=headers,
                timeout=30
            ) as response:
                
                if response.status == 200:
                    result = await response.json()
                    self.logger.info(f"✅ AI analysis complete - Risk: {result.get('risk_score', 0):.2f}")
                    
                    # Notify analysis complete callback
                    if self.callbacks.get('on_analysis_complete'):
                        asyncio.create_task(self.callbacks['on_analysis_complete'](result))
                    
                    return {
                        'quarantine_recommended': result.get('action') in ['WARN', 'BLOCK'],
                        'risk_score': result.get('risk_score', 0),
                        'confidence': result.get('confidence', 0),
                        'reasoning': result.get('user_explanation', ''),
                        'user_explanation': result.get('user_explanation', ''),
                        'threat_categories': result.get('threat_categories', []),
                        'chain_of_thought': result.get('chain_of_thought', []),
                        'technical_details': result.get('technical_details', {}),
                        'analysis_time_ms': result.get('analysis_time_ms', 0),
                        'ai_generated_code': result.get('ai_generated_code', ''),
                        'action': result.get('action', 'ALLOW')
                    }
                else:
                    error_text = await response.text()
                    self.logger.error(f"❌ API error {response.status}: {error_text}")
                    return self._fallback_analysis(transaction_data, f"API error: {response.status}")
                    
        except asyncio.TimeoutError:
            self.logger.error("⏰ AI analysis timeout")
            return self._fallback_analysis(transaction_data, "Analysis timeout")
            
        except Exception as e:
            self.logger.error(f"💥 AI analysis failed: {str(e)}")
            return self._fallback_analysis(transaction_data, f"Analysis failed: {str(e)}")
    
    def _fallback_analysis(self, transaction_data: Dict, error_reason: str) -> Dict:
        """Fallback analysis when AI agent is unavailable"""
        self.logger.warning(f"🔄 Using fallback analysis: {error_reason}")
        
        risk_score = 0.0
        threats = []
        
        # Basic rule-based analysis
        from_address = str(transaction_data.get('from_address', '')).lower()
        token_name = str(transaction_data.get('token_name', '')).lower()
        value = float(transaction_data.get('amount', 0) or transaction_data.get('value', 0))
        
        # Known scammer patterns
        if any(pattern in from_address for pattern in ['dead', '1111', '0000']):
            risk_score += 0.8
            threats.append('suspicious_address_pattern')
        
        # Fake token patterns
        if any(fake in token_name for fake in ['fake', 'scam', 'test']):
            risk_score += 0.9
            threats.append('fake_token')
        
        # Dust attacks
        if 0 < value < 0.001:
            risk_score += 0.6
            threats.append('dust_attack')
        
        return {
            'quarantine_recommended': risk_score > 0.5,
            'risk_score': min(risk_score, 1.0),
            'confidence': 0.3,
            'reasoning': f"Fallback analysis: {error_reason}. Risk score: {risk_score:.2f}",
            'user_explanation': f"Fallback analysis: {error_reason}",
            'threat_categories': threats,
            'chain_of_thought': [
                f"AI agent unavailable: {error_reason}",
                "Using basic rule-based fallback analysis",
                f"Detected threats: {threats}",
                f"Final risk score: {min(risk_score, 1.0):.2f}"
            ],
            'technical_details': {'fallback': True, 'error': error_reason},
            'analysis_time_ms': 0,
            'action': 'WARN' if risk_score > 0.5 else 'ALLOW',
            'analysis_method': 'fallback'
        }
    
    # ========== USER FEEDBACK ==========
    
    async def send_user_feedback(self, decision: SecurityDecision, user_action: str, feedback: str = ""):
        """Send user feedback to AI for learning"""
        try:
            if not self.session:
                return
            
            feedback_data = {
                'wallet_provider_id': self.wallet_provider_id,
                'original_decision': decision.action,
                'risk_score': decision.risk_score,
                'threat_categories': decision.threat_categories,
                'user_action': user_action,  # 'accepted', 'rejected', 'overridden'
                'user_feedback': feedback,
                'timestamp': datetime.now().isoformat()
            }
            
            async with self.session.post(
                f"{self.agent_url}/api/v1/user-feedback",
                json=feedback_data,
                timeout=5
            ) as response:
                if response.status == 200:
                    self.logger.info(f"📚 Sent user feedback to AI: {user_action}")
                else:
                    self.logger.warning(f"⚠️ Failed to send feedback: {response.status}")
                    
        except Exception as e:
            self.logger.warning(f"⚠️ Could not send feedback to AI: {e}")
    
    # ========== UTILITY METHODS ==========
    
    def set_callback(self, event: str, callback: Callable):
        """Set callback functions for wallet provider"""
        if event in self.callbacks:
            self.callbacks[event] = callback
            self.logger.info(f"📞 Set callback for {event}")
    
    # ========== BATCH ANALYSIS ==========
    
    async def analyze_multiple_tokens(self, tokens: List[Dict]) -> List[SecurityDecision]:
        """Analyze multiple tokens in batch"""
        self.logger.info(f"🔍 Analyzing {len(tokens)} tokens in batch")
        
        tasks = [self.analyze_token(token) for token in tokens]
        return await asyncio.gather(*tasks)
    
    async def analyze_transaction_batch(self, transactions: List[Dict]) -> List[SecurityDecision]:
        """Analyze multiple transactions in batch"""
        self.logger.info(f"🔍 Analyzing {len(transactions)} transactions in batch")
        
        tasks = []
        for tx in transactions:
            if tx.get('transaction_type') == 'incoming':
                tasks.append(self.analyze_incoming_transaction(tx))
            else:
                tasks.append(self.analyze_outgoing_transaction(tx))
        
        return await asyncio.gather(*tasks)