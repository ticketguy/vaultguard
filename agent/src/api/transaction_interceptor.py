"""
Transaction Interceptor API
Real-time transaction analysis service for wallet providers
Provides ALLOW/WARN/BLOCK decisions before transaction signing
"""

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
import json
from datetime import datetime
import logging

from src.agent.security import SecurityAgent
from src.sensor.security import SecuritySensor
from src.client.rag import RAGClient
from src.db import SQLiteDB
from src.genner import get_genner
from src.container import ContainerManager
import docker
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Solana Security Interceptor API",
    description="Real-time transaction security analysis for wallet providers",
    version="1.0.0"
)

class TransactionRequest(BaseModel):
    """Transaction data from wallet provider for analysis"""
    transaction_hash: Optional[str] = None
    from_address: str
    to_address: str
    amount: Optional[float] = None
    token_address: Optional[str] = None
    program_id: Optional[str] = None
    instruction_data: Optional[str] = None
    value_usd: Optional[float] = None
    user_id: str
    wallet_provider: str  # "solflare", "phantom", etc.
    transaction_type: str  # "send", "swap", "contract_interaction"
    additional_data: Optional[Dict[str, Any]] = {}

class SecurityResponse(BaseModel):
    """Security analysis response to wallet provider"""
    action: str  # "ALLOW", "WARN", "BLOCK"
    risk_score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    reason: str
    chain_of_thought: List[str]  # Step-by-step reasoning
    threat_categories: List[str]
    recommendations: List[str]
    analysis_time_ms: int
    quarantine_recommended: bool
    user_warnings: List[str]

class MultiWalletStatusRequest(BaseModel):
    """Request to check status across multiple wallets"""
    user_id: str
    wallet_addresses: List[str]
    wallet_provider: str

class MultiWalletStatusResponse(BaseModel):
    """Status response for multiple wallets"""
    overall_risk_level: str  # "low", "medium", "high"
    total_threats_detected: int
    active_quarantine_items: int
    wallet_statuses: Dict[str, Dict[str, Any]]
    cross_wallet_patterns: List[str]
    recommendations: List[str]

# Global security agent instance
security_agent: Optional[SecurityAgent] = None

@app.on_event("startup")
async def startup_event():
    """Initialize security agent on API startup"""
    global security_agent
    
    try:
        logger.info("🛡️ Initializing Security Agent for API service...")
        
        # Initialize components
        db = SQLiteDB(db_path=os.getenv("SQLITE_PATH", "./db/security-api.db"))
        
        # Initialize RAG client
        rag_service_url = os.getenv("RAG_SERVICE_URL", "http://localhost:8080")
        rag = RAGClient(rag_service_url)
        
        # Initialize security sensor
        rpc_url = os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")
        meta_swap_api_url = os.getenv("TXN_SERVICE_URL", "http://localhost:9009")
        sensor = SecuritySensor(rpc_url=rpc_url, meta_swap_api_url=meta_swap_api_url)
        
        # Initialize LLM
        genner = get_genner(
            backend="claude",
            anthropic_client=None,  # Will be initialized based on env
            stream_fn=None
        )
        
        # Initialize container manager
        container_manager = ContainerManager(
            docker.from_env(),
            "agent-executor",
            "./code",
            {}
        )
        
        # Create security agent
        from src.agent.security import SecurityPromptGenerator
        prompt_generator = SecurityPromptGenerator({})
        
        security_agent = SecurityAgent(
            agent_id="api_security_agent",
            sensor=sensor,
            genner=genner,
            container_manager=container_manager,
            prompt_generator=prompt_generator,
            db=db,
            rag=rag,
        )
        
        logger.info("✅ Security Agent initialized successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize Security Agent: {e}")
        raise e

@app.post("/api/v1/analyze-transaction", response_model=SecurityResponse)
async def analyze_transaction(
    request: TransactionRequest,
    x_api_key: Optional[str] = Header(None),
    x_wallet_provider: Optional[str] = Header(None)
):
    """
    Real-time transaction analysis endpoint
    Called by wallet providers BEFORE transaction signing
    """
    start_time = datetime.now()
    
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="Security agent not initialized")
        
        logger.info(f"🔍 Analyzing transaction from {request.wallet_provider} for user {request.user_id}")
        
        # Prepare transaction data for analysis
        transaction_data = {
            "hash": request.transaction_hash or f"pending_{start_time.timestamp()}",
            "from_address": request.from_address,
            "to_address": request.to_address,
            "value": request.amount or 0,
            "value_usd": request.value_usd or 0,
            "token_address": request.token_address,
            "program_id": request.program_id,
            "instruction_data": request.instruction_data,
            "transaction_type": request.transaction_type,
            "timestamp": start_time.isoformat(),
            "user_id": request.user_id,
            "wallet_provider": request.wallet_provider,
            **request.additional_data
        }
        
        # Chain of thought reasoning list
        reasoning_steps = []
        
        # Step 1: Basic transaction validation
        reasoning_steps.append("🔍 Step 1: Validating transaction structure and addresses")
        
        # Step 2: Security sensor analysis
        reasoning_steps.append("📊 Step 2: Running comprehensive security analysis")
        security_status = await security_agent.sensor.get_security_status()
        
        # Step 3: Multi-module threat analysis
        reasoning_steps.append("🛡️ Step 3: Analyzing with MEV, dust, contract, and behavior detectors")
        
        # MEV analysis
        mev_result = await security_agent.sensor.mev_detector.analyze_mev_risk(transaction_data)
        mev_risk = mev_result.get('mev_risk', 0)
        if mev_risk > 0.5:
            reasoning_steps.append(f"⚠️ MEV risk detected: {mev_risk:.2f} - {mev_result.get('analysis', 'Potential front-running')}")
        
        # Dust attack analysis
        dust_result = await security_agent.sensor.dust_detector.analyze_dust_attack(transaction_data)
        dust_risk = dust_result.get('is_dust_attack', False)
        if dust_risk:
            reasoning_steps.append(f"🏠 Dust attack detected: {dust_result.get('analysis', 'Small value tracking transaction')}")
        
        # Contract analysis (if applicable)
        contract_risk = 0
        if request.program_id:
            reasoning_steps.append(f"📋 Step 4: Analyzing smart contract {request.program_id[:8]}...")
            contract_data = {"address": request.program_id}
            contract_result = await security_agent.sensor.contract_analyzer.analyze_contract_for_drain_risk(contract_data)
            contract_risk = contract_result.get('drain_risk_score', 0)
            if contract_result.get('is_drain_contract', False):
                reasoning_steps.append(f"🚨 DRAIN CONTRACT DETECTED: {contract_result.get('analysis', 'High risk contract')}")
        
        # Behavioral analysis
        reasoning_steps.append("👤 Step 5: Analyzing user behavioral patterns")
        behavior_result = await security_agent.sensor.behavior_analyzer.analyze_wallet_behavior(request.from_address)
        behavior_risk = behavior_result.get('anomaly_score', 0)
        if behavior_result.get('has_anomalies', False):
            reasoning_steps.append(f"📈 Behavioral anomaly: {behavior_result.get('analysis', 'Unusual activity pattern')}")
        
        # Step 6: Calculate overall risk and make decision
        reasoning_steps.append("⚖️ Step 6: Calculating overall risk score and making decision")
        
        # Combine risk scores
        overall_risk = max(mev_risk, contract_risk, behavior_risk)
        if dust_risk:
            overall_risk = max(overall_risk, 0.8)
        
        # Decision logic with chain of thought
        action = "ALLOW"
        reason = "Transaction appears safe"
        quarantine_recommended = False
        threat_categories = []
        user_warnings = []
        recommendations = []
        
        if overall_risk >= 0.8:
            action = "BLOCK"
            reason = "High security risk detected - transaction blocked for user protection"
            reasoning_steps.append(f"🛑 DECISION: BLOCK (risk: {overall_risk:.2f}) - Protecting user from high-risk transaction")
            quarantine_recommended = True
            
        elif overall_risk >= 0.5:
            action = "WARN"
            reason = "Moderate security risk detected - user should review carefully"
            reasoning_steps.append(f"⚠️ DECISION: WARN (risk: {overall_risk:.2f}) - User should be cautious")
            
        else:
            reasoning_steps.append(f"✅ DECISION: ALLOW (risk: {overall_risk:.2f}) - Transaction appears safe")
        
        # Add specific threat categories
        if mev_risk > 0.3:
            threat_categories.append("mev_risk")
            user_warnings.append(f"MEV risk detected - consider adjusting slippage")
            
        if dust_risk:
            threat_categories.append("dust_attack")
            user_warnings.append("Dust attack detected - transaction will be quarantined")
            
        if contract_risk > 0.3:
            threat_categories.append("contract_risk")
            user_warnings.append("Smart contract has elevated risk factors")
            
        if behavior_risk > 0.3:
            threat_categories.append("behavioral_anomaly")
            user_warnings.append("Unusual activity pattern detected")
        
        # Generate recommendations
        if action == "BLOCK":
            recommendations.extend([
                "Do not proceed with this transaction",
                "Verify the recipient address manually",
                "Check if this is a legitimate contract or token"
            ])
        elif action == "WARN":
            recommendations.extend([
                "Review transaction details carefully",
                "Consider using lower amounts for testing",
                "Verify recipient legitimacy through official channels"
            ])
        
        # Calculate analysis time
        end_time = datetime.now()
        analysis_time_ms = int((end_time - start_time).total_seconds() * 1000)
        
        reasoning_steps.append(f"⏱️ Analysis completed in {analysis_time_ms}ms")
        
        # Create response
        response = SecurityResponse(
            action=action,
            risk_score=overall_risk,
            confidence=0.85,  # Could be calculated based on data quality
            reason=reason,
            chain_of_thought=reasoning_steps,
            threat_categories=threat_categories,
            recommendations=recommendations,
            analysis_time_ms=analysis_time_ms,
            quarantine_recommended=quarantine_recommended,
            user_warnings=user_warnings
        )
        
        logger.info(f"✅ Analysis complete: {action} (risk: {overall_risk:.2f}) in {analysis_time_ms}ms")
        
        return response
        
    except Exception as e:
        logger.error(f"❌ Transaction analysis failed: {e}")
        # Return safe default - block on error
        return SecurityResponse(
            action="BLOCK",
            risk_score=1.0,
            confidence=0.0,
            reason=f"Analysis failed: {str(e)}",
            chain_of_thought=[f"❌ Error during analysis: {str(e)}", "🛑 Blocking transaction for safety"],
            threat_categories=["analysis_error"],
            recommendations=["Retry transaction later", "Contact support if issue persists"],
            analysis_time_ms=0,
            quarantine_recommended=True,
            user_warnings=["Transaction analysis failed - blocked for safety"]
        )

@app.post("/api/v1/multi-wallet-status", response_model=MultiWalletStatusResponse)
async def check_multi_wallet_status(
    request: MultiWalletStatusRequest,
    x_api_key: Optional[str] = Header(None)
):
    """
    Check security status across multiple user wallets
    Used for cross-wallet threat detection
    """
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="Security agent not initialized")
        
        logger.info(f"🔍 Checking multi-wallet status for user {request.user_id}")
        
        wallet_statuses = {}
        total_threats = 0
        quarantine_items = 0
        cross_wallet_patterns = []
        
        # Analyze each wallet
        for wallet_address in request.wallet_addresses:
            try:
                # Get wallet security status
                behavior_result = await security_agent.sensor.behavior_analyzer.analyze_wallet_behavior(wallet_address)
                
                wallet_status = {
                    "risk_level": "low",
                    "anomaly_score": behavior_result.get('anomaly_score', 0),
                    "threats_detected": behavior_result.get('anomalies_found', 0),
                    "last_analyzed": datetime.now().isoformat(),
                    "status": "monitored"
                }
                
                # Determine risk level
                risk_score = behavior_result.get('anomaly_score', 0)
                if risk_score > 0.7:
                    wallet_status["risk_level"] = "high"
                elif risk_score > 0.4:
                    wallet_status["risk_level"] = "medium"
                
                wallet_statuses[wallet_address] = wallet_status
                total_threats += wallet_status["threats_detected"]
                
            except Exception as e:
                logger.warning(f"Failed to analyze wallet {wallet_address}: {e}")
                wallet_statuses[wallet_address] = {
                    "risk_level": "unknown",
                    "anomaly_score": 0,
                    "threats_detected": 0,
                    "last_analyzed": datetime.now().isoformat(),
                    "status": "error",
                    "error": str(e)
                }
        
        # Determine overall risk level
        max_risk_score = max([w.get('anomaly_score', 0) for w in wallet_statuses.values()])
        if max_risk_score > 0.7:
            overall_risk = "high"
        elif max_risk_score > 0.4:
            overall_risk = "medium"
        else:
            overall_risk = "low"
        
        # Generate recommendations
        recommendations = []
        if overall_risk == "high":
            recommendations.extend([
                "Immediate security review recommended",
                "Consider temporarily limiting high-value transactions",
                "Review recent activity across all wallets"
            ])
        elif overall_risk == "medium":
            recommendations.extend([
                "Monitor wallet activity closely",
                "Verify legitimacy of recent transactions"
            ])
        else:
            recommendations.append("All wallets appear secure")
        
        response = MultiWalletStatusResponse(
            overall_risk_level=overall_risk,
            total_threats_detected=total_threats,
            active_quarantine_items=quarantine_items,
            wallet_statuses=wallet_statuses,
            cross_wallet_patterns=cross_wallet_patterns,
            recommendations=recommendations
        )
        
        logger.info(f"✅ Multi-wallet status check complete: {overall_risk} risk")
        return response
        
    except Exception as e:
        logger.error(f"❌ Multi-wallet status check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "security_agent_ready": security_agent is not None,
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

@app.get("/api/v1/stats")
async def get_stats():
    """Get API usage statistics"""
    return {
        "total_transactions_analyzed": 0,  # TODO: Implement counter
        "blocked_transactions": 0,
        "warnings_issued": 0,
        "average_analysis_time_ms": 0,
        "uptime_seconds": 0
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)