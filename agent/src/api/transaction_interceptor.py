"""
Transaction Interceptor API - AI Code Generation Integration
Real-time transaction analysis using SecurityAgent's AI code generation
Provides ALLOW/WARN/BLOCK decisions before transaction signing
"""

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
import json
from datetime import datetime
import logging
import os
import time

# Simplified imports - only what we need
from src.agent.security import SecurityAgent, SecurityPromptGenerator
from src.sensor.security import SecuritySensor
from src.client.rag import RAGClient
from src.db import SQLiteDB
from src.genner import get_genner
from src.container import ContainerManager
import docker

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI Security Transaction Interceptor",
    description="Real-time transaction security analysis using AI code generation",
    version="2.0.0"
)

# ========== REQUEST/RESPONSE MODELS ==========

class TransactionRequest(BaseModel):
    """Transaction data from wallet provider for analysis"""
    transaction_hash: Optional[str] = None
    from_address: str
    to_address: str
    amount: Optional[float] = None
    token_address: Optional[str] = None
    token_name: Optional[str] = None
    program_id: Optional[str] = None
    instruction_data: Optional[str] = None
    value_usd: Optional[float] = None
    user_id: str
    wallet_provider: str  # "solflare", "phantom", etc.
    transaction_type: str  # "send", "swap", "contract_interaction"
    dapp_url: Optional[str] = None
    dapp_name: Optional[str] = None
    user_language: str = "english"
    additional_data: Optional[Dict[str, Any]] = {}

class SecurityResponse(BaseModel):
    """AI-powered security analysis response"""
    action: str  # "ALLOW", "WARN", "BLOCK"
    risk_score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    user_explanation: str  # AI-generated explanation in user's language
    chain_of_thought: List[str]  # Step-by-step AI reasoning
    threat_categories: List[str]
    ai_generated_code: str  # The actual code AI wrote for analysis
    technical_details: Dict[str, Any]  # Raw analysis results
    analysis_time_ms: int
    quarantine_recommended: bool
    analysis_method: str = "ai_code_generation"

class DAppCheckRequest(BaseModel):
    """Request to check DApp safety"""
    dapp_url: str
    dapp_name: Optional[str] = ""
    user_id: str
    user_language: str = "english"

class DAppCheckResponse(BaseModel):
    """DApp safety check response"""
    status: str  # "safe", "risky", "unknown"
    risk_score: float
    explanation: str
    recommendations: List[str]
    analysis_details: Dict[str, Any]

class UserQueryRequest(BaseModel):
    """User natural language query request"""
    user_message: str
    user_id: str
    user_language: str = "english"
    context: Optional[Dict[str, Any]] = {}

class UserQueryResponse(BaseModel):
    """Response to user natural language query"""
    response: str
    action_taken: Optional[str] = None
    analysis_performed: Optional[Dict[str, Any]] = None

# ========== GLOBAL SECURITY AGENT ==========

security_agent: Optional[SecurityAgent] = None

@app.on_event("startup")
async def startup_event():
    """Initialize AI-powered security agent on API startup"""
    global security_agent
    
    try:
        logger.info("🤖 Initializing AI-Powered Security Agent...")
        
        # Initialize components
        db = SQLiteDB(db_path=os.getenv("SQLITE_PATH", "./db/security-api.db"))
        
        # Initialize RAG client for threat intelligence
        rag_service_url = os.getenv("RAG_SERVICE_URL", "http://localhost:8080")
        # Generate unique IDs for this API instance
        agent_id = f"api_security_agent_{int(time.time())}"
        session_id = f"api_session_{int(time.time())}"
        rag = RAGClient(agent_id, session_id, rag_service_url)
        
        # Initialize security sensor with real Solana monitoring
        monitored_wallets = []
        wallet_env_vars = [key for key in os.environ.keys() if key.startswith("MONITOR_WALLET_")]
        for wallet_var in wallet_env_vars:
            wallet_address = os.environ[wallet_var]
            if wallet_address:
                monitored_wallets.append(wallet_address)
        
        if not monitored_wallets:
            monitored_wallets = ["demo_wallet_1", "demo_wallet_2"]  # Demo wallets
        
        # FIXED: Use correct SecuritySensor parameters
        sensor = SecuritySensor(
            wallet_addresses=monitored_wallets,
            solana_rpc_url=os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com"),
            rpc_api_key=os.getenv("HELIUS_API_KEY", ""),  # Fixed parameter name
            rpc_provider_name="helius"  # Added missing parameter
        )
        
        # Initialize AI generator
        genner = get_genner(
            backend="claude",
            anthropic_client=None,  # Will be initialized from env
            stream_fn=None
        )
        
        # Initialize container manager for safe code execution
        container_manager = ContainerManager(
            docker.from_env(),
            "ai-security-executor",
            "./code",
            {}
        )
        
        # Initialize prompt generator
        prompt_generator = SecurityPromptGenerator({})
        
        # Create AI-powered security agent
        security_agent = SecurityAgent(
            agent_id="api_ai_security_agent",
            sensor=sensor,
            genner=genner,
            container_manager=container_manager,
            prompt_generator=prompt_generator,
            db=db,
            rag=rag,
        )
        
        # Connect sensor to agent
        sensor.set_security_agent(security_agent)
        
        logger.info("✅ AI Security Agent initialized successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize AI Security Agent: {e}")
        raise e

# ========== MAIN TRANSACTION ANALYSIS ENDPOINT ==========

@app.post("/api/v1/analyze-transaction", response_model=SecurityResponse)
async def analyze_transaction_with_ai(
    request: TransactionRequest,
    x_api_key: Optional[str] = Header(None),
    x_wallet_provider: Optional[str] = Header(None)
):
    """
    MAIN ENDPOINT: Real-time transaction analysis using AI code generation
    Called by wallet providers BEFORE transaction signing
    """
    start_time = datetime.now()
    
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="AI Security agent not initialized")
        
        logger.info(f"🔍 AI analyzing transaction from {request.wallet_provider} for user {request.user_id}")
        
        # Prepare transaction data for AI analysis
        transaction_data = {
            "hash": request.transaction_hash or f"pending_{start_time.timestamp()}",
            "from_address": request.from_address,
            "to_address": request.to_address,
            "value": request.amount or 0,
            "value_usd": request.value_usd or 0,
            "token_address": request.token_address,
            "token_name": request.token_name,
            "program_id": request.program_id,
            "instruction_data": request.instruction_data,
            "transaction_type": request.transaction_type,
            "dapp_url": request.dapp_url,
            "dapp_name": request.dapp_name,
            "timestamp": start_time.isoformat(),
            "user_id": request.user_id,
            "wallet_provider": request.wallet_provider,
            "analysis_type": "outgoing_transaction",
            **request.additional_data
        }
        
        # AI Code Generation Analysis Pipeline
        logger.info("🤖 Starting AI code generation analysis...")
        analysis_result = await security_agent.analyze_with_ai_code_generation(
            transaction_data, 
            request.user_language
        )
        
        # Calculate analysis time
        end_time = datetime.now()
        analysis_time_ms = int((end_time - start_time).total_seconds() * 1000)
        
        # Extract threat categories from AI analysis
        threat_categories = []
        threats_found = analysis_result.get('execution_results', {}).get('threats_found', [])
        for threat in threats_found:
            if 'mev' in threat.lower():
                threat_categories.append('mev_attack')
            elif 'honeypot' in threat.lower():
                threat_categories.append('honeypot_token')
            elif 'drain' in threat.lower():
                threat_categories.append('drain_contract')
            elif 'dust' in threat.lower():
                threat_categories.append('dust_attack')
            else:
                threat_categories.append('unknown_threat')
        
        # Determine quarantine recommendation
        quarantine_recommended = analysis_result.get('risk_score', 0) >= 0.7
        
        # Build response
        response = SecurityResponse(
            action=analysis_result.get('action', 'ALLOW'),
            risk_score=analysis_result.get('risk_score', 0.0),
            confidence=0.85,  # High confidence due to AI analysis
            user_explanation=analysis_result.get('user_explanation', 'Transaction analyzed by AI'),
            chain_of_thought=analysis_result.get('chain_of_thought', []),
            threat_categories=threat_categories,
            ai_generated_code=analysis_result.get('ai_generated_code', ''),
            technical_details=analysis_result.get('technical_details', {}),
            analysis_time_ms=analysis_time_ms,
            quarantine_recommended=quarantine_recommended,
            analysis_method="ai_code_generation"
        )
        
        logger.info(f"✅ AI Analysis complete: {response.action} (risk: {response.risk_score:.2f}) in {analysis_time_ms}ms")
        
        return response
        
    except Exception as e:
        logger.error(f"❌ AI transaction analysis failed: {e}")
        
        # Safe default - block on error with explanation
        return SecurityResponse(
            action="BLOCK",
            risk_score=1.0,
            confidence=0.0,
            user_explanation=f"AI analysis system unavailable. Transaction blocked for safety. Error: {str(e)}",
            chain_of_thought=[f"❌ AI analysis error: {str(e)}", "🛑 Blocking transaction for safety"],
            threat_categories=["analysis_error"],
            ai_generated_code="# Analysis failed - no code generated",
            technical_details={"error": str(e)},
            analysis_time_ms=0,
            quarantine_recommended=True
        )

# ========== DAPP REPUTATION CHECK ENDPOINT ==========

@app.post("/api/v1/check-dapp", response_model=DAppCheckResponse)
async def check_dapp_reputation(request: DAppCheckRequest):
    """
    Check DApp safety using AI analysis and community intelligence
    """
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="AI Security agent not initialized")
        
        logger.info(f"🔍 Checking DApp reputation: {request.dapp_name or request.dapp_url}")
        
        # Use SecuritySensor's DApp analysis
        dapp_analysis = await security_agent.sensor.analyze_dapp_reputation(
            request.dapp_url, 
            request.dapp_name
        )
        
        # Convert to API response format
        recommendations = []
        if dapp_analysis['status'] == 'safe':
            recommendations.append("DApp appears safe to use")
        elif dapp_analysis['status'] == 'risky':
            recommendations.extend([
                "Avoid using this DApp",
                "Verify the official URL",
                "Check community reports before proceeding"
            ])
        else:
            recommendations.extend([
                "Unknown DApp - exercise caution",
                "Verify legitimacy through official channels",
                "Start with small amounts if you choose to proceed"
            ])
        
        response = DAppCheckResponse(
            status=dapp_analysis['status'],
            risk_score=dapp_analysis.get('risk_score', 0.5),
            explanation=dapp_analysis.get('reason', 'DApp analysis completed'),
            recommendations=recommendations,
            analysis_details=dapp_analysis.get('details', {})
        )
        
        logger.info(f"✅ DApp check complete: {response.status}")
        return response
        
    except Exception as e:
        logger.error(f"❌ DApp check failed: {e}")
        return DAppCheckResponse(
            status="error",
            risk_score=0.5,
            explanation=f"Unable to analyze DApp: {str(e)}",
            recommendations=["Could not verify DApp safety - proceed with extreme caution"],
            analysis_details={"error": str(e)}
        )

# ========== CONVERSATIONAL AI ENDPOINT ==========

@app.post("/api/v1/user-query", response_model=UserQueryResponse)
async def handle_user_query(request: UserQueryRequest):
    """
    Handle natural language user requests like 'analyze this contract'
    """
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="AI Security agent not initialized")
        
        logger.info(f"💬 Processing user query: {request.user_message[:50]}...")
        
        # Use SecurityAgent's conversational interface
        response_text = await security_agent.handle_user_request(
            request.user_message, 
            {
                'user_id': request.user_id,
                'language': request.user_language,
                **request.context
            }
        )
        
        # Check if any action was taken (like starting monitoring)
        action_taken = None
        if "tracking" in response_text.lower() or "monitoring" in response_text.lower():
            action_taken = "monitoring_started"
        elif "analysis" in response_text.lower():
            action_taken = "analysis_performed"
        
        response = UserQueryResponse(
            response=response_text,
            action_taken=action_taken,
            analysis_performed=None  # Could include analysis details if performed
        )
        
        logger.info(f"✅ User query processed")
        return response
        
    except Exception as e:
        logger.error(f"❌ User query failed: {e}")
        return UserQueryResponse(
            response=f"I'm sorry, I couldn't process your request: {str(e)}. Please try again or contact support.",
            action_taken=None,
            analysis_performed=None
        )

# ========== INCOMING TRANSACTION PROCESSING ==========

@app.post("/api/v1/process-incoming")
async def process_incoming_transaction(
    request: TransactionRequest,
    x_api_key: Optional[str] = Header(None)
):
    """
    Process incoming transactions for quarantine decisions
    """
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="AI Security agent not initialized")
        
        logger.info(f"📥 Processing incoming transaction for {request.user_id}")
        
        # Prepare transaction data
        transaction_data = {
            "hash": request.transaction_hash or f"incoming_{datetime.now().timestamp()}",
            "from_address": request.from_address,
            "to_address": request.to_address,
            "value": request.amount or 0,
            "token_name": request.token_name,
            "token_address": request.token_address,
            "direction": "incoming",
            "analysis_type": "quarantine_assessment",
            "user_id": request.user_id,
            "wallet_provider": request.wallet_provider
        }
        
        # Use SecuritySensor's incoming transaction processing
        analysis_result = await security_agent.sensor.process_incoming_transaction(
            transaction_data, 
            request.user_language
        )
        
        return {
            "quarantine_recommended": analysis_result.get('quarantine_recommended', False),
            "risk_score": analysis_result.get('risk_score', 0.0),
            "explanation": analysis_result.get('user_explanation', 'Transaction processed'),
            "action": analysis_result.get('action', 'ALLOW'),
            "analysis_details": analysis_result
        }
        
    except Exception as e:
        logger.error(f"❌ Incoming transaction processing failed: {e}")
        return {
            "quarantine_recommended": True,  # Safe default
            "risk_score": 0.8,
            "explanation": f"Processing error - quarantined for safety: {str(e)}",
            "action": "QUARANTINE",
            "error": str(e)
        }

# ========== WALLET STATUS ENDPOINT ==========

@app.get("/api/v1/wallet-status/{wallet_address}")
async def get_wallet_security_status(wallet_address: str):
    """
    Get comprehensive security status for a wallet
    """
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="AI Security agent not initialized")
        
        # Get security status from sensor
        security_status = security_agent.sensor.get_security_status()
        
        # Add wallet-specific information
        wallet_status = {
            "wallet_address": wallet_address,
            "security_score": security_status.get('security_score', 0.8),
            "threats_detected_24h": security_status.get('total_threats_detected', 0),
            "ai_protection_active": security_status.get('ai_agent_connected', False),
            "monitoring_active": security_status.get('monitoring_active', False),
            "last_analysis": security_status.get('last_analysis', ''),
            "protection_modules": security_status.get('modules_loaded', ''),
            "analysis_method": security_status.get('analysis_method', 'ai_code_generation')
        }
        
        return wallet_status
        
    except Exception as e:
        logger.error(f"❌ Wallet status check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")

# ========== HEALTH CHECK ==========

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy" if security_agent else "unhealthy",
        "ai_agent_initialized": security_agent is not None,
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "analysis_method": "ai_code_generation"
    }

# ========== ERROR HANDLERS ==========

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for safety"""
    logger.error(f"❌ Unhandled exception: {exc}")
    
    return {
        "action": "BLOCK",
        "risk_score": 1.0,
        "explanation": "Security system error - transaction blocked for safety",
        "error": str(exc),
        "status": "error"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9009)  # Changed from 8001 to 9009