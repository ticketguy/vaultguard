"""
🛡️ UNIFIED AI WALLET SECURITY SYSTEM
Event-driven architecture - Only processes when transactions actually happen!
Integrates SecurityAgent + FastAPI + Background Monitoring in one process
"""

import asyncio
import os
import requests
import inquirer
import time
import uvicorn
from contextlib import asynccontextmanager
from typing import Callable, Optional, List, Dict, Any

# Core imports - no mock dependencies
from src.db import SQLiteDB
from src.client.rag import RAGClient
from src.sensor.security import SecuritySensor
from src.sensor.interface import SecuritySensorInterface
from src.db import DBInterface
from src.rpc_config import FlexibleRPCConfig
from src.agent.security import SecurityAgent, SecurityPromptGenerator
from src.datatypes import StrategyData
from src.container import ContainerManager
from src.helper import services_to_envs, services_to_prompts
from src.genner import get_genner
from src.genner.Base import Genner
from src.client.openrouter import OpenRouter
from src.summarizer import get_summarizer
from anthropic import Anthropic
import docker
from functools import partial
from src.flows.security import assisted_flow as security_assisted_flow
from loguru import logger
from src.constants import SERVICE_TO_ENV
from src.manager import fetch_default_prompt
from dotenv import load_dotenv

# FastAPI imports for integrated API
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from datetime import datetime

# Background monitoring (optional)
try:
    from src.intelligence.background_monitor import BackgroundIntelligenceMonitor, start_background_monitor
    BACKGROUND_MONITOR_AVAILABLE = True
except ImportError:
    BACKGROUND_MONITOR_AVAILABLE = False
    logger.warning("⚠️ Background monitor not available")

# Load environment variables
load_dotenv()

# ========== GLOBAL SYSTEM STATE ==========
security_agent: Optional[SecurityAgent] = None
background_monitor: Optional[Any] = None

# ========== MODEL SELECTION SYSTEM ==========

def get_available_models():
    """Get available AI models based on configured API keys - no mock options"""
    available = []
    
    if os.getenv("OPENROUTER_API_KEY"):
        available.extend([
            "Gemini (openrouter)",
            "QWQ (openrouter)", 
            "OpenAI (openrouter)"
        ])
    
    if os.getenv("ANTHROPIC_API_KEY"):
        available.append("Claude")
    
    if os.getenv("OPENAI_API_KEY"):
        available.append("OpenAI")
    
    if not available:
        raise Exception("No AI API keys configured! Please set OPENROUTER_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY")
    
    return available

def get_model_backend(model_choice: str) -> str:
    """Convert user-friendly model name to backend name - no mock options"""
    model_naming = {
        "OpenAI": "openai",
        "OpenAI (openrouter)": "openai",
        "Gemini (openrouter)": "gemini",
        "QWQ (openrouter)": "qwq",
        "Claude": "claude",
    }
    backend = model_naming.get(model_choice)
    if not backend:
        raise Exception(f"Unsupported model choice: {model_choice}")
    return backend

def auto_select_model():
    """Auto-select best available AI model - no mock fallbacks"""
    model_override = os.getenv("SECURITY_AI_MODEL", "").strip()
    if model_override:
        logger.info(f"🎯 Using model from SECURITY_AI_MODEL: {model_override}")
        return model_override
    
    available = get_available_models()
    if "Gemini (openrouter)" in available:
        return "Gemini (openrouter)"
    elif "QWQ (openrouter)" in available:
        return "QWQ (openrouter)"
    elif "OpenAI (openrouter)" in available:
        return "OpenAI (openrouter)"
    elif "Claude" in available:
        return "Claude"
    elif "OpenAI" in available:
        return "OpenAI"
    else:
        raise Exception("No valid AI models available - check your API keys")

def setup_ai_genner(model_choice: str):
    """Setup AI generator based on model choice"""
    backend_name = get_model_backend(model_choice)
    logger.info(f"🤖 Initializing AI: {model_choice} → {backend_name}")
    
    or_client = OpenRouter(
        base_url="https://openrouter.ai/api/v1",
        api_key=os.getenv("OPENROUTER_API_KEY"),
        include_reasoning=True,
    ) if os.getenv("OPENROUTER_API_KEY") else None
    
    anthropic_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY")) if os.getenv("ANTHROPIC_API_KEY") else None
    
    if backend_name in ["gemini", "qwq", "openai"] and model_choice.endswith("(openrouter)"):
        if not or_client:
            raise Exception(f"OpenRouter API key required for {model_choice}")
        return get_genner(backend=backend_name, or_client=or_client, stream_fn=None)
        
    elif backend_name == "claude":
        if not anthropic_client:
            raise Exception("ANTHROPIC_API_KEY required for Claude")
        return get_genner(backend=backend_name, anthropic_client=anthropic_client, stream_fn=None)
        
    elif backend_name == "openai" and model_choice == "OpenAI":
        return get_genner(backend=backend_name, stream_fn=None)
        
    elif backend_name == "mock":
        raise Exception("Mock AI not allowed - configure a real AI model")
    else:
        raise Exception(f"Unsupported model: {model_choice}")

# ========== FASTAPI REQUEST/RESPONSE MODELS ==========

class TransactionRequest(BaseModel):
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
    wallet_provider: str
    transaction_type: str = "send"
    dapp_url: Optional[str] = None
    dapp_name: Optional[str] = None
    user_language: str = "english"
    additional_data: Optional[Dict[str, Any]] = {}

class SecurityResponse(BaseModel):
    action: str  # "ALLOW", "WARN", "BLOCK"
    risk_score: float
    confidence: float
    user_explanation: str
    chain_of_thought: List[str]
    threat_categories: List[str]
    ai_generated_code: str
    technical_details: Dict[str, Any]
    analysis_time_ms: int
    quarantine_recommended: bool
    analysis_method: str = "ai_code_generation"

# ========== SECURITY SYSTEM INITIALIZATION ==========

async def initialize_security_system(fe_data: dict):
    """Initialize the complete security system"""
    global security_agent, background_monitor
    
    logger.info("🛡️ Initializing Unified AI Security System...")
    
    # 1. Setup AI Model
    selected_model = auto_select_model()
    genner = setup_ai_genner(selected_model)
    logger.info(f"✅ AI Model: {selected_model}")
    
    # 2. Setup Database
    db = SQLiteDB(db_path=os.getenv("SQLITE_PATH", "./db/security.db"))
    logger.info("✅ Database initialized")
    
    # 3. Setup RAG Client - Real RAG required, no fallbacks
    rag_service_url = os.getenv("RAG_SERVICE_URL", "http://localhost:8080")
    agent_id = f"security_agent_{fe_data['agent_name']}"
    session_id = f"security_session_{int(time.time())}"
    
    rag = RAGClient(agent_id, session_id, rag_service_url)
    logger.info("✅ RAG Client connected")
    
    # 4. Setup Security Sensor
    sensor = setup_security_sensor()
    logger.info("✅ Security Sensor initialized")
    
    # 5. Setup Container Manager
    container_manager = ContainerManager(
        docker.from_env(),
        "unified-security-executor", 
        "./code",
        {}
    )
    logger.info("✅ Container Manager ready")
    
    # 6. Setup Prompt Generator
    prompt_generator = SecurityPromptGenerator(fe_data.get("prompts", {}))
    
    # 7. Create Security Agent
    security_agent = SecurityAgent(
        agent_id=agent_id,
        sensor=sensor,
        genner=genner,
        container_manager=container_manager,
        prompt_generator=prompt_generator,
        db=db,
        rag=rag,
    )
    
    # 8. Connect Sensor to Agent
    if hasattr(sensor, 'set_security_agent'):
        sensor.set_security_agent(security_agent)
        logger.info("🔗 SecuritySensor ↔ SecurityAgent connected")
    
    # 9. Start Background Monitor (Optional)
    if BACKGROUND_MONITOR_AVAILABLE and fe_data.get("enable_background_monitor", False):
        try:
            background_monitor = await start_background_monitor(db, rag)
            logger.info("✅ Background Intelligence Monitor started")
        except Exception as e:
            logger.warning(f"⚠️ Background Monitor failed: {e}")
            background_monitor = None
    
    # 10. Start Real-Time Incoming Transaction Monitoring
    if hasattr(sensor, 'start_incoming_monitor'):
        try:
            await sensor.start_incoming_monitor()
            logger.info("✅ Real-time incoming transaction monitoring started!")
            logger.info("📥 Auto-quarantine system active for suspicious incoming tokens/NFTs")
        except Exception as e:
            logger.warning(f"⚠️ Could not start incoming monitoring: {e}")
    
    logger.info("🚀 Security System Initialization Complete!")
    return security_agent

def setup_security_sensor() -> SecuritySensorInterface:
    """Setup security sensor with flexible RPC configuration - wallets added dynamically"""
    rpc_config = FlexibleRPCConfig()
    primary_url, provider_name, all_endpoints, api_key = rpc_config.detect_and_configure_rpc()
    
    # Start with empty wallet list - wallets will be added via API calls from wallet providers
    monitored_wallets = []
    
    logger.info(f"🛡️ Security sensor ready with {provider_name}")
    logger.info("📡 Wallets will be monitored when wallet providers connect")
    
    return SecuritySensor(
        wallet_addresses=monitored_wallets,
        solana_rpc_url=primary_url,
        rpc_api_key=api_key,
        rpc_provider_name=provider_name,
    )

# ========== EVENT-DRIVEN SECURITY ANALYSIS ==========

async def analyze_transaction_event(transaction_data: dict, user_language: str = "english"):
    """Event-driven transaction analysis - only runs when needed!"""
    if not security_agent:
        raise Exception("Security system not initialized")
    
    logger.info(f"🔍 EVENT: Analyzing transaction to {transaction_data.get('to_address', 'unknown')}")
    
    try:
        # Use SecurityAgent's AI analysis
        analysis_result = await security_agent.analyze_with_ai_code_generation(
            transaction_data, user_language
        )
        
        # Log the analysis for transparency
        logger.info(f"✅ Analysis complete - Risk: {analysis_result.get('risk_score', 0):.2f}")
        
        return analysis_result
        
    except Exception as e:
        logger.error(f"❌ Analysis failed: {e}")
        # Return safe fallback
        return {
            'action': 'WARN',
            'risk_score': 0.5,
            'confidence': 0.0,
            'user_explanation': f'Analysis failed: {str(e)}',
            'chain_of_thought': [f'Analysis error: {str(e)}'],
            'threat_categories': ['analysis_error'],
            'technical_details': {'error': str(e)},
            'quarantine_recommended': True,
            'ai_generated_code': '# Analysis failed',
            'analysis_time_ms': 0
        }

# ========== FASTAPI APPLICATION WITH LIFESPAN ==========

@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan manager - initializes security system on startup"""
    # Startup
    fe_data = {
        "agent_name": os.getenv("SECURITY_AGENT_NAME", "unified_security"),
        "model": auto_select_model(),
        "enable_background_monitor": os.getenv("ENABLE_BACKGROUND_MONITOR", "false").lower() == "true",
        "prompts": {}
    }
    
    await initialize_security_system(fe_data)
    logger.info("🚀 Security API ready for wallet integration!")
    
    yield
    
    # Shutdown
    if background_monitor:
        logger.info("🛑 Stopping background monitor...")
        try:
            await background_monitor.stop_monitoring()
        except:
            pass
    logger.info("👋 Security system shutdown complete")

# Create FastAPI app with lifespan
app = FastAPI(
    title="🛡️ AI Wallet Security System",
    description="Event-driven security analysis for Web3 wallets",
    version="3.0.0",
    lifespan=lifespan
)

# ========== API ENDPOINTS ==========

@app.post("/api/v1/register-wallet")
async def register_wallet_for_monitoring(
    wallet_address: str,
    wallet_provider: str,
    user_id: Optional[str] = None
):
    """🔗 Register a wallet address for real-time monitoring"""
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="Security system not initialized")
        
        # Add wallet to monitoring list
        if wallet_address not in security_agent.sensor.wallet_addresses:
            security_agent.sensor.wallet_addresses.append(wallet_address)
            logger.info(f"📡 Registered wallet for monitoring: {wallet_address[:8]}...{wallet_address[-8:]}")
            logger.info(f"🛡️ Now monitoring {len(security_agent.sensor.wallet_addresses)} wallets")
            
            # Start monitoring this specific wallet if real-time monitoring is active
            if hasattr(security_agent.sensor, 'monitoring_active') and security_agent.sensor.monitoring_active:
                # Add monitoring task for this wallet
                import asyncio
                task = asyncio.create_task(security_agent.sensor._monitor_wallet_incoming(wallet_address))
                security_agent.sensor.monitoring_tasks.append(task)
                logger.info(f"🔄 Started real-time monitoring for new wallet")
        
        return {
            "status": "success",
            "message": f"Wallet {wallet_address[:8]}...{wallet_address[-8:]} registered for monitoring",
            "total_monitored_wallets": len(security_agent.sensor.wallet_addresses),
            "real_time_monitoring": hasattr(security_agent.sensor, 'monitoring_active') and security_agent.sensor.monitoring_active
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to register wallet: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to register wallet: {str(e)}")

@app.post("/api/v1/analyze-transaction", response_model=SecurityResponse)
async def analyze_transaction_endpoint(
    request: TransactionRequest,
    x_api_key: Optional[str] = Header(None),
    x_wallet_provider: Optional[str] = Header(None)
):
    """🔍 MAIN ENDPOINT: Real-time transaction analysis using AI"""
    start_time = datetime.now()
    
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="Security system not initialized")
        
        logger.info(f"🚀 API: Analyzing {request.transaction_type} from {request.wallet_provider}")
        
        # Prepare transaction data
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
        
        # EVENT-DRIVEN ANALYSIS (only runs when called!)
        analysis_result = await analyze_transaction_event(transaction_data, request.user_language)
        
        # Calculate timing
        analysis_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        # Extract threat categories
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
        
        # Build response
        response = SecurityResponse(
            action=analysis_result.get('action', 'ALLOW'),
            risk_score=analysis_result.get('risk_score', 0.0),
            confidence=analysis_result.get('confidence', 0.8),
            user_explanation=analysis_result.get('user_explanation', 'Transaction analyzed'),
            chain_of_thought=analysis_result.get('chain_of_thought', []),
            threat_categories=threat_categories,
            ai_generated_code=analysis_result.get('ai_generated_code', ''),
            technical_details=analysis_result.get('technical_details', {}),
            analysis_time_ms=analysis_time_ms,
            quarantine_recommended=analysis_result.get('risk_score', 0) >= 0.7,
            analysis_method="event_driven_ai_analysis"
        )
        
        logger.info(f"✅ API: {response.action} (risk: {response.risk_score:.2f}) in {analysis_time_ms}ms")
        return response
        
    except Exception as e:
        logger.error(f"❌ API Error: {e}")
        return SecurityResponse(
            action="BLOCK",
            risk_score=1.0,
            confidence=0.0,
            user_explanation=f"Security analysis unavailable: {str(e)}",
            chain_of_thought=[f"API Error: {str(e)}", "Blocking for safety"],
            threat_categories=["api_error"],
            ai_generated_code="# Analysis failed",
            technical_details={"error": str(e)},
            analysis_time_ms=0,
            quarantine_recommended=True
        )

@app.post("/api/v1/process-incoming")
async def process_incoming_transaction(
    request: TransactionRequest,
    x_api_key: Optional[str] = Header(None)
):
    """📥 Process incoming transactions for auto-quarantine decisions"""
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="Security system not initialized")
        
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
        
        action = analysis_result.get('action', 'ALLOW')
        quarantine = analysis_result.get('quarantine_recommended', False)
        
        logger.info(f"✅ Incoming analysis: {action} | Quarantine: {quarantine}")
        
        return {
            "quarantine_recommended": quarantine,
            "risk_score": analysis_result.get('risk_score', 0.0),
            "explanation": analysis_result.get('user_explanation', 'Transaction processed'),
            "action": action,
            "threat_categories": analysis_result.get('threat_categories', []),
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

@app.get("/health")
async def health_check():
    """🩺 Health check endpoint"""
    available_models = get_available_models()
    current_model = auto_select_model()
    
    return {
        "status": "healthy" if security_agent else "initializing",
        "ai_model": current_model,
        "available_models": available_models,
        "security_agent_ready": security_agent is not None,
        "background_monitor_active": background_monitor is not None,
        "timestamp": datetime.now().isoformat(),
        "version": "3.0.0",
        "architecture": "unified_event_driven"
    }

@app.get("/api/v1/system-status")
async def get_system_status():
    """📊 Detailed system status"""
    if not security_agent:
        return {"status": "initializing", "message": "Security system starting up..."}
    
    try:
        security_status = security_agent.sensor.get_security_status()
        
        system_status = {
            "security_agent": {
                "status": "active",
                "agent_id": security_agent.agent_id,
                "analysis_method": "event_driven_ai"
            },
            "security_sensor": {
                "status": "active",
                "monitored_wallets": security_status.get('monitored_wallets', 0),
                "modules_loaded": security_status.get('modules_loaded', ''),
                "rpc_provider": security_status.get('rpc_provider', 'unknown'),
                "incoming_monitoring": security_status.get('monitoring_active', False)
            },
            "background_monitor": {
                "status": "active" if background_monitor else "disabled",
                "threats_detected": security_status.get('total_threats_detected', 0)
            },
            "ai_model": {
                "current": auto_select_model(),
                "backend": get_model_backend(auto_select_model())
            },
            "performance": {
                "last_analysis": security_status.get('last_analysis', ''),
                "analysis_method": "event_driven"
            }
        }
        
        return system_status
        
    except Exception as e:
        return {"status": "error", "error": str(e)}

# ========== USER CONFIGURATION ==========

def starter_prompt():
    """Interactive configuration for unified security system"""
    
    questions = [
        inquirer.Text("agent_name", message="Security Agent Name:", default="unified_security"),
        inquirer.List(
            name="model",
            message="Which AI model do you want to use?",
            choices=get_available_models(),  # Dynamic list based on API keys
        ),
        inquirer.Confirm("enable_background_monitor", message="Enable background threat monitoring?", default=True),
        inquirer.Confirm("start_api", message="Start wallet integration API?", default=True),
    ]
    
    answers = inquirer.prompt(questions)
    
    # Set environment variables for API mode
    os.environ["SECURITY_AGENT_NAME"] = answers["agent_name"]
    os.environ["SECURITY_AI_MODEL"] = answers["model"]
    os.environ["ENABLE_BACKGROUND_MONITOR"] = str(answers["enable_background_monitor"]).lower()
    
    logger.info("🛡️ Starting Unified AI Security System...")
    logger.info(f"🤖 AI Model: {answers['model']}")
    logger.info(f"📡 Background Monitor: {'Enabled' if answers['enable_background_monitor'] else 'Disabled'}")
    
    if answers["start_api"]:
        # Start unified system with API
        api_port = int(os.getenv("SECURITY_API_PORT", "9009"))
        logger.info(f"🚀 Starting unified security system on port {api_port}")
        
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=api_port,
            log_level="info"
        )
    else:
        # Just run security monitoring without API
        logger.info("🔍 Starting security monitoring only (no API)")
        fe_data = {
            "agent_name": answers["agent_name"],
            "model": answers["model"],
            "enable_background_monitor": answers["enable_background_monitor"],
            "prompts": {}
        }
        asyncio.run(initialize_security_system(fe_data))
        logger.info("✅ Security monitoring active - press Ctrl+C to stop")
        try:
            asyncio.run(asyncio.Event().wait())  # Wait forever
        except KeyboardInterrupt:
            logger.info("👋 Security system stopped")

# ========== MAIN ENTRY POINT ==========

if __name__ == "__main__":
    starter_prompt()