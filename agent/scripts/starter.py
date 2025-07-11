import asyncio
import os
import json
import inquirer
import time
import uvicorn
from contextlib import asynccontextmanager
from typing import Callable, Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from datetime import datetime
from loguru import logger

# Core imports
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
from src.constants import SERVICE_TO_ENV
from src.manager import fetch_default_prompt
from dotenv import load_dotenv

# EdgeLearningEngine and Background monitoring
try:
    from src.intelligence.edge_learning_engine import EdgeLearningEngine, create_edge_learning_engine
    EDGE_LEARNING_AVAILABLE = True
except ImportError:
    EDGE_LEARNING_AVAILABLE = False
    logger.warning("⚠️ EdgeLearningEngine not available")

try:
    from src.intelligence.background_monitor import EnhancedBackgroundIntelligenceMonitor, start_enhanced_background_monitor
    BACKGROUND_MONITOR_AVAILABLE = True
except ImportError:
    BACKGROUND_MONITOR_AVAILABLE = False
    logger.warning("⚠️ Background monitor not available")

try:
    from src.analysis.adaptive_community_database import AdaptiveCommunityDatabase
    COMMUNITY_DB_AVAILABLE = True
except ImportError:
    COMMUNITY_DB_AVAILABLE = False
    logger.warning("⚠️ AdaptiveCommunityDatabase not available")

# Load environment variables
load_dotenv()

# ========== GLOBAL SYSTEM STATE ==========
security_agent: Optional[SecurityAgent] = None
edge_learning_engine: Optional[EdgeLearningEngine] = None
background_monitor: Optional[EnhancedBackgroundIntelligenceMonitor] = None

# ========== MODEL SELECTION SYSTEM ==========
def get_available_models():
    """Get available AI models based on configured API keys"""
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
    
    if os.getenv("GOOGLE_API_KEY"):
        available.append("Gemini (direct)")
    
    if not available:
        raise Exception("No AI API keys configured!")
    
    return available

def get_model_backend(model_choice: str) -> str:
    """Convert user-friendly model name to backend name"""
    model_naming = {
        "OpenAI": "openai",
        "OpenAI (openrouter)": "openai",
        "Gemini (openrouter)": "gemini",
        "QWQ (openrouter)": "qwq",
        "Claude": "claude",
        "Gemini (direct)": "gemini_direct", 
    }
    backend = model_naming.get(model_choice)
    if not backend:
        raise Exception(f"Unsupported model choice: {model_choice}")
    return backend

def auto_select_model():
    """Auto-select best available AI model"""
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
    
    elif backend_name == "gemini_direct":
        google_api_key = os.getenv("GOOGLE_API_KEY")
        if not google_api_key:
            raise Exception("GOOGLE_API_KEY required for direct Gemini access")
        return get_genner(backend="gemini_direct", stream_fn=None)
        
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

class UserFeedbackRequest(BaseModel):
    transaction_data: Dict[str, Any]
    user_decision: str  # "approved" or "quarantined"
    user_reasoning: Optional[str] = ""
    confidence: Optional[float] = 0.8
    user_id: str
    wallet_provider: str

class WalletRegistrationRequest(BaseModel):
    wallet_address: str
    wallet_provider: str
    user_id: Optional[str] = None

class WalletAnalysisRequest(BaseModel):
    wallet_address: str
    analysis_type: str = "security"
    user_id: str
    wallet_provider: str

class WalletTrackingRequest(BaseModel):
    wallet_address: str
    tracking_reason: str
    user_id: str
    wallet_provider: str

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

# ========== CONFIGURATION LOADING ==========
def load_config():
    """Load configuration from security.json"""
    import os
    
    # Try multiple possible paths
    possible_paths = [
        "starter/security.json",           # When running from agent/ directory
        "agent/starter/security.json",     # When running from root directory
        "./starter/security.json",         # Alternative relative path
    ]
    
    for path in possible_paths:
        try:
            if os.path.exists(path):
                with open(path, "r") as f:
                    logger.info(f"✅ Loaded config from: {path}")
                    return json.load(f)
        except Exception as e:
            continue
    
    logger.warning(f"⚠️ Failed to load security.json from any location")
    return {}

# ========== ENHANCED SECURITY SYSTEM INITIALIZATION ==========
async def initialize_enhanced_security_system(fe_data: dict):
    """Initialize the complete security system with EdgeLearningEngine"""
    global security_agent, edge_learning_engine, background_monitor
    
    logger.info("🛡️ Initializing Enhanced AI Security System with Edge Learning...")
    
    # Merge config from security.json
    config = load_config()
    fe_data = {**config, **fe_data}
    
    # Setup AI Model
    selected_model = auto_select_model()
    genner = setup_ai_genner(selected_model)
    logger.info(f"✅ AI Model: {selected_model}")
    
    # Setup Database
    db = SQLiteDB(db_path=os.getenv("SQLITE_PATH", "./db/security.db"))
    logger.info("✅ Database initialized")
    
    # Setup RAG Client
    rag_service_url = os.getenv("RAG_SERVICE_URL", "http://localhost:8080")
    agent_id = f"security_agent_{fe_data['agent_name']}"
    session_id = f"security_session_{int(time.time())}"
    
    rag = RAGClient(agent_id, session_id, rag_service_url)
    logger.info("✅ RAG Client connected")
    
    # Setup Community Database
    community_db = None
    if COMMUNITY_DB_AVAILABLE:
        try:
            community_db = AdaptiveCommunityDatabase(rag)
            logger.info("✅ Community Database initialized")
        except Exception as e:
            logger.warning(f"⚠️ Community Database failed: {e}")
    
    # Setup EdgeLearningEngine
    if EDGE_LEARNING_AVAILABLE and community_db:
        try:
            edge_learning_engine = create_edge_learning_engine(rag, db, community_db)
            
            # Configure external APIs
            if fe_data.get("jupiter_integration", {}).get("enabled", False):
                edge_learning_engine.configure_jupiter_integration({
                    'enabled': True,
                    'api_url': fe_data["jupiter_integration"].get("api_url", "https://quote-api.jup.ag/v6"),
                    'api_key': os.getenv("JUPITER_API_KEY", ""),
                    'rate_limit': fe_data["jupiter_integration"].get("rate_limit", 30),
                    'timeout': fe_data["jupiter_integration"].get("timeout", 10)
                })
                logger.info("🪐 Jupiter integration configured")
            
            await edge_learning_engine.start()
            logger.info("🧠 EdgeLearningEngine started - instant cached intelligence ready!")
            
        except Exception as e:
            logger.error(f"❌ EdgeLearningEngine failed: {e}")
            edge_learning_engine = None
    else:
        logger.warning("⚠️ EdgeLearningEngine not available - using fallback cache")
    
    # Setup Security Sensor
    sensor = setup_security_sensor()
    logger.info("✅ Security Sensor initialized")
    
    # Setup Container Manager
    container_manager = ContainerManager(
        docker.from_env(),
        "unified-security-executor", 
        "./code",
        {}
    )
    logger.info("✅ Container Manager ready")
    
    # Setup Prompt Generator
    prompt_generator = SecurityPromptGenerator(fe_data.get("prompts", {}))
    
    # Create Security Agent
    security_agent = SecurityAgent(
        agent_id=agent_id,
        sensor=sensor,
        genner=genner,
        container_manager=container_manager,
        prompt_generator=prompt_generator,
        db=db,
        rag=rag,
        edge_learning_engine=edge_learning_engine
    )
    
    # Connect EdgeLearningEngine to SecurityAgent
    if edge_learning_engine:
        await edge_learning_engine.integrate_with_security_agent(security_agent)
        logger.info("🔗 SecurityAgent ↔ EdgeLearningEngine connected")
    
    # Connect Sensor to Agent
    if hasattr(sensor, 'set_security_agent'):
        sensor.set_security_agent(security_agent)
        logger.info("🔗 SecuritySensor ↔ SecurityAgent connected")
    
    security_agent.sensor = sensor
    logger.info("🔗 SecuritySensor connected to SecurityAgent for module access")

    # Start Background Monitor
    if BACKGROUND_MONITOR_AVAILABLE and fe_data.get("enable_background_monitor", False):
        try:
            background_monitor = await start_enhanced_background_monitor(db, rag, edge_learning_engine)
            logger.info("✅ Background Intelligence Monitor started")
        except Exception as e:
            logger.warning(f"⚠️ Background Monitor failed: {e}")
            background_monitor = None
    
    # Start Real-Time Incoming Transaction Monitoring
    if hasattr(sensor, 'start_incoming_monitor'):
        try:
            await sensor.start_incoming_monitor()
            logger.info("✅ Real-time incoming transaction monitoring started!")
            logger.info("📥 Auto-quarantine system active for suspicious incoming tokens/NFTs")
        except Exception as e:
            logger.warning(f"⚠️ Could not start incoming monitoring: {e}")
    
    logger.info("🚀 Enhanced Security System Initialization Complete!")
    logger.info("⚡ Transactions now use instant cached intelligence!")
    return security_agent

def setup_security_sensor() -> SecuritySensorInterface:
    """Setup security sensor with flexible RPC configuration"""
    rpc_config = FlexibleRPCConfig()
    primary_url, provider_name, all_endpoints, api_key = rpc_config.detect_and_configure_rpc()
    
    monitored_wallets = []
    
    logger.info(f"🛡️ Security sensor ready with {provider_name}")
    logger.info("📡 Wallets will be monitored when wallet providers connect")
    
    return SecuritySensor(
        wallet_addresses=monitored_wallets,
        solana_rpc_url=primary_url,
        rpc_api_key=api_key,
        rpc_provider_name=provider_name,
        rag_client=RAGClient(
            agent_id=f"security_sensor_{int(time.time())}",
            session_id=f"sensor_session_{int(time.time())}",
            base_url=os.getenv("RAG_SERVICE_URL", "http://localhost:8080")
        )
    )

# ========== ENHANCED EVENT-DRIVEN SECURITY ANALYSIS ==========
async def analyze_transaction_event(transaction_data: dict, user_language: str = "english"):
    """Enhanced event-driven transaction analysis using cached intelligence"""
    if not security_agent:
        raise Exception("Security system not initialized")
    
    logger.info(f"⚡ EVENT: Fast analysis using cached intelligence - {transaction_data.get('to_address', 'unknown')[:8]}")
    
    try:
        analysis_result = await security_agent.analyze_with_ai_code_generation(
            transaction_data, user_language
        )
        
        cache_used = analysis_result.get('cached_intelligence', {}).get('cache_available', False)
        logger.info(f"✅ Analysis complete - Risk: {analysis_result.get('risk_score', 0):.2f} | Cache: {'HIT' if cache_used else 'MISS'}")
        
        return analysis_result
        
    except Exception as e:
        logger.error(f"❌ Analysis failed: {e}")
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

# ========== FASTAPI APPLICATION WITH ENHANCED LIFESPAN ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Enhanced FastAPI lifespan manager with EdgeLearningEngine"""
    fe_data = {
        "agent_name": os.getenv("SECURITY_AGENT_NAME", "enhanced_security"),
        "model": auto_select_model(),
        "enable_background_monitor": os.getenv("ENABLE_BACKGROUND_MONITOR", "false").lower() == "true",
        "enable_edge_learning": os.getenv("ENABLE_EDGE_LEARNING", "true").lower() == "true",
        "prompts": {}
    }
    
    await initialize_enhanced_security_system(fe_data)
    logger.info("🚀 Enhanced Security API ready for wallet integration!")
    logger.info("⚡ Instant transaction analysis with cached intelligence!")
    
    yield
    
    if edge_learning_engine:
        logger.info("🧠 Stopping EdgeLearningEngine...")
        try:
            await edge_learning_engine.stop()
            logger.info("✅ EdgeLearningEngine stopped")
        except Exception as e:
            logger.warning(f"⚠️ EdgeLearningEngine shutdown error: {e}")
    
    if background_monitor:
        logger.info("🛑 Stopping background monitor...")
        try:
            await background_monitor.stop_monitoring()
        except Exception as e:
            logger.warning(f"⚠️ Background monitor shutdown error: {e}")
    
    logger.info("👋 Enhanced security system shutdown complete")

app = FastAPI(
    title="🛡️ AI Wallet Security System with Edge Learning",
    description="Event-driven security analysis with instant cached intelligence",
    version="4.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== ENHANCED API ENDPOINTS (NO AUTHENTICATION) ==========
@app.post("/api/v1/analyze-transaction", response_model=SecurityResponse)
async def analyze_transaction_endpoint(request: TransactionRequest):
    """Instant transaction analysis using cached intelligence"""
    start_time = datetime.now()
    
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="Security system not initialized")
        
        logger.info(f"⚡ API: Instant analysis for {request.transaction_type} from {request.wallet_provider}")
        
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
        
        analysis_result = await analyze_transaction_event(transaction_data, request.user_language)
        
        analysis_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
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
            analysis_method="instant_cached_intelligence"
        )
        
        cache_used = analysis_result.get('cached_intelligence', {}).get('cache_available', False)
        logger.info(f"✅ API: {response.action} (risk: {response.risk_score:.2f}) in {analysis_time_ms}ms | Cache: {'HIT' if cache_used else 'MISS'}")
        
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

@app.post("/api/v1/user-feedback")
async def submit_user_feedback(request: UserFeedbackRequest):
    """Submit user feedback for background learning"""
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="Security system not initialized")
        
        logger.info(f"📚 User feedback: {request.user_decision} for transaction")
        
        security_agent.learn_from_user_decision(
            target_data=request.transaction_data,
            user_decision=request.user_decision,
            user_reasoning=request.user_reasoning,
            confidence=request.confidence
        )
        
        return {
            "status": "success",
            "message": f"User feedback '{request.user_decision}' submitted for background learning",
            "learning_queued": True,
            "cache_updated": True,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ User feedback failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit feedback: {str(e)}")

@app.get("/api/v1/intelligence-status")
async def get_intelligence_status():
    """Get EdgeLearningEngine status and metrics"""
    try:
        if not security_agent or not edge_learning_engine:
            return {
                "edge_learning_available": False,
                "fallback_mode": True,
                "message": "EdgeLearningEngine not available"
            }
        
        engine_status = edge_learning_engine.get_engine_status()
        
        return {
            "edge_learning_available": True,
            "engine_status": engine_status,
            "cache_performance": {
                "cache_hits": engine_status.get('metrics', {}).get('cache_hits', 0),
                "cache_misses": engine_status.get('metrics', {}).get('cache_misses', 0),
                "hit_rate": engine_status.get('cache_stats', {}).get('cache_hit_rate', 0.0)
            },
            "background_learning": {
                "queue_size": engine_status.get('queue_size', 0),
                "tasks_processed": engine_status.get('metrics', {}).get('tasks_processed', 0)
            },
            "external_integrations": engine_status.get('external_integrations', {}),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ Intelligence status error: {e}")
        return {"error": str(e), "edge_learning_available": False}

@app.post("/api/v1/force-refresh")
async def force_intelligence_refresh(target_data: Dict[str, Any]):
    """Force intelligence refresh for debugging"""
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="Security system not initialized")
        
        result = await edge_learning_engine.force_intelligence_refresh(target_data)
        
        return {
            "status": "success",
            "refresh_result": result,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ Force refresh failed: {e}")
        raise HTTPException(status_code=500, detail=f"Force refresh failed: {str(e)}")

@app.post("/api/v1/register-wallet")
async def register_wallet_for_monitoring(request: WalletRegistrationRequest):
    """Register a wallet address for real-time monitoring"""
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="Security system not initialized")
        
        if request.wallet_address not in security_agent.sensor.wallet_addresses:
            security_agent.sensor.wallet_addresses.append(request.wallet_address)
            logger.info(f"📡 Registered wallet for monitoring: {request.wallet_address[:8]}...{request.wallet_address[-8:]}")
            logger.info(f"🛡️ Now monitoring {len(security_agent.sensor.wallet_addresses)} wallets")
            
            if hasattr(security_agent.sensor, 'monitoring_active') and security_agent.sensor.monitoring_active:
                task = asyncio.create_task(security_agent.sensor._monitor_wallet_incoming(request.wallet_address))
                security_agent.sensor.monitoring_tasks.append(task)
                logger.info(f"🔄 Started real-time monitoring for new wallet")
        
        return {
            "status": "success",
            "message": f"Wallet {request.wallet_address[:8]}...{request.wallet_address[-8:]} registered for monitoring",
            "total_monitored_wallets": len(security_agent.sensor.wallet_addresses),
            "real_time_monitoring": hasattr(security_agent.sensor, 'monitoring_active') and security_agent.sensor.monitoring_active,
            "edge_learning_active": edge_learning_engine is not None
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to register wallet: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to register wallet: {str(e)}")

@app.post("/api/v1/analyze-wallet")
async def analyze_wallet_endpoint(request: WalletAnalysisRequest):
    """Analyze any Solana wallet for security threats with cached intelligence"""
    start_time = datetime.now()
    
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="Security system not initialized")
        
        logger.info(f"⚡ Fast wallet analysis: {request.wallet_address[:8]}...{request.wallet_address[-8:]}")
        
        analysis_data = {
            "wallet_address": request.wallet_address,
            "analysis_type": request.analysis_type,
            "user_id": request.user_id,
            "wallet_provider": request.wallet_provider,
            "timestamp": start_time.isoformat()
        }
        
        analysis_result = await security_agent.analyze_with_ai_code_generation(
            analysis_data, "english"
        )
        
        analysis_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        response = {
            "wallet_address": request.wallet_address,
            "analysis_type": request.analysis_type,
            "risk_score": analysis_result.get('risk_score', 0.0),
            "confidence": analysis_result.get('confidence', 0.8),
            "explanation": analysis_result.get('user_explanation', 'Wallet analysis completed'),
            "threat_categories": analysis_result.get('threat_categories', []),
            "chain_of_thought": analysis_result.get('chain_of_thought', []),
            "technical_details": analysis_result.get('technical_details', {}),
            "analysis_time_ms": analysis_time_ms,
            "cache_used": analysis_result.get('cached_intelligence', {}).get('cache_available', False),
            "status": "completed"
        }
        
        logger.info(f"✅ Wallet analysis complete - Risk: {response['risk_score']:.2f} in {analysis_time_ms}ms")
        return response
        
    except Exception as e:
        logger.error(f"❌ Wallet analysis failed: {e}")
        return {
            "wallet_address": request.wallet_address,
            "analysis_type": request.analysis_type,
            "risk_score": 0.5,
            "confidence": 0.0,
            "explanation": f"Analysis failed: {str(e)}",
            "threat_categories": ["analysis_error"],
            "error": str(e),
            "status": "failed"
        }

@app.post("/api/v1/track-wallet")
async def track_wallet_endpoint(request: WalletTrackingRequest):
    """Add wallet to tracking/monitoring list"""
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="Security system not initialized")
        
        logger.info(f"📡 Adding wallet to tracking: {request.wallet_address[:8]}...{request.wallet_address[-8:]}")
        logger.info(f"🏷️ Reason: {request.tracking_reason}")
        
        if request.wallet_address not in security_agent.sensor.wallet_addresses:
            security_agent.sensor.wallet_addresses.append(request.wallet_address)
            logger.info(f"📡 Added to monitoring list")
        
        tracking_data = {
            "wallet_address": request.wallet_address,
            "tracking_reason": request.tracking_reason,
            "user_id": request.user_id,
            "wallet_provider": request.wallet_provider,
            "added_timestamp": datetime.now().isoformat(),
            "status": "active"
        }
        
        response = {
            "status": "success",
            "message": f"Wallet {request.wallet_address[:8]}...{request.wallet_address[-8:]} added to tracking",
            "tracking_reason": request.tracking_reason,
            "total_tracked_wallets": len(security_agent.sensor.wallet_addresses),
            "tracking_data": tracking_data,
            "edge_learning_active": edge_learning_engine is not None
        }
        
        logger.info(f"✅ Wallet tracking enabled")
        return response
        
    except Exception as e:
        logger.error(f"❌ Wallet tracking failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to track wallet: {str(e)}")

@app.post("/api/v1/process-incoming")
async def process_incoming_transaction(request: TransactionRequest):
    """Process incoming transactions for auto-quarantine decisions with cached intelligence"""
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="Security system not initialized")
        
        logger.info(f"📥 Processing incoming transaction for {request.user_id}")
        
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
            "analysis_details": analysis_result,
            "cache_used": analysis_result.get('cached_intelligence', {}).get('cache_available', False)
        }
        
    except Exception as e:
        logger.error(f"❌ Incoming transaction processing failed: {e}")
        return {
            "quarantine_recommended": True,
            "risk_score": 0.8,
            "explanation": f"Processing error - quarantined for safety: {str(e)}",
            "action": "QUARANTINE",
            "error": str(e)
        }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    available_models = get_available_models()
    current_model = auto_select_model()
    
    return {
        "status": "healthy" if security_agent else "initializing",
        "ai_model": current_model,
        "available_models": available_models,
        "security_agent_ready": security_agent is not None,
        "edge_learning_engine_active": edge_learning_engine is not None,
        "background_monitor_active": background_monitor is not None,
        "features": {
            "instant_cached_intelligence": EDGE_LEARNING_AVAILABLE,
            "background_learning": EDGE_LEARNING_AVAILABLE,
            "community_database": COMMUNITY_DB_AVAILABLE,
            "external_api_integration": EDGE_LEARNING_AVAILABLE
        },
        "timestamp": datetime.now().isoformat(),
        "version": "4.0.0",
        "architecture": "enhanced_edge_agent"
    }

@app.get("/api/v1/system-status")
async def get_system_status():
    """Enhanced system status with EdgeLearningEngine metrics"""
    if not security_agent:
        return {"status": "initializing", "message": "Security system starting up..."}
    
    try:
        security_status = security_agent.sensor.get_security_status()
        
        edge_status = {}
        if edge_learning_engine:
            engine_status = edge_learning_engine.get_engine_status()
            edge_status = {
                "status": "active",
                "cache_entries": engine_status.get('cache_stats', {}).get('total_entries', 0),
                "cache_hit_rate": engine_status.get('cache_stats', {}).get('cache_hit_rate', 0.0),
                "queue_size": engine_status.get('queue_size', 0),
                "tasks_processed": engine_status.get('metrics', {}).get('tasks_processed', 0),
                "external_integrations": engine_status.get('external_integrations', {})
            }
        else:
            edge_status = {"status": "disabled", "fallback_mode": True}
        
        system_status = {
            "security_agent": {
                "status": "active",
                "agent_id": security_agent.agent_id,
                "analysis_method": "instant_cached_intelligence"
            },
            "edge_learning_engine": edge_status,
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
                "analysis_method": "instant_cached_intelligence",
                "cache_enabled": edge_learning_engine is not None
            }
        }
        
        return system_status
        
    except Exception as e:
        return {"status": "error", "error": str(e)}

# ========== LEGACY ENDPOINTS FOR BACKWARD COMPATIBILITY ==========
@app.post("/security/analyze")
async def legacy_analyze_endpoint(request: Dict[str, Any]):
    """Legacy endpoint for backward compatibility (no auth required)"""
    try:
        if not security_agent:
            raise HTTPException(status_code=503, detail="Security system not initialized")
        
        logger.info(f"⚡ Legacy analysis for {request.get('transaction_type', 'unknown')}")
        
        analysis_result = await security_agent.analyze_with_ai_code_generation(
            request, request.get('user_language', 'english')
        )
        
        return {
            "action": analysis_result.get('action', 'ALLOW'),
            "risk_score": analysis_result.get('risk_score', 0.0),
            "confidence": analysis_result.get('confidence', 0.8),
            "user_explanation": analysis_result.get('user_explanation', ''),
            "threat_categories": analysis_result.get('threat_categories', []),
            "chain_of_thought": analysis_result.get('chain_of_thought', []),
            "analysis_time_ms": analysis_result.get('analysis_time_ms', 0)
        }
        
    except Exception as e:
        logger.error(f"❌ Legacy analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/security/status")
async def legacy_security_status():
    """Legacy security status endpoint (no auth required)"""
    try:
        if not security_agent:
            return {"status": "not_initialized"}
        
        return {
            "status": "operational",
            "security_agent": "active",
            "edge_learning_engine": edge_learning_engine is not None,
            "background_monitor": background_monitor is not None,
            "monitored_wallets": len(security_agent.sensor.wallet_addresses) if security_agent.sensor else 0
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}

@app.get("/security/engine/status")
async def legacy_engine_status():
    """Legacy EdgeLearningEngine status endpoint (no auth required)"""
    try:
        if not edge_learning_engine:
            return {"engine_available": False}
        
        return edge_learning_engine.get_engine_status()
        
    except Exception as e:
        return {"engine_available": False, "error": str(e)}

# ========== ENHANCED USER CONFIGURATION ==========
def starter_prompt():
    """Enhanced interactive configuration for security system"""
    questions = [
        inquirer.Text("agent_name", message="Security Agent Name:", default="VaultGuard"),
        inquirer.List(
            name="model",
            message="Which AI model do you want to use?",
            choices=get_available_models(),
        ),
        inquirer.Confirm("enable_background_monitor", message="Enable background threat monitoring?", default=True),
        inquirer.Confirm("enable_edge_learning", message="Enable EdgeLearningEngine for instant analysis?", default=True),
        inquirer.Confirm("enable_jupiter_integration", message="Enable Jupiter API integration?", default=True),
        inquirer.Confirm("start_api", message="Start wallet integration API?", default=True),
    ]
    
    answers = inquirer.prompt(questions)
    
    os.environ["SECURITY_AGENT_NAME"] = answers["agent_name"]
    os.environ["SECURITY_AI_MODEL"] = answers["model"]
    os.environ["ENABLE_BACKGROUND_MONITOR"] = str(answers["enable_background_monitor"]).lower()
    os.environ["ENABLE_EDGE_LEARNING"] = str(answers["enable_edge_learning"]).lower()
    os.environ["JUPITER_API_ENABLED"] = str(answers["enable_jupiter_integration"]).lower()
    
    logger.info("🛡️ Starting Enhanced AI Security System...")
    logger.info(f"🤖 AI Model: {answers['model']}")
    logger.info(f"🧠 EdgeLearningEngine: {'Enabled' if answers['enable_edge_learning'] else 'Disabled'}")
    logger.info(f"📡 Background Monitor: {'Enabled' if answers['enable_background_monitor'] else 'Disabled'}")
    logger.info(f"🪐 Jupiter Integration: {'Enabled' if answers['enable_jupiter_integration'] else 'Disabled'}")
    
    if answers["start_api"]:
        api_port = int(os.getenv("SECURITY_API_PORT", "8001"))
        logger.info(f"🚀 Starting enhanced security system on port {api_port}")
        logger.info("⚡ Instant transaction analysis with cached intelligence!")
        
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=api_port,
            log_level="info"
        )
    else:
        logger.info("🔍 Starting enhanced security monitoring only (no API)")
        fe_data = {
            "agent_name": answers["agent_name"],
            "model": answers["model"],
            "enable_background_monitor": answers["enable_background_monitor"],
            "enable_edge_learning": answers["enable_edge_learning"],
            "prompts": {}
        }
        asyncio.run(initialize_enhanced_security_system(fe_data))
        logger.info("✅ Enhanced security monitoring active - press Ctrl+C to stop")
        logger.info("⚡ Using instant cached intelligence for analysis!")
        try:
            asyncio.run(asyncio.Event().wait())
        except KeyboardInterrupt:
            logger.info("👋 Enhanced security system stopped")

# ========== BACKWARD COMPATIBILITY ==========
async def initialize_security_system(fe_data: dict):
    """Redirect to enhanced system"""
    logger.info("🔄 Redirecting to enhanced security system...")
    return await initialize_enhanced_security_system(fe_data)

# ========== MAIN ENTRY POINT ==========
if __name__ == "__main__":
    starter_prompt()