"""
Wallet Provider Service Template Generator
Creates isolated, customized security services for different wallet providers
Leverages existing VaultGuard ecosystem (EdgeLearningEngine, Background Monitor, NetworkAnalyzer)
"""

import asyncio
import os
import json
import time
import docker
import uvicorn
from typing import Dict, Any, Optional, List
from pathlib import Path
from loguru import logger
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime

# Import existing VaultGuard components
from src.db import SQLiteDB
from src.client.rag import RAGClient
from src.sensor.security import SecuritySensor
from src.agent.security import SecurityAgent, SecurityPromptGenerator
from src.container import ContainerManager
from src.genner import get_genner
from src.intelligence.edge_learning_engine import create_edge_learning_engine
from src.intelligence.background_monitor import start_enhanced_background_monitor
from src.analysis.adaptive_community_database import AdaptiveCommunityDatabase
from src.rpc_config import FlexibleRPCConfig
from dotenv import load_dotenv

load_dotenv()

class WalletServiceConfig:
    """Configuration generator for wallet provider services"""
    
    def __init__(self, client_name: str, custom_config: Dict[str, Any] = None):
        self.client_name = client_name.lower()
        self.client_display_name = client_name.title()
        self.custom_config = custom_config or {}
        
        # Generate isolated paths and identifiers
        self.service_dir = Path(f"./services/{self.client_name}")
        self.database_path = f"./db/{self.client_name}_security.db"
        self.config_path = f"./services/{self.client_name}/{self.client_name}_config.json"
        self.agent_id = f"security_agent_{self.client_name}"
        self.api_port = self._get_available_port()
        
        # Ensure service directory exists
        self.service_dir.mkdir(parents=True, exist_ok=True)
        
    def _get_available_port(self) -> int:
        """Get available port for this service"""
        base_port = 8001
        client_ports = {
            'phantom': 8001,
            'solflare': 8002, 
            'backpack': 8003,
            'glow': 8004,
            'slope': 8005,
            'sollet': 8006,
            'solong': 8007,
            'exodus': 8008,
            'trust': 8009,
            'ledger': 8010
        }
        return client_ports.get(self.client_name, base_port + hash(self.client_name) % 100)
    
    def generate_service_config(self) -> Dict[str, Any]:
        """Generate complete service configuration"""
        return {
            "service_info": {
                "client_name": self.client_name,
                "display_name": self.client_display_name,
                "service_type": "wallet_provider",
                "created_at": datetime.now().isoformat(),
                "version": "1.0.0"
            },
            "agent_config": {
                "agent_id": self.agent_id,
                "agent_name": f"{self.client_name}_security_agent",
                "model": self.custom_config.get("ai_model", "gemini"),
                "role": f"Real-time {self.client_display_name} wallet security monitor",
                "network": "solana",
                "metric_name": "security"
            },
            "infrastructure": {
                "database_path": self.database_path,
                "api_port": self.api_port,
                "service_directory": str(self.service_dir),
                "log_file": f"./logs/{self.client_name}_security.log"
            },
            "api_config": {
                "host": "0.0.0.0",
                "port": self.api_port,
                "api_prefix": f"/api/v1/{self.client_name}",
                "cors_origins": self.custom_config.get("cors_origins", ["*"]),
                "rate_limiting": {
                    "enabled": True,
                    "requests_per_minute": 100
                }
            },
            "branding": {
                "service_name": f"{self.client_display_name} Security Shield",
                "response_prefix": f"{self.client_display_name} Security:",
                "custom_warnings": True,
                "brand_voice": self.custom_config.get("brand_voice", "professional"),
                "ui_theme": self.custom_config.get("ui_theme", "default")
            },
            "features": {
                "real_time_analysis": True,
                "background_monitoring": True,
                "edge_learning": True,
                "network_analysis": True,
                "community_intelligence": True,
                "custom_risk_thresholds": self.custom_config.get("risk_thresholds", {}),
                "client_specific_features": self._get_client_specific_features()
            },
            "security_settings": {
                "isolation_level": "complete",
                "data_retention_days": 90,
                "share_community_intelligence": True,
                "privacy_level": "high"
            },
            "prompts": self._generate_client_prompts()
        }
    
    def _get_client_specific_features(self) -> Dict[str, Any]:
        """Generate client-specific features based on wallet type"""
        client_features = {
            "phantom": {
                "phantom_ui_integration": True,
                "phantom_transaction_formats": True,
                "phantom_nft_protection": True,
                "popup_integration": True
            },
            "solflare": {
                "solflare_mobile_support": True,
                "solflare_staking_analysis": True,
                "solflare_portfolio_tracking": True
            },
            "backpack": {
                "backpack_messaging_integration": True,
                "backpack_social_features": True,
                "backpack_mad_lads_protection": True
            },
            "glow": {
                "glow_defi_focus": True,
                "glow_yield_farming_analysis": True
            }
        }
        return client_features.get(self.client_name, {})
    
    def _generate_client_prompts(self) -> Dict[str, str]:
        """Generate client-specific prompts"""
        brand_voice = self.custom_config.get("brand_voice", "professional")
        
        if brand_voice == "friendly":
            tone = "friendly and approachable"
            explanation_style = "simple terms with emojis"
        elif brand_voice == "technical":
            tone = "technical and detailed"
            explanation_style = "comprehensive technical analysis"
        else:
            tone = "professional but accessible"
            explanation_style = "clear explanations with context"
        
        return {
            "system": f"""You are the {self.client_display_name} Security Shield, an AI security agent protecting {self.client_display_name} wallet users.
            
Your role: Real-time Solana blockchain security monitoring specifically for {self.client_display_name} users.
Communication style: {tone}
Response format: {explanation_style}

Always include the {self.client_display_name} branding in responses and tailor security advice to {self.client_display_name} users.""",
            
            "analysis_code_prompt": f"""Generate {self.client_display_name}-optimized security analysis code. RETURN ONLY EXECUTABLE CODE.

Client: {self.client_display_name} Wallet
Branding: Include {self.client_display_name}-specific context in explanations
Communication: {tone} tone with {explanation_style}

Code must perform comprehensive security analysis with {self.client_display_name} user experience in mind.""",
            
            "user_explanation_template": f"""{self.client_display_name} Security Analysis:

{{risk_assessment}}

{{detailed_explanation}}

{{recommendations}}

- The {self.client_display_name} Security Team"""
        }
    
    def save_config(self) -> str:
        """Save configuration to file"""
        config = self.generate_service_config()
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
        logger.info(f"✅ Saved {self.client_display_name} service config to {self.config_path}")
        return self.config_path

class WalletServiceGenerator:
    """Generates isolated wallet provider services using existing VaultGuard ecosystem"""
    
    def __init__(self):
        self.active_services: Dict[str, Dict] = {}
        self.community_db = None
        
    async def create_wallet_service(self, client_name: str, custom_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create complete isolated wallet provider service"""
        logger.info(f"🏗️ Creating {client_name.title()} Security Service...")
        
        try:
            # Generate service configuration
            service_config = WalletServiceConfig(client_name, custom_config)
            config = service_config.generate_service_config()
            
            # Save configuration
            config_path = service_config.save_config()
            
            # Initialize isolated components
            components = await self._initialize_service_components(config)
            
            # Create FastAPI app for this service
            app = self._create_service_api(config, components)
            
            # Store service information
            service_info = {
                "config": config,
                "components": components,
                "app": app,
                "status": "created",
                "created_at": datetime.now().isoformat()
            }
            
            self.active_services[client_name.lower()] = service_info
            
            logger.info(f"✅ {client_name.title()} Security Service created successfully!")
            logger.info(f"📁 Config: {config_path}")
            logger.info(f"🗄️ Database: {config['infrastructure']['database_path']}")
            logger.info(f"🌐 API Port: {config['api_config']['port']}")
            
            return service_info
            
        except Exception as e:
            logger.error(f"❌ Failed to create {client_name} service: {e}")
            raise
    
    async def _initialize_service_components(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Initialize all service components using existing VaultGuard ecosystem"""
        agent_config = config["agent_config"]
        infrastructure = config["infrastructure"]
        
        logger.info("🧠 Initializing EdgeLearningEngine...")
        
        # Setup Database (isolated)
        db = SQLiteDB(db_path=infrastructure["database_path"])
        
        # Setup RAG Client (isolated session)
        rag = RAGClient(
            agent_id=agent_config["agent_id"],
            session_id=f"{agent_config['agent_name']}_session_{int(time.time())}",
            base_url=os.getenv("RAG_SERVICE_URL", "http://localhost:8080")
        )
        
        # Setup Community Database (shared)
        if not self.community_db:
            try:
                self.community_db = AdaptiveCommunityDatabase(rag)
                logger.info("✅ Community Database initialized")
            except Exception as e:
                logger.warning(f"⚠️ Community Database failed: {e}")
                self.community_db = None
        
        # Setup EdgeLearningEngine (leverages existing ecosystem)
        edge_learning_engine = None
        if self.community_db:
            try:
                edge_learning_engine = create_edge_learning_engine(rag, db, self.community_db)
                await edge_learning_engine.start()
                logger.info("🧠 EdgeLearningEngine started")
            except Exception as e:
                logger.warning(f"⚠️ EdgeLearningEngine failed: {e}")
        
        # Setup Security Sensor
        rpc_config = FlexibleRPCConfig()
        primary_url, provider_name, _, api_key = rpc_config.detect_and_configure_rpc()
        
        security_sensor = SecuritySensor(
            wallet_addresses=[],
            solana_rpc_url=primary_url,
            rpc_api_key=api_key,
            rpc_provider_name=provider_name,
            rag_client=rag
        )
        
        # Setup AI Model
        model_name = agent_config.get("model", "claude")
        
        # Define a simple stream function (not needed for service but required by get_genner)
        def stream_fn(token: str) -> None:
            pass  # No-op for service mode
        
        genner = get_genner(model_name, stream_fn)
        
        # Setup Container Manager
        container_manager = ContainerManager(
            docker.from_env(),
            f"{agent_config['agent_name']}-executor",
            infrastructure.get("code_directory", "./code"),
            {}
        )
        
        # Setup Prompt Generator with custom prompts
        prompt_generator = SecurityPromptGenerator(config.get("prompts", {}))
        
        # Create SecurityAgent
        security_agent = SecurityAgent(
            agent_id=agent_config["agent_id"],
            sensor=security_sensor,
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
        security_sensor.set_security_agent(security_agent)
        security_agent.sensor = security_sensor
        logger.info("🔗 SecuritySensor ↔ SecurityAgent connected")
        
        # Start Background Monitor (leverages existing system)
        background_monitor = None
        try:
            background_monitor = await start_enhanced_background_monitor(db, rag, edge_learning_engine)
            background_monitor.set_security_sensor(security_sensor)
            logger.info("✅ Background Intelligence Monitor started")
        except Exception as e:
            logger.warning(f"⚠️ Background Monitor failed: {e}")
        
        return {
            "security_agent": security_agent,
            "edge_learning_engine": edge_learning_engine,
            "background_monitor": background_monitor,
            "security_sensor": security_sensor,
            "database": db,
            "rag_client": rag,
            "community_db": self.community_db
        }
    
    def _create_service_api(self, config: Dict[str, Any], components: Dict[str, Any]) -> FastAPI:
        """Create FastAPI application for the service"""
        service_info = config["service_info"]
        api_config = config["api_config"]
        branding = config["branding"]
        
        app = FastAPI(
            title=branding["service_name"],
            description=f"Isolated security service for {service_info['display_name']} wallet users",
            version=service_info["version"]
        )
        
        # Add CORS middleware
        app.add_middleware(
            CORSMiddleware,
            allow_origins=api_config["cors_origins"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        security_agent = components["security_agent"]
        
        # Define API models
        class TransactionAnalysisRequest(BaseModel):
            transaction_data: Dict[str, Any]
            user_language: str = "english"
            user_id: Optional[str] = None
            
        class SecurityResponse(BaseModel):
            action: str
            risk_score: float
            confidence: float
            user_explanation: str
            threat_categories: List[str]
            service_branding: Dict[str, str]
            analysis_time_ms: int
            quarantine_recommended: bool
        
        # Health check endpoint
        @app.get(f"{api_config['api_prefix']}/health")
        async def health_check():
            return {
                "status": "healthy",
                "service": branding["service_name"],
                "client": service_info["display_name"],
                "version": service_info["version"],
                "features": {
                    "edge_learning_active": components["edge_learning_engine"] is not None,
                    "background_monitor_active": components["background_monitor"] is not None,
                    "community_intelligence": components["community_db"] is not None
                },
                "timestamp": datetime.now().isoformat()
            }
        
        # Main analysis endpoint
        @app.post(f"{api_config['api_prefix']}/analyze", response_model=SecurityResponse)
        async def analyze_transaction(request: TransactionAnalysisRequest):
            try:
                start_time = time.time()
                
                # Add service context to transaction data
                enhanced_transaction_data = {
                    **request.transaction_data,
                    "service_context": {
                        "client_name": service_info["client_name"],
                        "service_name": branding["service_name"],
                        "analysis_timestamp": datetime.now().isoformat()
                    }
                }
                
                # Perform analysis using existing VaultGuard ecosystem
                analysis_result = await security_agent.analyze_with_ai_code_generation(
                    enhanced_transaction_data, 
                    request.user_language
                )
                
                analysis_time_ms = int((time.time() - start_time) * 1000)
                
                # Add service branding to response
                branded_explanation = f"{branding['response_prefix']} {analysis_result.get('user_explanation', '')}"
                
                return SecurityResponse(
                    action=analysis_result.get('action', 'ALLOW'),
                    risk_score=analysis_result.get('risk_score', 0.0),
                    confidence=analysis_result.get('confidence', 0.8),
                    user_explanation=branded_explanation,
                    threat_categories=analysis_result.get('threat_categories', []),
                    service_branding={
                        "service_name": branding["service_name"],
                        "client_name": service_info["display_name"],
                        "brand_voice": branding["brand_voice"]
                    },
                    analysis_time_ms=analysis_time_ms,
                    quarantine_recommended=analysis_result.get('quarantine_recommended', False)
                )
                
            except Exception as e:
                logger.error(f"❌ {service_info['display_name']} analysis failed: {e}")
                raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
        
        # Service-specific endpoints
        @app.get(f"{api_config['api_prefix']}/service-info")
        async def get_service_info():
            return {
                "service": config["service_info"],
                "features": config["features"],
                "branding": config["branding"],
                "status": "active"
            }
        
        # Intelligence status endpoint
        @app.get(f"{api_config['api_prefix']}/intelligence-status")
        async def get_intelligence_status():
            if components["edge_learning_engine"]:
                engine_status = components["edge_learning_engine"].get_engine_status()
                return {
                    "edge_learning_available": True,
                    "engine_status": engine_status,
                    "service_name": branding["service_name"]
                }
            else:
                return {
                    "edge_learning_available": False,
                    "service_name": branding["service_name"],
                    "fallback_mode": True
                }
        
        return app
    
    async def start_service(self, client_name: str) -> None:
        """Start the service API"""
        client_key = client_name.lower()
        if client_key not in self.active_services:
            raise ValueError(f"Service for {client_name} not found. Create it first.")
        
        service_info = self.active_services[client_key]
        config = service_info["config"]
        app = service_info["app"]
        
        api_port = config["api_config"]["port"]
        
        logger.info(f"🚀 Starting {config['branding']['service_name']}...")
        logger.info(f"🌐 API: http://localhost:{api_port}{config['api_config']['api_prefix']}/health")
        
        # Update service status
        self.active_services[client_key]["status"] = "running"
        self.active_services[client_key]["started_at"] = datetime.now().isoformat()
        
        uvicorn.run(
            app,
            host=config["api_config"]["host"],
            port=api_port,
            log_level="info"
        )
    
    def list_services(self) -> Dict[str, Any]:
        """List all created services"""
        return {
            "total_services": len(self.active_services),
            "services": {
                name: {
                    "display_name": info["config"]["service_info"]["display_name"],
                    "api_port": info["config"]["api_config"]["port"],
                    "status": info["status"],
                    "created_at": info["created_at"]
                }
                for name, info in self.active_services.items()
            }
        }


# CLI Interface
async def main():
    """Main CLI interface for wallet service generation"""
    import argparse
    
    parser = argparse.ArgumentParser(description="VaultGuard Wallet Service Generator")
    parser.add_argument("--create", type=str, help="Create service for wallet (e.g., phantom)")
    parser.add_argument("--start", type=str, help="Start service for wallet")
    parser.add_argument("--list", action="store_true", help="List all services")
    parser.add_argument("--config", type=str, help="Custom config file path")
    
    args = parser.parse_args()
    
    generator = WalletServiceGenerator()
    
    if args.create:
        custom_config = {}
        if args.config and os.path.exists(args.config):
            with open(args.config, 'r') as f:
                custom_config = json.load(f)
        
        service_info = await generator.create_wallet_service(args.create, custom_config)
        print(f"✅ {args.create.title()} Security Service created!")
        print(f"   API Port: {service_info['config']['api_config']['port']}")
        print(f"   Database: {service_info['config']['infrastructure']['database_path']}")
        print(f"   Start with: python wallet_service_template.py --start {args.create}")
    
    elif args.start:
        await generator.start_service(args.start)
    
    elif args.list:
        services = generator.list_services()
        print(f"📋 Active Services ({services['total_services']}):")
        for name, info in services["services"].items():
            print(f"   {info['display_name']}: Port {info['api_port']} ({info['status']})")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    asyncio.run(main())