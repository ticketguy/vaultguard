"""
Updated Starter Script with Background Intelligence Monitor
Integrates 24/7 threat monitoring with existing SecurityAgent system
"""

import asyncio
import os
import requests
import inquirer
import time

from src.db import SQLiteDB
from src.client.rag import RAGClient
from tests.mock_client.rag import MockRAGClient
from tests.mock_client.interface import RAGInterface
from tests.mock_sensor.security import MockSecuritySensor
from src.sensor.security import SecuritySensor
from src.sensor.interface import SecuritySensorInterface
from src.db import DBInterface
from typing import Callable
from src.agent.security import SecurityAgent, SecurityPromptGenerator
from src.datatypes import StrategyData
from src.container import ContainerManager
from src.helper import (
	services_to_envs,
	services_to_prompts,
)
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

# NEW: Import Background Monitor
from src.intelligence.background_monitor import BackgroundIntelligenceMonitor, start_background_monitor

load_dotenv()

# Security agent default configuration
FE_DATA_SECURITY_DEFAULTS = {
	"agent_name": "default_security_name",
	"type": "security",
	"model": "claude",
	"mode": "default",
	"role": "security analyst protecting Web3 wallets",
	"network": "solana",
	"time": "24h",
	"research_tools": ["Solana RPC", "Threat Intelligence"],
	"security_tools": ["quarantine", "block", "monitor", "analyze"],
	"metric_name": "security",
	"notifications": ["blockchain_alerts"],
}


async def start_security_agent_with_background_monitor(
	agent_type: str,
	session_id: str,
	agent_id: str,
	fe_data: dict,
	genner: Genner,
	rag: RAGInterface,
	sensor: SecuritySensorInterface,
	db: DBInterface,
	meta_swap_api_url: str,
	stream_fn: Callable[[str], None] = lambda x: print(x, flush=True, end=""),
):
	"""Start security agent with AI code generation AND 24/7 background monitoring"""
	role = fe_data["role"]
	network = fe_data["network"]
	services_used = fe_data["research_tools"]
	security_tools = fe_data["security_tools"]
	metric_name = fe_data["metric_name"]
	notif_sources = fe_data["notifications"]
	time_ = fe_data["time"]

	in_con_env = services_to_envs(services_used)
	apis = services_to_prompts(services_used)
	if fe_data["model"] == "deepseek":
		fe_data["model"] = "deepseek_or"

	prompt_generator = SecurityPromptGenerator(prompts=fe_data["prompts"])

	container_manager = ContainerManager(
		docker.from_env(),
		"agent-executor",
		"./code",
		in_con_env=in_con_env,
	)

	summarizer = get_summarizer(genner)
	previous_strategies = db.fetch_all_strategies(agent_id)

	rag.save_result_batch_v4(previous_strategies)

	# Create SecurityAgent with AI code generation
	agent = SecurityAgent(
		agent_id=agent_id,
		sensor=sensor,
		genner=genner,
		container_manager=container_manager,
		prompt_generator=prompt_generator,
		db=db,
		rag=rag,
	)

	# Connect SecuritySensor to SecurityAgent for real-time quarantine decisions
	if hasattr(sensor, 'set_security_agent'):
		sensor.set_security_agent(agent)
		logger.info("🔗 Connected SecuritySensor to SecurityAgent for AI analysis")
	
	# 🚀 NEW: Start Background Intelligence Monitor
	logger.info("🔍 Starting 24/7 Background Intelligence Monitor...")
	try:
		background_monitor = await start_background_monitor(db, rag)
		logger.info("✅ Background Intelligence Monitor started successfully!")
		logger.info("📡 Now monitoring: Twitter, Reddit, blacklisted wallets, blockchain patterns")
	except Exception as e:
		logger.warning(f"⚠️ Background Monitor failed to start: {e}")
		logger.info("📊 Continuing without background monitoring")
		background_monitor = None
	
	# Start real-time incoming transaction monitoring
	if hasattr(sensor, 'start_incoming_monitor'):
		try:
			await sensor.start_incoming_monitor()
			logger.info("🛡️ Real-time transaction monitoring started!")
		except Exception as e:
			logger.warning(f"⚠️ Could not start real-time monitoring: {e}")
			logger.info("📊 Continuing with periodic analysis only")

	flow_func = partial(
		security_assisted_flow,
		agent=agent,
		session_id=session_id,
		role=role,
		network=network,
		time=time_,
		apis=apis,
		security_tools=security_tools,
		metric_name=metric_name,
		meta_swap_api_url=meta_swap_api_url,
		summarizer=summarizer,
	)

	# Run main cycle with background monitoring active
	try:
		await run_cycle_with_background_monitor(
			agent,
			notif_sources,
			flow_func,
			db,
			session_id,
			agent_id,
			fe_data,
			background_monitor,
		)
	finally:
		# Cleanup: Stop background monitor when main cycle ends
		if background_monitor:
			logger.info("🛑 Stopping background monitor...")
			await background_monitor.stop_monitoring()


async def run_cycle_with_background_monitor(
	agent: SecurityAgent,
	notif_sources: list[str],
	flow: Callable[[StrategyData | None, str | None], None],
	db: DBInterface,
	session_id: str,
	agent_id: str,
	fe_data: dict | None = None,
	background_monitor: BackgroundIntelligenceMonitor | None = None,
):
	"""Execute security agent workflow cycle with background intelligence"""
	cycle_count = 0
	
	while True:  # Continuous monitoring loop
		try:
			cycle_count += 1
			logger.info(f"🔄 Starting security cycle #{cycle_count}")
			
			# Get previous strategy context
			prev_strat = agent.db.fetch_latest_strategy(agent.agent_id)
			if prev_strat is not None:
				logger.info(f"📚 Using previous security strategy: {prev_strat.summarized_desc[:100]}...")
				agent.rag.save_result_batch_v4([prev_strat])

			# Get latest notifications + background intelligence
			notif_limit = 5 if fe_data is None else 2
			current_notif = agent.db.fetch_latest_notification_str_v2(
				notif_sources, notif_limit
			)
			
			# 🚀 NEW: Enhance notifications with background intelligence
			if background_monitor:
				try:
					# Get recent threat intelligence from background monitor
					monitor_status = await background_monitor.get_monitoring_status()
					
					if monitor_status['statistics']['threats_discovered'] > 0:
						threat_summary = f"Background Monitor Alert: {monitor_status['statistics']['threats_discovered']} new threats detected. "
						threat_summary += f"Tracking {monitor_status['blacklisted_wallets']} blacklisted wallets. "
						threat_summary += f"Last update: {monitor_status['statistics']['last_update']}"
						
						# Combine with existing notifications
						if current_notif:
							current_notif = f"{threat_summary}\n\nOther notifications: {current_notif}"
						else:
							current_notif = threat_summary
						
						logger.info(f"🚨 Enhanced notifications with background intelligence")
				except Exception as e:
					logger.warning(f"⚠️ Failed to get background intelligence: {e}")
			
			logger.info(f"📢 Processing notifications: {current_notif[:100] if current_notif else 'No new notifications'}...")

			# Run the main security analysis flow
			flow(prev_strat=prev_strat, notif_str=current_notif)
			db.add_cycle_count(session_id, agent_id)
			
			# Show monitoring status every 10 cycles
			if cycle_count % 10 == 0 and background_monitor:
				try:
					status = await background_monitor.get_monitoring_status()
					logger.info(f"📊 Background Monitor Status:")
					logger.info(f"   🔍 Threats discovered: {status['statistics']['threats_discovered']}")
					logger.info(f"   🚫 Wallets tracked: {status['blacklisted_wallets']}")
					logger.info(f"   📱 Social media scans: {status['statistics']['social_media_scans']}")
					logger.info(f"   💾 Database updates: {status['statistics']['database_updates']}")
				except Exception as e:
					logger.warning(f"⚠️ Error getting monitor status: {e}")
			
			# Wait before next cycle (configurable)
			cycle_interval = int(os.getenv('SECURITY_CYCLE_INTERVAL', 900))  # 15 minutes default
			logger.info(f"⏰ Waiting {cycle_interval} seconds before next cycle...")
			await asyncio.sleep(cycle_interval)
			
		except KeyboardInterrupt:
			logger.info("🛑 Security monitoring stopped by user")
			break
		except Exception as e:
			logger.error(f"❌ Error in security cycle: {e}")
			# Wait before retrying
			await asyncio.sleep(60)


def setup_security_sensor() -> SecuritySensorInterface:
	"""Initialize Solana blockchain security sensor with real-time monitoring capability"""
	HELIUS_API_KEY = os.environ.get("HELIUS_API_KEY")
	SOLANA_RPC_URL = os.environ.get("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")
	
	# Get monitored wallet addresses from environment
	monitored_wallets = []
	wallet_env_vars = [key for key in os.environ.keys() if key.startswith("MONITOR_WALLET_")]
	for wallet_var in wallet_env_vars:
		wallet_address = os.environ[wallet_var]
		if wallet_address:
			monitored_wallets.append(wallet_address)
	
	# Default to demo wallets if none specified
	if not monitored_wallets:
		monitored_wallets = [
			"7xKs1aTF7YbL8C9s3mZNbGKPFXCWuBvf9Ss623VQ5DA",
			"9mNp2bK8fG3cCd4sVhMnBkLpQrTt5RwXyZ7nE8hS1kL"
		]
	
	logger.info(f"🛡️ Setting up SecuritySensor for {len(monitored_wallets)} wallets:")
	for wallet in monitored_wallets:
		logger.info(f"   📡 Monitoring: {wallet[:8]}...{wallet[-8:]}")
	
	sensor = SecuritySensor(
		wallet_addresses=monitored_wallets,
		solana_rpc_url=SOLANA_RPC_URL,
		helius_api_key=HELIUS_API_KEY or "",
	)
	return sensor


def extra_background_monitor_questions():
	"""Ask user about background monitoring configuration"""
	questions = [
		inquirer.List(
			name="enable_background_monitor",
			message="Enable 24/7 background intelligence monitoring?",
			choices=[
				"Yes - Monitor Twitter, Reddit, blacklisted wallets",
				"No - Just real-time transaction analysis"
			],
		)
	]
	
	if inquirer.prompt(questions)["enable_background_monitor"].startswith("Yes"):
		# Ask for API keys
		api_questions = []
		
		if not os.getenv("TWITTER_BEARER_TOKEN"):
			api_questions.append(
				inquirer.Password(
					"twitter_token", 
					message="Twitter Bearer Token (optional, for social media monitoring):",
					default=""
				)
			)
		
		if not os.getenv("REDDIT_CLIENT_ID"):
			api_questions.append(
				inquirer.Text(
					"reddit_client_id", 
					message="Reddit Client ID (optional, for Reddit monitoring):",
					default=""
				)
			)
		
		if api_questions:
			api_answers = inquirer.prompt(api_questions)
			
			if api_answers.get("twitter_token"):
				os.environ["TWITTER_BEARER_TOKEN"] = api_answers["twitter_token"]
			
			if api_answers.get("reddit_client_id"):
				os.environ["REDDIT_CLIENT_ID"] = api_answers["reddit_client_id"]
		
		return True
	else:
		return False


def extra_research_tools_questions(answer_research_tools):
	"""Prompt for API keys needed by selected research tools"""
	questions_rt = []
	var_rt = []
	for research_tool in answer_research_tools:
		if research_tool in SERVICE_TO_ENV:
			for env in SERVICE_TO_ENV[research_tool]:
				if not os.getenv(env):
					var_rt.append(env)
					questions_rt.append(
						inquirer.Text(
							name=env, message=f"Please enter value for this variable {env}"
						)
					)
	if questions_rt:
		answers_rt = inquirer.prompt(questions_rt)
		for env in var_rt:
			os.environ[env] = answers_rt[env]


def extra_model_questions(answer_model):
	"""Configure AI model and prompt for API keys"""
	model_naming = {
		"Mock LLM": "mock",
		"OpenAI": "openai",
		"OpenAI (openrouter)": "openai",
		"Gemini (openrouter)": "gemini",
		"QWQ (openrouter)": "qwq",
		"Claude": "claude",
	}

	if "Mock LLM" in answer_model:
		logger.info("Notice: Using mock LLM. Responses are simulated for testing.")
	elif "openrouter" in answer_model and not os.getenv("OPENROUTER_API_KEY"):
		question_or_key = [
			inquirer.Password(
				"or_api_key", message="Please enter the Openrouter API key"
			)
		]
		answers_or_key = inquirer.prompt(question_or_key)
		os.environ["OPENROUTER_API_KEY"] = answers_or_key["or_api_key"]
	elif "OpenAI" == answer_model and not os.getenv("OPENAI_API_KEY"):
		question_openai_key = [
			inquirer.Password(
				"openai_api_key", message="Please enter the OpenAI API key"
			)
		]
		answers_openai_key = inquirer.prompt(question_openai_key)
		os.environ["OPENAI_API_KEY"] = answers_openai_key["openai_api_key"]
	elif "Claude" in answer_model and not os.getenv("ANTHROPIC_API_KEY"):
		question_claude_key = [
			inquirer.Password(
				"claude_api_key", message="Please enter the Claude API key"
			)
		]
		answers_claude_key = inquirer.prompt(question_claude_key)
		os.environ["ANTHROPIC_API_KEY"] = answers_claude_key["claude_api_key"]
	return model_naming[answer_model]


def extra_sensor_questions():
	"""Configure security sensor for Solana monitoring with real-time protection"""
	sensor_api_keys = ["HELIUS_API_KEY", "SOLANA_RPC_URL"]
	question_security_sensor = [
		inquirer.List(
			name="sensor",
			message=f"Do you have these API keys {', '.join(sensor_api_keys)} for real-time monitoring?",
			choices=[
				"No, I'm using Mock Security Sensor for now",
				"Yes, i have these keys for real-time protection",
			],
		)
	]
	answer_security_sensor = inquirer.prompt(question_security_sensor)
	if answer_security_sensor["sensor"] == "Yes, i have these keys for real-time protection":
		sensor_api_keys = [x for x in sensor_api_keys if not os.getenv(x)]
		question_sensor_api_keys = [
			inquirer.Text(
				name=x, message=f"Please enter value for this variable {x}"
			)
			for x in sensor_api_keys
			if not os.getenv(x)
		]
		if question_sensor_api_keys:
			answer_sensor_api_keys = inquirer.prompt(question_sensor_api_keys)
			for x in sensor_api_keys:
				if x in answer_sensor_api_keys:
					os.environ[x] = answer_sensor_api_keys[x]
		
		sensor = setup_security_sensor()
		logger.info("🚀 Real-time SecuritySensor configured!")
		return sensor
	else:
		logger.info("📊 Using Mock SecuritySensor for testing")
		return MockSecuritySensor(["demo_wallet"], "mock_rpc", "mock_key")


def extra_rag_questions(answer_rag):
	"""Configure RAG client"""
	if answer_rag == "Yes, i have setup the RAG":
		return RAGClient(os.getenv("RAG_SERVICE_URL", "http://localhost:8080"))
	else:
		logger.info("📚 Using Mock RAG for testing")
		return MockRAGClient()


async def main_security_loop(fe_data, genner, rag_client, sensor):
	"""Main async loop for security agent with background monitoring"""
	
	# Initialize database
	db = SQLiteDB(db_path=os.getenv("SQLITE_PATH", "./db/security.db"))
	
	# Generate session and agent IDs
	session_id = f"security_session_{int(time.time())}"
	agent_id = f"security_agent_{fe_data['agent_name']}"
	
	logger.info(f"🆔 Session ID: {session_id}")
	logger.info(f"🤖 Agent ID: {agent_id}")
	
	# Start the enhanced security agent with background monitoring
	await start_security_agent_with_background_monitor(
		agent_type="security",
		session_id=session_id,
		agent_id=agent_id,
		fe_data=fe_data,
		genner=genner,
		rag=rag_client,
		sensor=sensor,
		db=db,
		meta_swap_api_url=os.getenv("META_SWAP_API_URL", "http://localhost:9009"),
	)


def starter_prompt():
	"""Enhanced starter prompt with background monitoring options"""
	
	choices_research_tools = [
		"Solana RPC",
		"Threat Intelligence", 
		"DuckDuckGo",
		"CoinGecko",
		"Etherscan", 
		"1inch",
		"Infura"
	]
	
	choices_notifications = [
		"blockchain_alerts",
		"security_alerts",
		"community_reports"
	]
	
	questions = [
		inquirer.Text("agent_name", message="What's the name of your security agent?", default="MySecurityAgent"),
		inquirer.List(
			name="model",
			message="Which AI model do you want to use for analysis and code generation?",
			choices=[
				"Claude",
				"OpenAI",
				"OpenAI (openrouter)",
				"Gemini (openrouter)", 
				"QWQ (openrouter)",
				"Mock LLM"
			],
		),
		inquirer.Checkbox(
			"research_tools",
			message="Which research tools do you want to use? (use space to choose)",
			choices=[service for service in choices_research_tools],
		),
		inquirer.Checkbox(
			"notifications",
			message="Which notifications do you want to use? (use space to choose) (optional)",
			choices=[service for service in choices_notifications],
		),
		inquirer.List(
			name="rag",
			message="Have you setup the RAG API (rag-api folder) for threat intelligence?",
			choices=["No, I'm using Mock RAG for now", "Yes, i have setup the RAG"],
		),
	]
	answers = inquirer.prompt(questions)

	# Setup components
	rag_client = extra_rag_questions(answers["rag"])
	model_name = extra_model_questions(answers["model"])
	extra_research_tools_questions(answers["research_tools"])
	sensor = extra_sensor_questions()
	
	# 🚀 NEW: Ask about background monitoring
	enable_background_monitor = extra_background_monitor_questions()

	# Set up security agent configuration
	fe_data = FE_DATA_SECURITY_DEFAULTS.copy()
	fe_data["agent_name"] = answers["agent_name"]

	# Filter research tools to security-relevant ones
	security_research_tools = ["Solana RPC", "Threat Intelligence", "DuckDuckGo"]
	fe_data["research_tools"] = [
		x for x in answers["research_tools"] if x in security_research_tools
	]
	
	fe_data["notifications"] = answers["notifications"]
	fe_data["prompts"] = fetch_default_prompt(fe_data, "security")
	fe_data["model"] = model_name
	fe_data["enable_background_monitor"] = enable_background_monitor

	# Initialize AI generators
	or_client = (
		OpenRouter(
			base_url="https://openrouter.ai/api/v1",
			api_key=os.getenv("OPENROUTER_API_KEY"),
			include_reasoning=True,
		)
		if os.getenv("OPENROUTER_API_KEY") is not None
		else None
	)

	anthropic_client = (
		Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
		if os.getenv("ANTHROPIC_API_KEY") is not None
		else None
	)

	genner = get_genner(
		backend=fe_data["model"],
		or_client=or_client,
		anthropic_client=anthropic_client,
		stream_fn=lambda token: print(token, end="", flush=True),
	)
	
	# Start the main security loop with background monitoring
	logger.info("🚀 Starting AI-Powered Security System with Background Intelligence...")
	asyncio.run(main_security_loop(fe_data, genner, rag_client, sensor))


if __name__ == "__main__":
	starter_prompt()