"""
SecurityAgent - Replaces TradingAgent with security monitoring
Follows exact same class structure and patterns as TradingAgent
"""

import re
from textwrap import dedent
from typing import Dict, List, Set, Tuple
from datetime import datetime
from src.db import DBInterface

from result import Err, Ok, Result

from src.container import ContainerManager
from src.genner.Base import Genner
from src.client.rag import RAGClient
from src.sensor.security import SecuritySensor
from src.types import ChatHistory, Message


class SecurityPromptGenerator:
	"""
	Generator for creating prompts used in security agent workflows.
	Follows exact same structure as TradingPromptGenerator but for security operations.
	
	This class is responsible for generating various prompts used by the security agent,
	including system prompts, analysis code prompts, threat detection prompts, and quarantine decision prompts.
	"""

	def __init__(self, prompts: Dict[str, str]):
		"""
		Initialize with custom prompts for each function.
		Follows exact same pattern as TradingPromptGenerator.__init__.

		Args:
		    prompts (Dict[str, str]): Dictionary containing custom prompts for each function
		"""
		if prompts:
			prompts = self.get_default_prompts()
		self._validate_prompts(prompts)
		self.prompts = self.get_default_prompts()

	def get_default_prompts(self) -> Dict[str, str]:
		"""
		Get default security analysis prompts.
		Replaces trading prompts with security-focused prompts.
		"""
		return {
			"system_prompt": dedent("""
				You are a {role} security agent protecting Web3 wallets from threats.
				Today's date: {today_date}
				Your goal: Analyze transactions and detect threats to maximize {metric_name} security over {time}.
				
				Current Security Status: {metric_state}
				Blockchain Network: {network}
				
				You have access to advanced threat detection capabilities:
				- Real-time transaction monitoring
				- Dust attack detection  
				- MEV protection
				- Smart contract analysis
				- Scam token identification
				- NFT fraud prevention
				
				Your responses should include:
				1. **Chain of Thought**: Show your security analysis reasoning step by step
				2. **Threat Assessment**: Identify specific risks and confidence levels
				3. **Protective Actions**: Recommend quarantine, block, or allow decisions
				4. **User Education**: Explain threats in simple terms
				
				Always prioritize user safety while minimizing false positives.
			""").strip(),
			
			"analysis_code_prompt_first": dedent("""
				As a security agent, generate Python code to analyze blockchain transactions for threats.
				
				Available Security APIs:
				{apis_str}
				Network: {network}
				
				Requirements:
				1. Connect to Solana blockchain and monitor transactions
				2. Implement real-time threat detection algorithms
				3. Search for suspicious patterns in transaction data
				4. Generate security intelligence reports
				5. Use print() statements to show your analysis reasoning (Chain of Thought)
				
				Focus on detecting:
				- Dust attacks (micro-transactions for tracking)
				- Suspicious token transfers
				- MEV exploitation attempts
				- Scam NFT airdrops
				- Contract interaction risks
				
				Print your thought process as you analyze each transaction.
				Format the code as follows:
				```python
				import ...

				def main():
				    # Chain of thought: Show reasoning
				    print("Starting security analysis...")
				    # Your analysis code here
				    ....

				main()
				```
				Please generate the analysis code.
			""").strip(),
			
			"analysis_code_prompt": dedent("""
				Based on these security notifications:
				<Notifications>
				{notifications_str}
				</Notifications>
				
				Previous analysis summary:
				<Previous_Analysis>
				{prev_analysis}
				</Previous_Analysis>
				
				RAG Security Intelligence:
				<RAG_Intelligence>
				{rag_summary}
				</RAG_Intelligence>
				
				Security status before: {before_metric_state}
				Security status after: {after_metric_state}
				
				Generate Python code to analyze these new threats and update security measures.
				
				Available APIs: {apis_str}
				Network: {network}
				
				Requirements:
				1. Analyze the new security notifications
				2. Cross-reference with previous threat patterns
				3. Use RAG intelligence to identify known attack vectors
				4. Update threat detection algorithms based on new patterns
				5. Show your reasoning with print() statements (Chain of Thought)
				
				Print your analysis process step by step.
				Format as:
				```python
				import ...

				def main():
				    print("Analyzing new security threats...")
				    # Your analysis code here
				    ....

				main()
				```
			""").strip(),
			
			"strategy_prompt": dedent("""
				Based on this security analysis:
				<Analysis_Results>
				{research_results}
				</Analysis_Results>
				
				Available protection tools: {apis_str}
				Current security metric: {before_metric_state}
				Network: {network}
				Time horizon: {time}
				
				Create a comprehensive security strategy that:
				
				1. **Threat Assessment** (Chain of Thought):
				   - Analyze the identified threats step by step
				   - Explain why each threat is dangerous
				   - Rate the risk level for each threat
				   
				2. **Protection Strategy**:
				   - Decide which transactions to quarantine/block/allow
				   - Explain the reasoning behind each decision
				   - Consider user experience vs security trade-offs
				   
				3. **Implementation Plan**:
				   - Specify exact protective measures to implement
				   - Include monitoring and alerting strategies
				   - Plan for user education and notification
				
				Show your reasoning process clearly so users understand why you're making these security decisions.
			""").strip(),
			
			"quarantine_code_prompt": dedent("""
				Implement this security strategy:
				<Security_Strategy>
				{strategy_output}
				</Security_Strategy>
				
				Available APIs:
				{apis_str}
				
				Current security status: {metric_state}
				Network: {network}
				
				Generate Python code that:
				1. Implements the security decisions (quarantine/block/allow)
				2. Updates threat detection rules
				3. Configures monitoring and alerts
				4. Documents all security actions taken
				5. Shows reasoning with print() statements (Chain of Thought)
				
				Use the quarantine API to safely isolate threats:
				{quarantine_tools}
				
				Print your decision-making process as you implement security measures.
				Don't try/catch errors - let the program crash if something unexpected happens.
				
				Format the code as follows:
				```python
				import ...

				def main():
				    print("Implementing security strategy...")
				    # Show your reasoning
				    ....

				main()
				```
				Please generate the code.
			""").strip(),
			
			"regen_code_prompt": dedent("""
				Given these errors:
				<Errors>
				{errors}
				</Errors>
				And the code it's from:
				<Code>
				{latest_response}
				</Code>
				
				Generate new security code that fixes the error without changing the original logic.
				Print everything and raise any errors or unexpected behavior.
				
				Show your debugging reasoning with print() statements.
				
				```python
				from dotenv import load_dotenv
				import ...

				load_dotenv()

				def main():
				    print("Debugging security implementation...")
				    # Show your fixing process
				    ....
				
				main()
				```
				Please generate the code that fixes the problem.
			""").strip(),
		}

	def _security_tools_to_api_prompt(
		self,
		tools: List[str],
		meta_swap_api_url: str,
		agent_id: str,
		session_id: str,
	):
		"""
		Convert security tools to API command prompts.
		Replaces _instruments_to_curl_prompt from TradingPromptGenerator.
		
		Args:
		    tools (List[str]): List of security tool types
		    meta_swap_api_url (str): URL of the meta-swap API service
		    agent_id (str): ID of the agent
		    session_id (str): ID of the session
		    
		Returns:
		    str: String containing API command examples for security tools
		"""
		try:
			mapping = {
				"quarantine": dedent(f"""
					# Quarantine suspicious transaction
					curl -X POST "http://{meta_swap_api_url}/api/v1/security/quarantine" \\
					-H "Content-Type: application/json" \\
					-H "x-superior-agent-id: {agent_id}" \\
					-H "x-superior-session-id: {session_id}" \\
					-d '{{
						"transaction_hash": "<tx_signature>",
						"wallet_address": "<affected_wallet>",
						"threat_type": "<dust_attack|suspicious_token|mev_risk|scam_nft>",
						"risk_score": <0.0_to_1.0>,
						"reason": "<human_readable_explanation>"
					}}'
				"""),
				
				"block": dedent(f"""
					# Block malicious transaction
					curl -X POST "http://{meta_swap_api_url}/api/v1/security/block" \\
					-H "Content-Type: application/json" \\
					-H "x-superior-agent-id: {agent_id}" \\
					-H "x-superior-session-id: {session_id}" \\
					-d '{{
						"address": "<malicious_address>",
						"block_type": "<permanent|temporary>",
						"duration_hours": <hours_if_temporary>,
						"threat_category": "<scammer|drain_contract|fake_token>",
						"evidence": "<threat_evidence_description>"
					}}'
				"""),
				
				"monitor": dedent(f"""
					# Add address to monitoring
					curl -X POST "http://{meta_swap_api_url}/api/v1/security/monitor" \\
					-H "Content-Type: application/json" \\
					-H "x-superior-agent-id: {agent_id}" \\
					-H "x-superior-session-id: {session_id}" \\
					-d '{{
						"wallet_addresses": ["<address1>", "<address2>"],
						"monitoring_level": "<basic|enhanced|real_time>",
						"alert_thresholds": {{
							"dust_amount": <sol_amount>,
							"risk_score": <0.0_to_1.0>,
							"frequency_limit": <transactions_per_hour>
						}}
					}}'
				"""),
				
				"analyze": dedent(f"""
					# Analyze transaction for threats
					curl -X POST "http://{meta_swap_api_url}/api/v1/security/analyze" \\
					-H "Content-Type: application/json" \\
					-H "x-superior-agent-id: {agent_id}" \\
					-H "x-superior-session-id: {session_id}" \\
					-d '{{
						"transaction_data": {{
							"signature": "<transaction_signature>",
							"from_address": "<sender_address>",
							"to_address": "<recipient_address>",
							"amount": "<amount_in_sol>",
							"token_mint": "<token_mint_address_if_applicable>",
							"program_id": "<solana_program_id>"
						}},
						"analysis_depth": "<quick|thorough|deep>",
						"include_mev_check": true,
						"include_dust_check": true
					}}'
				"""),
			}
			
			tools_str = [mapping[tool] for tool in tools]
			return "\n".join(tools_str)
			
		except KeyError as e:
			raise KeyError(
				f"Expected security tools to be in ['quarantine', 'block', 'monitor', 'analyze'], {e}"
			)

	@staticmethod
	def _metric_to_metric_prompt(metric_name="security"):
		"""
		Convert a metric name to a human-readable description.
		Replaces trading metric mapping with security metrics.

		Args:
		    metric_name (str, optional): Name of the metric. Defaults to "security".

		Returns:
		    str: Human-readable description of the metric
		"""
		try:
			mapping = {
				"security": "your wallet security and threat protection",
				"threats": "detected threats and risk levels",
				"quarantine": "quarantined suspicious items"
			}

			return mapping[metric_name]
		except KeyError as e:
			raise KeyError(f"Expected metric_name to be in ['security', 'threats', 'quarantine'], {e}")

	def _extract_default_placeholders(self) -> Dict[str, Set[str]]:
		"""
		Extract placeholders from default prompts to use as required placeholders.
		Same logic as TradingPromptGenerator.
		"""
		placeholder_pattern = re.compile(r"{([^}]+)}")
		return {
			prompt_name: {
				f"{{{p}}}" for p in placeholder_pattern.findall(prompt_content)
			}
			for prompt_name, prompt_content in self.get_default_prompts().items()
		}

	def _validate_prompts(self, prompts: Dict[str, str]) -> None:
		"""
		Validate prompts for required and unexpected placeholders.
		Same validation logic as TradingPromptGenerator.
		"""
		required_placeholders = self._extract_default_placeholders()

		# Check all required prompts exist
		missing_prompts = set(required_placeholders.keys()) - set(prompts.keys())
		if missing_prompts:
			raise ValueError(f"Missing required prompts: {missing_prompts}")

		# Extract placeholders using regex
		placeholder_pattern = re.compile(r"{([^}]+)}")

		# Check each prompt for missing and unexpected placeholders
		for prompt_name, prompt_content in prompts.items():
			if prompt_name not in required_placeholders:
				continue

			actual_placeholders = {
				f"{{{p}}}" for p in placeholder_pattern.findall(prompt_content)
			}
			required_set = required_placeholders[prompt_name]

			# Check for missing placeholders
			missing = required_set - actual_placeholders
			if missing:
				raise ValueError(
					f"Missing required placeholders in {prompt_name}: {missing}"
				)

			# Check for unexpected placeholders
			unexpected = actual_placeholders - required_set
			if unexpected:
				raise ValueError(
					f"Unexpected placeholders in {prompt_name}: {unexpected}"
				)

	def generate_system_prompt(
		self, role: str, time: str, metric_name: str, metric_state: str, network: str
	) -> str:
		"""
		Generate a system prompt for the security agent.
		Follows exact same pattern as TradingPromptGenerator.generate_system_prompt.

		Args:
		    role (str): The role of the agent (e.g., "security_analyst")
		    time (str): Time frame for the security monitoring
		    metric_name (str): Name of the security metric to track
		    metric_state (str): Current state of the security metric
		    network (str): Blockchain network being monitored

		Returns:
		    str: Formatted system prompt
		"""
		now = datetime.now()
		today_date = now.strftime("%Y-%m-%d")

		# Parse the metric state to extract security status
		try:
			metric_data = eval(metric_state)
			if isinstance(metric_data, dict) and "security_score" in metric_data:
				# Show security-relevant information
				metric_state = str({
					"security_score": metric_data["security_score"],
					"threats_detected": metric_data.get("total_threats_detected", 0),
					"quarantined_items": metric_data.get("quarantined_items", 0),
					"monitored_wallets": len(metric_data.get("monitored_wallets", [])),
				})
		except (ValueError, TypeError):
			pass  # Keep original metric_state if parsing fails

		return self.prompts["system_prompt"].format(
			role=role,
			today_date=today_date,
			metric_name=metric_name,
			time=time,
			network=network,
			metric_state=metric_state,
		)

	def generate_analysis_code_first_time_prompt(self, apis: List[str], network: str):
		"""
		Generate a prompt for first-time security analysis code generation.
		Replaces generate_research_code_first_time_prompt from TradingPromptGenerator.
		"""
		apis_str = ",\n".join(apis) if apis else self._get_default_apis_str()

		return self.prompts["analysis_code_prompt_first"].format(
			apis_str=apis_str, network=network
		)

	def generate_analysis_code_prompt(
		self,
		notifications_str: str,
		apis: List[str],
		prev_analysis: str,
		rag_summary: str,
		before_metric_state: str,
		after_metric_state: str,
	):
		"""
		Generate a prompt for security analysis code generation with context.
		Replaces generate_research_code_prompt from TradingPromptGenerator.
		"""
		apis_str = ",\n".join(apis) if apis else self._get_default_apis_str()

		return self.prompts["analysis_code_prompt"].format(
			notifications_str=notifications_str,
			apis_str=apis_str,
			prev_analysis=prev_analysis,
			rag_summary=rag_summary,
			before_metric_state=before_metric_state,
			after_metric_state=after_metric_state,
		)

	def _get_default_apis_str(self) -> str:
		"""
		Get default security APIs string.
		Replaces trading APIs with security-focused APIs.
		"""
		return dedent("""
			Solana RPC API - Real-time blockchain monitoring
			Meta-Swap Security API - Threat detection and quarantine
			Threat Intelligence Database - Known scammer addresses
			Transaction Pattern Analysis - Behavioral detection
			Token Metadata Verification - Scam token identification
		""").strip()


class SecurityAgent:
	"""
	Agent responsible for executing security strategies based on blockchain data and threat notifications.
	Follows exact same structure as TradingAgent but for security operations.

	This class orchestrates the entire security workflow, including system preparation,
	analysis code generation, threat detection, and protective action execution.
	"""

	def __init__(
		self,
		agent_id: str,
		rag: RAGClient,
		db: DBInterface,
		sensor: SecuritySensor,
		genner: Genner,
		container_manager: ContainerManager,
		prompt_generator: SecurityPromptGenerator,
	):
		"""
		Initialize the security agent with all required components.
		Follows exact same __init__ pattern as TradingAgent.

		Args:
		    agent_id (str): Unique identifier for this agent
		    rag (RAGClient): Client for retrieval-augmented generation (threat intelligence)
		    db (DBInterface): Database client for storing and retrieving data
		    sensor (SecuritySensor): Sensor for monitoring security-related metrics
		    genner (Genner): Generator for creating code and strategies
		    container_manager (ContainerManager): Manager for code execution in containers
		    prompt_generator (SecurityPromptGenerator): Generator for creating prompts
		"""
		self.agent_id = agent_id
		self.db = db
		self.rag = rag
		self.sensor = sensor
		self.genner = genner
		self.container_manager = container_manager
		self.prompt_generator = prompt_generator

		self.chat_history = ChatHistory()

	def reset(self) -> None:
		"""
		Reset the agent's chat history.
		Same as TradingAgent.reset().
		"""
		self.chat_history = ChatHistory()

	def prepare_system(
		self, role: str, time: str, metric_name: str, metric_state: str, network: str
	) -> ChatHistory:
		"""
		Prepare the system prompt for the security agent.
		Follows exact same pattern as TradingAgent.prepare_system.

		Args:
		    role (str): The role of the agent (e.g., "security_analyst")
		    time (str): Time frame for security monitoring
		    metric_name (str): Name of the security metric to track
		    metric_state (str): Current state of security metrics
		    network (str): Blockchain network being monitored

		Returns:
		    ChatHistory: Chat history with the system prompt
		"""
		ctx_ch = ChatHistory(
			Message(
				role="system",
				content=self.prompt_generator.generate_system_prompt(
					role=role,
					time=time,
					metric_name=metric_name,
					metric_state=metric_state,
					network=network,
				),
			)
		)

		return ctx_ch

	def gen_analysis_code_on_first(
		self, apis: List[str], network: str
	) -> Result[Tuple[str, ChatHistory], str]:
		"""
		Generate security analysis code for the first time.
		Replaces gen_research_code_on_first from TradingAgent.

		Args:
		    apis (List[str]): List of security APIs available
		    network (str): Blockchain network to monitor

		Returns:
		    Result: Success with (code, chat_history) or Error with message
		"""
		ctx_ch = self.chat_history
		user_prompt = self.prompt_generator.generate_analysis_code_first_time_prompt(
			apis, network
		)

		ctx_ch.add_message(Message(role="user", content=user_prompt))

		response = self.genner.gen(ctx_ch.messages)
		if isinstance(response, Err):
			return response

		ctx_ch.add_message(Message(role="assistant", content=response.unwrap()))

		self.chat_history = ctx_ch

		return Ok((response.unwrap(), ctx_ch))

	def gen_analysis_code(
		self,
		notifications_str: str,
		apis: List[str],
		prev_analysis: str,
		rag_summary: str,
		before_metric_state: str,
		after_metric_state: str,
	) -> Result[Tuple[str, ChatHistory], str]:
		"""
		Generate security analysis code with context.
		Replaces gen_research_code from TradingAgent.
		"""
		ctx_ch = self.chat_history
		user_prompt = self.prompt_generator.generate_analysis_code_prompt(
			notifications_str,
			apis,
			prev_analysis,
			rag_summary,
			before_metric_state,
			after_metric_state,
		)

		ctx_ch.add_message(Message(role="user", content=user_prompt))

		response = self.genner.gen(ctx_ch.messages)
		if isinstance(response, Err):
			return response

		ctx_ch.add_message(Message(role="assistant", content=response.unwrap()))

		self.chat_history = ctx_ch

		return Ok((response.unwrap(), ctx_ch))

	def gen_security_strategy(
		self,
		analysis_results: str,
		apis: List[str],
		before_metric_state: str,
		network: str,
		time: str,
	) -> Result[Tuple[str, ChatHistory], str]:
		"""
		Generate security strategy based on analysis results.
		Replaces gen_strategy from TradingAgent.
		"""
		ctx_ch = self.chat_history
		user_prompt = self.prompt_generator.prompts["strategy_prompt"].format(
			research_results=analysis_results,
			apis_str=",\n".join(apis),
			before_metric_state=before_metric_state,
			network=network,
			time=time,
		)

		ctx_ch.add_message(Message(role="user", content=user_prompt))

		response = self.genner.gen(ctx_ch.messages)
		if isinstance(response, Err):
			return response

		ctx_ch.add_message(Message(role="assistant", content=response.unwrap()))

		self.chat_history = ctx_ch

		return Ok((response.unwrap(), ctx_ch))

	def gen_quarantine_code(
		self,
		strategy_output: str,
		apis: List[str],
		metric_state: str,
		security_tools: List[str],
		meta_swap_api_url: str,
		network: str,
	) -> Result[Tuple[str, ChatHistory], str]:
		"""
		Generate code to implement security strategy (quarantine, block, etc.).
		Replaces gen_trading_code from TradingAgent.
		"""
		ctx_ch = self.chat_history
		
		quarantine_tools = self.prompt_generator._security_tools_to_api_prompt(
			security_tools, meta_swap_api_url, self.agent_id, "session_id"
		)
		
		user_prompt = self.prompt_generator.prompts["quarantine_code_prompt"].format(
			strategy_output=strategy_output,
			apis_str=",\n".join(apis),
			metric_state=metric_state,
			quarantine_tools=quarantine_tools,
			network=network,
		)

		ctx_ch.add_message(Message(role="user", content=user_prompt))

		response = self.genner.gen(ctx_ch.messages)
		if isinstance(response, Err):
			return response

		ctx_ch.add_message(Message(role="assistant", content=response.unwrap()))

		self.chat_history = ctx_ch

		return Ok((response.unwrap(), ctx_ch))

	def regen_on_error(self, errors: str, latest_response: str) -> Result[str, str]:
		"""
		Regenerate code when errors occur.
		Same as TradingAgent.regen_on_error.
		"""
		user_prompt = self.prompt_generator.prompts["regen_code_prompt"].format(
			errors=errors, latest_response=latest_response
		)

		ctx_ch = self.chat_history
		ctx_ch.add_message(Message(role="user", content=user_prompt))

		response = self.genner.gen(ctx_ch.messages)
		if isinstance(response, Err):
			return response

		ctx_ch.add_message(Message(role="assistant", content=response.unwrap()))

		self.chat_history = ctx_ch

		return response