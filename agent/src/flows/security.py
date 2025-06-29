"""
Security Flows - Replaces Trading Flows
Follows exact same workflow pattern as trading_assisted_flow but for security operations
"""

import json
from datetime import timedelta
from textwrap import dedent
from typing import Callable, List

from loguru import logger
from result import UnwrapError
from dateutil import parser
from src.agent.security import SecurityAgent
from src.datatypes import (
	StrategyData,
	StrategyDataParameters,
	StrategyInsertData,
)
from src.helper import nanoid
from src.types import ChatHistory

# Add this function at the top of the file
def extract_python_code(ai_response: str) -> str:
    """Extract only executable Python code from AI response"""
    import re
    
    # Extract code from markdown blocks
    code_block_pattern = r'```(?:python)?\s*\n(.*?)\n```'
    matches = re.findall(code_block_pattern, ai_response, re.DOTALL)
    
    if matches:
        return matches[0].strip()
    
    # Extract code starting from first import/def
    lines = ai_response.split('\n')
    code_started = False
    extracted_lines = []
    
    for line in lines:
        if not code_started:
            if (line.strip().startswith(('import ', 'from ', 'def ', 'class ', '#!')) or
                'load_dotenv' in line):
                code_started = True
                extracted_lines.append(line)
        else:
            if (line.strip().startswith(('Note:', 'This code', 'Below is')) and
                not line.strip().startswith('#')):
                break
            extracted_lines.append(line)
    
    if extracted_lines:
        return '\n'.join(extracted_lines).strip()
    
    return ai_response.strip()


def assisted_flow(
	agent: SecurityAgent,
	session_id: str,
	role: str,
	network: str,
	time: str,
	apis: List[str],
	security_tools: List[str],
	metric_name: str,
	prev_strat: StrategyData | None,
	notif_str: str,
	meta_swap_api_url: str,
	summarizer: Callable[[List[str]], str],
):
	"""
	Execute an assisted security workflow with the security agent.
	Follows exact same pattern as trading_assisted_flow but for security operations.

	This function orchestrates the complete security workflow, including threat analysis,
	strategy formulation, threat intelligence research, and protective action execution.
	It handles retries for failed steps and saves the results to the database.

	Args:
	    agent (SecurityAgent): The security agent to use
	    session_id (str): Identifier for the current session
	    role (str): Role of the agent (e.g., "security_analyst")
	    network (str): Blockchain network to monitor
	    time (str): Time frame for the security monitoring goal
	    apis (List[str]): List of APIs available to the agent
	    security_tools (List[str]): List of available security tools
	    metric_name (str): Name of the security metric to track
	    prev_strat (StrategyData | None): Previous security strategy, if any
	    notif_str (str): Security notification string to process
	    meta_swap_api_url (str): URL of the meta-swap API service
	    summarizer (Callable[[List[str]], str]): Function to summarize text

	Returns:
	    None: This function doesn't return a value but logs its progress
	"""
	agent.reset()

	for_training_chat_history = ChatHistory()

	logger.info("Reset agent")
	logger.info("Starting on assisted security flow")

	metric_fn = agent.sensor.get_metric_fn(metric_name)
	start_metric_state = metric_fn()

	if metric_name == "security":
		agent.db.insert_wallet_snapshot(
			snapshot_id=f"{nanoid(4)}-{session_id}-security",
			agent_id=agent.agent_id,
			total_value_usd=start_metric_state.get("security_score", 0.0) * 100,  # Convert security score to percentage
			assets=str(start_metric_state),
		)

	if notif_str:
		logger.info(
			f"Getting relevant RAG security strategies with `query`: \n{notif_str[:100].strip()}...{notif_str[-100:].strip()}"
		)
	else:
		logger.info(
			"Getting relevant RAG security strategies with `query`: notif_str is empty string."
		)

	rag_errors = []
	rag_result = {"summary": "", "start_metric_state": "", "end_metric_state": ""}

	try:
		if notif_str:
			related_strategies = agent.rag.relevant_strategy_raw(notif_str)
		else:
			related_strategies = []

		if related_strategies and len(related_strategies) > 0:
			logger.info(f"Found {len(related_strategies)} related security strategies")
			most_related_strat = related_strategies[0]
			
			rag_result["summary"] = most_related_strat.summarized_desc
			rag_result["start_metric_state"] = most_related_strat.parameters.get(
				"start_metric_state", ""
			)
			rag_result["end_metric_state"] = most_related_strat.parameters.get(
				"end_metric_state", ""
			)
		else:
			logger.info("No related security strategies found, using empty RAG result")
			rag_result = {
				"summary": "No previous security strategies found...",
				"start_metric_state": "No previous security state available...",
				"end_metric_state": "No previous security results available...",
			}

	except Exception as e:
		rag_errors.append(
			f"Error retrieving RAG security strategy for "
			f"`notif_str`: {notif_str}, "
			f"`time`: {time}, "
			f"`err`: \n{e}"
		)
		rag_result = {
			"summary": "Error retrieving security strategies from RAG...",
			"start_metric_state": "Error retrieving previous security state...",
			"end_metric_state": "Error retrieving previous security results...",
		}

	rag_summary = rag_result["summary"]
	rag_start_metric_state = rag_result["start_metric_state"]
	rag_end_metric_state = rag_result["end_metric_state"]

	if len(rag_errors) > 0:
		for error in rag_errors:
			logger.error(error)

	logger.info(f"RAG `rag_start_metric_state`: {rag_start_metric_state}")
	logger.info(f"RAG `rag_end_metric_state`: {rag_end_metric_state}")
	logger.info(f"RAG `rag_summary`: {rag_summary}")

	logger.info(f"Using security metric: {metric_name}")
	logger.info(f"Current state of the security metric: {start_metric_state}")

	new_ch = agent.prepare_system(
		role=role,
		time=time,
		metric_name=metric_name,
		network=network,
		metric_state=str(start_metric_state),
	)
	agent.chat_history += new_ch
	for_training_chat_history += new_ch

	logger.info("Initialized system prompt")

	logger.info("Attempt to generate security analysis code...")
	analysis_code = ""
	err_acc = ""
	regen = False
	success = False
	for i in range(3):
		try:
			if regen:
				logger.info("Attempt to regenerate security analysis code...")

				if new_ch.get_latest_instruction() == "":
					logger.warning("No instruction found on chat history")
				if new_ch.get_latest_response() == "":
					logger.warning("No response found on chat history")

				analysis_code_result = agent.regen_on_error(
					errors=err_acc,
					latest_response=new_ch.get_latest_response(),
				)
				analysis_code = analysis_code_result.unwrap()
			else:
				if not prev_strat:
					analysis_code_result, new_ch = agent.gen_analysis_code_on_first(
						apis=apis, network=network
					)
					analysis_code = analysis_code_result.unwrap()
				else:
					analysis_code_result, new_ch = agent.gen_analysis_code(
						notifications_str=notif_str if notif_str else "Fresh",
						apis=apis,
						prev_analysis=prev_strat.summarized_desc if prev_strat else "No previous analysis available",
						rag_summary=rag_summary,
						before_metric_state=rag_start_metric_state,
						after_metric_state=rag_end_metric_state,
					)
					analysis_code = analysis_code_result.unwrap()

			agent.chat_history += new_ch
			for_training_chat_history += new_ch

			logger.info("Running the resulting security analysis code in container...")
			# 🔧 FIX 1: Extract Python code before execution
			analysis_code = extract_python_code(analysis_code)
			code_execution_result = agent.container_manager.run_code_in_con(
				analysis_code, "security_analysis_code"
			)
			analysis_code_output, _ = code_execution_result.unwrap()
			success = True
			break
		except UnwrapError as e:
			e = e.result.err()
			if regen:
				logger.error(f"Regen failed on security analysis code, err: \n{e}")
			else:
				logger.error(f"Failed on first security analysis code, err: \n{e}")
			regen = True
			err_acc += f"\n{str(e)}"

	if not success:
		logger.error("Failed generating output of security analysis code after 3 times...")
		return

	logger.info("Succeeded security analysis")
	logger.info(f"Security analysis output: \n{analysis_code_output}")

	logger.info("Generating security strategy based on analysis...")
	strategy_output = ""
	err_acc = ""
	regen = False
	success = False
	for i in range(3):
		try:
			if regen:
				logger.info("Regenning on security strategy...")
				strategy_result = agent.regen_on_error(
					errors=err_acc,
					latest_response=new_ch.get_latest_response(),
				)
				strategy_output = strategy_result.unwrap()
			else:
				strategy_result, new_ch = agent.gen_security_strategy(
					analysis_results=analysis_code_output,
					apis=apis,
					before_metric_state=str(start_metric_state),
					network=network,
					time=time,
				)
				strategy_output = strategy_result.unwrap()

			agent.chat_history += new_ch
			for_training_chat_history += new_ch
			success = True
			break
		except UnwrapError as e:
			e = e.result.err()
			if regen:
				logger.error(f"Regen failed on security strategy, err: \n{e}")
			else:
				logger.error(f"Failed on first security strategy, err: \n{e}")
			regen = True
			err_acc += f"\n{str(e)}"

	if not success:
		logger.error("Failed generating security strategy after 3 times...")
		return

	logger.info("Succeeded security strategy")
	logger.info(f"Security strategy: \n{strategy_output}")

	logger.info("Generating threat intelligence research...")
	threat_research_output = ""
	err_acc = ""
	regen = False
	success = False
	for i in range(3):
		try:
			if regen:
				logger.info("Regenning on threat intelligence research...")
				threat_research_result = agent.regen_on_error(
					errors=err_acc,
					latest_response=new_ch.get_latest_response(),
				)
				threat_research_output = threat_research_result.unwrap()
			else:
				# Generate code to research threat intelligence for identified threats
				threat_research_result, new_ch = agent.gen_analysis_code(
					notifications_str=f"Research threat intelligence for: {strategy_output[:200]}...",
					apis=apis,
					prev_analysis="Threat intelligence research",
					rag_summary="Researching known threat patterns and scammer addresses",
					before_metric_state=str(start_metric_state),
					after_metric_state=str(start_metric_state),
				)
				threat_research_output = threat_research_result.unwrap()

			agent.chat_history += new_ch
			for_training_chat_history += new_ch

			logger.info("Running threat intelligence research code in container...")
			# 🔧 FIX 2: Extract Python code before execution
			threat_research_output = extract_python_code(threat_research_output)
			code_execution_result = agent.container_manager.run_code_in_con(
				threat_research_output, "threat_intelligence_research"
			)
			threat_research_code_output, _ = code_execution_result.unwrap()
			success = True
			break
		except UnwrapError as e:
			e = e.result.err()
			if regen:
				logger.error(f"Regen failed on threat intelligence research, err: \n{e}")
			else:
				logger.error(f"Failed on first threat intelligence research, err: \n{e}")
			regen = True
			err_acc += f"\n{str(e)}"

	if not success:
		logger.error("Failed generating threat intelligence research after 3 times...")
		return

	logger.info("Succeeded threat intelligence research")
	logger.info(f"Threat intelligence research: \n{threat_research_code_output}")

	logger.info("Generating security implementation code (quarantine/block actions)")
	quarantine_code = ""
	err_acc = ""
	code_output = ""
	success = False
	regen = False
	for i in range(3):
		try:
			if regen:
				logger.info("Regenning on security implementation code...")

				if new_ch.get_latest_instruction() == "":
					logger.warning("No instruction found on chat history")
				if new_ch.get_latest_response() == "":
					logger.warning("No response found on chat history")

				quarantine_code_result = agent.regen_on_error(
					errors=err_acc,
					latest_response=new_ch.get_latest_response(),
				)
				quarantine_code = quarantine_code_result.unwrap()
			else:
				quarantine_code_result, new_ch = agent.gen_quarantine_code(
					strategy_output=strategy_output,
					apis=apis,
					metric_state=str(start_metric_state),
					security_tools=security_tools,
					meta_swap_api_url=meta_swap_api_url,
					network=network,
				)
				quarantine_code = quarantine_code_result.unwrap()

			# Temporarily avoid new chat to reduce cost
			# agent.chat_history += new_ch
			for_training_chat_history += new_ch

			logger.info("Running the resulting security implementation code in container...")
			# 🔧 FIX 3: Extract Python code before execution
			quarantine_code = extract_python_code(quarantine_code)
			code_execution_result = agent.container_manager.run_code_in_con(
				quarantine_code, "security_implementation_code"
			)
			quarantine_code_output, _ = code_execution_result.unwrap()
			success = True
			break
		except UnwrapError as e:
			e = e.result.err()
			if regen:
				logger.error(f"Regen failed on security implementation code, err: \n{e}")
			else:
				logger.error(f"Failed on first security implementation code, err: \n{e}")
			regen = True
			err_acc += f"\n{str(e)}"

	if not success:
		logger.info("Failed generating output of security implementation code after 3 times...")
	else:
		logger.info("Succeeded generating output of security implementation code!")

	logger.info(f"Security implementation output: \n{quarantine_code_output}")

	agent.db.insert_chat_history(session_id, for_training_chat_history)

	end_metric_state = metric_fn()
	agent.db.insert_wallet_snapshot(
		snapshot_id=f"{nanoid(8)}-{session_id}-security",
		agent_id=agent.agent_id,
		total_value_usd=end_metric_state.get("security_score", 0.0) * 100,  # Convert security score to percentage
		assets=json.dumps(end_metric_state),
	)

	summarized_state_change = dedent(f"""
        Security Status Before: {str(start_metric_state).replace("\n", "")}
        Security Score Before: {start_metric_state.get("security_score", 0.0)}
        Security Status After: {str(end_metric_state).replace("\n", "")}
        Security Score After: {end_metric_state.get("security_score", 0.0)}
        Threats Detected: {end_metric_state.get("total_threats_detected", 0)}
        Items Quarantined: {end_metric_state.get("quarantined_items", 0)}
    """)

	summarized_code = summarizer(
		[
			quarantine_code,
			"Summarize the security implementation code above in points",
		]
	)
	logger.info("Summarizing security implementation code...")
	logger.info(f"Summarized security code: \n{summarized_code}")

	logger.info("Saving security strategy and its result...")
	agent.db.insert_strategy_and_result(
		agent_id=agent.agent_id,
		strategy_result=StrategyInsertData(
			summarized_desc=summarizer([strategy_output]),
			full_desc=strategy_output,
			parameters={
				"apis": apis,
				"security_tools": security_tools,
				"metric_name": metric_name,
				"start_metric_state": json.dumps(start_metric_state),
				"end_metric_state": json.dumps(end_metric_state),
				"summarized_state_change": summarized_state_change,
				"summarized_code": summarized_code,
				"code_output": quarantine_code_output,
				"prev_strat": prev_strat.summarized_desc if prev_strat else "",
				"security_score": end_metric_state.get("security_score", 0.0),
				"threats_detected": end_metric_state.get("total_threats_detected", 0),
				"notif_str": notif_str,
			},
			strategy_result="failed" if not success else "success",
		),
	)
	logger.info("Saved security strategy, quitting and preparing for next security monitoring cycle...")


def unassisted_flow(
	agent: SecurityAgent,
	session_id: str,
	role: str,
	time: str,
	apis: List[str],
	metric_name: str,
	prev_strat: StrategyData | None,
	notif_str: str | None,
	summarizer: Callable[[List[str]], str],
):
	"""
	Execute an unassisted security workflow with the security agent.
	Follows exact same pattern as marketing unassisted_flow but for security operations.

	This function orchestrates a simplified security workflow for continuous monitoring
	without user intervention.

	Args:
	    agent (SecurityAgent): The security agent to use
	    session_id (str): Identifier for the current session
	    role (str): Role of the agent (e.g., "security_monitor")
	    time (str): Time frame for the security monitoring goal
	    apis (List[str]): List of APIs available to the agent
	    metric_name (str): Name of the security metric to track
	    prev_strat (StrategyData | None): Previous security strategy, if any
	    notif_str (str | None): Security notification string to process
	    summarizer (Callable[[List[str]], str]): Function to summarize text

	Returns:
	    None: This function doesn't return a value but logs its progress
	"""
	agent.reset()
	logger.info("Reset agent")
	logger.info("Starting on unassisted security monitoring flow")

	start_metric_state = str(agent.sensor.get_metric_fn(metric_name)())

	try:
		assert notif_str is not None
		related_strategies = agent.rag.relevant_strategy_raw(notif_str)

		assert len(related_strategies) != 0
		most_related_strat = related_strategies[0]

		rag_summary = most_related_strat.summarized_desc
		rag_before_metric_state = most_related_strat.parameters["start_metric_state"]
		rag_after_metric_state = most_related_strat.parameters["end_metric_state"]
		logger.info(f"Using related RAG security summary {rag_summary}")
	except (AssertionError, Exception) as e:
		if isinstance(e, Exception):
			logger.warning(f"Error retrieving RAG security strategy: {str(e)}")

		rag_summary = "Unable to retrieve a relevant security strategy from RAG handler..."
		rag_before_metric_state = "Unable to retrieve a relevant security strategy from RAG handler..."
		rag_after_metric_state = "Unable to retrieve a relevant security strategy from RAG handler..."
		logger.info("Using empty RAG security result")

	logger.info(f"Using security metric: {metric_name}")
	logger.info(f"Current state of the security metric: {start_metric_state}")

	new_ch = agent.prepare_system(
		role=role,
		time=time,
		metric_name=metric_name,
		metric_state=start_metric_state,
		network="solana",  # Default to Solana for security monitoring
	)
	agent.chat_history += new_ch

	logger.info("Initialized system prompt")

	logger.info("Attempt to generate security analysis code...")
	analysis_code = ""
	err_acc = ""
	regen = False
	success = False
	for i in range(3):
		try:
			if regen:
				logger.info("Attempt to regenerate security analysis code...")
				analysis_code_result = agent.regen_on_error(
					errors=err_acc,
					latest_response=new_ch.get_latest_response(),
				)
				analysis_code = analysis_code_result.unwrap()
			else:
				if not prev_strat:
					analysis_code_result, new_ch = agent.gen_analysis_code_on_first(
						apis=apis, network="solana"
					)
					analysis_code = analysis_code_result.unwrap()
				else:
					analysis_code_result, new_ch = agent.gen_analysis_code(
						notifications_str=notif_str if notif_str else "Continuous monitoring",
						apis=apis,
						prev_analysis=prev_strat.summarized_desc if prev_strat else "No previous analysis",
						rag_summary=rag_summary,
						before_metric_state=rag_before_metric_state,
						after_metric_state=rag_after_metric_state,
					)
					analysis_code = analysis_code_result.unwrap()

			agent.chat_history += new_ch

			logger.info("Running the resulting security analysis code in container...")
			# ✅ Already fixed: Extract Python code before execution
			analysis_code = extract_python_code(analysis_code)
			code_execution_result = agent.container_manager.run_code_in_con(
				analysis_code, "unassisted_security_analysis"
			)
			analysis_code_output, _ = code_execution_result.unwrap()
			success = True
			break
		except UnwrapError as e:
			e = e.result.err()
			if regen:
				logger.error(f"Regen failed on security analysis code, err: \n{e}")
			else:
				logger.error(f"Failed on first security analysis code, err: \n{e}")
			regen = True
			err_acc += f"\n{str(e)}"

	if not success:
		logger.error("Failed generating output of security analysis code after 3 times...")
		return

	logger.info("Succeeded security analysis")
	logger.info(f"Security analysis output: \n{analysis_code_output}")

	end_metric_state = str(agent.sensor.get_metric_fn(metric_name)())

	logger.info("Saving unassisted security monitoring result...")
	agent.db.insert_strategy_and_result(
		agent_id=agent.agent_id,
		strategy_result=StrategyInsertData(
			summarized_desc=summarizer([analysis_code_output]),
			full_desc=analysis_code_output,
			parameters={
				"apis": apis,
				"metric_name": metric_name,
				"start_metric_state": start_metric_state,
				"end_metric_state": end_metric_state,
				"code_output": analysis_code_output,
				"prev_strat": prev_strat.summarized_desc if prev_strat else "",
				"notif_str": notif_str,
				"flow_type": "unassisted_security_monitoring",
			},
			strategy_result="success" if success else "failed",
		),
	)
	logger.info("Saved unassisted security monitoring result, preparing for next cycle...")