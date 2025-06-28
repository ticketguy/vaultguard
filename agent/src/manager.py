"""
Manager module for handling security agent configuration and prompts.
Updated to work with security-only framework.
"""

from pprint import pformat
from loguru import logger
from src.agent.security import SecurityPromptGenerator
from src.constants import FE_DATA_SECURITY_DEFAULTS


class ManagerClient:
	"""Client for interacting with the manager service to handle session data and communication."""

	def __init__(self, base_url: str, session_id: str):
		"""
		Initialize the ManagerClient with base URL and session ID.

		Args:
		        base_url (str): The base URL of the manager service API
		        session_id (str): The unique identifier for the current session
		"""
		self.base_url = base_url
		self.session_id = session_id

	def fetch_fe_data(self, type: str):
		"""
		Fetch frontend data for the specified agent type.

		Args:
		        type (str): The type of agent (only "security" supported)

		Returns:
		        dict: A dictionary containing the frontend data with defaults filled in

		Note:
		        If an error occurs during fetching, the method falls back to default values
		        and logs the error.
		"""
		# Only support security type now
		if type != "security":
			logger.warning(f"Unsupported agent type: {type}. Using security defaults.")
			type = "security"
		
		fe_data = FE_DATA_SECURITY_DEFAULTS.copy()

		try:
			# Get default prompts for security
			default_prompts = SecurityPromptGenerator.get_default_prompts()

			logger.info(f"Available default prompts: {list(default_prompts.keys())}")

			# Only fill in missing prompts from defaults
			missing_prompts = set(default_prompts.keys()) - set(
				fe_data["prompts"].keys()
			)
			if missing_prompts:
				logger.info(f"Adding missing default prompts: {list(missing_prompts)}")
				for key in missing_prompts:
					fe_data["prompts"][key] = default_prompts[key]
		except Exception as e:
			logger.error(f"Error fetching session logs: {e}, going with defaults")
			# In case of error, return fe_data with default prompts
			default_prompts = SecurityPromptGenerator.get_default_prompts()
			fe_data["prompts"].update(default_prompts)

		logger.info(f"Final prompts: \n{pformat(fe_data['prompts'], 1)}")

		return fe_data


def fetch_fe_data(type: str):
	manager_client = ManagerClient("", "")
	return manager_client.fetch_fe_data(type)


def fetch_default_prompt(fe_data, type: str):
    # Get default prompts for security only
    input_data = fe_data.copy()
    
    # Only support security type
    if type != "security":
        logger.warning(f"Unsupported agent type: {type}. Using security defaults.")
        type = "security"
    
    default_prompts = SecurityPromptGenerator.get_default_prompts()
    
    try:
        logger.info(f"Available default prompts: {list(default_prompts.keys())}")

        # Initialize prompts if it doesn't exist
        if "prompts" not in input_data:
            input_data["prompts"] = {}

        # Only fill in missing prompts from defaults
        missing_prompts = set(default_prompts.keys()) - set(
            input_data["prompts"].keys()
        )
        if missing_prompts:
            logger.info(f"Adding missing default prompts: {list(missing_prompts)}")
            for key in missing_prompts:
                input_data["prompts"][key] = default_prompts[key]
        return input_data["prompts"]
    except Exception as e:
        logger.error(f"Error fetching default prompts: {e}, going with defaults")
        return default_prompts