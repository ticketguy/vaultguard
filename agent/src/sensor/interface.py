from typing import Dict, Any, Callable


class SecuritySensorInterface:
	"""
	Interface for any SecuritySensor that provides blockchain security monitoring
	and threat detection capabilities.
	"""

	def get_security_status(self) -> Dict[str, Any]:
		"""
		Returns the current security status of monitored wallets.
		"""
		...

	def get_transaction_threats(self) -> Dict[str, Any]:
		"""
		Returns detected threats from recent transactions.
		"""
		...

	def get_metric_fn(
		self, metric_name: str = "security"
	) -> Callable[[], Dict[str, Any]]:
		"""
		Returns a callable that fetches a security metric by name.
		"""
		...