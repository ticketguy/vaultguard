"""
MockSecuritySensor - Replaces MockTradingSensor for testing
Follows exact same pattern as MockTradingSensor but for security testing
"""

from typing import Any, Dict
from functools import partial
import time

# Mock security data for testing (follows same pattern as mock_portfolio)
mock_security_status = {
	"total_threats_detected": 5,
	"security_score": 0.72,  # 72% security health
	"quarantined_items": 3,
	"wallets_monitored": [
		"7xKs1aTF7YbL8C9s3mZNbGKPFXCWuBvf9Ss623VQ5DA",
		"9mNp2bK8fG3cCd4sVhMnBkLpQrTt5RwXyZ7nE8hS1kL"
	],
	"threat_breakdown": {
		"dust_attacks": 2,
		"suspicious_tokens": 1,
		"mev_risks": 1,
		"scam_nfts": 1,
		"drain_contracts": 0,
	},
	"recent_threats": [
		{
			"threat_id": "dust_001",
			"threat_type": "dust_attack",
			"from_address": "11111111111111111111111111111112",
			"to_address": "7xKs1aTF7YbL8C9s3mZNbGKPFXCWuBvf9Ss623VQ5DA",
			"amount_sol": 0.00001,
			"risk_score": 0.85,
			"status": "quarantined",
			"detected_at": int(time.time() - 300),  # 5 minutes ago
		},
		{
			"threat_id": "token_002", 
			"threat_type": "suspicious_token",
			"token_mint": "FakeUSDC123tokenMintAddress456",
			"token_name": "Free USDC Airdrop",
			"risk_score": 0.92,
			"status": "quarantined",
			"detected_at": int(time.time() - 180),  # 3 minutes ago
		},
		{
			"threat_id": "mev_003",
			"threat_type": "mev_risk", 
			"program_id": "JUP4xgCGTCTqjF1VkL1PDQk3qsXTXJkxJxTpSn3dek4",
			"transaction_signature": "mock_signature_123abc",
			"risk_score": 0.68,
			"status": "warned",
			"detected_at": int(time.time() - 60),  # 1 minute ago
		},
	],
	"timestamp": int(time.time()),
}


def get_mock_security_stats(wallet_addresses: list, solana_rpc_url: str, helius_api_key: str) -> Dict[str, Any]:
	"""
	Get mock security statistics for testing.
	Follows exact same pattern as get_mock_wallet_stats from MockTradingSensor.
	"""
	
	# Mock response that simulates real security monitoring
	mock_response = {
		"monitored_wallets": wallet_addresses,
		"total_threats_detected": mock_security_status["total_threats_detected"],
		"security_score": mock_security_status["security_score"],
		"quarantined_items": mock_security_status["quarantined_items"],
		"threat_breakdown": mock_security_status["threat_breakdown"],
		"recent_activity": mock_security_status["recent_threats"],
		"protection_status": {
			"dust_protection": "enabled",
			"mev_protection": "enabled", 
			"token_scam_protection": "enabled",
			"nft_scam_protection": "enabled",
			"contract_analysis": "enabled",
		},
		"rpc_status": "connected_mock",
		"api_status": {
			"solana_rpc": "mock_connected",
			"helius": "mock_connected" if helius_api_key else "not_configured",
		},
		"last_scan": int(time.time()),
		"scan_frequency": "real_time",
		"performance": {
			"threats_blocked_24h": 12,
			"false_positives_24h": 1,
			"accuracy_rate": 0.95,
			"avg_detection_time_ms": 125,
		},
		"timestamp": int(time.time()),
	}
	
	return mock_response


class MockSecuritySensor:
	"""
	Mock SecuritySensor for testing without real blockchain connections.
	Follows exact same structure as MockTradingSensor.
	"""
	
	def __init__(
		self, wallet_addresses: list, solana_rpc_url: str, helius_api_key: str
	):
		"""
		Initialize MockSecuritySensor with same parameters as real SecuritySensor.
		Follows exact same __init__ pattern as MockTradingSensor.
		"""
		self.wallet_addresses = wallet_addresses
		self.solana_rpc_url = solana_rpc_url
		self.helius_api_key = helius_api_key

	def get_security_status(self) -> Dict[str, Any]:
		"""
		Get mock security status.
		Replaces get_portfolio_status() from MockTradingSensor.
		"""
		security_stats = get_mock_security_stats(
			self.wallet_addresses, self.solana_rpc_url, self.helius_api_key
		)
		
		return security_stats

	def get_transaction_threats(self) -> Dict[str, Any]:
		"""
		Get mock threat detection data.
		Additional method for security-specific functionality.
		"""
		security_stats = self.get_security_status()
		
		return {
			"recent_threats": security_stats.get("recent_activity", []),
			"threat_count": security_stats.get("total_threats_detected", 0),
			"last_scan": security_stats.get("last_scan", int(time.time())),
			"protection_enabled": True,
		}

	def get_metric_fn(self, metric_name: str = "security") -> callable:
		"""
		Get a callable that fetches mock security metrics.
		Follows exact same pattern as MockTradingSensor.get_metric_fn().
		"""
		metrics = {
			"security": partial(
				get_mock_security_stats,
				self.wallet_addresses,
				self.solana_rpc_url,
				self.helius_api_key,
			),
			"threats": partial(self.get_transaction_threats),
			"status": partial(self.get_security_status),
		}
		
		if metric_name not in metrics:
			raise ValueError(f"Unsupported metric: {metric_name}")
			
		return metrics[metric_name]


if __name__ == "__main__":
	# Test MockSecuritySensor following same pattern as MockTradingSensor test
	test_wallets = [
		"7xKs1aTF7YbL8C9s3mZNbGKPFXCWuBvf9Ss623VQ5DA",
		"9mNp2bK8fG3cCd4sVhMnBkLpQrTt5RwXyZ7nE8hS1kL"
	]
	
	mock_sensor = MockSecuritySensor(
		wallet_addresses=test_wallets,
		solana_rpc_url="mock://solana-rpc", 
		helius_api_key="mock_helius_key"
	)
	
	# Test the methods
	print("Mock Security Status:")
	print(mock_sensor.get_security_status())
	
	print("\nMock Threats:")
	print(mock_sensor.get_transaction_threats())
	
	# Test metric function  
	security_metric_fn = mock_sensor.get_metric_fn("security")
	print("\nMock Security Metric:")
	print(security_metric_fn())
	
	print("\n✅ MockSecuritySensor test completed")