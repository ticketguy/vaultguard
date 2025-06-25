"""
Constants for Security Framework
Updated to support security-only agents
"""

from textwrap import dedent
from typing import Dict, List

# Security framework defaults (replaces trading/marketing defaults)
FE_DATA_SECURITY_DEFAULTS = {
	"model": "claude",
	"role": "Web3 wallet security analyst with expertise in Solana blockchain threat detection",
	"network": "solana",
	"time": "24h",
	"metric_name": "security",
	"research_tools": [
		"Solana RPC",
		"Threat Intelligence",
		"DuckDuckGo",
	],
	"security_tools": [
		"quarantine",
		"block", 
		"monitor",
		"analyze"
	],
	"notifications": ["blockchain_alerts", "security_alerts"],
	"prompts": {},
}

# Keep the service mappings for research tools
SERVICE_TO_PROMPT = {
	"Solana RPC": "Solana RPC (env vars SOLANA_RPC_URL)",
	"Threat Intelligence": "Threat Intelligence feeds for security analysis",
	"DuckDuckGo": "DuckDuckGo search for threat research",
	"CoinGecko": dedent("""
		<CoinGeckoTrendingCoins>
		curl -X GET "https://pro-api.coingecko.com/api/v3/search/trending?x_cg_pro_api_key={{COINGECKO_API_KEY}}" # To find trending coins
		{{
			"type": "object",
			"required": [
				"coins"
			],
			"properties": {{
				"coins": {{
					"type": "array",
					"description": "List of trending cryptocurrencies",
					"items": {{
						"type": "object",
						"required": [
							"item"
						],
						"properties": {{
							"item": {{
								"type": "object",
								"required": [
									"id",
									"symbol",
									"market_cap_rank",
									"slug",
									"platforms"
								],
								"properties": {{
									"id": {{
										"type": "string",
										"description": "Unique identifier for the coin"
									}},
									"symbol": {{
										"type": "string",
										"description": "Trading symbol"
									}},
									"market_cap_rank": {{
										"type": "integer",
										"description": "Ranking by market cap"
									}},
									"slug": {{
										"type": "string",
										"description": "URL-friendly identifier"
									}},
									"platforms": {{
										"type": "object",
										"description": "Available blockchain platforms and contract addresses",
										"additionalProperties": {{
											"type": "string"
										}}
									}}
								}}
							}}
						}}
					}}
				}}
			}}
		}}
		</CoinGeckoTrendingCoins>
	"""),
	"Etherscan": "Etherscan (env vars ETHERSCAN_API_KEY)",
	"1inch": "1inch (env vars ONEINCH_API_KEY)",
	"Infura": "Infura (env vars INFURA_PROJECT_ID)",
}

SERVICE_TO_ENV: Dict[str, List[str]] = {
	"Solana RPC": [
		"SOLANA_RPC_URL",
	],
	"Threat Intelligence": [],
	"DuckDuckGo": [],
	"CoinGecko": [
		"COINGECKO_API_KEY",
	],
	"Etherscan": [
		"ETHERSCAN_API_KEY",
	],
	"1inch": [
		"ONEINCH_API_KEY",
	],
	"Infura": [
		"INFURA_PROJECT_ID",
	],
}