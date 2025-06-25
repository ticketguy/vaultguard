"""
MEV (Maximal Extractable Value) Detection for Solana
Detects sandwich attacks, front-running, and MEV exploitation attempts
Adapted to work with SecuritySensor framework
"""

import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import json


class MEVDetector:
    """
    Detect MEV attacks and exploitation patterns on Solana blockchain.
    Provides comprehensive analysis of MEV risks for transaction security.
    """
    
    def __init__(self):
        # Solana-specific MEV attack patterns and thresholds
        self.mev_patterns = {
            'sandwich_attacks': {
                'priority_fee_spike': 2.0,      # Priority fee multiplier indicating sandwich
                'timing_window_ms': 1000,       # Time window for sandwich detection
                'slippage_threshold': 0.03,     # Slippage percentage threshold
                'min_trade_size': 100           # Minimum USD value for profitable sandwich
            },
            'front_running': {
                'priority_fee_multiplier': 1.5, # Fee multiplier indicating front-running
                'mempool_position_risk': 0.8,   # Risk score for mempool position
                'token_launch_window': 300      # Seconds around token launches
            },
            'arbitrage_mev': {
                'price_discrepancy': 0.02,      # Price difference threshold across DEXs
                'high_frequency_threshold': 10, # Trade count indicating arbitrage bot
                'cross_dex_indicators': ['jupiter', 'raydium', 'orca']
            },
            'liquidation_mev': {
                'health_factor_threshold': 1.1, # Health factor indicating liquidation risk
                'borrowing_protocols': ['marginfi', 'solend', 'mango'],
                'priority_fee_competition': 3.0 # Fee competition for liquidations
            }
        }
        
        # Current network conditions for MEV analysis
        self.market_conditions = {
            'average_priority_fee': 0.001,     # Average priority fee in SOL
            'network_congestion': 0.3,         # Network congestion level (0-1)
            'active_mev_bots': 150,            # Estimated active MEV bots
            'high_mev_tokens': []              # Tokens with high MEV activity
        }
    
    async def analyze_mev_risk(self, transaction_data: Dict) -> Dict:
        """
        Analyze transaction for MEV risks and exploitation patterns.
        Returns comprehensive MEV risk assessment compatible with SecuritySensor.
        """
        analysis_start = datetime.now()
        
        # Initialize analysis result structure
        mev_analysis = {
            'mev_risk': 0.0,                    # Framework expects 'mev_risk' field
            'overall_mev_risk': 0.0,           # Keep original field for compatibility
            'mev_threats': [],
            'risk_factors': {},
            'user_warnings': [],
            'recommended_actions': [],
            'threats_found': 0,                 # SecuritySensor expects this field
            'high_risk': False,                 # SecuritySensor expects this field
            'analysis_time': 0.0
        }
        
        try:
            # Run all MEV detection analyses
            sandwich_risk = await self._detect_sandwich_risk(transaction_data)
            mev_analysis['risk_factors']['sandwich_attack'] = sandwich_risk
            
            front_running_risk = await self._detect_front_running_risk(transaction_data)
            mev_analysis['risk_factors']['front_running'] = front_running_risk
            
            arbitrage_risk = await self._detect_arbitrage_mev(transaction_data)
            mev_analysis['risk_factors']['arbitrage_mev'] = arbitrage_risk
            
            liquidation_risk = await self._detect_liquidation_mev(transaction_data)
            mev_analysis['risk_factors']['liquidation_mev'] = liquidation_risk
            
            priority_fee_risk = await self._analyze_priority_fee_competition(transaction_data)
            mev_analysis['risk_factors']['priority_fee_competition'] = priority_fee_risk
            
            # Calculate overall MEV risk score
            overall_risk = await self._calculate_overall_mev_risk(mev_analysis['risk_factors'])
            mev_analysis['overall_mev_risk'] = overall_risk
            mev_analysis['mev_risk'] = overall_risk  # Framework compatibility
            
            # Determine if this constitutes high risk
            mev_analysis['high_risk'] = overall_risk > 0.7
            
            # Count threats found for SecuritySensor
            mev_analysis['threats_found'] = sum(
                1 for factor in mev_analysis['risk_factors'].values() 
                if factor.get('risk_score', 0) > 0.5
            )
            
            # Generate user warnings and recommendations
            mev_analysis['user_warnings'] = await self._generate_mev_warnings(
                mev_analysis['risk_factors']
            )
            mev_analysis['recommended_actions'] = await self._generate_mev_recommendations(
                mev_analysis['risk_factors']
            )
            
            # Identify specific MEV threat categories
            mev_analysis['mev_threats'] = await self._identify_mev_threats(
                mev_analysis['risk_factors']
            )
            
        except Exception as e:
            # Handle analysis errors gracefully
            mev_analysis['error'] = f"MEV analysis failed: {str(e)}"
            mev_analysis['overall_mev_risk'] = 0.5  # Default to moderate risk
            mev_analysis['mev_risk'] = 0.5
            mev_analysis['threats_found'] = 1
        
        # Record analysis performance
        analysis_time = (datetime.now() - analysis_start).total_seconds()
        mev_analysis['analysis_time'] = analysis_time
        
        return mev_analysis
    
    async def _detect_sandwich_risk(self, transaction_data: Dict) -> Dict:
        """
        Detect potential sandwich attack risk based on transaction characteristics.
        Sandwich attacks involve front-running and back-running a victim's transaction.
        """
        risk_score = 0.0
        indicators = []
        
        # Check if transaction is a token swap (primary target for sandwiches)
        if self._is_swap_transaction(transaction_data):
            risk_score += 0.3
            indicators.append("swap_transaction")
        
        # Analyze trade size (larger trades are more profitable to sandwich)
        trade_value = float(transaction_data.get('value_usd', 0))
        if trade_value > self.mev_patterns['sandwich_attacks']['min_trade_size']:
            # Scale risk with trade size but cap at 0.4
            risk_score += min(trade_value / 1000 * 0.1, 0.4)
            indicators.append("large_trade_size")
        
        # Check slippage tolerance (higher tolerance = easier sandwich)
        slippage = transaction_data.get('slippage_tolerance', 0.01)
        if slippage > self.mev_patterns['sandwich_attacks']['slippage_threshold']:
            risk_score += 0.2
            indicators.append("high_slippage_tolerance")
        
        # Check DEX popularity (high-volume DEXs have more MEV activity)
        if self._is_high_mev_dex(transaction_data):
            risk_score += 0.3
            indicators.append("high_mev_dex")
        
        # Factor in network congestion
        if self.market_conditions['network_congestion'] > 0.7:
            risk_score += 0.2
            indicators.append("network_congestion")
        
        return {
            'risk_score': min(risk_score, 1.0),
            'indicators': indicators,
            'threat_level': self._get_threat_level(risk_score),
            'sandwich_profitable': trade_value > 500 and slippage > 0.02
        }
    
    async def _detect_front_running_risk(self, transaction_data: Dict) -> Dict:
        """
        Detect front-running risk where MEV bots copy transactions with higher fees.
        Common in token launches and time-sensitive operations.
        """
        risk_score = 0.0
        indicators = []
        
        # Check for new token launch activity (high front-running target)
        if self._is_token_launch_transaction(transaction_data):
            risk_score += 0.6
            indicators.append("token_launch")
        
        # Analyze priority fee competition
        priority_fee = float(transaction_data.get('priority_fee', 0))
        if priority_fee > self.market_conditions['average_priority_fee'] * 1.5:
            risk_score += 0.4
            indicators.append("high_priority_fee")
        
        # Check for time-sensitive operations
        if self._is_time_sensitive_operation(transaction_data):
            risk_score += 0.3
            indicators.append("time_sensitive")
        
        # Estimate mempool competition level
        mempool_competition = await self._estimate_mempool_competition(transaction_data)
        if mempool_competition > 0.7:
            risk_score += 0.3
            indicators.append("mempool_competition")
        
        return {
            'risk_score': min(risk_score, 1.0),
            'indicators': indicators,
            'threat_level': self._get_threat_level(risk_score),
            'front_running_likely': risk_score > 0.6
        }
    
    async def _detect_arbitrage_mev(self, transaction_data: Dict) -> Dict:
        """
        Detect arbitrage MEV opportunities that could affect transaction outcome.
        Arbitrage bots exploit price differences across DEXs.
        """
        risk_score = 0.0
        indicators = []
        
        # Check for cross-DEX arbitrage patterns
        if self._involves_multiple_dexs(transaction_data):
            risk_score += 0.4
            indicators.append("cross_dex_arbitrage")
        
        # Detect rapid sequential trades (arbitrage bot behavior)
        if await self._check_rapid_trades(transaction_data):
            risk_score += 0.4
            indicators.append("rapid_sequential_trades")
        
        # Check for price discrepancies that enable arbitrage
        price_discrepancy = await self._check_price_discrepancies(transaction_data)
        if price_discrepancy > self.mev_patterns['arbitrage_mev']['price_discrepancy']:
            risk_score += 0.3
            indicators.append("price_discrepancy")
        
        return {
            'risk_score': min(risk_score, 1.0),
            'indicators': indicators,
            'threat_level': self._get_threat_level(risk_score),
            'arbitrage_opportunity': price_discrepancy > 0.01
        }
    
    async def _detect_liquidation_mev(self, transaction_data: Dict) -> Dict:
        """
        Detect liquidation MEV where bots compete to liquidate undercollateralized positions.
        High competition leads to failed transactions and priority fee wars.
        """
        risk_score = 0.0
        indicators = []
        
        # Check if transaction involves lending protocols
        if self._involves_lending_protocol(transaction_data):
            risk_score += 0.4
            indicators.append("lending_protocol")
        
        # Check for liquidation-related instructions
        if self._is_liquidation_transaction(transaction_data):
            risk_score += 0.6
            indicators.append("liquidation_transaction")
        
        # Check priority fee competition for liquidations
        priority_fee = float(transaction_data.get('priority_fee', 0))
        if priority_fee > self.market_conditions['average_priority_fee'] * 3.0:
            risk_score += 0.3
            indicators.append("liquidation_fee_competition")
        
        return {
            'risk_score': min(risk_score, 1.0),
            'indicators': indicators,
            'threat_level': self._get_threat_level(risk_score),
            'liquidation_competition': risk_score > 0.5
        }
    
    async def _analyze_priority_fee_competition(self, transaction_data: Dict) -> Dict:
        """
        Analyze priority fee competition that may cause transaction failures.
        High competition indicates MEV bot activity.
        """
        risk_score = 0.0
        indicators = []
        
        priority_fee = float(transaction_data.get('priority_fee', 0))
        average_fee = self.market_conditions['average_priority_fee']
        
        # Calculate fee ratio compared to network average
        fee_ratio = priority_fee / max(average_fee, 0.0001)
        
        if fee_ratio > 3.0:
            risk_score = 0.8
            indicators.append("extreme_fee_competition")
        elif fee_ratio > 2.0:
            risk_score = 0.6
            indicators.append("high_fee_competition")
        elif fee_ratio > 1.5:
            risk_score = 0.4
            indicators.append("moderate_fee_competition")
        
        return {
            'risk_score': risk_score,
            'fee_ratio': fee_ratio,
            'indicators': indicators,
            'threat_level': self._get_threat_level(risk_score),
            'likely_to_fail': fee_ratio < 0.5 and self.market_conditions['network_congestion'] > 0.6
        }
    
    async def _calculate_overall_mev_risk(self, risk_factors: Dict) -> float:
        """
        Calculate weighted overall MEV risk score from individual risk factors.
        Higher weights assigned to more dangerous MEV types.
        """
        weights = {
            'sandwich_attack': 0.3,      # High impact on user trades
            'front_running': 0.25,       # Common and harmful
            'arbitrage_mev': 0.2,        # Moderate impact
            'liquidation_mev': 0.15,     # Specific to lending protocols
            'priority_fee_competition': 0.1  # General network condition
        }
        
        overall_risk = 0.0
        for factor, weight in weights.items():
            if factor in risk_factors:
                factor_risk = risk_factors[factor].get('risk_score', 0)
                overall_risk += factor_risk * weight
        
        return min(overall_risk, 1.0)
    
    async def _generate_mev_warnings(self, risk_factors: Dict) -> List[str]:
        """Generate clear, actionable warnings about MEV risks for users"""
        warnings = []
        
        # Sandwich attack warnings
        sandwich_data = risk_factors.get('sandwich_attack', {})
        if sandwich_data.get('risk_score', 0) > 0.6:
            warnings.append("⚡ High sandwich attack risk - consider reducing trade size or increasing slippage tolerance")
        
        # Front-running warnings
        front_running_data = risk_factors.get('front_running', {})
        if front_running_data.get('risk_score', 0) > 0.6:
            warnings.append("🏃 Front-running risk detected - your transaction may be copied with higher priority fees")
        
        # Priority fee competition warnings
        fee_data = risk_factors.get('priority_fee_competition', {})
        if fee_data.get('fee_ratio', 0) > 2.0:
            warnings.append("💰 High priority fee competition - transaction may be delayed or fail")
        
        # Arbitrage warnings
        arbitrage_data = risk_factors.get('arbitrage_mev', {})
        if arbitrage_data.get('risk_score', 0) > 0.5:
            warnings.append("🔄 Arbitrage MEV detected - price impact may be higher than expected")
        
        # Liquidation warnings
        liquidation_data = risk_factors.get('liquidation_mev', {})
        if liquidation_data.get('risk_score', 0) > 0.7:
            warnings.append("🚨 Liquidation MEV risk - position may be liquidated by MEV bots")
        
        return warnings
    
    async def _generate_mev_recommendations(self, risk_factors: Dict) -> List[str]:
        """Generate actionable recommendations to mitigate MEV risks"""
        recommendations = []
        
        # Sandwich protection recommendations
        if risk_factors.get('sandwich_attack', {}).get('risk_score', 0) > 0.5:
            recommendations.extend([
                "Consider breaking large trades into smaller chunks",
                "Use private mempools or MEV-protected transaction pools",
                "Increase slippage tolerance slightly to reduce sandwich profitability"
            ])
        
        # Front-running protection recommendations
        if risk_factors.get('front_running', {}).get('risk_score', 0) > 0.5:
            recommendations.extend([
                "Use commit-reveal schemes for sensitive transactions",
                "Consider timing transactions during low-congestion periods",
                "Use MEV-protected DEXs when available"
            ])
        
        # Priority fee optimization recommendations
        fee_data = risk_factors.get('priority_fee_competition', {})
        if fee_data.get('risk_score', 0) > 0.6:
            recommendations.append("Wait for lower network congestion or increase priority fees significantly")
        
        return recommendations
    
    async def _identify_mev_threats(self, risk_factors: Dict) -> List[str]:
        """Identify specific MEV threat categories present in the transaction"""
        threats = []
        
        for threat_type, data in risk_factors.items():
            if data.get('risk_score', 0) > 0.5:
                threats.append(f"mev_{threat_type}")
        
        return threats
    
    # Helper methods for transaction classification and analysis
    
    def _is_swap_transaction(self, transaction_data: Dict) -> bool:
        """Check if transaction involves token swapping"""
        instruction_type = transaction_data.get('instruction_type', '').lower()
        program_id = transaction_data.get('program_id', '').lower()
        return ('swap' in instruction_type or 'trade' in instruction_type or
                any(dex in program_id for dex in ['jupiter', 'raydium', 'orca']))
    
    def _is_high_mev_dex(self, transaction_data: Dict) -> bool:
        """Check if transaction uses a DEX with high MEV activity"""
        program_id = transaction_data.get('program_id', '').lower()
        high_mev_programs = ['jupiter', 'raydium', 'orca', 'serum']
        return any(program in program_id for program in high_mev_programs)
    
    def _is_token_launch_transaction(self, transaction_data: Dict) -> bool:
        """Check if transaction is related to new token launch"""
        instruction_type = transaction_data.get('instruction_type', '').lower()
        return ('mint' in instruction_type or 'launch' in instruction_type or
                transaction_data.get('is_new_token', False))
    
    def _is_time_sensitive_operation(self, transaction_data: Dict) -> bool:
        """Check if operation is time-sensitive (target for front-running)"""
        time_sensitive_ops = ['liquidate', 'claim', 'mint', 'redeem']
        instruction_type = transaction_data.get('instruction_type', '').lower()
        return any(op in instruction_type for op in time_sensitive_ops)
    
    def _involves_multiple_dexs(self, transaction_data: Dict) -> bool:
        """Check if transaction involves multiple DEXs (arbitrage indicator)"""
        # Check for multiple program interactions in compound transactions
        programs = transaction_data.get('involved_programs', [])
        dex_programs = ['jupiter', 'raydium', 'orca', 'serum']
        involved_dexs = sum(1 for program in programs if any(dex in program.lower() for dex in dex_programs))
        return involved_dexs > 1
    
    def _involves_lending_protocol(self, transaction_data: Dict) -> bool:
        """Check if transaction involves lending/borrowing protocols"""
        program_id = transaction_data.get('program_id', '').lower()
        lending_protocols = self.mev_patterns['liquidation_mev']['borrowing_protocols']
        return any(protocol in program_id for protocol in lending_protocols)
    
    def _is_liquidation_transaction(self, transaction_data: Dict) -> bool:
        """Check if transaction is a liquidation operation"""
        instruction_type = transaction_data.get('instruction_type', '').lower()
        return 'liquidate' in instruction_type
    
    def _get_threat_level(self, risk_score: float) -> str:
        """Convert numerical risk score to threat level description"""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        elif risk_score >= 0.2:
            return "low"
        else:
            return "minimal"
    
    # Placeholder methods for blockchain data integration
    # Replace these with real Solana RPC calls via meta-swap-api
    
    async def _estimate_mempool_competition(self, transaction_data: Dict) -> float:
        """Estimate competition level in mempool for similar transactions"""
        # TODO: Integrate with real mempool analysis
        # For now, return moderate competition based on network congestion
        return self.market_conditions['network_congestion'] * 0.8
    
    async def _check_rapid_trades(self, transaction_data: Dict) -> bool:
        """Check for rapid sequential trades indicating arbitrage bot activity"""
        # TODO: Integrate with transaction history analysis
        # For now, use heuristic based on transaction timing patterns
        return False
    
    async def _check_price_discrepancies(self, transaction_data: Dict) -> float:
        """Check price discrepancies across DEXs for arbitrage opportunities"""
        # TODO: Integrate with real price data from multiple DEXs
        # For now, return small discrepancy to avoid false positives
        return 0.01