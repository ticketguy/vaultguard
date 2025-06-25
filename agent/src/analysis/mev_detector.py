"""
MEV (Maximal Extractable Value) Detection for Solana
Detects sandwich attacks, front-running, and MEV exploitation attempts
"""

import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import json

class MEVDetector:
    """
    Detect MEV attacks and exploitation patterns on Solana
    """
    
    def __init__(self):
        # Solana-specific MEV patterns
        self.mev_patterns = {
            'sandwich_attacks': {
                'priority_fee_spike': 2.0,      # 2x normal priority fee indicates sandwich
                'timing_window_ms': 1000,       # 1 second window for sandwich detection
                'slippage_threshold': 0.03,     # 3% slippage warning
                'min_trade_size': 100           # USD minimum for sandwich profitability
            },
            'front_running': {
                'priority_fee_multiplier': 1.5, # 1.5x priority fee indicates front-running
                'mempool_position_risk': 0.8,   # High risk if many competing txns
                'token_launch_window': 300      # 5 minutes around token launches
            },
            'arbitrage_mev': {
                'price_discrepancy': 0.02,      # 2% price difference across DEXs
                'high_frequency_threshold': 10, # 10+ trades in short period
                'cross_dex_indicators': ['jupiter', 'raydium', 'orca']
            },
            'liquidation_mev': {
                'health_factor_threshold': 1.1, # Close to liquidation
                'borrowing_protocols': ['marginfi', 'solend', 'mango'],
                'priority_fee_competition': 3.0 # 3x normal fee competition
            }
        }
        
        # Current market conditions (would be updated in real-time)
        self.market_conditions = {
            'average_priority_fee': 0.001,     # SOL
            'network_congestion': 0.3,         # 0-1 scale
            'active_mev_bots': 150,            # Estimated active MEV bots
            'high_mev_tokens': []              # Tokens with active MEV
        }
    
    async def analyze_mev_risk(self, transaction_data: Dict) -> Dict:
        """
        Comprehensive MEV risk analysis for a transaction
        """
        analysis_start = datetime.now()
        
        mev_analysis = {
            'overall_mev_risk': 0.0,
            'mev_threats': [],
            'risk_factors': {},
            'user_warnings': [],
            'recommended_actions': [],
            'analysis_time': 0.0
        }
        
        try:
            # 1. Sandwich Attack Detection
            sandwich_risk = await self._detect_sandwich_risk(transaction_data)
            mev_analysis['risk_factors']['sandwich_attack'] = sandwich_risk
            
            # 2. Front-Running Detection
            front_running_risk = await self._detect_front_running_risk(transaction_data)
            mev_analysis['risk_factors']['front_running'] = front_running_risk
            
            # 3. Arbitrage MEV Detection
            arbitrage_risk = await self._detect_arbitrage_mev(transaction_data)
            mev_analysis['risk_factors']['arbitrage_mev'] = arbitrage_risk
            
            # 4. Liquidation MEV Detection
            liquidation_risk = await self._detect_liquidation_mev(transaction_data)
            mev_analysis['risk_factors']['liquidation_mev'] = liquidation_risk
            
            # 5. Priority Fee Analysis
            priority_fee_risk = await self._analyze_priority_fee_competition(transaction_data)
            mev_analysis['risk_factors']['priority_fee_competition'] = priority_fee_risk
            
            # Calculate overall MEV risk
            mev_analysis['overall_mev_risk'] = await self._calculate_overall_mev_risk(
                mev_analysis['risk_factors']
            )
            
            # Generate user warnings and recommendations
            mev_analysis['user_warnings'] = await self._generate_mev_warnings(
                mev_analysis['risk_factors']
            )
            mev_analysis['recommended_actions'] = await self._generate_mev_recommendations(
                mev_analysis['risk_factors']
            )
            
            # Identify specific MEV threats
            mev_analysis['mev_threats'] = await self._identify_mev_threats(
                mev_analysis['risk_factors']
            )
            
        except Exception as e:
            mev_analysis['error'] = f"MEV analysis failed: {str(e)}"
            mev_analysis['overall_mev_risk'] = 0.5  # Default to moderate risk on error
        
        # Analysis performance
        analysis_time = (datetime.now() - analysis_start).total_seconds()
        mev_analysis['analysis_time'] = analysis_time
        
        return mev_analysis
    
    async def _detect_sandwich_risk(self, transaction_data: Dict) -> Dict:
        """Detect potential sandwich attack risk"""
        risk_score = 0.0
        indicators = []
        
        # Check transaction type (swaps are primary targets)
        if self._is_swap_transaction(transaction_data):
            risk_score += 0.3
            indicators.append("swap_transaction")
        
        # Check trade size (larger trades = higher sandwich profitability)
        trade_value = float(transaction_data.get('value', 0))
        if trade_value > self.mev_patterns['sandwich_attacks']['min_trade_size']:
            risk_score += min(trade_value / 1000 * 0.1, 0.4)  # Scale with trade size
            indicators.append("large_trade_size")
        
        # Check slippage tolerance
        slippage = transaction_data.get('slippage_tolerance', 0.01)
        if slippage > self.mev_patterns['sandwich_attacks']['slippage_threshold']:
            risk_score += 0.2
            indicators.append("high_slippage_tolerance")
        
        # Check for popular DEX usage (higher MEV activity)
        if self._is_high_mev_dex(transaction_data):
            risk_score += 0.3
            indicators.append("high_mev_dex")
        
        # Check network congestion
        if self.market_conditions['network_congestion'] > 0.7:
            risk_score += 0.2
            indicators.append("network_congestion")
        
        return {
            'risk_score': min(risk_score, 1.0),
            'indicators': indicators,
            'threat_level': self._get_threat_level(risk_score)
        }
    
    async def _detect_front_running_risk(self, transaction_data: Dict) -> Dict:
        """Detect front-running risk"""
        risk_score = 0.0
        indicators = []
        
        # Check if transaction involves new token launch
        if self._is_token_launch_transaction(transaction_data):
            risk_score += 0.6
            indicators.append("token_launch")
        
        # Check priority fee competition
        priority_fee = float(transaction_data.get('priority_fee', 0))
        if priority_fee > self.market_conditions['average_priority_fee'] * 1.5:
            risk_score += 0.4
            indicators.append("high_priority_fee")
        
        # Check for time-sensitive operations
        if self._is_time_sensitive_operation(transaction_data):
            risk_score += 0.3
            indicators.append("time_sensitive")
        
        # Check mempool competition
        mempool_competition = await self._estimate_mempool_competition(transaction_data)
        if mempool_competition > 0.7:
            risk_score += 0.3
            indicators.append("mempool_competition")
        
        return {
            'risk_score': min(risk_score, 1.0),
            'indicators': indicators,
            'threat_level': self._get_threat_level(risk_score)
        }
    
    async def _detect_arbitrage_mev(self, transaction_data: Dict) -> Dict:
        """Detect arbitrage MEV opportunities that could affect user"""
        risk_score = 0.0
        indicators = []
        
        # Check for cross-DEX arbitrage patterns
        if self._involves_multiple_dexs(transaction_data):
            risk_score += 0.4
            indicators.append("cross_dex_arbitrage")
        
        # Check for rapid sequential trades
        if await self._detect_rapid_trading_pattern(transaction_data):
            risk_score += 0.3
            indicators.append("rapid_trading")
        
        # Check for price discrepancies
        price_discrepancy = await self._check_price_discrepancies(transaction_data)
        if price_discrepancy > self.mev_patterns['arbitrage_mev']['price_discrepancy']:
            risk_score += 0.5
            indicators.append("price_discrepancy")
        
        return {
            'risk_score': min(risk_score, 1.0),
            'indicators': indicators,
            'threat_level': self._get_threat_level(risk_score)
        }
    
    async def _detect_liquidation_mev(self, transaction_data: Dict) -> Dict:
        """Detect liquidation MEV scenarios"""
        risk_score = 0.0
        indicators = []
        
        # Check if transaction involves lending protocols
        if self._involves_lending_protocol(transaction_data):
            risk_score += 0.3
            indicators.append("lending_protocol")
        
        # Check for liquidation-related operations
        if self._is_liquidation_transaction(transaction_data):
            risk_score += 0.7
            indicators.append("liquidation_transaction")
        
        # Check for health factor risks
        health_factor = transaction_data.get('health_factor', 2.0)
        if health_factor < self.mev_patterns['liquidation_mev']['health_factor_threshold']:
            risk_score += 0.6
            indicators.append("low_health_factor")
        
        return {
            'risk_score': min(risk_score, 1.0),
            'indicators': indicators,
            'threat_level': self._get_threat_level(risk_score)
        }
    
    async def _analyze_priority_fee_competition(self, transaction_data: Dict) -> Dict:
        """Analyze priority fee competition levels"""
        priority_fee = float(transaction_data.get('priority_fee', 0))
        average_fee = self.market_conditions['average_priority_fee']
        
        if priority_fee == 0:
            fee_ratio = 0
        else:
            fee_ratio = priority_fee / average_fee
        
        risk_score = 0.0
        indicators = []
        
        if fee_ratio > 3.0:
            risk_score = 0.9
            indicators.append("extreme_fee_competition")
        elif fee_ratio > 2.0:
            risk_score = 0.7
            indicators.append("high_fee_competition")
        elif fee_ratio > 1.5:
            risk_score = 0.4
            indicators.append("moderate_fee_competition")
        
        return {
            'risk_score': risk_score,
            'fee_ratio': fee_ratio,
            'indicators': indicators,
            'threat_level': self._get_threat_level(risk_score)
        }
    
    async def _calculate_overall_mev_risk(self, risk_factors: Dict) -> float:
        """Calculate weighted overall MEV risk score"""
        weights = {
            'sandwich_attack': 0.3,
            'front_running': 0.25,
            'arbitrage_mev': 0.2,
            'liquidation_mev': 0.15,
            'priority_fee_competition': 0.1
        }
        
        overall_risk = 0.0
        for factor, weight in weights.items():
            if factor in risk_factors:
                overall_risk += risk_factors[factor]['risk_score'] * weight
        
        return min(overall_risk, 1.0)
    
    async def _generate_mev_warnings(self, risk_factors: Dict) -> List[str]:
        """Generate user-friendly MEV warnings"""
        warnings = []
        
        # Sandwich attack warnings
        if risk_factors.get('sandwich_attack', {}).get('risk_score', 0) > 0.6:
            warnings.append("⚡ High sandwich attack risk - consider reducing trade size or increasing slippage tolerance")
        
        # Front-running warnings
        if risk_factors.get('front_running', {}).get('risk_score', 0) > 0.6:
            warnings.append("🏃 Front-running risk detected - your transaction may be copied with higher priority fees")
        
        # Priority fee warnings
        fee_data = risk_factors.get('priority_fee_competition', {})
        if fee_data.get('fee_ratio', 0) > 2.0:
            warnings.append("💰 High priority fee competition - transaction may be delayed or fail")
        
        # Arbitrage warnings
        if risk_factors.get('arbitrage_mev', {}).get('risk_score', 0) > 0.5:
            warnings.append("🔄 Arbitrage MEV detected - price impact may be higher than expected")
        
        # Liquidation warnings
        if risk_factors.get('liquidation_mev', {}).get('risk_score', 0) > 0.7:
            warnings.append("🚨 Liquidation MEV risk - position may be liquidated by MEV bots")
        
        return warnings
    
    async def _generate_mev_recommendations(self, risk_factors: Dict) -> List[str]:
        """Generate actionable MEV protection recommendations"""
        recommendations = []
        
        # Sandwich protection
        if risk_factors.get('sandwich_attack', {}).get('risk_score', 0) > 0.5:
            recommendations.extend([
                "Consider breaking large trades into smaller chunks",
                "Use private mempools or flashloan-protected DEXs",
                "Increase slippage tolerance slightly to avoid MEV"
            ])
        
        # Front-running protection
        if risk_factors.get('front_running', {}).get('risk_score', 0) > 0.5:
            recommendations.extend([
                "Use commit-reveal schemes for sensitive transactions",
                "Consider using MEV-protected transaction pools",
                "Time transactions during low-congestion periods"
            ])
        
        # Priority fee optimization
        fee_data = risk_factors.get('priority_fee_competition', {})
        if fee_data.get('risk_score', 0) > 0.6:
            recommendations.append("Wait for lower network congestion or increase priority fees")
        
        return recommendations
    
    async def _identify_mev_threats(self, risk_factors: Dict) -> List[str]:
        """Identify specific MEV threat categories"""
        threats = []
        
        for threat_type, data in risk_factors.items():
            if data.get('risk_score', 0) > 0.5:
                threats.append(f"mev_{threat_type}")
        
        return threats
    
    # Helper methods for transaction classification
    def _is_swap_transaction(self, transaction_data: Dict) -> bool:
        """Check if transaction is a token swap"""
        instruction_type = transaction_data.get('instruction_type', '').lower()
        return 'swap' in instruction_type or 'trade' in instruction_type
    
    def _is_high_mev_dex(self, transaction_data: Dict) -> bool:
        """Check if transaction uses high-MEV DEX"""
        program_id = transaction_data.get('program_id', '').lower()
        high_mev_programs = ['jupiter', 'raydium', 'orca', 'serum']
        return any(program in program_id for program in high_mev_programs)
    
    def _is_token_launch_transaction(self, transaction_data: Dict) -> bool:
        """Check if transaction is related to token launch"""
        return transaction_data.get('is_token_launch', False)
    
    def _is_time_sensitive_operation(self, transaction_data: Dict) -> bool:
        """Check if operation is time-sensitive"""
        time_sensitive_ops = ['auction', 'nft_mint', 'token_launch', 'liquidation']
        op_type = transaction_data.get('operation_type', '').lower()
        return any(op in op_type for op in time_sensitive_ops)
    
    def _involves_multiple_dexs(self, transaction_data: Dict) -> bool:
        """Check if transaction involves multiple DEXs"""
        return len(transaction_data.get('dex_programs', [])) > 1
    
    def _involves_lending_protocol(self, transaction_data: Dict) -> bool:
        """Check if transaction involves lending protocols"""
        program_id = transaction_data.get('program_id', '').lower()
        lending_programs = ['marginfi', 'solend', 'mango', 'tulip']
        return any(program in program_id for program in lending_programs)
    
    def _is_liquidation_transaction(self, transaction_data: Dict) -> bool:
        """Check if transaction is a liquidation"""
        instruction_type = transaction_data.get('instruction_type', '').lower()
        return 'liquidat' in instruction_type
    
    def _get_threat_level(self, risk_score: float) -> str:
        """Convert risk score to threat level"""
        if risk_score >= 0.8:
            return 'critical'
        elif risk_score >= 0.6:
            return 'high'
        elif risk_score >= 0.4:
            return 'medium'
        elif risk_score >= 0.2:
            return 'low'
        else:
            return 'minimal'
    
    # Placeholder methods for real-time data (would connect to actual APIs)
    async def _estimate_mempool_competition(self, transaction_data: Dict) -> float:
        """Estimate mempool competition level"""
        # In production, this would analyze current mempool
        return 0.3  # Placeholder
    
    async def _detect_rapid_trading_pattern(self, transaction_data: Dict) -> bool:
        """Detect rapid trading patterns"""
        # In production, this would check recent transaction history
        return False  # Placeholder
    
    async def _check_price_discrepancies(self, transaction_data: Dict) -> float:
        """Check for price discrepancies across DEXs"""
        # In production, this would query multiple DEX APIs
        return 0.01  # Placeholder 1% discrepancy