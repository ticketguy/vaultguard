"""
Behavior Analysis Module for Wallet Security
Analyzes user transaction patterns using REAL Solana blockchain data
Adapted to work with SecuritySensor framework
"""

import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import json
import statistics
from .solana_rpc_client import SolanaRPCClient  # Import our new RPC client


class BehaviorAnalyzer:
    """
    Analyze wallet behavior patterns using REAL Solana blockchain data.
    Builds user profiles and identifies deviations from normal patterns.
    """
    
    def __init__(self, rpc_url: str = "https://api.mainnet-beta.solana.com", meta_swap_api_url: str = "http://localhost:9009"):
        # Initialize Solana RPC client for real data
        self.solana_client = SolanaRPCClient(rpc_url=rpc_url, meta_swap_api_url=meta_swap_api_url)
        
        # User behavioral profiles storage
        self.user_profiles = {}
        
        # Behavioral pattern templates
        self.behavior_patterns = {
            'normal_user': {
                'avg_transaction_value': 50.0,
                'transactions_per_day': 3.0,
                'common_time_hours': [9, 12, 15, 18, 21],  # Common transaction hours
                'preferred_tokens': ['SOL', 'USDC', 'USDT'],
                'typical_gas_usage': 0.001,
                'interaction_diversity': 0.3  # Variety of programs interacted with
            },
            'suspicious_patterns': {
                'rapid_transactions': 20,      # Transactions per hour
                'unusual_hours': [1, 2, 3, 4, 5],  # 1-5 AM activity
                'high_value_threshold': 10000,  # USD
                'micro_transaction_count': 50,  # Many tiny transactions
                'new_wallet_age_days': 1       # Very new wallets
            },
            'anomaly_indicators': {
                'value_spike_multiplier': 10,    # Transaction 10x normal
                'frequency_spike_multiplier': 5, # 5x normal frequency
                'unusual_time_weight': 0.3,     # Weight for unusual timing
                'new_token_interaction': 0.2,   # Weight for new token types
                'geographic_anomaly': 0.4       # Geographic location change
            }
        }
    
    async def analyze_wallet_behavior(self, wallet_address: str) -> Dict:
        """
        Analyze complete wallet behavior using REAL Solana blockchain data.
        Primary method called by SecuritySensor for behavior analysis.
        """
        # Initialize analysis result for framework compatibility
        behavior_analysis = {
            'has_anomalies': False,            # SecuritySensor expects this field
            'anomaly_score': 0.0,
            'anomalies_found': 0,              # SecuritySensor expects this field
            'analysis': "",                    # SecuritySensor expects analysis description
            'behavioral_profile': {},
            'anomaly_details': [],
            'risk_factors': [],
            'recommendations': []
        }
        
        try:
            # Get or create user profile
            user_profile = await self._get_or_create_profile(wallet_address)
            behavior_analysis['behavioral_profile'] = user_profile
            
            # Analyze recent transaction patterns using real blockchain data
            recent_analysis = await self._analyze_recent_patterns_real(wallet_address)
            behavior_analysis.update(recent_analysis)
            
            # Detect behavioral anomalies using real data
            anomaly_analysis = await self._detect_anomalies_real(wallet_address, user_profile)
            behavior_analysis['anomaly_details'] = anomaly_analysis['details']
            behavior_analysis['anomaly_score'] = anomaly_analysis['overall_score']
            
            # Determine if anomalies are significant
            if behavior_analysis['anomaly_score'] > 0.6:
                behavior_analysis['has_anomalies'] = True
                behavior_analysis['anomalies_found'] = len(anomaly_analysis['details'])
            
            # Generate risk factors and recommendations
            behavior_analysis['risk_factors'] = await self._identify_risk_factors(behavior_analysis)
            behavior_analysis['recommendations'] = await self._generate_recommendations(behavior_analysis)
            
            # Create analysis summary
            behavior_analysis['analysis'] = self._create_behavior_summary(behavior_analysis)
            
            # Update user profile with new real data
            await self._update_profile_with_real_data(wallet_address, behavior_analysis)
        
        except Exception as e:
            # Handle analysis errors gracefully
            behavior_analysis['error'] = f"Behavior analysis failed: {str(e)}"
            behavior_analysis['analysis'] = f"Behavior analysis encountered an error: {str(e)}"
            behavior_analysis['anomaly_score'] = 0.0
        
        return behavior_analysis
    
    async def analyze_deviation(self, transaction_data: Dict) -> Dict:
        """
        Analyze single transaction for behavioral deviations using real profile data.
        Legacy method for compatibility with existing security agent.
        """
        wallet_address = transaction_data.get('from_address', '')
        transaction_value = float(transaction_data.get('value_usd', 0))
        timestamp = transaction_data.get('timestamp', datetime.now().isoformat())
        
        # Initialize deviation analysis
        deviation_analysis = {
            'anomaly_score': 0.0,
            'analysis_type': 'single_transaction',
            'details': 'Behavioral deviation analysis for single transaction',
            'factors_analyzed': [],
            'status': 'available'
        }
        
        try:
            # Get user profile with real data for comparison
            user_profile = await self._get_or_create_profile_real(wallet_address)
            
            # Analyze value deviation using real historical data
            value_anomaly = await self._analyze_value_deviation_real(transaction_value, user_profile, wallet_address)
            deviation_analysis['anomaly_score'] += value_anomaly['score']
            deviation_analysis['factors_analyzed'].append('transaction_value')
            
            # Analyze timing deviation using real activity patterns
            timing_anomaly = await self._analyze_timing_deviation_real(timestamp, user_profile, wallet_address)
            deviation_analysis['anomaly_score'] += timing_anomaly['score']
            deviation_analysis['factors_analyzed'].append('transaction_timing')
            
            # Analyze frequency deviation using real transaction history
            frequency_anomaly = await self._analyze_frequency_deviation_real(wallet_address, user_profile)
            deviation_analysis['anomaly_score'] += frequency_anomaly['score']
            deviation_analysis['factors_analyzed'].append('transaction_frequency')
            
            # Cap anomaly score at 1.0
            deviation_analysis['anomaly_score'] = min(deviation_analysis['anomaly_score'], 1.0)
            
            # Update details based on findings
            if deviation_analysis['anomaly_score'] > 0.6:
                deviation_analysis['details'] = 'Significant behavioral deviation detected from real data analysis'
            elif deviation_analysis['anomaly_score'] > 0.3:
                deviation_analysis['details'] = 'Minor behavioral deviation observed compared to historical patterns'
            else:
                deviation_analysis['details'] = 'Transaction within normal behavioral patterns based on real data'
        
        except Exception as e:
            deviation_analysis['details'] = f"Behavioral analysis error: {str(e)}"
            deviation_analysis['anomaly_score'] = 0.0
        
        return deviation_analysis
    
    async def _analyze_recent_patterns_real(self, wallet_address: str) -> Dict:
        """Analyze recent behavioral patterns using REAL Solana blockchain data"""
        try:
            async with self.solana_client as client:
                # Get real transaction history from Solana blockchain
                recent_transactions = await client.get_wallet_transaction_history(wallet_address, limit=50)
                
                if not recent_transactions:
                    return {
                        'recent_activity_level': 'no_activity',
                        'transaction_frequency_change': 0.0,
                        'value_pattern_change': 0.0,
                        'new_interactions': [],
                        'real_data_available': False
                    }
                
                # Analyze real transaction patterns
                now = datetime.now()
                last_24h = now - timedelta(days=1)
                last_7d = now - timedelta(days=7)
                
                # Count transactions in different time periods
                txs_24h = [tx for tx in recent_transactions if tx['timestamp'] > last_24h]
                txs_7d = [tx for tx in recent_transactions if tx['timestamp'] > last_7d]
                
                # Calculate real activity metrics
                activity_level = 'normal'
                if len(txs_24h) > 20:
                    activity_level = 'very_high'
                elif len(txs_24h) > 10:
                    activity_level = 'high'
                elif len(txs_24h) == 0:
                    activity_level = 'inactive'
                
                # Calculate transaction value patterns from real data
                if txs_7d:
                    recent_values = []
                    for tx in txs_7d:
                        # Calculate USD value from real transaction data
                        for transfer in tx.get('token_transfers', []):
                            if transfer.get('amount_change', 0) != 0:
                                # This would need real token price data
                                # For now, use SOL value estimation
                                amount = abs(transfer['amount_change']) / (10 ** transfer.get('decimals', 9))
                                recent_values.append(amount * 25)  # Approximate SOL price
                    
                    avg_recent_value = statistics.mean(recent_values) if recent_values else 0
                else:
                    avg_recent_value = 0
                
                # Analyze new program interactions from real data
                recent_programs = set()
                for tx in txs_7d:
                    for instruction in tx.get('instructions', []):
                        program_id = instruction.get('program_id', '')
                        if program_id:
                            recent_programs.add(program_id)
                
                return {
                    'recent_activity_level': activity_level,
                    'transaction_frequency_change': len(txs_24h) / max(len(txs_7d), 1),
                    'value_pattern_change': avg_recent_value,
                    'new_interactions': list(recent_programs),
                    'real_data_available': True,
                    'total_recent_transactions': len(recent_transactions),
                    'transactions_24h': len(txs_24h),
                    'transactions_7d': len(txs_7d)
                }
                
        except Exception as e:
            print(f"Failed to analyze recent patterns with real data: {e}")
            return {
                'recent_activity_level': 'unknown',
                'transaction_frequency_change': 0.0,
                'value_pattern_change': 0.0,
                'new_interactions': [],
                'real_data_available': False,
                'error': str(e)
            }
    
    async def _detect_anomalies_real(self, wallet_address: str, user_profile: Dict) -> Dict:
        """Detect behavioral anomalies using REAL blockchain data"""
        anomalies = []
        overall_score = 0.0
        
        try:
            # Value anomalies using real transaction data
            value_anomaly = await self._check_value_anomalies_real(wallet_address, user_profile)
            if value_anomaly['detected']:
                anomalies.append(value_anomaly)
                overall_score += value_anomaly['severity']
            
            # Frequency anomalies using real transaction history
            frequency_anomaly = await self._check_frequency_anomalies_real(wallet_address, user_profile)
            if frequency_anomaly['detected']:
                anomalies.append(frequency_anomaly)
                overall_score += frequency_anomaly['severity']
            
            # Timing anomalies using real activity patterns
            timing_anomaly = await self._check_timing_anomalies_real(wallet_address, user_profile)
            if timing_anomaly['detected']:
                anomalies.append(timing_anomaly)
                overall_score += timing_anomaly['severity']
            
            # Token interaction anomalies using real program interaction data
            token_anomaly = await self._check_token_anomalies_real(wallet_address, user_profile)
            if token_anomaly['detected']:
                anomalies.append(token_anomaly)
                overall_score += token_anomaly['severity']
            
        except Exception as e:
            print(f"Error detecting anomalies with real data: {e}")
        
        return {
            'details': anomalies,
            'overall_score': min(overall_score, 1.0),
            'count': len(anomalies)
        }
    
    async def _check_value_anomalies_real(self, wallet_address: str, user_profile: Dict) -> Dict:
        """Check for value-based anomalies using real transaction data"""
        try:
            async with self.solana_client as client:
                recent_transactions = await client.get_wallet_transaction_history(wallet_address, limit=20)
                
                if not recent_transactions:
                    return {'detected': False, 'severity': 0.0}
                
                # Calculate real transaction values
                recent_values = []
                for tx in recent_transactions:
                    total_value = 0
                    for transfer in tx.get('token_transfers', []):
                        amount = abs(transfer.get('amount_change', 0)) / (10 ** transfer.get('decimals', 9))
                        # Approximate USD value (would need real token prices)
                        total_value += amount * 25  # Rough SOL price estimate
                    
                    if total_value > 0:
                        recent_values.append(total_value)
                
                if len(recent_values) < 2:
                    return {'detected': False, 'severity': 0.0}
                
                # Check for significant value spikes in real data
                avg_value = statistics.mean(recent_values)
                max_value = max(recent_values)
                
                if max_value > avg_value * 10:  # 10x spike
                    return {
                        'detected': True,
                        'severity': 0.8,
                        'type': 'value_spike',
                        'details': f'Transaction value spike detected: ${max_value:.2f} vs avg ${avg_value:.2f}'
                    }
                
                return {'detected': False, 'severity': 0.0}
                
        except Exception as e:
            print(f"Error checking value anomalies: {e}")
            return {'detected': False, 'severity': 0.0}
    
    async def _check_frequency_anomalies_real(self, wallet_address: str, user_profile: Dict) -> Dict:
        """Check for frequency-based anomalies using real transaction data"""
        try:
            async with self.solana_client as client:
                recent_transactions = await client.get_wallet_transaction_history(wallet_address, limit=100)
                
                if len(recent_transactions) < 10:
                    return {'detected': False, 'severity': 0.0}
                
                # Analyze real transaction frequency patterns
                now = datetime.now()
                last_hour = now - timedelta(hours=1)
                last_day = now - timedelta(days=1)
                
                txs_last_hour = [tx for tx in recent_transactions if tx['timestamp'] > last_hour]
                txs_last_day = [tx for tx in recent_transactions if tx['timestamp'] > last_day]
                
                # Check for rapid transaction bursts
                if len(txs_last_hour) > 20:  # More than 20 transactions in 1 hour
                    return {
                        'detected': True,
                        'severity': 0.9,
                        'type': 'frequency_spike',
                        'details': f'Rapid transaction burst: {len(txs_last_hour)} transactions in 1 hour'
                    }
                
                # Check for unusual daily activity
                avg_daily_normal = user_profile.get('statistics', {}).get('transactions_per_day', 3)
                if len(txs_last_day) > avg_daily_normal * 5:
                    return {
                        'detected': True,
                        'severity': 0.6,
                        'type': 'frequency_anomaly',
                        'details': f'Unusual daily activity: {len(txs_last_day)} vs normal {avg_daily_normal}'
                    }
                
                return {'detected': False, 'severity': 0.0}
                
        except Exception as e:
            print(f"Error checking frequency anomalies: {e}")
            return {'detected': False, 'severity': 0.0}
    
    async def _check_timing_anomalies_real(self, wallet_address: str, user_profile: Dict) -> Dict:
        """Check for timing-based anomalies using real transaction data"""
        try:
            async with self.solana_client as client:
                recent_transactions = await client.get_wallet_transaction_history(wallet_address, limit=50)
                
                if len(recent_transactions) < 5:
                    return {'detected': False, 'severity': 0.0}
                
                # Extract real transaction hours
                transaction_hours = []
                for tx in recent_transactions:
                    hour = tx['timestamp'].hour
                    transaction_hours.append(hour)
                
                # Check for unusual time patterns
                unusual_hours = [1, 2, 3, 4, 5]  # 1-5 AM
                unusual_count = sum(1 for hour in transaction_hours if hour in unusual_hours)
                
                if unusual_count > len(transaction_hours) * 0.3:  # More than 30% at unusual hours
                    return {
                        'detected': True,
                        'severity': 0.7,
                        'type': 'timing_anomaly',
                        'details': f'Unusual timing pattern: {unusual_count}/{len(transaction_hours)} transactions at 1-5 AM'
                    }
                
                return {'detected': False, 'severity': 0.0}
                
        except Exception as e:
            print(f"Error checking timing anomalies: {e}")
            return {'detected': False, 'severity': 0.0}
    
    async def _check_token_anomalies_real(self, wallet_address: str, user_profile: Dict) -> Dict:
        """Check for token interaction anomalies using real blockchain data"""
        try:
            async with self.solana_client as client:
                recent_transactions = await client.get_wallet_transaction_history(wallet_address, limit=50)
                
                if not recent_transactions:
                    return {'detected': False, 'severity': 0.0}
                
                # Extract real program interactions
                recent_programs = set()
                for tx in recent_transactions:
                    for instruction in tx.get('instructions', []):
                        program_id = instruction.get('program_id', '')
                        if program_id:
                            recent_programs.add(program_id)
                
                # Compare with user's historical program interactions
                known_programs = set(user_profile.get('patterns', {}).get('program_interactions', []))
                new_programs = recent_programs - known_programs
                
                # Check for interaction with many unknown programs
                if len(new_programs) > 5:
                    return {
                        'detected': True,
                        'severity': 0.5,
                        'type': 'token_anomaly',
                        'details': f'Interaction with {len(new_programs)} new programs: {list(new_programs)[:3]}'
                    }
                
                return {'detected': False, 'severity': 0.0}
                
        except Exception as e:
            print(f"Error checking token anomalies: {e}")
            return {'detected': False, 'severity': 0.0}
    
    async def _get_or_create_profile_real(self, wallet_address: str) -> Dict:
        """Get or create user profile using real blockchain data"""
        if wallet_address not in self.user_profiles:
            # Create profile with real blockchain data
            profile = await self._create_profile_from_real_data(wallet_address)
            self.user_profiles[wallet_address] = profile
        
        return self.user_profiles[wallet_address]
    
    async def _create_profile_from_real_data(self, wallet_address: str) -> Dict:
        """Create user profile using real Solana blockchain data"""
        try:
            async with self.solana_client as client:
                # Get real transaction history
                transactions = await client.get_wallet_transaction_history(wallet_address, limit=100)
                
                if not transactions:
                    return await self._create_new_profile()
                
                # Calculate real statistics from blockchain data
                total_transactions = len(transactions)
                
                # Calculate real transaction values
                values = []
                active_hours = []
                program_interactions = []
                
                for tx in transactions:
                    # Extract hour
                    active_hours.append(tx['timestamp'].hour)
                    
                    # Extract program interactions
                    for instruction in tx.get('instructions', []):
                        program_id = instruction.get('program_id', '')
                        if program_id:
                            program_interactions.append(program_id)
                    
                    # Calculate transaction value
                    total_value = 0
                    for transfer in tx.get('token_transfers', []):
                        amount = abs(transfer.get('amount_change', 0)) / (10 ** transfer.get('decimals', 9))
                        total_value += amount * 25  # Rough SOL price estimate
                    
                    if total_value > 0:
                        values.append(total_value)
                
                # Calculate averages from real data
                avg_value = statistics.mean(values) if values else 0
                
                # Calculate activity period
                if transactions:
                    oldest_tx = min(tx['timestamp'] for tx in transactions)
                    days_active = (datetime.now() - oldest_tx).days
                else:
                    days_active = 1
                
                return {
                    'created_at': datetime.now().isoformat(),
                    'last_updated': datetime.now().isoformat(),
                    'data_source': 'real_blockchain',
                    'statistics': {
                        'transaction_count': total_transactions,
                        'avg_transaction_value': avg_value,
                        'total_volume': sum(values),
                        'days_active': max(days_active, 1),
                        'unique_tokens': len(set(program_interactions)),
                        'transactions_per_day': total_transactions / max(days_active, 1)
                    },
                    'patterns': {
                        'active_hours': active_hours[-100:],  # Keep last 100 hours
                        'common_values': values[-50:],  # Keep last 50 values
                        'program_interactions': list(set(program_interactions)),
                        'transaction_intervals': []
                    },
                    'preferences': {
                        'tokens': [],
                        'programs': list(set(program_interactions)[:10]),  # Top 10 programs
                        'typical_gas': 0.001
                    },
                    'risk_indicators': {
                        'rapid_transaction_periods': 0,
                        'unusual_hour_activity': 0,
                        'high_value_transactions': len([v for v in values if v > 1000]),
                        'micro_transactions': len([v for v in values if v < 1])
                    }
                }
                
        except Exception as e:
            print(f"Error creating profile from real data: {e}")
            return await self._create_new_profile()
    
    # Keep the remaining methods unchanged as they don't need real blockchain data
    async def _get_or_create_profile(self, wallet_address: str) -> Dict:
        """Get existing profile or create new one for wallet"""
        if wallet_address not in self.user_profiles:
            self.user_profiles[wallet_address] = await self._create_new_profile()
        
        return self.user_profiles[wallet_address]
    
    async def _create_new_profile(self) -> Dict:
        """Create new behavioral profile template"""
        return {
            'created_at': datetime.now().isoformat(),
            'last_updated': datetime.now().isoformat(),
            'data_source': 'template',
            'statistics': {
                'transaction_count': 0,
                'avg_transaction_value': 0.0,
                'total_volume': 0.0,
                'days_active': 0,
                'unique_tokens': 0
            },
            'patterns': {
                'active_hours': [],
                'common_values': [],
                'transaction_intervals': [],
                'program_interactions': []
            },
            'preferences': {
                'tokens': [],
                'programs': [],
                'typical_gas': 0.001
            },
            'risk_indicators': {
                'rapid_transaction_periods': 0,
                'unusual_hour_activity': 0,
                'high_value_transactions': 0,
                'micro_transactions': 0
            }
        }
    
    async def _analyze_value_deviation_real(self, transaction_value: float, user_profile: Dict, wallet_address: str) -> Dict:
        """Analyze value deviation using real historical data"""
        try:
            # Use real average from profile if available
            if user_profile.get('data_source') == 'real_blockchain':
                avg_value = user_profile['statistics']['avg_transaction_value']
            else:
                # Fall back to getting real data
                async with self.solana_client as client:
                    recent_transactions = await client.get_wallet_transaction_history(wallet_address, limit=20)
                    if recent_transactions:
                        values = []
                        for tx in recent_transactions:
                            total_value = 0
                            for transfer in tx.get('token_transfers', []):
                                amount = abs(transfer.get('amount_change', 0)) / (10 ** transfer.get('decimals', 9))
                                total_value += amount * 25
                            if total_value > 0:
                                values.append(total_value)
                        avg_value = statistics.mean(values) if values else 0
                    else:
                        avg_value = 0
            
            if avg_value == 0:  # New user or no transaction history
                return {'score': 0.1, 'reason': 'new_user_baseline'}
            
            value_ratio = transaction_value / avg_value
            
            if value_ratio > self.behavior_patterns['anomaly_indicators']['value_spike_multiplier']:
                return {
                    'score': 0.6,
                    'reason': f'transaction_value_spike',
                    'details': f'Value {value_ratio:.1f}x higher than usual (${transaction_value:.2f} vs avg ${avg_value:.2f})'
                }
            elif value_ratio < 0.1:  # Micro transaction
                return {
                    'score': 0.3,
                    'reason': 'micro_transaction',
                    'details': f'Much smaller than typical transaction (${transaction_value:.2f} vs avg ${avg_value:.2f})'
                }
            else:
                return {'score': 0.0, 'reason': 'normal_value_range'}
                
        except Exception as e:
            print(f"Error analyzing value deviation: {e}")
            return {'score': 0.0, 'reason': 'analysis_error'}
    
    async def _analyze_timing_deviation_real(self, timestamp: str, user_profile: Dict, wallet_address: str) -> Dict:
        """Analyze timing deviation using real activity patterns"""
        try:
            hour = datetime.fromisoformat(timestamp).hour
            
            # Use real activity hours from profile if available
            if user_profile.get('data_source') == 'real_blockchain':
                active_hours = user_profile['patterns']['active_hours']
            else:
                # Fall back to getting real data
                async with self.solana_client as client:
                    recent_transactions = await client.get_wallet_transaction_history(wallet_address, limit=50)
                    active_hours = [tx['timestamp'].hour for tx in recent_transactions]
            
            if not active_hours:  # New user
                return {'score': 0.0, 'reason': 'no_timing_history'}
            
            # Check if hour is in user's typical activity pattern
            hour_frequency = active_hours.count(hour) / len(active_hours)
            
            if hour_frequency < 0.05:  # Very rare hour for this user
                return {
                    'score': 0.4,
                    'reason': 'unusual_activity_hour',
                    'details': f'Activity at {hour}:00 is unusual for this user (frequency: {hour_frequency:.1%})'
                }
            else:
                return {'score': 0.0, 'reason': 'normal_activity_time'}
        
        except Exception:
            return {'score': 0.0, 'reason': 'timing_analysis_error'}
    
    async def _analyze_frequency_deviation_real(self, wallet_address: str, user_profile: Dict) -> Dict:
        """Analyze transaction frequency deviations using real data"""
        try:
            async with self.solana_client as client:
                recent_transactions = await client.get_wallet_transaction_history(wallet_address, limit=50)
                
                if len(recent_transactions) < 5:
                    return {'score': 0.0, 'reason': 'insufficient_transaction_history'}
                
                # Calculate recent frequency
                now = datetime.now()
                last_24h = now - timedelta(days=1)
                recent_24h = [tx for tx in recent_transactions if tx['timestamp'] > last_24h]
                
                current_frequency = len(recent_24h)
                normal_frequency = user_profile.get('statistics', {}).get('transactions_per_day', 3)
                
                if current_frequency > normal_frequency * 5:
                    return {
                        'score': 0.7,
                        'reason': 'frequency_spike',
                        'details': f'Frequency spike: {current_frequency} transactions vs normal {normal_frequency}'
                    }
                
                return {'score': 0.0, 'reason': 'normal_frequency'}
                
        except Exception as e:
            print(f"Error analyzing frequency deviation: {e}")
            return {'score': 0.0, 'reason': 'frequency_analysis_error'}
    
    async def _update_profile_with_real_data(self, wallet_address: str, behavior_analysis: Dict):
        """Update user profile with new real blockchain data"""
        try:
            if wallet_address in self.user_profiles:
                profile = self.user_profiles[wallet_address]
                profile['last_updated'] = datetime.now().isoformat()
                
                # Update risk indicators based on real analysis
                if behavior_analysis.get('has_anomalies', False):
                    profile['risk_indicators']['rapid_transaction_periods'] += 1
                
                # Update with real behavioral data if available
                if behavior_analysis.get('real_data_available', False):
                    profile['data_source'] = 'real_blockchain'
                    
                    # Update statistics from real analysis
                    recent_analysis = behavior_analysis.get('behavioral_profile', {})
                    if recent_analysis and 'statistics' in recent_analysis:
                        profile['statistics'].update(recent_analysis['statistics'])
                        
        except Exception as e:
            print(f"Error updating profile with real data: {e}")
    
    # Keep all other existing methods unchanged
    async def update_user_profile(self, user_id: str, transaction_data: Dict):
        """Update user behavioral profile with new transaction data"""
        try:
            if user_id not in self.user_profiles:
                self.user_profiles[user_id] = await self._create_new_profile()
            
            profile = self.user_profiles[user_id]
            
            # Update transaction statistics
            value_usd = float(transaction_data.get('value_usd', 0))
            timestamp = transaction_data.get('timestamp', datetime.now().isoformat())
            token_symbol = transaction_data.get('token_symbol', 'SOL')
            
            # Update average transaction value
            current_avg = profile['statistics']['avg_transaction_value']
            current_count = profile['statistics']['transaction_count']
            new_avg = ((current_avg * current_count) + value_usd) / (current_count + 1)
            profile['statistics']['avg_transaction_value'] = new_avg
            profile['statistics']['transaction_count'] += 1
            
            # Update token preferences
            if token_symbol not in profile['preferences']['tokens']:
                profile['preferences']['tokens'].append(token_symbol)
            
            # Update timing patterns
            hour = datetime.fromisoformat(timestamp).hour
            profile['patterns']['active_hours'].append(hour)
            
            # Keep only last 100 hours for pattern analysis
            profile['patterns']['active_hours'] = profile['patterns']['active_hours'][-100:]
            
            profile['last_updated'] = datetime.now().isoformat()
            
        except Exception as e:
            print(f"Error updating user profile: {e}")
    
    async def _identify_risk_factors(self, behavior_analysis: Dict) -> List[str]:
        """Identify behavioral risk factors"""
        risk_factors = []
        
        anomaly_score = behavior_analysis.get('anomaly_score', 0)
        
        if anomaly_score > 0.7:
            risk_factors.append('high_behavioral_anomaly')
        
        if behavior_analysis.get('has_anomalies', False):
            risk_factors.append('multiple_behavioral_deviations')
        
        # Check specific anomaly types
        anomaly_details = behavior_analysis.get('anomaly_details', [])
        for anomaly in anomaly_details:
            if anomaly.get('type') == 'value_spike':
                risk_factors.append('unusual_transaction_values')
            elif anomaly.get('type') == 'timing_anomaly':
                risk_factors.append('unusual_activity_timing')
            elif anomaly.get('type') == 'frequency_spike':
                risk_factors.append('rapid_transaction_frequency')
        
        return risk_factors
    
    async def _generate_recommendations(self, behavior_analysis: Dict) -> List[str]:
        """Generate behavioral security recommendations"""
        recommendations = []
        
        anomaly_score = behavior_analysis.get('anomaly_score', 0)
        
        if anomaly_score > 0.6:
            recommendations.extend([
                "Monitor account for unusual activity",
                "Verify all recent transactions are legitimate",
                "Consider enabling additional security measures"
            ])
        elif anomaly_score > 0.3:
            recommendations.extend([
                "Review recent transaction patterns",
                "Ensure account security is up to date"
            ])
        
        if behavior_analysis.get('has_anomalies', False):
            recommendations.append("Investigate the cause of behavioral changes")
        
        if behavior_analysis.get('real_data_available', False):
            recommendations.append("Analysis based on real blockchain data")
        
        return recommendations
    
    def _create_behavior_summary(self, behavior_analysis: Dict) -> str:
        """Create human-readable behavior analysis summary"""
        anomaly_score = behavior_analysis.get('anomaly_score', 0)
        anomalies_count = behavior_analysis.get('anomalies_found', 0)
        
        data_source = "real blockchain data" if behavior_analysis.get('real_data_available', False) else "template data"
        
        if behavior_analysis.get('has_anomalies', False):
            return f"Behavioral anomalies detected (score: {anomaly_score:.1%}) using {data_source}. Found {anomalies_count} unusual patterns requiring attention."
        elif anomaly_score > 0.3:
            return f"Minor behavioral deviations observed (score: {anomaly_score:.1%}) using {data_source}. Patterns appear mostly normal."
        else:
            return f"Normal behavioral patterns detected (score: {anomaly_score:.1%}) using {data_source}. No significant anomalies found."
    
    async def get_user_risk_summary(self, wallet_address: str) -> Dict:
        """Get comprehensive risk summary for a user using real data"""
        if wallet_address not in self.user_profiles:
            # Try to create profile from real data
            await self._get_or_create_profile_real(wallet_address)
        
        if wallet_address not in self.user_profiles:
            return {
                'risk_level': 'unknown',
                'confidence': 0.0,
                'summary': 'No behavioral data available'
            }
        
        profile = self.user_profiles[wallet_address]
        risk_indicators = profile['risk_indicators']
        
        # Calculate overall risk score
        total_risks = sum(risk_indicators.values())
        transaction_count = profile['statistics']['transaction_count']
        
        if transaction_count == 0:
            risk_ratio = 0
        else:
            risk_ratio = total_risks / max(transaction_count, 1)
        
        # Determine risk level
        if risk_ratio > 0.3:
            risk_level = 'high'
        elif risk_ratio > 0.1:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Higher confidence if we have real blockchain data
        confidence_base = min(transaction_count / 50, 1.0)
        if profile.get('data_source') == 'real_blockchain':
            confidence = min(confidence_base + 0.3, 1.0)
        else:
            confidence = confidence_base
        
        return {
            'risk_level': risk_level,
            'confidence': confidence,
            'risk_ratio': risk_ratio,
            'total_transactions': transaction_count,
            'total_risk_events': total_risks,
            'data_source': profile.get('data_source', 'template'),
            'summary': f"User shows {risk_level} risk based on {transaction_count} transactions from {profile.get('data_source', 'template')} analysis"
        }