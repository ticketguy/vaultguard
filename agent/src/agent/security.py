
import re
import json
import asyncio
from textwrap import dedent
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from enum import Enum
from loguru import logger

from result import Err, Ok, Result
from src.container import ContainerManager
from src.genner.Base import Genner
from src.client.rag import RAGClient
from src.sensor.security import SecuritySensor
from src.types import ChatHistory, Message
from src.db import DBInterface

class SecurityPromptGenerator:
    """
    Generates AI prompts for security analysis using chain-of-thought reasoning.
    Creates prompts that leverage existing analysis modules for comprehensive threat detection.
    """
    
    def __init__(self, prompts: Dict[str, str]):
        if not prompts:
            prompts = self.get_default_prompts()
        self._validate_prompts(prompts)
        self.prompts = prompts

    def _validate_prompts(self, prompts: Dict[str, str]):
        """Ensure all required prompt templates are present for security operations"""
        required_prompts = [
            'system', 'analysis_code_prompt', 'analysis_code_on_first_prompt',
            'strategy_prompt', 'quarantine_code_prompt', 'regen_code_prompt'
        ]
        for prompt in required_prompts:
            if prompt not in prompts:
                prompts[prompt] = f"Default {prompt} prompt for security analysis"

    @staticmethod
    def get_default_prompts() -> Dict[str, str]:
        """
        Default prompt templates for security analysis operations.
        """
        return {
            'system': dedent("""
                You are an AI security analyst for Web3 wallets specializing in {role}.
                Network: {network}
                Time frame: {time}
                Current security metric: {metric_name} = {metric_state}

                Generate custom Python analysis code that orchestrates existing security modules.
                Focus on protecting users from scams, exploits, and malicious contracts.
                Provide clear explanations that users can understand.
            """).strip(),
            
            'analysis_code_prompt': dedent("""
                Generate Python security analysis code that uses existing analysis modules.
                
                Notifications: {notifications_str}
                Available APIs: {apis_str}
                Previous Analysis: {prev_analysis}
                Cached Intelligence: {cached_intelligence}
                
                Generate code that calls existing security modules based on threat type.
                Use real Solana blockchain data through available APIs.
                Return detailed threat analysis with risk scores and evidence.
            """).strip(),
            
            'analysis_code_on_first_prompt': dedent("""
                Generate initial security monitoring code using existing analysis modules.
                
                Available APIs: {apis_str}
                Network: {network}
                
                Create code that orchestrates multiple security modules:
                1. MEV detection for transaction analysis
                2. Contract analysis for drain risk detection
                3. Behavior analysis for wallet anomalies
                4. NFT scam detection for suspicious tokens
                
                Use available APIs to gather real blockchain data for analysis.
            """).strip(),
            
            'strategy_prompt': dedent("""
                Generate security strategy based on analysis module results.
                
                Analysis Results: {analysis_results}
                Available APIs: {apis_str}
                Current Security State: {before_metric_state}
                Network: {network}
                Time Frame: {time}
                
                Create comprehensive security strategy that addresses identified threats
                and implements protective measures based on module findings.
            """).strip(),
            
            'quarantine_code_prompt': dedent("""
                Generate quarantine management code for security threats.
                
                Strategy: {strategy_output}
                Available APIs: {apis_str}
                Current State: {before_metric_state}
                
                Create code that safely isolates suspicious items and manages user approvals
                based on threat analysis results from security modules.
            """).strip(),
            
            'regen_code_prompt': dedent("""
                Fix errors in security code while maintaining analysis module integration.
                
                Errors: {errors}
                Previous code: {previous_code}
                
                Generate corrected code that fixes errors while preserving
                integration with existing security analysis modules.
            """).strip()
        }

    def generate_system_prompt(self, role: str, time: str, metric_name: str, 
                              metric_state: str, network: str) -> str:
        """Generate system prompt with security analysis context"""
        return self.prompts['system'].format(
            role=role,
            time=time,
            metric_name=metric_name,
            metric_state=metric_state,
            network=network
        )

    def generate_analysis_code_prompt(self, notifications_str: str, apis_str: str, 
                                    prev_analysis: str, cached_intelligence: str,
                                    before_metric_state: str, after_metric_state: str) -> str:
        """Generate prompt for AI to create code that uses existing analysis modules"""
        return self.prompts['analysis_code_prompt'].format(
            notifications_str=notifications_str,
            apis_str=apis_str,
            prev_analysis=prev_analysis,
            cached_intelligence=cached_intelligence,
            before_metric_state=before_metric_state,
            after_metric_state=after_metric_state
        )

    def generate_strategy_prompt(self, analysis_results: str, apis_str: str,
                               before_metric_state: str, network: str, time: str) -> str:
        """Generate prompt for creating security strategy based on module analysis results"""
        return self.prompts['strategy_prompt'].format(
            analysis_results=analysis_results,
            apis_str=apis_str,
            before_metric_state=before_metric_state,
            network=network,
            time=time
        )

    def generate_quarantine_code_prompt(self, strategy_output: str, apis_str: str,
                                      before_metric_state: str) -> str:
        """Generate prompt for quarantine implementation code"""
        return self.prompts['quarantine_code_prompt'].format(
            strategy_output=strategy_output,
            apis_str=apis_str,
            before_metric_state=before_metric_state
        )

class SecurityAgent:
    """
    AI-powered SecurityAgent that generates custom analysis code for every threat.
    Orchestrates existing analysis modules through AI-generated code.
    Uses EdgeLearningEngine for instant cached intelligence and background learning.
    """
    
    def __init__(self, agent_id: str, rag: RAGClient, db: DBInterface,
                 sensor: SecuritySensor, genner: Genner, 
                 container_manager: ContainerManager,
                 prompt_generator, edge_learning_engine=None):
        """Initialize security agent with EdgeLearningEngine integration"""
        self.agent_id = agent_id
        self.db = db
        self.rag = rag
        self.sensor = sensor
        self.genner = genner
        self.container_manager = container_manager
        self.prompt_generator = prompt_generator
        self.edge_learning_engine = edge_learning_engine
        
        self.chat_history = ChatHistory()
        self.fallback_cache = {}
        self.cache_expiry_seconds = 3600
        self.feedback_timestamps = {}
        self.feedback_rate_limit = 10  # Max 10 feedback submissions per minute
        
        self.ai_code_config = {
            'max_execution_time': 15,
            'max_code_generation_time': 10,
            'supported_languages': ['english', 'spanish', 'french', 'japanese', 'portuguese'],
            'default_language': 'english',
            'enable_cached_intelligence': True,
            'enable_background_learning': True,
            'enable_module_orchestration': True
        }
        
        logger.info(f"🛡️ SecurityAgent initialized with ID: {agent_id}")
        if edge_learning_engine:
            logger.info("🧠 EdgeLearningEngine integration enabled")

    async def analyze_with_ai_code_generation(self, target_data: Dict, user_language: str = "english") -> Dict:
        """
        Main AI code generation pipeline for instant transaction analysis.
        """
        analysis_result = {
            'action': 'ALLOW',
            'risk_score': 0.0,
            'confidence': 0.8,
            'chain_of_thought': [],
            'user_explanation': '',
            'technical_details': {},
            'ai_generated_code': '',
            'execution_results': {},
            'cached_intelligence': {},
            'analysis_time_ms': 0,
            'threat_categories': [],
            'quarantine_recommended': False,
            'analysis_method': 'instant_cached_intelligence'
        }
        
        start_time = datetime.now()
        
        try:
            analysis_result['chain_of_thought'].append("⚡ Step 1: Getting cached threat intelligence...")
            cached_intelligence = await self._get_cached_intelligence(target_data)
            analysis_result['cached_intelligence'] = cached_intelligence
            
            analysis_result['chain_of_thought'].append("🤖 Step 2: AI generating analysis code with cached intelligence...")
            ai_code = await self._generate_module_orchestration_code_cached(target_data, cached_intelligence)
            analysis_result['ai_generated_code'] = ai_code
            
            analysis_result['chain_of_thought'].append("🚀 Step 3: Executing analysis with existing modules...")
            execution_results = await self._execute_ai_analysis_code_with_timeout(ai_code, target_data)
            analysis_result['execution_results'] = execution_results
            analysis_result['technical_details'] = execution_results
            
            analysis_result['chain_of_thought'].append("⚖️ Step 4: Making instant security decision...")
            risk_assessment = await self._assess_risk_from_cached_results(execution_results, cached_intelligence)
            analysis_result.update(risk_assessment)
            
            analysis_result['chain_of_thought'].append("💬 Step 5: Generating user explanation...")
            user_explanation = await self._generate_user_explanation_with_timeout(
                execution_results, cached_intelligence, risk_assessment, user_language
            )
            analysis_result['user_explanation'] = user_explanation
            
            analysis_result['quarantine_recommended'] = self._should_quarantine(analysis_result)
            
            analysis_result['chain_of_thought'].append("🧠 Step 7: Triggering background learning...")
            self._trigger_background_learning(target_data, analysis_result)
            
        except asyncio.TimeoutError:
            analysis_result['action'] = 'WARN'
            analysis_result['risk_score'] = 0.6
            analysis_result['user_explanation'] = "⚠️ Analysis timed out - proceeding with caution recommended"
            analysis_result['chain_of_thought'].append("⏰ Analysis timed out - using safe fallback")
            
        except Exception as e:
            analysis_result['action'] = 'BLOCK'
            analysis_result['risk_score'] = 0.9
            analysis_result['user_explanation'] = f"🚨 Analysis failed for safety - blocked: {str(e)}"
            analysis_result['chain_of_thought'].append(f"❌ Error occurred: {str(e)}")
        
        analysis_result['analysis_time_ms'] = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return analysis_result

    async def _get_cached_intelligence(self, target_data: Dict) -> Dict:
        """
        Get cached threat intelligence instantly using EdgeLearningEngine.
        """
        self._cleanup_fallback_cache()  # Clean up expired cache entries
        
        if self.edge_learning_engine:
            cache_keys = self._generate_cache_keys(target_data)
            miss_count = getattr(self, '_cache_miss_count', {})
            
            for cache_key in cache_keys:
                cached_intelligence = await self.edge_learning_engine.get_cached_intelligence(cache_key)
                if cached_intelligence.get('cache_available'):
                    self.edge_learning_engine.trigger_intelligence_refresh(target_data, cache_keys)
                    return cached_intelligence
                
                miss_count[cache_key] = miss_count.get(cache_key, 0) + 1
                if miss_count[cache_key] > 3:
                    logger.warning(f"⚠️ Repeated cache miss for {cache_key}: {miss_count[cache_key]} attempts")
            
            self._cache_miss_count = miss_count
            self.edge_learning_engine.trigger_intelligence_refresh(target_data, cache_keys)
            logger.info(f"Cache miss for keys: {cache_keys}")
            return {
                'cache_available': False,
                'threat_patterns': [],
                'analysis_suggestions': self._get_fallback_analysis_suggestions(target_data),
                'confidence_boost': 0.0,
                'background_refresh_triggered': True
            }
        
        return await self._get_cached_intelligence_fallback(target_data)

    async def _get_cached_intelligence_fallback(self, target_data: Dict) -> Dict:
        """
        Fallback cached intelligence method when EdgeLearningEngine not available.
        """
        cached_intelligence = {
            'cache_available': False,
            'threat_patterns': [],
            'analysis_suggestions': [],
            'confidence_boost': 0.0,
            'cache_age_seconds': 0,
            'background_refresh_triggered': False
        }
        
        cache_keys = self._generate_cache_keys(target_data)
        
        for cache_key in cache_keys:
            if cache_key in self.fallback_cache:
                cached_data = self.fallback_cache[cache_key]
                cache_age = (datetime.now() - cached_data['cached_at']).total_seconds()
                
                if cache_age < self.cache_expiry_seconds:
                    cached_intelligence['cache_available'] = True
                    cached_intelligence['threat_patterns'].extend(cached_data.get('threat_patterns', []))
                    cached_intelligence['analysis_suggestions'].extend(cached_data.get('analysis_suggestions', []))
                    cached_intelligence['confidence_boost'] = cached_data.get('confidence_boost', 0.1)
                    cached_intelligence['cache_age_seconds'] = int(cache_age)
                    break
        
        if not cached_intelligence['analysis_suggestions']:
            cached_intelligence['analysis_suggestions'] = self._get_fallback_analysis_suggestions(target_data)
        
        return cached_intelligence

    def _generate_cache_keys(self, target_data: Dict) -> List[str]:
        """Generate cache keys from transaction data for intelligence lookup"""
        cache_keys = []
        
        if target_data.get('from_address'):
            cache_keys.append(f"address_{target_data['from_address']}")
        if target_data.get('to_address'):
            cache_keys.append(f"address_{target_data['to_address']}")
        if target_data.get('token_name'):
            cache_keys.append(f"token_{target_data['token_name'].lower()}")
        if target_data.get('token_address'):
            cache_keys.append(f"token_address_{target_data['token_address']}")
        if target_data.get('program_id'):
            cache_keys.append(f"program_{target_data['program_id']}")
        if target_data.get('transaction_type'):
            cache_keys.append(f"tx_type_{target_data['transaction_type']}")
        
        return cache_keys

    def _cleanup_fallback_cache(self):
        """Clean up expired entries in fallback cache"""
        now = datetime.now()
        expired_keys = [
            key for key, data in self.fallback_cache.items()
            if (now - data['cached_at']).total_seconds() > self.cache_expiry_seconds
        ]
        for key in expired_keys:
            del self.fallback_cache[key]
        logger.debug(f"🧹 Cleaned {len(expired_keys)} expired cache entries")

    def set_edge_learning_engine(self, edge_learning_engine):
        """Inject EdgeLearningEngine for advanced background intelligence"""
        self.edge_learning_engine = edge_learning_engine
        logger.info("🔗 SecurityAgent connected to EdgeLearningEngine")

    def get_engine_status(self) -> Dict[str, Any]:
        """Get EdgeLearningEngine status for monitoring"""
        if self.edge_learning_engine:
            return self.edge_learning_engine.get_engine_status()
        return {
            'edge_learning_available': False,
            'fallback_cache_size': len(self.fallback_cache),
            'fallback_queue_size': len(getattr(self, 'fallback_learning_queue', []))
        }

    async def force_intelligence_refresh(self, target_data: Dict) -> Dict[str, Any]:
        """Force immediate intelligence refresh for debugging/testing"""
        if self.edge_learning_engine:
            return await self.edge_learning_engine.force_intelligence_refresh(target_data)
        return {'error': 'EdgeLearningEngine not available', 'fallback_used': True}

    def clear_intelligence_cache(self) -> Dict[str, Any]:
        """Clear all cached intelligence for testing/debugging"""
        if self.edge_learning_engine:
            return self.edge_learning_engine.clear_cache()
        cleared_count = len(self.fallback_cache)
        self.fallback_cache = {}
        return {'cleared_entries': cleared_count, 'cache_type': 'fallback'}

    async def process_fallback_learning_queue(self):
        """
        Process fallback learning queue when EdgeLearningEngine not available.
        """
        if self.edge_learning_engine:
            return
        
        if not hasattr(self, 'fallback_learning_queue') or not self.fallback_learning_queue:
            return
        
        items_to_process = self.fallback_learning_queue[:10]
        self.fallback_learning_queue = self.fallback_learning_queue[10:]
        
        for item in items_to_process:
            try:
                if item['task_type'] == 'analysis_learning':
                    await self._process_fallback_analysis_learning(item)
            except Exception as e:
                logger.error(f"❌ Fallback learning error: {e}")

    async def _process_fallback_analysis_learning(self, task: Dict):
        """Process analysis learning in fallback mode"""
        analysis_result = task['analysis_result']
        target_data = task['target_data']
        
        cache_keys = self._generate_cache_keys(target_data)
        action = analysis_result.get('action', 'ALLOW')
        risk_score = analysis_result.get('risk_score', 0.0)
        
        for cache_key in cache_keys:
            if cache_key not in self.fallback_cache:
                self.fallback_cache[cache_key] = {
                    'threat_patterns': [],
                    'analysis_suggestions': [],
                    'confidence_boost': 0.0,
                    'cached_at': datetime.now()
                }
            
            cached_data = self.fallback_cache[cache_key]
            
            if action == 'BLOCK' and risk_score > 0.7:
                cached_data['confidence_boost'] = min(cached_data['confidence_boost'] + 0.2, 1.0)
                cached_data['threat_patterns'].append(f"High risk detected: {risk_score:.2f}")
            elif action == 'ALLOW' and risk_score < 0.3:
                cached_data['confidence_boost'] = max(cached_data['confidence_boost'] - 0.1, 0.0)
                cached_data['threat_patterns'].append(f"Low risk confirmed: {risk_score:.2f}")
            
            cached_data['cached_at'] = datetime.now()

    def _trigger_background_learning(self, target_data: Dict, analysis_result: Dict):
        """
        NON-BLOCKING: Trigger background learning from analysis results.
        """
        if self.edge_learning_engine:
            learning_data = {
                'target_data': target_data,
                'analysis_result': {
                    'action': analysis_result.get('action'),
                    'risk_score': analysis_result.get('risk_score'),
                    'threat_categories': analysis_result.get('threat_categories', []),
                    'confidence': analysis_result.get('confidence')
                },
                'timestamp': datetime.now().isoformat()
            }
            self.edge_learning_engine.queue_learning_task('analysis_learning', learning_data, priority='normal')
        else:
            learning_task = {
                'task_type': 'analysis_learning',
                'target_data': target_data,
                'analysis_result': analysis_result,
                'timestamp': datetime.now().isoformat()
            }
            if not hasattr(self, 'fallback_learning_queue'):
                self.fallback_learning_queue = []
            self.fallback_learning_queue.append(learning_task)
            if len(self.fallback_learning_queue) > 1000:
                self.fallback_learning_queue = self.fallback_learning_queue[-500:]

    def learn_from_user_decision(self, target_data: Dict, user_decision: str, 
                               user_reasoning: str = "", confidence: float = 0.8):
        """
        NON-BLOCKING: Learn from user decisions with rate limiting.
        """
        user_id = target_data.get('user_id', 'unknown')
        now = datetime.now()
        
        if user_id in self.feedback_timestamps:
            timestamps = [t for t in self.feedback_timestamps[user_id] if now - t < timedelta(minutes=1)]
            self.feedback_timestamps[user_id] = timestamps
            if len(timestamps) >= self.feedback_rate_limit:
                logger.warning(f"Rate limit exceeded for user {user_id}")
                return
            self.feedback_timestamps[user_id].append(now)
        else:
            self.feedback_timestamps[user_id] = [now]
        
        if self.edge_learning_engine:
            self.edge_learning_engine.learn_from_user_decision(
                target_data, user_decision, user_reasoning, confidence
            )
        else:
            self._update_fallback_cache_from_user_decision(target_data, user_decision, confidence)

    def _update_fallback_cache_from_user_decision(self, target_data: Dict, user_decision: str, confidence: float):
        """Update fallback cache based on user decision"""
        cache_keys = self._generate_cache_keys(target_data)
        
        for cache_key in cache_keys:
            if cache_key not in self.fallback_cache:
                self.fallback_cache[cache_key] = {
                    'threat_patterns': [],
                    'analysis_suggestions': [],
                    'confidence_boost': 0.0,
                    'cached_at': datetime.now()
                }
            
            cached_data = self.fallback_cache[cache_key]
            
            if user_decision == 'quarantined':
                cached_data['confidence_boost'] = 0.3
                cached_data['threat_patterns'].append(f"User quarantined: {user_decision}")
                if 'comprehensive_analysis' not in cached_data['analysis_suggestions']:
                    cached_data['analysis_suggestions'].append('comprehensive_analysis')
            elif user_decision == 'approved':
                cached_data['confidence_boost'] = max(cached_data['confidence_boost'] - 0.1, 0.0)
                cached_data['threat_patterns'].append(f"User approved: {user_decision}")
            
            cached_data['cached_at'] = datetime.now()

    async def _generate_module_orchestration_code_cached(self, target_data: Dict, cached_intelligence: Dict) -> str:
        """
        AI generates code using cached intelligence.
        """
        analysis_suggestions = cached_intelligence.get('analysis_suggestions', ['comprehensive_analysis'])
        threat_patterns = cached_intelligence.get('threat_patterns', [])
        available_modules = self._get_available_modules()
        
        code_generation_prompt = f"""
Generate Python code that orchestrates existing security analysis modules for this Solana transaction.

Target Data:
{json.dumps(target_data, indent=2)}

Cached Intelligence:
- Analysis Needed: {', '.join(analysis_suggestions)}
- Available Security Modules: {', '.join(available_modules)}
- Known Threat Patterns: {threat_patterns[:2] if threat_patterns else ['No cached patterns']}
- Cache Age: {cached_intelligence.get('cache_age_seconds', 0)} seconds

Generate a complete Python function called 'analyze_security_threats' that:

1. Uses the available security modules based on transaction type:
   - MEVDetector for transaction analysis (mev_detector.analyze_mev_risk)
   - EnhancedContractAnalyzer for contract analysis (contract_analyzer.analyze_contract_for_drain_risk)
   - BehaviorAnalyzer for wallet analysis (behavior_analyzer.analyze_wallet_behavior)
   - NFTScamDetector for NFT analysis (nft_scam_detector.analyze_nft_scam_risk)
   - AdaptiveDustDetector for dust analysis (dust_detector.analyze_transaction)

2. Prioritizes analysis based on cached threat patterns
3. Combines results from multiple modules into comprehensive analysis
4. Returns structured result with risk_score, threats_found, evidence, and explanations

Code Requirements:
- Use 'await module.method(target_data)' for each module call
- Handle module unavailability gracefully (check if module exists)
- Combine risk scores using weighted average
- Include evidence from each module
- Return risk scores from 0.0 to 1.0
- Include simple explanations for each threat found

ONLY return the Python function code, no explanations or markdown.
"""
        try:
            instruction_message = Message(role="user", content=code_generation_prompt)
            ai_response = await asyncio.wait_for(
                self._generate_ai_completion(instruction_message),
                timeout=self.ai_code_config['max_code_generation_time']
            )
            return self._extract_python_code(ai_response)
        except asyncio.TimeoutError:
            return self._generate_fallback_module_orchestration_code(target_data, analysis_suggestions)
        except Exception as e:
            logger.error(f"AI code generation error: {e}")
            return self._generate_fallback_module_orchestration_code(target_data, analysis_suggestions)

    async def _assess_risk_from_cached_results(self, execution_results: Dict, cached_intelligence: Dict) -> Dict:
        """
        Assess overall risk using cached intelligence and module results.
        """
        base_risk_score = execution_results.get('risk_score', 0.0)
        threats_found = execution_results.get('threats_found', [])
        module_results = execution_results.get('module_results', {})
        
        adjusted_risk = base_risk_score
        if cached_intelligence.get('cache_available') and cached_intelligence.get('threat_patterns'):
            adjusted_risk += cached_intelligence.get('confidence_boost', 0.0)
        
        threat_weights = {
            'drain_contract_risk': 0.9,
            'mev_attack_risk': 0.7,
            'nft_scam': 0.6,
            'dust_attack': 0.5,
            'behavioral_anomaly': 0.4,
            'execution_error': 0.8,
            'analysis_timeout': 0.7
        }
        
        max_threat_weight = 0.0
        for threat in threats_found:
            threat_weight = threat_weights.get(threat, 0.3)
            max_threat_weight = max(max_threat_weight, threat_weight)
        
        final_risk = max(adjusted_risk, max_threat_weight)
        final_risk = min(final_risk, 1.0)
        
        if final_risk >= 0.8:
            action = 'BLOCK'
            confidence = 0.9
        elif final_risk >= 0.5:
            action = 'WARN'
            confidence = 0.8
        else:
            action = 'ALLOW'
            confidence = 0.85
        
        if cached_intelligence.get('cache_available'):
            cache_age = cached_intelligence.get('cache_age_seconds', 3600)
            if cache_age < 300:
                confidence = min(confidence + 0.1, 1.0)
        
        threat_categories = list(set(threats_found))
        
        return {
            'action': action,
            'risk_score': final_risk,
            'confidence': confidence,
            'threat_categories': threat_categories,
            'decision_reasoning': f'Risk: {final_risk:.2f}, Threats: {", ".join(threat_categories) if threat_categories else "None"}',
            'modules_used': execution_results.get('modules_used', []),
            'cache_utilized': cached_intelligence.get('cache_available', False)
        }

    def _trigger_background_intelligence_refresh(self, target_data: Dict, cache_keys: List[str]):
        """
        Fallback method for triggering background intelligence refresh.
        """
        if self.edge_learning_engine:
            return
        logger.info(f"🔄 Background refresh needed for keys: {cache_keys[:3]}")

    async def _generate_ai_completion(self, instruction_message: Message) -> str:
        """Generate AI completion with proper error handling"""
        try:
            response_result = self.genner.generate_completion([instruction_message])
            if hasattr(response_result, 'unwrap'):
                return response_result.unwrap()
            return str(response_result)
        except Exception as e:
            logger.error(f"AI generation failed: {str(e)}")
            raise

    def _get_available_modules(self) -> List[str]:
        """Get list of available analysis modules from SecuritySensor"""
        modules = []
        if hasattr(self.sensor, 'mev_detector') and self.sensor.mev_detector:
            modules.append('MEVDetector')
        if hasattr(self.sensor, 'contract_analyzer') and self.sensor.contract_analyzer:
            modules.append('EnhancedContractAnalyzer')
        if hasattr(self.sensor, 'behavior_analyzer') and self.sensor.behavior_analyzer:
            modules.append('BehaviorAnalyzer')
        if hasattr(self.sensor, 'nft_scam_detector') and self.sensor.nft_scam_detector:
            modules.append('NFTScamDetector')
        if hasattr(self.sensor, 'dust_detector') and self.sensor.dust_detector:
            modules.append('AdaptiveDustDetector')
        if hasattr(self.sensor, 'contract_explainer') and self.sensor.contract_explainer:
            modules.append('SmartContractExplainer')
        if hasattr(self.sensor, 'network_analyzer') and self.sensor.network_analyzer:
            modules.append('NetworkAnalyzer')
        return modules

    def _extract_python_code(self, ai_response: str) -> str:
        """Extract Python code from AI response"""
        code_block_pattern = r'```python\s*(.*?)\s*```'
        matches = re.findall(code_block_pattern, ai_response, re.DOTALL)
        
        if matches:
            return matches[0].strip()
        
        function_pattern = r'(async def analyze_security_threats.*?)(?=\n\n|\Z)'
        matches = re.findall(function_pattern, ai_response, re.DOTALL)
        
        if matches:
            return matches[0].strip()
        
        if 'def ' in ai_response:
            start_idx = ai_response.find('def ')
            if start_idx != -1:
                return ai_response[start_idx:].strip()
        
        return ai_response.strip()

    def _generate_fallback_module_orchestration_code(self, target_data: Dict, analysis_suggestions: List[str]) -> str:
        """
        Generate fallback code that orchestrates existing modules when AI generation fails.
        """
        return dedent(f"""
        async def analyze_security_threats(target_data):
            import asyncio
            from datetime import datetime
            
            analysis_result = {{
                'risk_score': 0.0,
                'threats_found': [],
                'evidence': [],
                'module_results': {{}},
                'analysis_type': 'module_orchestration_fallback',
                'timestamp': datetime.now().isoformat(),
                'modules_used': []
            }}
            
            total_risk = 0.0
            module_count = 0
            
            if hasattr(sensor, 'mev_detector') and sensor.mev_detector:
                try:
                    mev_result = await sensor.mev_detector.analyze_mev_risk(target_data)
                    if mev_result.get('mev_risk', 0) > 0.5:
                        analysis_result['threats_found'].append('mev_attack_risk')
                        analysis_result['evidence'].append(f"MEV risk detected: {{mev_result.get('mev_risk', 0):.2f}}")
                        total_risk += mev_result.get('mev_risk', 0) * 0.3
                    analysis_result['module_results']['mev'] = mev_result
                    analysis_result['modules_used'].append('MEVDetector')
                    module_count += 1
                except Exception as e:
                    analysis_result['evidence'].append(f"MEV analysis error: {{str(e)}}")
            
            if hasattr(sensor, 'contract_analyzer') and sensor.contract_analyzer and target_data.get('program_id'):
                try:
                    contract_result = await sensor.contract_analyzer.analyze_contract_for_drain_risk(target_data)
                    if contract_result.get('security_risk_score', 0) > 0.6:
                        analysis_result['threats_found'].append('drain_contract_risk')
                        analysis_result['evidence'].append("Potential drain contract detected")
                        total_risk += contract_result.get('security_risk_score', 0) * 0.4
                    analysis_result['module_results']['contract'] = contract_result
                    analysis_result['modules_used'].append('EnhancedContractAnalyzer')
                    module_count += 1
                except Exception as e:
                    analysis_result['evidence'].append(f"Contract analysis error: {{str(e)}}")
            
            if hasattr(sensor, 'dust_detector') and sensor.dust_detector:
                try:
                    dust_result = await sensor.dust_detector.analyze_transaction(target_data)
                    if dust_result.get('is_dust_attack', False):
                        analysis_result['threats_found'].append('dust_attack')
                        analysis_result['evidence'].append("Dust attack pattern detected")
                        total_risk += 0.5
                    analysis_result['module_results']['dust'] = dust_result
                    analysis_result['modules_used'].append('AdaptiveDustDetector')
                    module_count += 1
                except Exception as e:
                    analysis_result['evidence'].append(f"Dust analysis error: {{str(e)}}")
            
            if hasattr(sensor, 'nft_scam_detector') and sensor.nft_scam_detector and target_data.get('token_name'):
                try:
                    nft_result = await sensor.nft_scam_detector.analyze_nft_scam_risk(target_data)
                    if nft_result.get('scam_risk_score', 0) > 0.6:
                        analysis_result['threats_found'].append('nft_scam')
                        analysis_result['evidence'].append("Suspicious NFT characteristics detected")
                        total_risk += nft_result.get('scam_risk_score', 0) * 0.3
                    analysis_result['module_results']['nft'] = nft_result
                    analysis_result['modules_used'].append('NFTScamDetector')
                    module_count += 1
                except Exception as e:
                    analysis_result['evidence'].append(f"NFT analysis error: {{str(e)}}")
            
            if hasattr(sensor, 'behavior_analyzer') and sensor.behavior_analyzer and target_data.get('from_address'):
                try:
                    behavior_result = await sensor.behavior_analyzer.analyze_wallet_behavior(target_data['from_address'])
                    if behavior_result.get('anomaly_score', 0) > 0.7:
                        analysis_result['threats_found'].append('behavioral_anomaly')
                        analysis_result['evidence'].append("Unusual wallet behavior detected")
                        total_risk += behavior_result.get('anomaly_score', 0) * 0.2
                    analysis_result['module_results']['behavior'] = behavior_result
                    analysis_result['modules_used'].append('BehaviorAnalyzer')
                    module_count += 1
                except Exception as e:
                    analysis_result['evidence'].append(f"Behavior analysis error: {{str(e)}}")
            
            if module_count > 0:
                analysis_result['risk_score'] = min(total_risk, 1.0)
            else:
                value = target_data.get('value', target_data.get('amount', 0))
                if isinstance(value, (int, float)) and 0 < value < 0.001:
                    analysis_result['threats_found'].append('small_value_transaction')
                    analysis_result['risk_score'] = 0.4
                    analysis_result['evidence'].append(f"Small transaction amount: {{value}}")
            
            return analysis_result
        """)

    async def _execute_ai_analysis_code_with_timeout(self, analysis_code: str, target_data: Dict) -> Dict:
        """
        Execute AI-generated analysis code with timeout protection.
        """
        try:
            execution_code = f"""
import json
import asyncio
from datetime import datetime

sensor = globals().get('sensor')

{analysis_code}

result = await analyze_security_threats({json.dumps(target_data)})
print(json.dumps(result, default=str))
"""
            execution_result = await asyncio.wait_for(
                self._safe_execute_code(execution_code),
                timeout=self.ai_code_config['max_execution_time']
            )
            output, _ = execution_result.unwrap()
            
            try:
                parsed_result = json.loads(output.strip())
                return parsed_result
            except json.JSONDecodeError:
                return {
                    'risk_score': 0.5,
                    'threats_found': ['execution_parse_error'],
                    'evidence': ['Analysis completed but output parsing failed'],
                    'raw_output': output[:500],
                    'execution_status': 'parse_error'
                }
        except asyncio.TimeoutError:
            return {
                'risk_score': 0.7,
                'threats_found': ['analysis_timeout'],
                'evidence': [f'Analysis timed out after {self.ai_code_config["max_execution_time"]} seconds'],
                'execution_status': 'timeout'
            }
        except Exception as e:
            return {
                'risk_score': 0.8,
                'threats_found': ['execution_error'],
                'evidence': [f'Analysis execution failed: {str(e)}'],
                'error': str(e),
                'execution_status': 'error'
            }

    async def _safe_execute_code(self, execution_code: str):
        """Safely execute code in container with sensor context"""
        execution_context = {'sensor': self.sensor}
        return self.container_manager.run_code_in_con(
            execution_code, 
            "ai_security_analysis",
            context=execution_context
        )

    def _should_quarantine(self, analysis_result: Dict) -> bool:
        """Determine if item should be quarantined based on analysis results"""
        risk_score = analysis_result.get('risk_score', 0.0)
        action = analysis_result.get('action', 'ALLOW')
        threat_categories = analysis_result.get('threat_categories', [])
        
        if risk_score >= 0.7:
            return True
        if any(threat in threat_categories for threat in ['drain_contract_risk', 'nft_scam', 'dust_attack']):
            return True
        if action == 'BLOCK':
            return True
        return False

    async def _generate_user_explanation_with_timeout(self, execution_results: Dict, cached_intelligence: Dict, 
                                                    risk_assessment: Dict, user_language: str) -> str:
        """
        Generate user-friendly explanation with timeout protection.
        """
        try:
            threats_found = execution_results.get('threats_found', [])
            evidence = execution_results.get('evidence', [])
            action = risk_assessment.get('action', 'ALLOW')
            risk_score = risk_assessment.get('risk_score', 0.0)
            
            explanation_prompt = f"""
Generate a clear, simple security explanation for a user in {user_language}.

Analysis Results:
- Action: {action}
- Risk Score: {risk_score:.2f}
- Threats Found: {threats_found}
- Evidence: {evidence[:3]}
- Modules Used: {risk_assessment.get('modules_used', [])}
- Cache Used: {cached_intelligence.get('cache_available', False)}

Create explanation that:
1. Uses simple, non-technical language
2. Explains WHAT was found and WHY it matters
3. Gives clear recommendation
4. Maximum 2-3 sentences
5. Include appropriate emoji
6. Language: {user_language}

ONLY return the explanation text, no formatting.
"""
            instruction_message = Message(role="user", content=explanation_prompt)
            explanation = await asyncio.wait_for(
                self._generate_ai_completion(instruction_message),
                timeout=3
            )
            return explanation.strip()
        except asyncio.TimeoutError:
            return self._generate_fallback_explanation(risk_assessment, user_language)
        except Exception:
            return self._generate_fallback_explanation(risk_assessment, user_language)

    def _generate_fallback_explanation(self, risk_assessment: Dict, user_language: str) -> str:
        """Generate fallback explanation when AI explanation generation fails"""
        action = risk_assessment.get('action', 'ALLOW')
        risk_score = risk_assessment.get('risk_score', 0.0)
        threat_categories = risk_assessment.get('threat_categories', [])
        
        explanations = {
            'english': {
                'BLOCK': f"🚨 BLOCKED: High security risk detected ({risk_score:.0%}). This could be a scam or malicious transaction.",
                'WARN': f"⚠️ WARNING: Moderate security risk detected ({risk_score:.0%}). Please review carefully before proceeding.",
                'ALLOW': f"✅ SAFE: Low security risk ({risk_score:.0%}). Transaction appears legitimate."
            },
            'spanish': {
                'BLOCK': f"🚨 BLOQUEADO: Alto riesgo de seguridad detectado ({risk_score:.0%}). Podría ser una estafa.",
                'WARN': f"⚠️ ADVERTENCIA: Riesgo moderado de seguridad ({risk_score:.0%}). Revise cuidadosamente.",
                'ALLOW': f"✅ SEGURO: Bajo riesgo de seguridad ({risk_score:.0%}). La transacción parece legítima."
            }
        }
        
        lang_explanations = explanations.get(user_language, explanations['english'])
        return lang_explanations.get(action, lang_explanations['ALLOW'])

    def gen_analysis_code_on_first(self, apis: List[str], network: str) -> Tuple[Result[str, str], ChatHistory]:
        """Generate initial security monitoring code for first-time setup"""
        try:
            prompt = self.prompt_generator.prompts['analysis_code_on_first_prompt'].format(
                apis_str="\n".join(apis),
                network=network
            )
            instruction_message = Message(role="user", content=prompt)
            chat_history = ChatHistory()
            chat_history.messages.append(instruction_message)
            response_result = self.genner.ch_completion(chat_history)
            
            if response_result.is_err():
                return Err(f"AI generation failed: {response_result.unwrap_err()}"), ChatHistory()
            
            response = response_result.unwrap()
            chat_history.messages.append(Message(role="assistant", content=response))
            return Ok(response), chat_history
        except Exception as e:
            return Err(f"Failed to generate initial analysis code: {str(e)}"), ChatHistory()

    def regen_on_error(self, errors: str, latest_response: str) -> Result[str, str]:
        """Regenerate code when errors occur during execution"""
        try:
            prompt = self.prompt_generator.prompts['regen_code_prompt'].format(
                errors=errors,
                previous_code=latest_response
            )
            instruction_message = Message(role="user", content=prompt)
            chat_history = ChatHistory()
            chat_history.messages.append(instruction_message)
            response_result = self.genner.ch_completion(chat_history)
            
            if response_result.is_err():
                return Err(f"AI regeneration failed: {response_result.unwrap_err()}")
            
            return Ok(response_result.unwrap())
        except Exception as e:
            return Err(f"Failed to regenerate code: {str(e)}")

    def gen_analysis_code(self, notifications_str: str, apis: List[str], prev_analysis: str, 
                        rag_summary: str, before_metric_state: str, after_metric_state: str) -> Tuple[Result[str, str], ChatHistory]:
        """Generate security analysis code using cached intelligence"""
        try:
            cached_intel_summary = "Using cached threat intelligence for faster analysis"
            prompt = self.prompt_generator.generate_analysis_code_prompt(
                notifications_str=notifications_str,
                apis_str="\n".join(apis),
                prev_analysis=prev_analysis,
                cached_intelligence=cached_intel_summary,
                before_metric_state=before_metric_state,
                after_metric_state=after_metric_state
            )
            instruction_message = Message(role="user", content=prompt)
            chat_history = ChatHistory()
            chat_history.messages.append(instruction_message)
            response_result = self.genner.ch_completion(chat_history)
            
            if response_result.is_err():
                return Err(f"AI generation failed: {response_result.unwrap_err()}"), ChatHistory()
            
            response = response_result.unwrap()
            chat_history.messages.append(Message(role="assistant", content=response))
            return Ok(response), chat_history
        except Exception as e:
            return Err(f"Failed to generate analysis code: {str(e)}"), ChatHistory()

    def gen_security_strategy(self, analysis_results: str, apis: List[str], before_metric_state: str, 
                            network: str, time: str) -> Tuple[Result[str, str], ChatHistory]:
        """Generate security strategy based on analysis results"""
        try:
            prompt = self.prompt_generator.generate_strategy_prompt(
                analysis_results=analysis_results,
                apis_str="\n".join(apis),
                before_metric_state=before_metric_state,
                network=network,
                time=time
            )
            instruction_message = Message(role="user", content=prompt)
            chat_history = ChatHistory()
            chat_history.messages.append(instruction_message)
            response_result = self.genner.ch_completion(chat_history)
            
            if response_result.is_err():
                return Err(f"AI generation failed: {response_result.unwrap_err()}"), ChatHistory()
            
            response = response_result.unwrap()
            chat_history.messages.append(Message(role="assistant", content=response))
            return Ok(response), chat_history
        except Exception as e:
            return Err(f"Failed to generate security strategy: {str(e)}"), ChatHistory()

    def gen_quarantine_code(self, strategy_output: str, apis: List[str], metric_state: str,
                        security_tools: List[str], meta_swap_api_url: str, network: str) -> Tuple[Result[str, str], ChatHistory]:
        """Generate quarantine implementation code"""
        try:
            prompt = self.prompt_generator.generate_quarantine_code_prompt(
                strategy_output=strategy_output,
                apis_str="\n".join(apis),
                before_metric_state=metric_state
            )
            instruction_message = Message(role="user", content=prompt)
            chat_history = ChatHistory()
            chat_history.messages.append(instruction_message)
            response_result = self.genner.ch_completion(chat_history)
            
            if response_result.is_err():
                return Err(f"AI generation failed: {response_result.unwrap_err()}"), ChatHistory()
            
            response = response_result.unwrap()
            chat_history.messages.append(Message(role="assistant", content=response))
            return Ok(response), chat_history
        except Exception as e:
            return Err(f"Failed to generate quarantine code: {str(e)}"), ChatHistory()

    async def handle_user_request(self, user_message: str, user_context: Dict) -> str:
        """
        Handle natural language user requests for security analysis.
        """
        request_type = self._parse_user_intent(user_message)
        
        if request_type == 'analyze_contract':
            contract_address = self._extract_address_from_message(user_message)
            if contract_address:
                result = await self.analyze_with_ai_code_generation({
                    'program_id': contract_address,
                    'analysis_type': 'contract_analysis'
                }, user_context.get('language', 'english'))
                return result['user_explanation']
            return "❌ Could not find a valid contract address in your message. Please provide a Solana program ID."
        
        elif request_type == 'analyze_token':
            token_name = self._extract_token_from_message(user_message)
            if token_name:
                result = await self.analyze_with_ai_code_generation({
                    'token_name': token_name,
                    'analysis_type': 'token_analysis'
                }, user_context.get('language', 'english'))
                return result['user_explanation']
            return "❌ Could not find a token name in your message. Please specify the token you want analyzed."
        
        elif request_type == 'track_wallet':
            wallet_address = self._extract_address_from_message(user_message)
            if wallet_address:
                await self.setup_custom_monitoring(wallet_address, 'wallet_tracking')
                return f"✅ Now tracking wallet {wallet_address[:8]}... for suspicious activity."
            return "❌ Could not find a valid wallet address. Please provide a Solana wallet address."
        
        return "I can help you analyze contracts, tokens, or track wallets. Try: 'analyze this contract: [address]' or 'check token: [name]'"

    def _parse_user_intent(self, message: str) -> str:
        """Parse user intent from natural language message"""
        message_lower = message.lower()
        if 'contract' in message_lower and ('analyze' in message_lower or 'check' in message_lower):
            return 'analyze_contract'
        elif 'token' in message_lower and ('analyze' in message_lower or 'check' in message_lower):
            return 'analyze_token'
        elif 'track' in message_lower or 'monitor' in message_lower:
            return 'track_wallet'
        return 'unknown'

    def _extract_address_from_message(self, message: str) -> Optional[str]:
        """Extract Solana address from user message"""
        pattern = r'[A-HJ-NP-Z1-9]{32,44}'
        matches = re.findall(pattern, message)
        return matches[0] if matches else None

    def _extract_token_from_message(self, message: str) -> Optional[str]:
        """Extract token name from user message"""
        pattern = r'(?:token|coin)\s+([A-Z]{2,10}|[a-zA-Z]+)'
        matches = re.findall(pattern, message, re.IGNORECASE)
        return matches[0] if matches else None

    async def setup_custom_monitoring(self, target: str, monitoring_type: str) -> Dict:
        """
        Set up custom monitoring for user-requested targets.
        """
        monitoring_request = {
            'user_id': self.agent_id,
            'target': target,
            'monitoring_type': monitoring_type,
            'created_at': datetime.now().isoformat(),
            'is_active': True
        }
        
        try:
            self.db.insert_monitoring_request(monitoring_request)
            return {'success': True, 'message': f'Monitoring activated for {target}'}
        except Exception as e:
            logger.error(f"Failed to setup monitoring: {e}")
            return {'success': False, 'message': f'Failed to setup monitoring: {str(e)}'}

    def reset(self) -> None:
        """Reset agent's chat history for new analysis session"""
        self.chat_history = ChatHistory()

    def prepare_system(self, role: str, time: str, metric_name: str, 
                      metric_state: str, network: str) -> ChatHistory:
        """Prepare system prompt for security analysis context"""
        system_prompt = f"""
You are an AI security analyst for Web3 wallets. Your role: {role}
Network: {network}
Time frame: {time}
Current security metric: {metric_name} = {metric_state}

Generate custom Python analysis code that orchestrates existing security modules.
Focus on protecting users from scams, exploits, and malicious contracts.
Use cached intelligence for instant responses.
"""
        return ChatHistory(Message(role="system", content=system_prompt))
