"""
SecurityAgent with AI Code Generation
Core AI engine that generates custom analysis code for each threat
"""

import re
import json
from textwrap import dedent
from typing import Dict, List, Set, Tuple, Optional
from datetime import datetime, timedelta
from enum import Enum

from result import Err, Ok, Result
from src.container import ContainerManager
from src.genner.Base import Genner
from src.client.rag import RAGClient
from src.sensor.security import SecuritySensor
from src.types import ChatHistory, Message
from src.db import DBInterface


class SecurityPromptGenerator:
    """Generates prompts for security analysis using chain of thought reasoning"""
    
    def __init__(self, prompts: Dict[str, str]):
        if not prompts:
            prompts = self.get_default_prompts()
        self._validate_prompts(prompts)
        self.prompts = prompts

    def _validate_prompts(self, prompts: Dict[str, str]):
        """Ensure all required prompts are present"""
        required_prompts = [
            'system', 'analysis_code_prompt', 'analysis_code_on_first_prompt',
            'strategy_prompt', 'quarantine_code_prompt', 'regen_code_prompt'
        ]
        for prompt in required_prompts:
            if prompt not in prompts:
                prompts[prompt] = f"Default {prompt} prompt for security analysis"

    def get_default_prompts(self) -> Dict[str, str]:
        """Get default security prompts"""
        return {
            'system': dedent("""
                You are an AI security analyst for Web3 wallets specializing in {role}.
                Network: {network}
                Time frame: {time}
                Current security metric: {metric_name} = {metric_state}

                Generate custom Python analysis code for each security threat based on available intelligence.
                Focus on protecting users from scams, exploits, and malicious contracts.
                Provide clear explanations that users can understand.
            """).strip(),
            
            'analysis_code_prompt': dedent("""
                Generate Python security analysis code based on threat intelligence.
                
                Notifications: {notifications_str}
                Available APIs: {apis_str}
                Previous Analysis: {prev_analysis}
                RAG Intelligence: {rag_summary}
                
                Generate code that analyzes current security threats and provides protection.
                Focus on real Solana blockchain analysis using available APIs.
                Return detailed threat analysis with risk scores and evidence.
            """).strip(),
            
            'analysis_code_on_first_prompt': dedent("""
                Generate initial security analysis code for blockchain monitoring.
                
                Available APIs: {apis_str}
                Network: {network}
                
                Create comprehensive security monitoring code that:
                1. Analyzes wallet transactions for threats
                2. Detects scam tokens and contracts
                3. Identifies MEV attacks and exploits
                4. Returns detailed security assessment
                
                Use the available APIs to gather real blockchain data.
            """).strip(),
            
            'strategy_prompt': dedent("""
                Generate security strategy based on threat analysis results.
                
                Analysis Results: {analysis_results}
                Available APIs: {apis_str}
                Current Security State: {before_metric_state}
                Network: {network}
                Time Frame: {time}
                
                Create a comprehensive security strategy that:
                1. Addresses identified threats
                2. Implements protective measures
                3. Provides user recommendations
                4. Updates security protocols
                
                Focus on actionable security improvements.
            """).strip(),
            
            'quarantine_code_prompt': dedent("""
                Generate quarantine management code for security threats.
                
                Strategy: {strategy_output}
                Available APIs: {apis_str}
                Current State: {before_metric_state}
                
                Create code that:
                1. Implements quarantine decisions
                2. Manages threat isolation
                3. Handles user approvals
                4. Updates security database
                
                Ensure safe handling of suspicious items.
            """).strip(),
            
            'regen_code_prompt': dedent("""
                Fix errors in security code while maintaining threat detection logic.
                
                Errors: {errors}
                Previous code: {previous_code}
                
                Generate corrected code that fixes the errors while preserving security effectiveness.
                Include proper error handling and maintain chain of thought reasoning.
            """).strip()
        }

    def generate_system_prompt(self, role: str, time: str, metric_name: str, 
                              metric_state: str, network: str) -> str:
        """Generate system prompt with security context"""
        return self.prompts['system'].format(
            role=role,
            time=time,
            metric_name=metric_name,
            metric_state=metric_state,
            network=network
        )

    def generate_analysis_code_prompt(self, notifications_str: str, apis_str: str, 
                                    prev_analysis: str, rag_summary: str,
                                    before_metric_state: str, after_metric_state: str) -> str:
        """Generate prompt for security analysis code"""
        return self.prompts['analysis_code_prompt'].format(
            notifications_str=notifications_str,
            apis_str=apis_str,
            prev_analysis=prev_analysis,
            rag_summary=rag_summary,
            before_metric_state=before_metric_state,
            after_metric_state=after_metric_state
        )

    def generate_strategy_prompt(self, analysis_results: str, apis_str: str,
                               before_metric_state: str, network: str, time: str) -> str:
        """Generate prompt for security strategy"""
        return self.prompts['strategy_prompt'].format(
            analysis_results=analysis_results,
            apis_str=apis_str,
            before_metric_state=before_metric_state,
            network=network,
            time=time
        )

    def generate_quarantine_code_prompt(self, strategy_output: str, apis_str: str,
                                      before_metric_state: str) -> str:
        """Generate prompt for quarantine code"""
        return self.prompts['quarantine_code_prompt'].format(
            strategy_output=strategy_output,
            apis_str=apis_str,
            before_metric_state=before_metric_state
        )

class SecurityAgent:
    """
    AI-powered SecurityAgent that generates custom analysis code for every threat.
    Uses RAG intelligence to determine what analysis to perform, then generates
    Python code specific to each transaction/contract/threat.
    """

    def __init__(self, agent_id: str, rag: RAGClient, db: DBInterface,
                 sensor: SecuritySensor, genner: Genner, 
                 container_manager: ContainerManager,
                 prompt_generator):
        """Initialize security agent with AI code generation capabilities"""
        self.agent_id = agent_id
        self.db = db
        self.rag = rag
        self.sensor = sensor
        self.genner = genner
        self.container_manager = container_manager
        self.prompt_generator = prompt_generator
        
        self.chat_history = ChatHistory()
        
        # AI Code Generation Configuration
        self.ai_code_config = {
            'max_execution_time': 10,  # seconds
            'supported_languages': ['english', 'spanish', 'french', 'japanese', 'portuguese'],
            'default_language': 'english'
        }

    # ========== AI CODE GENERATION CORE METHODS ==========

    async def analyze_with_ai_code_generation(self, target_data: Dict, user_language: str = "english") -> Dict:
        """
        MAIN METHOD: AI Code Generation Pipeline
        1. RAG Search → 2. AI Generates Code → 3. Execute → 4. AI Explains
        """
        analysis_result = {
            'action': 'ALLOW',  # ALLOW/WARN/BLOCK
            'risk_score': 0.0,
            'chain_of_thought': [],
            'user_explanation': '',
            'technical_details': {},
            'ai_generated_code': '',
            'execution_results': {},
            'rag_intelligence': {},
            'analysis_time_ms': 0
        }
        
        start_time = datetime.now()
        
        try:
            # STEP 1: RAG Intelligence Search
            analysis_result['chain_of_thought'].append("🔍 Step 1: Searching threat intelligence database...")
            rag_results = await self._search_threat_intelligence(target_data)
            analysis_result['rag_intelligence'] = rag_results
            
            # STEP 2: AI Generates Custom Analysis Code
            analysis_result['chain_of_thought'].append("🤖 Step 2: AI generating custom analysis code...")
            ai_code = await self._generate_analysis_code(target_data, rag_results)
            analysis_result['ai_generated_code'] = ai_code
            
            # STEP 3: Execute AI-Generated Code
            analysis_result['chain_of_thought'].append("⚡ Step 3: Executing AI-generated analysis...")
            execution_results = await self._execute_ai_analysis_code(ai_code, target_data)
            analysis_result['execution_results'] = execution_results
            analysis_result['technical_details'] = execution_results
            
            # STEP 4: Calculate Risk and Decision
            analysis_result['chain_of_thought'].append("⚖️ Step 4: Evaluating risk and making decision...")
            risk_assessment = await self._assess_risk_from_results(execution_results, rag_results)
            analysis_result.update(risk_assessment)
            
            # STEP 5: AI Generates User Explanation
            analysis_result['chain_of_thought'].append("💬 Step 5: Generating user-friendly explanation...")
            user_explanation = await self._generate_user_explanation(
                execution_results, rag_results, risk_assessment, user_language
            )
            analysis_result['user_explanation'] = user_explanation
            
        except Exception as e:
            analysis_result['action'] = 'BLOCK'
            analysis_result['risk_score'] = 1.0
            analysis_result['user_explanation'] = f"Analysis failed for safety: {str(e)}"
            analysis_result['chain_of_thought'].append(f"❌ Error: {str(e)}")
        
        # Calculate analysis time
        end_time = datetime.now()
        analysis_result['analysis_time_ms'] = int((end_time - start_time).total_seconds() * 1000)
        
        return analysis_result

    async def _search_threat_intelligence(self, target_data: Dict) -> Dict:
        """Step 1: Search RAG for relevant threat intelligence"""
        search_queries = []
        
        # Build search queries based on target data
        if target_data.get('token_name'):
            search_queries.append(f"token {target_data['token_name']} scam honeypot risks")
        
        if target_data.get('contract_address'):
            search_queries.append(f"contract {target_data['contract_address']} drain exploit")
        
        if target_data.get('from_address'):
            search_queries.append(f"address {target_data['from_address']} blacklist scammer")
        
        if target_data.get('transaction_type'):
            search_queries.append(f"{target_data['transaction_type']} mev attacks patterns")
        
        # Default comprehensive search if no specific data
        if not search_queries:
            search_queries.append("solana security threats scams exploits")
        
        rag_intelligence = {
            'search_queries': search_queries,
            'threat_patterns': [],
            'similar_cases': [],
            'community_reports': [],
            'analysis_suggestions': []
        }
        
        # Search RAG for each query
        for query in search_queries:
            try:
                # Search your existing RAG system
                rag_results = await self.rag.search_threat_intelligence(query, top_k=5)
                
                for result in rag_results:
                    if 'honeypot' in result.get('content', '').lower():
                        rag_intelligence['analysis_suggestions'].append('honeypot_analysis')
                    if 'mev' in result.get('content', '').lower():
                        rag_intelligence['analysis_suggestions'].append('mev_analysis')
                    if 'drain' in result.get('content', '').lower():
                        rag_intelligence['analysis_suggestions'].append('drain_contract_analysis')
                    if 'dust' in result.get('content', '').lower():
                        rag_intelligence['analysis_suggestions'].append('dust_attack_analysis')
                    
                    rag_intelligence['threat_patterns'].append(result.get('content', ''))
                
            except Exception as e:
                rag_intelligence['analysis_suggestions'].append('comprehensive_analysis')
        
        # If no specific threats found, default to comprehensive analysis
        if not rag_intelligence['analysis_suggestions']:
            rag_intelligence['analysis_suggestions'] = ['comprehensive_security_analysis']
        
        return rag_intelligence

    async def _generate_analysis_code(self, target_data: Dict, rag_intelligence: Dict) -> str:
        """Step 2: AI generates custom Python analysis code"""
        
        # Build prompt for AI code generation
        analysis_types = rag_intelligence.get('analysis_suggestions', ['comprehensive_security_analysis'])
        threat_patterns = rag_intelligence.get('threat_patterns', [])
        
        code_generation_prompt = f"""
Generate Python code to analyze this Solana transaction/token for security threats.

Target Data:
{json.dumps(target_data, indent=2)}

RAG Intelligence Found:
- Analysis Types Needed: {', '.join(analysis_types)}
- Threat Patterns: {threat_patterns[:3] if threat_patterns else ['No specific patterns found']}

Generate a complete Python function called 'analyze_security_threats' that:
1. Takes the target_data as input
2. Performs the specific analyses suggested by RAG intelligence
3. Returns a detailed analysis result dictionary

If RAG found specific threats (like honeypot, MEV, etc.), focus the analysis on those.
If RAG found nothing, perform comprehensive security analysis checking for:
- Honeypot token mechanics (if token analysis)
- MEV attack patterns (if transaction analysis)  
- Drain contract functions (if contract analysis)
- Dust attack patterns (if small value transaction)
- Behavioral anomalies

Code Requirements:
- Use async/await for any external calls
- Include detailed logging of what was found
- Return risk scores from 0.0 to 1.0
- Include specific evidence in results
- Handle errors gracefully

ONLY return the Python code, no explanations.
"""

        try:
            # Generate code using your existing AI generator
            instruction_message = Message(role="user", content=code_generation_prompt)
            ai_response = self.genner.generate_completion([instruction_message])
            
            # Extract Python code from AI response
            python_code = self._extract_python_code(ai_response)
            
            return python_code
            
        except Exception as e:
            # Fallback: Generate basic comprehensive analysis code
            return self._generate_fallback_analysis_code(target_data, analysis_types)

    def _extract_python_code(self, ai_response: str) -> str:
        """Extract Python code from AI response"""
        # Find Python code blocks
        code_pattern = r'```python\s*(.*?)\s*```'
        matches = re.findall(code_pattern, ai_response, re.DOTALL)
        
        if matches:
            return matches[0].strip()
        
        # If no code blocks found, try to extract function
        function_pattern = r'(async def analyze_security_threats.*?(?=\n\n|\Z))'
        matches = re.findall(function_pattern, ai_response, re.DOTALL)
        
        if matches:
            return matches[0].strip()
        
        # Return the whole response if no patterns match
        return ai_response.strip()

    def _generate_fallback_analysis_code(self, target_data: Dict, analysis_types: List[str]) -> str:
        """Generate fallback analysis code when AI generation fails"""
        
        return dedent(f"""
        async def analyze_security_threats(target_data):
            import asyncio
            import json
            from datetime import datetime
            
            analysis_result = {{
                'risk_score': 0.0,
                'threats_found': [],
                'evidence': [],
                'analysis_type': 'fallback_comprehensive',
                'timestamp': datetime.now().isoformat()
            }}
            
            # Analysis based on target data
            if target_data.get('value'):
                value = float(target_data.get('value', 0))
                if 0 < value < 0.001:
                    analysis_result['threats_found'].append('potential_dust_attack')
                    analysis_result['risk_score'] += 0.6
                    analysis_result['evidence'].append(f'Very small transaction amount: {{value}} SOL')
            
            if target_data.get('token_name'):
                token_name = target_data['token_name'].lower()
                suspicious_keywords = ['usdc', 'ethereum', 'bitcoin', 'wrapped']
                for keyword in suspicious_keywords:
                    if keyword in token_name and token_name != keyword:
                        analysis_result['threats_found'].append('potential_fake_token')
                        analysis_result['risk_score'] += 0.7
                        analysis_result['evidence'].append(f'Token name may be impersonating: {{keyword}}')
            
            if target_data.get('from_address'):
                # Basic address pattern analysis
                address = target_data['from_address']
                if address.count('0') > 30 or address.count('1') > 30:
                    analysis_result['threats_found'].append('suspicious_address_pattern')
                    analysis_result['risk_score'] += 0.4
                    analysis_result['evidence'].append('Address has suspicious character patterns')
            
            # Cap risk score at 1.0
            analysis_result['risk_score'] = min(analysis_result['risk_score'], 1.0)
            
            return analysis_result
        """)

    async def _execute_ai_analysis_code(self, analysis_code: str, target_data: Dict) -> Dict:
        """Step 3: Execute the AI-generated analysis code safely"""
        try:
            # Prepare the execution environment
            execution_code = f"""
{analysis_code}

# Execute the analysis
import json
result = await analyze_security_threats({json.dumps(target_data)})
print(json.dumps(result))
"""
            
            # Execute in container for safety
            execution_result = self.container_manager.run_code_in_con(
                execution_code, 
                "ai_generated_security_analysis"
            )
            
            output, _ = execution_result.unwrap()
            
            # Parse the JSON result
            try:
                return json.loads(output.strip())
            except json.JSONDecodeError:
                # If not JSON, wrap in basic structure
                return {
                    'risk_score': 0.5,
                    'threats_found': ['execution_parse_error'],
                    'evidence': [f'Analysis output: {output[:200]}...'],
                    'raw_output': output
                }
                
        except Exception as e:
            return {
                'risk_score': 0.8,
                'threats_found': ['analysis_execution_error'],
                'evidence': [f'Error executing analysis: {str(e)}'],
                'error': str(e)
            }

    async def _assess_risk_from_results(self, execution_results: Dict, rag_intelligence: Dict) -> Dict:
        """Step 4: Assess overall risk and make ALLOW/WARN/BLOCK decision"""
        
        risk_score = execution_results.get('risk_score', 0.0)
        threats_found = execution_results.get('threats_found', [])
        
        # Adjust risk based on RAG intelligence
        if rag_intelligence.get('threat_patterns'):
            risk_score += 0.2  # Increase risk if known threat patterns exist
        
        # Make decision based on risk score
        if risk_score >= 0.8:
            action = 'BLOCK'
        elif risk_score >= 0.4:
            action = 'WARN'
        else:
            action = 'ALLOW'
        
        return {
            'action': action,
            'risk_score': min(risk_score, 1.0),
            'threats_found': threats_found,
            'decision_reasoning': f'Risk score: {risk_score:.2f}, Threats: {", ".join(threats_found) if threats_found else "None"}'
        }

    async def _generate_user_explanation(self, execution_results: Dict, rag_intelligence: Dict, 
                                       risk_assessment: Dict, user_language: str) -> str:
        """Step 5: AI generates user-friendly explanation"""
        
        explanation_prompt = f"""
Generate a clear, simple explanation for a user about this security analysis in {user_language}.

Analysis Results:
- Action: {risk_assessment['action']}
- Risk Score: {risk_assessment['risk_score']:.2f}
- Threats Found: {execution_results.get('threats_found', [])}
- Evidence: {execution_results.get('evidence', [])}

RAG Intelligence:
- Known Patterns: {rag_intelligence.get('threat_patterns', [])[:2]}

Requirements:
1. Use simple, non-technical language
2. Explain WHAT the threat is and WHY it's dangerous
3. Give clear recommendation (Allow/Warning/Block)
4. Maximum 3-4 sentences
5. Use language: {user_language}
6. Include appropriate emoji

ONLY return the explanation text, no code or extra formatting.
"""

        try:
            instruction_message = Message(role="user", content=explanation_prompt)
            explanation = self.genner.generate_completion([instruction_message])
            return explanation.strip()
            
        except Exception:
            # Fallback explanation
            action = risk_assessment['action']
            risk_score = risk_assessment['risk_score']
            
            if action == 'BLOCK':
                return f"🚨 BLOCKED: High security risk detected ({risk_score:.0%}). This could be a scam or malicious transaction. Do not proceed."
            elif action == 'WARN':
                return f"⚠️ WARNING: Moderate security risk detected ({risk_score:.0%}). Please review carefully before proceeding."
            else:
                return f"✅ SAFE: Low security risk ({risk_score:.0%}). Transaction appears legitimate."

    # ========== CONVERSATIONAL INTERFACE ==========

    async def handle_user_request(self, user_message: str, user_context: Dict) -> str:
        """Handle natural language user requests like 'analyze this contract'"""
        
        # Parse user intent
        request_type = self._parse_user_intent(user_message)
        
        if request_type == 'analyze_contract':
            contract_address = self._extract_address_from_message(user_message)
            if contract_address:
                result = await self.analyze_with_ai_code_generation({
                    'contract_address': contract_address,
                    'analysis_type': 'contract_analysis'
                }, user_context.get('language', 'english'))
                return result['user_explanation']
        
        elif request_type == 'analyze_token':
            token_name = self._extract_token_from_message(user_message)
            if token_name:
                result = await self.analyze_with_ai_code_generation({
                    'token_name': token_name,
                    'analysis_type': 'token_analysis'
                }, user_context.get('language', 'english'))
                return result['user_explanation']
        
        elif request_type == 'track_wallet':
            wallet_address = self._extract_address_from_message(user_message)
            if wallet_address:
                await self.setup_custom_monitoring(wallet_address, 'wallet_tracking')
                return f"✅ Now tracking wallet {wallet_address[:8]}... for suspicious activity."
        
        else:
            return "I can help you analyze contracts, tokens, or track wallets. Try: 'analyze this contract: [address]' or 'track this wallet: [address]'"

    def _parse_user_intent(self, message: str) -> str:
        """Parse user intent from natural language"""
        message_lower = message.lower()
        
        if 'contract' in message_lower and ('analyze' in message_lower or 'check' in message_lower):
            return 'analyze_contract'
        elif 'token' in message_lower and ('analyze' in message_lower or 'check' in message_lower):
            return 'analyze_token'
        elif 'track' in message_lower or 'monitor' in message_lower:
            return 'track_wallet'
        else:
            return 'unknown'

    def _extract_address_from_message(self, message: str) -> Optional[str]:
        """Extract Solana address from user message"""
        # Basic pattern for Solana addresses (base58, 32-44 chars)
        pattern = r'[A-HJ-NP-Z1-9]{32,44}'
        matches = re.findall(pattern, message)
        return matches[0] if matches else None

    def _extract_token_from_message(self, message: str) -> Optional[str]:
        """Extract token name from user message"""
        # Look for token names after keywords
        pattern = r'(?:token|coin)\s+([A-Z]{2,10}|[a-zA-Z]+)'
        matches = re.findall(pattern, message, re.IGNORECASE)
        return matches[0] if matches else None

    async def setup_custom_monitoring(self, target: str, monitoring_type: str) -> Dict:
        """Set up user-requested monitoring"""
        monitoring_request = {
            'user_id': self.agent_id,
            'target': target,
            'monitoring_type': monitoring_type,
            'created_at': datetime.now().isoformat(),
            'is_active': True
        }
        
        # Save to database
        try:
            self.db.insert_monitoring_request(monitoring_request)
            return {'success': True, 'message': f'Monitoring activated for {target}'}
        except Exception as e:
            return {'success': False, 'message': f'Failed to setup monitoring: {str(e)}'}

    # ========== LEGACY METHODS FOR COMPATIBILITY ==========

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

Generate custom Python analysis code for each security threat based on available intelligence.
"""
        
        return ChatHistory(Message(role="system", content=system_prompt))