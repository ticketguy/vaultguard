"""
SecurityAgent with integrated quarantine management
Follows TradingAgent pattern but handles security analysis and quarantine decisions
"""

import re
from textwrap import dedent
from typing import Dict, List, Set, Tuple
from datetime import datetime, timedelta
from enum import Enum
import json

from result import Err, Ok, Result
from src.container import ContainerManager
from src.genner.Base import Genner
from src.client.rag import RAGClient
from src.sensor.security import SecuritySensor
from src.types import ChatHistory, Message
from src.db import DBInterface


class QuarantineStatus(Enum):
    """Status types for quarantined security items"""
    QUARANTINED = "quarantined"
    APPROVED = "approved"
    BURNED = "burned"
    PENDING_REVIEW = "pending_review"


class QuarantineItem:
    """Represents a security item placed in quarantine"""
    
    def __init__(self, item_data: Dict, risk_score: float, reasoning: str):
        self.id = item_data.get('hash', f"item_{datetime.now().timestamp()}")
        self.item_data = item_data
        self.risk_score = risk_score
        self.reasoning = reasoning
        self.status = QuarantineStatus.QUARANTINED
        self.quarantined_at = datetime.now()
        self.reviewed_at = None
        self.user_decision = None
        self.auto_burn_at = None
        
        # Schedule auto-burn for high-confidence threats
        if risk_score > 0.9:
            self.auto_burn_at = self.quarantined_at + timedelta(hours=168)


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
                raise ValueError(f"Missing required prompt: {prompt}")

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

    def generate_analysis_code_prompt(self, notifications_str: str, apis: str, 
                                    prev_analysis: str, rag_summary: str,
                                    before_metric_state: str, after_metric_state: str) -> str:
        """Generate prompt for security analysis code with chain of thought"""
        return self.prompts['analysis_code_prompt'].format(
            notifications_str=notifications_str,
            apis_str=apis,
            prev_analysis=prev_analysis,
            rag_summary=rag_summary,
            before_metric_state=before_metric_state,
            after_metric_state=after_metric_state
        )

    def generate_quarantine_code_prompt(self, strategy_output: str, apis: str,
                                      metric_state: str, security_tools: List[str],
                                      meta_swap_api_url: str, network: str) -> str:
        """Generate prompt for quarantine implementation code"""
        security_tools_str = '\n'.join([f"- {tool}: {'quarantine suspicious items' if tool == 'quarantine' else f'{tool} threats'}" 
                                       for tool in security_tools])
        
        return self.prompts['quarantine_code_prompt'].format(
            strategy_output=strategy_output,
            apis_str=apis,
            metric_state=metric_state,
            security_tools_str=security_tools_str,
            meta_swap_api_url=meta_swap_api_url,
            network=network
        )

    @staticmethod
    def get_default_prompts() -> Dict[str, str]:
        """Default prompts for security operations with chain of thought reasoning"""
        return {
            "system": dedent("""
                You are a Web3 wallet security analyst specializing in blockchain threat detection.
                
                Your role: {role}
                Time horizon: {time}
                Network: {network}
                Current security metric: {metric_name}
                Security state: {metric_state}
                
                Your capabilities:
                - Analyze blockchain transactions for security threats
                - Detect scams, drains, MEV attacks, and suspicious patterns
                - Make quarantine decisions with confidence scores
                - Provide clear chain of thought reasoning for all decisions
                
                Always show your reasoning step by step so users understand your analysis.
            """).strip(),
            
            "analysis_code_prompt": dedent("""
                Generate Python code to analyze security threats in blockchain transactions.
                
                Security notifications: {notifications_str}
                Available APIs: {apis_str}
                Previous analysis: {prev_analysis}
                RAG security intelligence: {rag_summary}
                
                Create code that:
                1. Fetches recent transaction data
                2. Analyzes for known threat patterns
                3. Checks addresses against threat databases
                4. Calculates risk scores with reasoning
                5. Provides detailed threat assessment
                
                Use chain of thought reasoning in your analysis.
            """).strip(),
            
            "analysis_code_on_first_prompt": dedent("""
                Generate initial security analysis code for baseline monitoring.
                
                Available APIs: {apis_str}
                Network: {network}
                
                Create code that establishes security monitoring and provides initial threat assessment.
                Show your analytical reasoning throughout the process.
            """).strip(),
            
            "strategy_prompt": dedent("""
                Based on security analysis results, formulate a comprehensive security strategy.
                
                Analysis results: {analysis_results}
                Current security state: {before_metric_state}
                
                Create a strategy with:
                1. Threat assessment with chain of thought reasoning
                2. Risk prioritization with evidence
                3. Recommended quarantine actions with confidence levels
                4. User education about identified threats
                5. Monitoring adjustments based on findings
                
                Explain your reasoning for each strategic decision.
            """).strip(),
            
            "quarantine_code_prompt": dedent("""
                Generate code to implement security actions based on the strategy.
                
                Security strategy: {strategy_output}
                Available APIs: {apis_str}
                Security tools: {security_tools_str}
                Meta-swap API: {meta_swap_api_url}
                
                Implement:
                1. Quarantine decisions with confidence thresholds
                2. Automatic blocking for high-confidence threats
                3. User review flags for medium-confidence threats
                4. Detailed logging with reasoning chains
                5. Security monitoring updates
                
                Show decision logic and reasoning for all actions taken.
            """).strip(),
            
            "regen_code_prompt": dedent("""
                Fix errors in security code while maintaining threat detection logic.
                
                Errors: {errors}
                Previous code: {previous_code}
                
                Generate corrected code that fixes the errors while preserving security effectiveness.
                Include proper error handling and maintain chain of thought reasoning.
            """).strip()
        }


class SecurityAgent:
    """
    Security agent that analyzes threats and manages quarantine decisions.
    Follows the same architectural pattern as TradingAgent but for security operations.
    """

    def __init__(self, agent_id: str, rag: RAGClient, db: DBInterface,
                 sensor: SecuritySensor, genner: Genner, 
                 container_manager: ContainerManager,
                 prompt_generator: SecurityPromptGenerator):
        """Initialize security agent with all required framework components"""
        self.agent_id = agent_id
        self.db = db
        self.rag = rag
        self.sensor = sensor
        self.genner = genner
        self.container_manager = container_manager
        self.prompt_generator = prompt_generator
        
        self.chat_history = ChatHistory()
        
        # Quarantine management - core security execution logic
        self.quarantined_items: Dict[str, QuarantineItem] = {}
        self.approved_items: Dict[str, QuarantineItem] = {}
        self.burned_items: Dict[str, QuarantineItem] = {}
        
        # Security configuration
        self.quarantine_threshold = 0.7
        self.auto_burn_threshold = 0.9
        self.auto_burn_delay_hours = 168  # 7 days
        
        # Security statistics
        self.security_stats = {
            'total_quarantined': 0,
            'total_approved': 0,
            'total_burned': 0,
            'auto_burned': 0,
            'threats_detected': 0,
            'false_positives': 0
        }

    def reset(self) -> None:
        """Reset agent's chat history for new analysis session"""
        self.chat_history = ChatHistory()

    def prepare_system(self, role: str, time: str, metric_name: str, 
                      metric_state: str, network: str) -> ChatHistory:
        """Prepare system prompt for security analysis context"""
        system_prompt = self.prompt_generator.generate_system_prompt(
            role=role, time=time, metric_name=metric_name,
            metric_state=metric_state, network=network
        )
        
        return ChatHistory(Message(role="system", content=system_prompt))

    def gen_analysis_code_on_first(self, apis: List[str], network: str) -> Result[Tuple[str, ChatHistory], str]:
        """Generate initial security analysis code for first-time setup"""
        try:
            apis_str = '\n'.join([f"- {api}" for api in apis])
            
            prompt = self.prompt_generator.prompts['analysis_code_on_first_prompt'].format(
                apis_str=apis_str,
                network=network
            )
            
            instruction_message = Message(role="user", content=prompt)
            
            response = self.genner.generate_completion([instruction_message])
            response_message = Message(role="assistant", content=response)
            
            new_chat_history = ChatHistory([instruction_message, response_message])
            
            return Ok((response, new_chat_history))
            
        except Exception as e:
            return Err(f"Failed to generate analysis code: {str(e)}")

    def gen_analysis_code(self, notifications_str: str, apis: List[str],
                         prev_analysis: str, rag_summary: str,
                         before_metric_state: str, after_metric_state: str) -> Result[Tuple[str, ChatHistory], str]:
        """Generate security analysis code based on notifications and context"""
        try:
            apis_str = '\n'.join([f"- {api}" for api in apis])
            
            prompt = self.prompt_generator.generate_analysis_code_prompt(
                notifications_str=notifications_str,
                apis=apis_str,
                prev_analysis=prev_analysis,
                rag_summary=rag_summary,
                before_metric_state=before_metric_state,
                after_metric_state=after_metric_state
            )
            
            instruction_message = Message(role="user", content=prompt)
            
            response = self.genner.generate_completion(
                self.chat_history.messages + [instruction_message]
            )
            response_message = Message(role="assistant", content=response)
            
            new_chat_history = ChatHistory([instruction_message, response_message])
            
            return Ok((response, new_chat_history))
            
        except Exception as e:
            return Err(f"Failed to generate analysis code: {str(e)}")

    def gen_security_strategy(self, analysis_results: str, apis: List[str],
                            before_metric_state: str, network: str, time: str) -> Result[Tuple[str, ChatHistory], str]:
        """Generate security strategy based on threat analysis results"""
        try:
            apis_str = '\n'.join([f"- {api}" for api in apis])
            
            prompt = self.prompt_generator.prompts['strategy_prompt'].format(
                analysis_results=analysis_results,
                apis_str=apis_str,
                before_metric_state=before_metric_state,
                network=network,
                time=time
            )
            
            instruction_message = Message(role="user", content=prompt)
            
            response = self.genner.generate_completion(
                self.chat_history.messages + [instruction_message]
            )
            response_message = Message(role="assistant", content=response)
            
            new_chat_history = ChatHistory([instruction_message, response_message])
            
            return Ok((response, new_chat_history))
            
        except Exception as e:
            return Err(f"Failed to generate security strategy: {str(e)}")

    def gen_quarantine_code(self, strategy_output: str, apis: List[str],
                          metric_state: str, security_tools: List[str],
                          meta_swap_api_url: str, network: str) -> Result[Tuple[str, ChatHistory], str]:
        """Generate code to implement quarantine and security actions"""
        try:
            apis_str = '\n'.join([f"- {api}" for api in apis])
            
            prompt = self.prompt_generator.generate_quarantine_code_prompt(
                strategy_output=strategy_output,
                apis=apis_str,
                metric_state=metric_state,
                security_tools=security_tools,
                meta_swap_api_url=meta_swap_api_url,
                network=network
            )
            
            instruction_message = Message(role="user", content=prompt)
            
            response = self.genner.generate_completion(
                self.chat_history.messages + [instruction_message]
            )
            response_message = Message(role="assistant", content=response)
            
            new_chat_history = ChatHistory([instruction_message, response_message])
            
            return Ok((response, new_chat_history))
            
        except Exception as e:
            return Err(f"Failed to generate quarantine code: {str(e)}")

    def regen_on_error(self, errors: str, latest_response: str) -> Result[str, str]:
        """Regenerate code when errors occur, maintaining security logic"""
        try:
            prompt = self.prompt_generator.prompts['regen_code_prompt'].format(
                errors=errors,
                previous_code=latest_response
            )
            
            instruction_message = Message(role="user", content=prompt)
            
            response = self.genner.generate_completion(
                self.chat_history.messages + [instruction_message]
            )
            
            return Ok(response)
            
        except Exception as e:
            return Err(f"Failed to regenerate code: {str(e)}")

    # Core quarantine management methods - security execution logic

    def evaluate_for_quarantine(self, item_data: Dict, risk_score: float, reasoning: str) -> bool:
        """Determine if security item should be quarantined based on risk assessment"""
        should_quarantine = risk_score > self.quarantine_threshold
        
        if should_quarantine:
            self.quarantine_item(item_data, risk_score, reasoning)
            return True
        
        return False

    def quarantine_item(self, item_data: Dict, risk_score: float, reasoning: str) -> QuarantineItem:
        """Place security threat in quarantine with detailed reasoning"""
        quarantine_item = QuarantineItem(item_data, risk_score, reasoning)
        
        self.quarantined_items[quarantine_item.id] = quarantine_item
        self.security_stats['total_quarantined'] += 1
        self.security_stats['threats_detected'] += 1
        
        print(f"🚨 QUARANTINED: {quarantine_item.id}")
        print(f"   Risk Score: {risk_score:.2f}")
        print(f"   Reasoning: {reasoning}")
        
        # Chain of thought logging
        if risk_score > self.auto_burn_threshold:
            print(f"   → High confidence threat, scheduled for auto-burn in {self.auto_burn_delay_hours}h")
        
        return quarantine_item

    def approve_quarantined_item(self, item_id: str, user_feedback: str = "") -> bool:
        """Approve quarantined item based on user review or false positive detection"""
        if item_id not in self.quarantined_items:
            return False
        
        item = self.quarantined_items[item_id]
        item.status = QuarantineStatus.APPROVED
        item.reviewed_at = datetime.now()
        item.user_decision = "approved"
        
        # Move from quarantine to approved storage
        self.approved_items[item_id] = item
        del self.quarantined_items[item_id]
        
        self.security_stats['total_approved'] += 1
        
        print(f"✅ APPROVED: {item_id}")
        if user_feedback:
            print(f"   User feedback: {user_feedback}")
            # Learn from false positive for future improvements
            self.security_stats['false_positives'] += 1
        
        return True

    def burn_quarantined_item(self, item_id: str, auto_burn: bool = False, user_feedback: str = "") -> bool:
        """Permanently remove quarantined threat item"""
        if item_id not in self.quarantined_items:
            return False
        
        item = self.quarantined_items[item_id]
        item.status = QuarantineStatus.BURNED
        item.reviewed_at = datetime.now()
        
        if auto_burn:
            item.user_decision = "auto_burned"
            self.security_stats['auto_burned'] += 1
        else:
            item.user_decision = "user_burned"
        
        # Move from quarantine to burned storage for audit trail
        self.burned_items[item_id] = item
        del self.quarantined_items[item_id]
        
        self.security_stats['total_burned'] += 1
        
        burn_type = "🔥 AUTO-BURNED" if auto_burn else "🗑️ BURNED"
        print(f"{burn_type}: {item_id}")
        if user_feedback:
            print(f"   User feedback: {user_feedback}")
        
        return True

    def get_quarantine_summary(self) -> Dict:
        """Get comprehensive summary of quarantine status and security metrics"""
        current_time = datetime.now()
        
        # Check for items ready for auto-burn
        auto_burn_ready = []
        for item in self.quarantined_items.values():
            if item.auto_burn_at and current_time >= item.auto_burn_at:
                auto_burn_ready.append(item.id)
        
        return {
            'summary': {
                'total_quarantined': len(self.quarantined_items),
                'total_approved': len(self.approved_items),
                'total_burned': len(self.burned_items),
                'auto_burn_ready': len(auto_burn_ready),
                'last_updated': current_time.isoformat()
            },
            'statistics': self.security_stats,
            'quarantined_items': [
                {
                    'id': item.id,
                    'risk_score': item.risk_score,
                    'reasoning': item.reasoning,
                    'quarantined_at': item.quarantined_at.isoformat(),
                    'auto_burn_at': item.auto_burn_at.isoformat() if item.auto_burn_at else None,
                    'days_in_quarantine': (current_time - item.quarantined_at).days
                }
                for item in self.quarantined_items.values()
            ],
            'auto_burn_ready': auto_burn_ready
        }

    def get_security_metrics(self) -> Dict:
        """Get current security performance metrics for monitoring"""
        total_decisions = self.security_stats['threats_detected']
        accuracy_rate = 1.0 - (self.security_stats['false_positives'] / max(total_decisions, 1))
        
        return {
            'threat_detection_rate': self.security_stats['threats_detected'],
            'quarantine_accuracy': accuracy_rate,
            'auto_burn_rate': self.security_stats['auto_burned'] / max(self.security_stats['total_burned'], 1),
            'user_approval_rate': self.security_stats['total_approved'] / max(total_decisions, 1),
            'current_quarantine_count': len(self.quarantined_items),
            'system_confidence': min(accuracy_rate + 0.1, 1.0)  # Bounded confidence score
        }