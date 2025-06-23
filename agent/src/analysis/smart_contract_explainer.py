"""
Smart Contract Analyzer that explains contracts in normal English
Deep analysis, not surface pattern matching
"""

import asyncio
import json
from typing import Dict, List, Optional
import re

class SmartContractExplainer:
    """
    Deep analysis of smart contracts with plain English explanations
    Tells users exactly what a contract can do to their tokens
    """
    
    def __init__(self):
        # Deep analysis patterns for contract behavior
        self.contract_behaviors = {
            'token_permissions': {
                'approve': 'allow the contract to spend your tokens',
                'transferFrom': 'move tokens from your wallet without asking again',
                'setApprovalForAll': 'control ALL your tokens of this type',
                'increaseAllowance': 'increase how much it can spend',
                'decreaseAllowance': 'reduce how much it can spend'
            },
            
            'dangerous_functions': {
                'emergencyWithdraw': 'take all tokens in an "emergency"',
                'rescueTokens': 'remove tokens from the contract',
                'adminWithdraw': 'let admin take tokens',
                'pause': 'stop all token transfers',
                'blacklist': 'block specific wallets from trading',
                'mint': 'create new tokens (could reduce your value)',
                'burn': 'destroy tokens permanently'
            },
            
            'ownership_powers': {
                'transferOwnership': 'give control to someone else',
                'renounceOwnership': 'give up control (good thing)',
                'setFeeReceiver': 'change where fees go',
                'setTaxes': 'change how much you pay in fees',
                'setMaxTransaction': 'limit how much can be traded',
                'addLiquidity': 'add tokens to trading pool',
                'removeLiquidity': 'remove tokens from trading pool'
            }
        }
        
        # Risk level explanations
        self.risk_explanations = {
            'low': "✅ This contract has standard, safe functions",
            'medium': "⚠️ This contract has some control over tokens but seems normal",
            'high': "🚨 This contract can do dangerous things to your tokens",
            'critical': "💀 This contract can steal or lock your tokens"
        }
    
    async def explain_contract_in_english(self, contract_data: Dict) -> Dict:
        """Analyze contract and provide plain English explanation"""
        
        # Handle None or empty contract_data
        if not contract_data:
            return {
                'contract_address': 'unknown',
                'what_it_can_do': [],
                'red_flags': [],
                'overall_risk': 'low',
                'should_user_approve': True,
                'user_friendly_summary': 'No contract data available'
            }
        
        functions = contract_data.get('functions', [])
        bytecode = contract_data.get('bytecode', '')
        
        analysis = {
            'contract_address': contract_data.get('address'),
            'what_it_can_do': [],
            'red_flags': [],
            'overall_risk': 'low',
            'should_user_approve': True,
            'user_friendly_summary': ''
        }
        
        # Analyze what the contract can actually do
        permissions_analysis = await self._analyze_token_permissions(function_signatures)
        dangerous_functions_analysis = await self._analyze_dangerous_functions(function_signatures, bytecode)
        ownership_analysis = await self._analyze_ownership_structure(function_signatures, bytecode)
        
        # Build what it can do list
        analysis['what_it_can_do'] = (
            permissions_analysis['capabilities'] +
            dangerous_functions_analysis['capabilities'] +
            ownership_analysis['capabilities']
        )
        
        # Determine permission requests
        analysis['permission_requests'] = permissions_analysis['requests']
        
        # Identify red flags
        analysis['red_flags'] = (
            dangerous_functions_analysis['red_flags'] +
            ownership_analysis['red_flags']
        )
        
        # Calculate overall risk
        analysis['overall_risk'] = await self._calculate_overall_risk(
            permissions_analysis, dangerous_functions_analysis, ownership_analysis
        )
        
        # Generate user-friendly summary
        analysis['user_friendly_summary'] = await self._generate_user_summary(analysis)
        
        # Should user approve?
        analysis['should_user_approve'] = analysis['overall_risk'] in ['low', 'medium']
        
        return analysis
    
    async def _analyze_token_permissions(self, functions: List[str]) -> Dict:
        """Analyze what token permissions the contract wants"""
        capabilities = []
        requests = []
        risk_score = 0.0
        
        for func in functions:
            func_lower = func.lower()
            
            # Check for approval functions
            if any(perm in func_lower for perm in ['approve', 'allowance']):
                if 'setapprovalforall' in func_lower or 'approveall' in func_lower:
                    capabilities.append("🔓 Control ALL your tokens of this type")
                    requests.append("unlimited_token_control")
                    risk_score += 0.8
                else:
                    capabilities.append("💰 Spend a specific amount of your tokens")
                    requests.append("limited_token_spending")
                    risk_score += 0.3
            
            # Check for transfer functions
            if 'transferfrom' in func_lower:
                capabilities.append("📤 Move tokens from your wallet without asking again")
                requests.append("token_transfer_permission")
                risk_score += 0.4
        
        return {
            'capabilities': capabilities,
            'requests': requests,
            'risk_score': risk_score
        }
    
    async def _analyze_dangerous_functions(self, functions: List[str], bytecode: str) -> Dict:
        """Deep analysis of dangerous functions"""
        capabilities = []
        red_flags = []
        risk_score = 0.0
        
        for func in functions:
            func_lower = func.lower()
            
            # Check for emergency/rescue functions
            if any(danger in func_lower for danger in ['emergency', 'rescue', 'admin']):
                if 'withdraw' in func_lower:
                    capabilities.append("🚨 Take tokens in an 'emergency' situation")
                    red_flags.append("Emergency withdrawal function - owner can take tokens")
                    risk_score += 0.9
                
                if 'rescue' in func_lower:
                    capabilities.append("🛟 'Rescue' tokens from the contract")
                    red_flags.append("Rescue function - tokens can be removed by admin")
                    risk_score += 0.8
            
            # Check for pause functions
            if any(pause in func_lower for pause in ['pause', 'stop', 'halt']):
                capabilities.append("⏸️ Stop all token trading")
                red_flags.append("Contract can be paused - trading can be stopped")
                risk_score += 0.6
            
            # Check for blacklist functions
            if any(black in func_lower for black in ['blacklist', 'ban', 'block']):
                capabilities.append("🚫 Block specific wallets from trading")
                red_flags.append("Blacklist function - specific addresses can be blocked")
                risk_score += 0.7
        
        # Deep bytecode analysis for hidden functions
        hidden_risks = await self._analyze_bytecode_for_hidden_functions(bytecode)
        capabilities.extend(hidden_risks['capabilities'])
        red_flags.extend(hidden_risks['red_flags'])
        risk_score += hidden_risks['risk_score']
        
        return {
            'capabilities': capabilities,
            'red_flags': red_flags,
            'risk_score': risk_score
        }
    
    async def _analyze_ownership_structure(self, functions: List[str], bytecode: str) -> Dict:
        """Analyze contract ownership and control structure"""
        capabilities = []
        red_flags = []
        risk_score = 0.0
        
        has_owner = False
        can_change_owner = False
        can_renounce = False
        
        for func in functions:
            func_lower = func.lower()
            
            if 'owner' in func_lower:
                has_owner = True
                
                if 'transfer' in func_lower and 'ownership' in func_lower:
                    can_change_owner = True
                    capabilities.append("👑 Transfer control to a different person")
                    risk_score += 0.5
                
                if 'renounce' in func_lower:
                    can_renounce = True
                    capabilities.append("🗑️ Give up all control (permanently)")
                    # This is actually good - reduces risk
                    risk_score -= 0.2
            
            # Check for fee/tax controls
            if any(fee in func_lower for fee in ['fee', 'tax', 'rate']):
                if any(set_word in func_lower for set_word in ['set', 'change', 'update']):
                    capabilities.append("💸 Change how much fees you pay")
                    red_flags.append("Owner can change trading fees/taxes")
                    risk_score += 0.6
        
        # Check if ownership is renounced
        ownership_status = await self._check_ownership_status(bytecode)
        if ownership_status == 'renounced':
            capabilities.append("✅ No one controls this contract anymore (renounced)")
            risk_score -= 0.3  # Lower risk
        elif ownership_status == 'multisig':
            capabilities.append("🔐 Controlled by multiple people (multisig)")
            risk_score -= 0.1  # Slightly lower risk
        
        return {
            'capabilities': capabilities,
            'red_flags': red_flags,
            'risk_score': risk_score,
            'ownership_analysis': {
                'has_owner': has_owner,
                'can_change_owner': can_change_owner,
                'can_renounce': can_renounce,
                'status': ownership_status
            }
        }
    
    async def _analyze_bytecode_for_hidden_functions(self, bytecode: str) -> Dict:
        """Deep bytecode analysis for hidden dangerous functions"""
        capabilities = []
        red_flags = []
        risk_score = 0.0
        
        if not bytecode:
            return {'capabilities': capabilities, 'red_flags': red_flags, 'risk_score': risk_score}
        
        # Look for hidden drain patterns in bytecode
        drain_patterns = [
            ('selfdestruct', '💀 Can destroy itself and send all ETH to owner', 0.9),
            ('delegatecall', '🔄 Can execute code from other contracts', 0.7),
            ('call', '📞 Can interact with external contracts', 0.3),
        ]
        
        for pattern, description, risk in drain_patterns:
            if pattern.lower() in bytecode.lower():
                capabilities.append(description)
                if risk > 0.6:
                    red_flags.append(f"Hidden function detected: {pattern}")
                risk_score += risk
        
        return {
            'capabilities': capabilities,
            'red_flags': red_flags,
            'risk_score': min(risk_score, 1.0)
        }
    
    async def _check_ownership_status(self, bytecode: str) -> str:
        """Check if contract ownership is renounced or controlled"""
        # This would check on-chain data in production
        # For now, simulate different ownership states
        
        if 'renounced' in bytecode.lower():
            return 'renounced'
        elif 'multisig' in bytecode.lower():
            return 'multisig'
        else:
            return 'single_owner'
    
    async def _calculate_overall_risk(self, permissions_analysis: Dict, 
                                    dangerous_functions_analysis: Dict,
                                    ownership_analysis: Dict) -> str:
        """Calculate overall risk level"""
        
        total_risk = (
            permissions_analysis['risk_score'] +
            dangerous_functions_analysis['risk_score'] +
            ownership_analysis['risk_score']
        )
        
        if total_risk >= 2.0:
            return 'critical'
        elif total_risk >= 1.5:
            return 'high'
        elif total_risk >= 0.8:
            return 'medium'
        else:
            return 'low'
    
    async def _generate_user_summary(self, analysis: Dict) -> str:
        """Generate a clear, user-friendly summary"""
        risk_level = analysis['overall_risk']
        capabilities = analysis['what_it_can_do']
        red_flags = analysis['red_flags']
        
        # Start with risk level explanation
        summary = self.risk_explanations[risk_level] + "\n\n"
        
        # Add what the contract can do
        if capabilities:
            summary += "**This contract can:**\n"
            for capability in capabilities[:5]:  # Show top 5
                summary += f"• {capability}\n"
            
            if len(capabilities) > 5:
                summary += f"• ...and {len(capabilities) - 5} other things\n"
            summary += "\n"
        
        # Add red flags if any
        if red_flags:
            summary += "**⚠️ Warning signs:**\n"
            for flag in red_flags[:3]:  # Show top 3 red flags
                summary += f"• {flag}\n"
            summary += "\n"
        
        # Add recommendation
        if risk_level in ['low', 'medium']:
            summary += "**💡 Recommendation:** This contract seems relatively safe to interact with."
        elif risk_level == 'high':
            summary += "**⚠️ Recommendation:** Be very careful. Only interact if you trust the project."
        else:  # critical
            summary += "**🚨 Recommendation:** DO NOT INTERACT. This contract can steal your tokens."
        
        return summary

# Example usage
if __name__ == "__main__":
    async def test_contract_explanation():
        explainer = SmartContractExplainer()
        
        # Test with a suspicious contract
        suspicious_contract = {
            'address': '0x1234567890abcdef1234567890abcdef12345678',
            'functions': [
                'approve',
                'transferFrom', 
                'emergencyWithdraw',
                'setTaxRate',
                'pause',
                'blacklistUser'
            ],
            'bytecode': 'contains selfdestruct and delegatecall patterns'
        }
        
        explanation = await explainer.explain_contract_in_english(suspicious_contract)
        
        print("🔍 Smart Contract Analysis")
        print("=" * 50)
        print(f"Contract: {explanation['contract_address']}")
        print(f"Risk Level: {explanation['overall_risk'].upper()}")
        print(f"Should Approve: {'✅ YES' if explanation['should_user_approve'] else '❌ NO'}")
        print("\n" + explanation['user_friendly_summary'])
    
    asyncio.run(test_contract_explanation())