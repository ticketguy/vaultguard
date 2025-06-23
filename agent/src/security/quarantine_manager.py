from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json
import asyncio
from enum import Enum

class QuarantineStatus(Enum):
    QUARANTINED = "quarantined"
    APPROVED = "approved"
    BURNED = "burned"
    PENDING_REVIEW = "pending_review"

class QuarantineItem:
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
        
        # Set auto-burn time for high-confidence items
        if risk_score > 0.9:
            self.auto_burn_at = self.quarantined_at + timedelta(hours=168)  # 7 days

class QuarantineManager:
    """
    Manages quarantined items - the core differentiator of our security system.
    This replaces the trading execution logic in the original framework.
    """
    
    def __init__(self, security_config: Dict):
        self.config = security_config
        self.quarantine_threshold = security_config.get('quarantine_threshold', 0.7)
        self.auto_burn_delay = security_config.get('auto_burn_delay', 168)  # hours
        
        # Storage for quarantined items
        self.quarantined_items: Dict[str, QuarantineItem] = {}
        self.approved_items: Dict[str, QuarantineItem] = {}
        self.burned_items: Dict[str, QuarantineItem] = {}
        
        # Statistics
        self.stats = {
            'total_quarantined': 0,
            'total_approved': 0,
            'total_burned': 0,
            'auto_burned': 0,
            'user_approved': 0,
            'user_burned': 0
        }
    
    async def evaluate_for_quarantine(self, item_data: Dict, risk_score: float, 
                                    reasoning: str) -> bool:
        """Determine if an item should be quarantined"""
        should_quarantine = risk_score > self.quarantine_threshold
        
        if should_quarantine:
            await self.quarantine_item(item_data, risk_score, reasoning)
            return True
        
        return False
    
    async def quarantine_item(self, item_data: Dict, risk_score: float, 
                            reasoning: str) -> QuarantineItem:
        """Add item to quarantine"""
        quarantine_item = QuarantineItem(item_data, risk_score, reasoning)
        
        self.quarantined_items[quarantine_item.id] = quarantine_item
        self.stats['total_quarantined'] += 1
        
        print(f"🚨 Item quarantined: {quarantine_item.id}")
        print(f"   Risk Score: {risk_score:.2f}")
        print(f"   Reasoning: {reasoning}")
        
        return quarantine_item
    
    async def approve_item(self, item_id: str, user_feedback: str = "") -> bool:
        """Approve a quarantined item (move to main wallet)"""
        if item_id not in self.quarantined_items:
            return False
        
        item = self.quarantined_items[item_id]
        item.status = QuarantineStatus.APPROVED
        item.reviewed_at = datetime.now()
        item.user_decision = "approved"
        
        # Move to approved items
        self.approved_items[item_id] = item
        del self.quarantined_items[item_id]
        
        self.stats['total_approved'] += 1
        self.stats['user_approved'] += 1
        
        print(f"✅ Item approved: {item_id}")
        if user_feedback:
            print(f"   User feedback: {user_feedback}")
        
        return True
    
    async def burn_item(self, item_id: str, auto_burn: bool = False, 
                       user_feedback: str = "") -> bool:
        """Burn a quarantined item (remove entirely)"""
        if item_id not in self.quarantined_items:
            return False
        
        item = self.quarantined_items[item_id]
        item.status = QuarantineStatus.BURNED
        item.reviewed_at = datetime.now()
        
        if auto_burn:
            item.user_decision = "auto_burned"
            self.stats['auto_burned'] += 1
        else:
            item.user_decision = "burned"
            self.stats['user_burned'] += 1
        
        # Move to burned items
        self.burned_items[item_id] = item
        del self.quarantined_items[item_id]
        
        self.stats['total_burned'] += 1
        
        burn_type = "🔥 Auto-burned" if auto_burn else "🗑️  User burned"
        print(f"{burn_type}: {item_id}")
        if user_feedback:
            print(f"   User feedback: {user_feedback}")
        
        return True
    
    async def burn_all_quarantined(self, user_confirmation: bool = False) -> int:
        """Burn all items in quarantine"""
        if not user_confirmation:
            print("⚠️  Burn all requires user confirmation")
            return 0
        
        items_to_burn = list(self.quarantined_items.keys())
        burned_count = 0
        
        for item_id in items_to_burn:
            if await self.burn_item(item_id, auto_burn=False):
                burned_count += 1
        
        print(f"🔥 Burned {burned_count} quarantined items")
        return burned_count
    
    async def check_auto_burn_candidates(self) -> List[str]:
        """Check for items ready for auto-burn"""
        current_time = datetime.now()
        auto_burn_candidates = []
        
        for item_id, item in self.quarantined_items.items():
            if item.auto_burn_at and current_time >= item.auto_burn_at:
                auto_burn_candidates.append(item_id)
        
        return auto_burn_candidates
    
    async def process_auto_burns(self) -> int:
        """Process all items ready for auto-burn"""
        candidates = await self.check_auto_burn_candidates()
        burned_count = 0
        
        for item_id in candidates:
            if await self.burn_item(item_id, auto_burn=True):
                burned_count += 1
        
        if burned_count > 0:
            print(f"🔥 Auto-burned {burned_count} items")
        
        return burned_count
    
    def get_quarantine_summary(self) -> Dict:
        """Get summary of quarantine status"""
        # Synchronously estimate pending_auto_burn by checking auto_burn_at timestamps
        current_time = datetime.now()
        pending_auto_burn = sum(
            1 for item in self.quarantined_items.values()
            if item.auto_burn_at and current_time >= item.auto_burn_at
        )
        return {
            'currently_quarantined': len(self.quarantined_items),
            'pending_auto_burn': pending_auto_burn,
            'statistics': self.stats,
            'items': {
                'quarantined': [
                    {
                        'id': item.id,
                        'risk_score': item.risk_score,
                        'reasoning': item.reasoning,
                        'quarantined_at': item.quarantined_at.isoformat(),
                        'auto_burn_at': item.auto_burn_at.isoformat() if item.auto_burn_at else None
                    }
                    for item in self.quarantined_items.values()
                ]
            }
        }
    
    def get_item_details(self, item_id: str) -> Optional[Dict]:
        """Get detailed information about a specific item"""
        # Check all storage locations
        item = (self.quarantined_items.get(item_id) or 
                self.approved_items.get(item_id) or 
                self.burned_items.get(item_id))
        
        if not item:
            return None
        
        return {
            'id': item.id,
            'status': item.status.value,
            'risk_score': item.risk_score,
            'reasoning': item.reasoning,
            'quarantined_at': item.quarantined_at.isoformat(),
            'reviewed_at': item.reviewed_at.isoformat() if item.reviewed_at else None,
            'user_decision': item.user_decision,
            'auto_burn_at': item.auto_burn_at.isoformat() if item.auto_burn_at else None,
            'item_data': item.item_data
        }

# Example usage
if __name__ == "__main__":
    async def test_quarantine_manager():
        config = {'quarantine_threshold': 0.7, 'auto_burn_delay': 168}
        manager = QuarantineManager(config)
        
        # Test quarantine
        test_item = {
            'hash': '0x123...',
            'from_address': '0xscammer...',
            'token_name': 'FakeUSDC',
            'amount': '1000000'
        }
        
        await manager.quarantine_item(test_item, 0.95, "Known scammer address")
        
        # Check summary
        summary = manager.get_quarantine_summary()
        print(json.dumps(summary, indent=2))
    
    asyncio.run(test_quarantine_manager())