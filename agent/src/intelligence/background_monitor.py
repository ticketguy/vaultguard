"""
Background Intelligence Monitor - 24/7 Threat Detection
Monitors social media, tracks blacklisted wallets, updates threat database
Feeds fresh intelligence to RAG system for AI code generation
"""

import asyncio
import json
import os
import time
import requests
import re
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
from pathlib import Path
import logging

# Twitter API (if available)
try:
    import tweepy
except ImportError:
    tweepy = None

# Reddit API (if available)  
try:
    import praw
except ImportError:
    praw = None

# Database and RAG integration
from src.db import SQLiteDB
from src.client.rag import RAGClient
# Try to import from rag-api, fallback if not available
try:
    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(__file__), '../../../rag-api'))
    from src.fetch import update_community_intelligence
except ImportError:
    # Fallback: create a mock function
    async def update_community_intelligence(data):
        print(f"📝 Would update community intelligence: {data}")
        return True

        
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("BackgroundMonitor")


@dataclass
class ThreatIntelligence:
    """Structure for threat intelligence data"""
    threat_type: str
    content: str
    source: str
    confidence: float
    addresses: List[str]
    tokens: List[str]
    discovered_at: datetime
    severity: str  # low, medium, high, critical


@dataclass
class BlacklistedWallet:
    """Structure for blacklisted wallet tracking"""
    address: str
    threat_type: str
    last_activity: Optional[datetime]
    activity_count: int
    confidence: float
    sources: List[str]


class BackgroundIntelligenceMonitor:
    """
    24/7 Background Intelligence Monitor
    Continuously gathers threat intelligence from multiple sources
    """
    
    def __init__(self, db: SQLiteDB, rag: RAGClient):
        self.db = db
        self.rag = rag
        
        # Monitoring configuration
        self.config = {
            'monitor_interval': int(os.getenv('MONITOR_INTERVAL', 300)),  # 5 minutes
            'social_media_interval': int(os.getenv('SOCIAL_INTERVAL', 1800)),  # 30 minutes
            'wallet_tracking_interval': int(os.getenv('WALLET_INTERVAL', 600)),  # 10 minutes
            'threat_update_interval': int(os.getenv('THREAT_UPDATE_INTERVAL', 3600)),  # 1 hour
        }
        
        # Data storage
        self.blacklisted_wallets: Dict[str, BlacklistedWallet] = {}
        self.threat_keywords = [
            'scam', 'rug pull', 'honeypot', 'drain', 'exploit', 'hack',
            'phishing', 'fake token', 'solana scam', 'mev attack',
            'dust attack', 'pump and dump', 'exit scam'
        ]
        
        # API clients
        self.twitter_client = None
        self.reddit_client = None
        
        # Monitoring state
        self.monitoring_active = False
        self.monitoring_tasks = []
        
        # Statistics
        self.stats = {
            'threats_discovered': 0,
            'wallets_tracked': 0,
            'social_media_scans': 0,
            'database_updates': 0,
            'last_update': datetime.now()
        }
        
        logger.info("🔍 Background Intelligence Monitor initialized")

    async def initialize(self):
        """Initialize API clients and load existing data"""
        logger.info("🚀 Initializing Background Intelligence Monitor...")
        
        # Initialize social media clients
        await self._init_social_media_clients()
        
        # Load existing blacklisted wallets
        await self._load_blacklisted_wallets()
        
        # Load threat intelligence patterns
        await self._load_threat_patterns()
        
        logger.info("✅ Background Monitor initialization complete")

    async def _init_social_media_clients(self):
        """Initialize Twitter and Reddit API clients"""
        
        # Initialize Twitter client
        if tweepy and os.getenv('TWITTER_BEARER_TOKEN'):
            try:
                self.twitter_client = tweepy.Client(
                    bearer_token=os.getenv('TWITTER_BEARER_TOKEN'),
                    wait_on_rate_limit=True
                )
                logger.info("🐦 Twitter client initialized")
            except Exception as e:
                logger.warning(f"⚠️ Twitter client failed: {e}")
        
        # Initialize Reddit client
        if praw and os.getenv('REDDIT_CLIENT_ID'):
            try:
                self.reddit_client = praw.Reddit(
                    client_id=os.getenv('REDDIT_CLIENT_ID'),
                    client_secret=os.getenv('REDDIT_CLIENT_SECRET'),
                    user_agent='SecurityMonitor/1.0'
                )
                logger.info("🔴 Reddit client initialized")
            except Exception as e:
                logger.warning(f"⚠️ Reddit client failed: {e}")

    async def _load_blacklisted_wallets(self):
        """Load existing blacklisted wallets from database"""
        try:
            # Query database for blacklisted wallets
            blacklist_data = self.db.fetch_blacklisted_wallets()
            
            for wallet_data in blacklist_data:
                wallet = BlacklistedWallet(
                    address=wallet_data['wallet_address'],
                    threat_type=wallet_data['threat_type'],
                    last_activity=wallet_data.get('last_activity'),
                    activity_count=wallet_data.get('activity_count', 0),
                    confidence=wallet_data.get('confidence', 0.8),
                    sources=wallet_data.get('sources', ['database'])
                )
                self.blacklisted_wallets[wallet.address] = wallet
            
            logger.info(f"📋 Loaded {len(self.blacklisted_wallets)} blacklisted wallets")
            
        except Exception as e:
            logger.warning(f"⚠️ Failed to load blacklisted wallets: {e}")
            self.blacklisted_wallets = {}

    async def _load_threat_patterns(self):
        """Load known threat patterns"""
        try:
            patterns_file = Path("data/threat_patterns.json")
            if patterns_file.exists():
                with open(patterns_file, 'r') as f:
                    patterns = json.load(f)
                    self.threat_keywords.extend(patterns.get('keywords', []))
                    logger.info(f"📚 Loaded {len(self.threat_keywords)} threat keywords")
        except Exception as e:
            logger.warning(f"⚠️ Failed to load threat patterns: {e}")

    # ========== MAIN MONITORING METHODS ==========

    async def start_monitoring(self):
        """Start all background monitoring tasks"""
        if self.monitoring_active:
            logger.warning("⚠️ Background monitoring already active")
            return
        
        self.monitoring_active = True
        logger.info("🛡️ Starting 24/7 background intelligence monitoring...")
        
        # Start monitoring tasks
        self.monitoring_tasks = [
            asyncio.create_task(self._social_media_monitor()),
            asyncio.create_task(self._wallet_activity_tracker()),
            asyncio.create_task(self._threat_database_updater()),
            asyncio.create_task(self._blockchain_scanner()),
        ]
        
        logger.info(f"📡 Started {len(self.monitoring_tasks)} monitoring tasks")

    async def stop_monitoring(self):
        """Stop all monitoring tasks"""
        self.monitoring_active = False
        
        for task in self.monitoring_tasks:
            task.cancel()
        
        logger.info("🛑 Background monitoring stopped")

    # ========== SOCIAL MEDIA MONITORING ==========

    async def _social_media_monitor(self):
        """Monitor social media for new threat intelligence"""
        while self.monitoring_active:
            try:
                logger.info("🔍 Scanning social media for threats...")
                
                # Monitor Twitter
                if self.twitter_client:
                    await self._monitor_twitter()
                
                # Monitor Reddit
                if self.reddit_client:
                    await self._monitor_reddit()
                
                # Monitor other sources
                await self._monitor_security_blogs()
                
                self.stats['social_media_scans'] += 1
                
                # Wait before next scan
                await asyncio.sleep(self.config['social_media_interval'])
                
            except Exception as e:
                logger.error(f"❌ Social media monitoring error: {e}")
                await asyncio.sleep(self.config['social_media_interval'])

    async def _monitor_twitter(self):
        """Monitor Twitter for security alerts"""
        try:
            # Search for security-related tweets
            security_accounts = [
                '@SolanaFloor', '@SolanaSecurity', '@DeFiSafety',
                '@SlowMist_Team', '@PeckShieldAlert', '@CertiKAlert'
            ]
            
            for keyword in self.threat_keywords[:5]:  # Limit API calls
                try:
                    tweets = self.twitter_client.search_recent_tweets(
                        query=f'"{keyword}" (solana OR sol) -is:retweet',
                        max_results=10,
                        tweet_fields=['created_at', 'author_id', 'public_metrics']
                    )
                    
                    if tweets.data:
                        for tweet in tweets.data:
                            await self._process_social_media_threat(
                                content=tweet.text,
                                source='twitter',
                                created_at=tweet.created_at,
                                url=f"https://twitter.com/i/status/{tweet.id}"
                            )
                    
                    # Rate limiting delay
                    await asyncio.sleep(2)
                    
                except Exception as e:
                    logger.warning(f"⚠️ Twitter search error for '{keyword}': {e}")
            
        except Exception as e:
            logger.error(f"❌ Twitter monitoring error: {e}")

    async def _monitor_reddit(self):
        """Monitor Reddit for security discussions"""
        try:
            subreddits = ['solana', 'defi', 'CryptoCurrency', 'SolanaScams']
            
            for subreddit_name in subreddits:
                try:
                    subreddit = self.reddit_client.subreddit(subreddit_name)
                    
                    # Check hot posts for security content
                    for submission in subreddit.hot(limit=20):
                        title_lower = submission.title.lower()
                        
                        # Check if post contains threat keywords
                        if any(keyword in title_lower for keyword in self.threat_keywords):
                            await self._process_social_media_threat(
                                content=f"{submission.title}\n{submission.selftext[:500]}",
                                source=f'reddit_{subreddit_name}',
                                created_at=datetime.fromtimestamp(submission.created_utc),
                                url=f"https://reddit.com{submission.permalink}"
                            )
                    
                    await asyncio.sleep(1)  # Rate limiting
                    
                except Exception as e:
                    logger.warning(f"⚠️ Reddit error for r/{subreddit_name}: {e}")
                    
        except Exception as e:
            logger.error(f"❌ Reddit monitoring error: {e}")

    async def _monitor_security_blogs(self):
        """Monitor security blogs and news sources"""
        security_sources = [
            'https://rss.cnn.com/rss/edition.rss',  # Example RSS feeds
            # Add more security blog RSS feeds here
        ]
        
        # Simple RSS monitoring (you can enhance this)
        for source in security_sources:
            try:
                # In a real implementation, you'd parse RSS feeds
                # For now, just log that we're monitoring
                logger.debug(f"📰 Monitoring security source: {source}")
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.warning(f"⚠️ Blog monitoring error: {e}")

    async def _process_social_media_threat(self, content: str, source: str, created_at: datetime, url: str):
        """Process discovered threat from social media"""
        try:
            # Extract addresses and tokens from content
            addresses = self._extract_solana_addresses(content)
            tokens = self._extract_token_names(content)
            
            # Determine threat type and severity
            threat_type = self._classify_threat_type(content)
            severity = self._assess_threat_severity(content)
            confidence = self._calculate_confidence(content, source)
            
            if addresses or tokens or confidence > 0.6:
                threat = ThreatIntelligence(
                    threat_type=threat_type,
                    content=content,
                    source=source,
                    confidence=confidence,
                    addresses=addresses,
                    tokens=tokens,
                    discovered_at=created_at,
                    severity=severity
                )
                
                # Add to threat database
                await self._add_threat_intelligence(threat)
                
                # Update blacklisted wallets if addresses found
                for address in addresses:
                    await self._add_blacklisted_wallet(address, threat_type, source)
                
                logger.info(f"🚨 New threat discovered from {source}: {threat_type}")
                self.stats['threats_discovered'] += 1
                
        except Exception as e:
            logger.error(f"❌ Error processing social media threat: {e}")

    # ========== WALLET ACTIVITY TRACKING ==========

    async def _wallet_activity_tracker(self):
        """Track activity of blacklisted wallets"""
        while self.monitoring_active:
            try:
                logger.info(f"👁️ Tracking {len(self.blacklisted_wallets)} blacklisted wallets...")
                
                for address, wallet in self.blacklisted_wallets.items():
                    try:
                        # Check wallet activity using Solana RPC
                        activity = await self._check_wallet_activity(address)
                        
                        if activity['has_new_activity']:
                            # Update wallet tracking data
                            wallet.last_activity = datetime.now()
                            wallet.activity_count += activity['new_transactions']
                            
                            # Create threat intelligence about new activity
                            threat_content = f"Blacklisted wallet {address} shows new activity: {activity['activity_summary']}"
                            
                            threat = ThreatIntelligence(
                                threat_type='blacklisted_wallet_activity',
                                content=threat_content,
                                source='wallet_tracker',
                                confidence=0.8,
                                addresses=[address],
                                tokens=activity.get('tokens_involved', []),
                                discovered_at=datetime.now(),
                                severity='medium'
                            )
                            
                            await self._add_threat_intelligence(threat)
                            
                            logger.warning(f"⚠️ Blacklisted wallet {address[:8]}... is active!")
                        
                        # Rate limiting
                        await asyncio.sleep(1)
                        
                    except Exception as e:
                        logger.warning(f"⚠️ Error tracking wallet {address}: {e}")
                
                # Wait before next tracking cycle
                await asyncio.sleep(self.config['wallet_tracking_interval'])
                
            except Exception as e:
                logger.error(f"❌ Wallet tracking error: {e}")
                await asyncio.sleep(self.config['wallet_tracking_interval'])

    async def _check_wallet_activity(self, address: str) -> Dict:
        """Check if wallet has new activity"""
        try:
            # In a real implementation, this would call Solana RPC
            # For now, simulate activity check
            
            # Mock activity check (replace with real Solana RPC calls)
            import random
            has_activity = random.random() < 0.1  # 10% chance of activity
            
            if has_activity:
                return {
                    'has_new_activity': True,
                    'new_transactions': random.randint(1, 5),
                    'activity_summary': f'New transactions detected',
                    'tokens_involved': ['SOL', 'USDC']
                }
            else:
                return {'has_new_activity': False}
                
        except Exception as e:
            logger.error(f"❌ Activity check error for {address}: {e}")
            return {'has_new_activity': False}

    # ========== THREAT DATABASE MANAGEMENT ==========

    async def _threat_database_updater(self):
        """Update threat database and RAG system"""
        while self.monitoring_active:
            try:
                logger.info("📚 Updating threat intelligence database...")
                
                # Update RAG system with new threats
                await self._update_rag_with_threats()
                
                # Clean old threat data
                await self._cleanup_old_threats()
                
                # Update statistics
                await self._update_statistics()
                
                self.stats['database_updates'] += 1
                self.stats['last_update'] = datetime.now()
                
                # Wait before next update
                await asyncio.sleep(self.config['threat_update_interval'])
                
            except Exception as e:
                logger.error(f"❌ Database update error: {e}")
                await asyncio.sleep(self.config['threat_update_interval'])

    async def _update_rag_with_threats(self):
        """Update RAG system with new threat intelligence"""
        try:
            # Get recent threats from last hour
            recent_threats = await self._get_recent_threats(hours=1)
            
            for threat in recent_threats:
                # Format threat data for RAG
                rag_data = {
                    'type': 'threat_intelligence',
                    'threat_type': threat.threat_type,
                    'content': threat.content,
                    'source': threat.source,
                    'confidence': threat.confidence,
                    'addresses': threat.addresses,
                    'tokens': threat.tokens,
                    'severity': threat.severity,
                    'discovered_at': threat.discovered_at.isoformat()
                }
                
                # Update community intelligence via RAG
                await update_community_intelligence(rag_data)
                
            if recent_threats:
                logger.info(f"📝 Updated RAG with {len(recent_threats)} new threats")
                
        except Exception as e:
            logger.error(f"❌ RAG update error: {e}")

    async def _get_recent_threats(self, hours: int = 1) -> List[ThreatIntelligence]:
        """Get threats discovered in the last N hours"""
        # This would query your threat database
        # For now, return empty list
        return []

    async def _cleanup_old_threats(self):
        """Clean up old threat intelligence data"""
        try:
            # Remove threats older than 30 days
            cutoff_date = datetime.now() - timedelta(days=30)
            
            # This would clean up your threat database
            logger.debug(f"🧹 Cleaning threats older than {cutoff_date}")
            
        except Exception as e:
            logger.error(f"❌ Cleanup error: {e}")

    # ========== BLOCKCHAIN SCANNING ==========

    async def _blockchain_scanner(self):
        """Scan blockchain for suspicious patterns"""
        while self.monitoring_active:
            try:
                logger.info("🔗 Scanning blockchain for suspicious patterns...")
                
                # Scan for new suspicious contracts
                await self._scan_new_contracts()
                
                # Scan for large value movements from known bad actors
                await self._scan_large_movements()
                
                # Scan for unusual token minting patterns
                await self._scan_token_patterns()
                
                # Wait before next scan
                await asyncio.sleep(self.config['monitor_interval'] * 2)  # Less frequent
                
            except Exception as e:
                logger.error(f"❌ Blockchain scan error: {e}")
                await asyncio.sleep(self.config['monitor_interval'] * 2)

    async def _scan_new_contracts(self):
        """Scan for newly deployed suspicious contracts"""
        try:
            # In real implementation, scan recent program deployments
            logger.debug("🔍 Scanning new contract deployments...")
            
        except Exception as e:
            logger.warning(f"⚠️ Contract scan error: {e}")

    async def _scan_large_movements(self):
        """Scan for large value movements from blacklisted addresses"""
        try:
            for address in self.blacklisted_wallets.keys():
                # Check for large outgoing transactions
                # In real implementation, query Solana for recent large transactions
                pass
                
        except Exception as e:
            logger.warning(f"⚠️ Large movement scan error: {e}")

    async def _scan_token_patterns(self):
        """Scan for suspicious token creation patterns"""
        try:
            # Look for tokens with suspicious names matching known projects
            logger.debug("🪙 Scanning token creation patterns...")
            
        except Exception as e:
            logger.warning(f"⚠️ Token pattern scan error: {e}")

    # ========== UTILITY METHODS ==========

    def _extract_solana_addresses(self, text: str) -> List[str]:
        """Extract Solana addresses from text"""
        # Solana address pattern (base58, 32-44 chars)
        pattern = r'\b[A-HJ-NP-Z1-9]{32,44}\b'
        addresses = re.findall(pattern, text)
        
        # Filter out obvious false positives
        valid_addresses = []
        for addr in addresses:
            if len(addr) >= 32 and not addr.isdigit():
                valid_addresses.append(addr)
        
        return valid_addresses

    def _extract_token_names(self, text: str) -> List[str]:
        """Extract token names from text"""
        # Common token name patterns
        patterns = [
            r'\$([A-Z]{2,10})',  # $TOKEN format
            r'\b([A-Z]{2,10})\s+token',  # TOKEN token format
            r'token\s+([A-Z]{2,10})',  # token TOKEN format
        ]
        
        tokens = []
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            tokens.extend(matches)
        
        return list(set(tokens))  # Remove duplicates

    def _classify_threat_type(self, content: str) -> str:
        """Classify the type of threat from content"""
        content_lower = content.lower()
        
        if 'honeypot' in content_lower:
            return 'honeypot'
        elif 'rug pull' in content_lower or 'rugpull' in content_lower:
            return 'rug_pull'
        elif 'drain' in content_lower:
            return 'drain_attack'
        elif 'dust' in content_lower:
            return 'dust_attack'
        elif 'mev' in content_lower:
            return 'mev_attack'
        elif 'phishing' in content_lower:
            return 'phishing'
        elif 'fake' in content_lower:
            return 'fake_token'
        else:
            return 'general_scam'

    def _assess_threat_severity(self, content: str) -> str:
        """Assess threat severity from content"""
        content_lower = content.lower()
        
        critical_indicators = ['major loss', 'millions', 'exploit', 'hack']
        high_indicators = ['scam', 'fraud', 'drain', 'stolen']
        medium_indicators = ['suspicious', 'warning', 'caution']
        
        if any(indicator in content_lower for indicator in critical_indicators):
            return 'critical'
        elif any(indicator in content_lower for indicator in high_indicators):
            return 'high'
        elif any(indicator in content_lower for indicator in medium_indicators):
            return 'medium'
        else:
            return 'low'

    def _calculate_confidence(self, content: str, source: str) -> float:
        """Calculate confidence score for threat intelligence"""
        confidence = 0.3  # Base confidence
        
        # Source reputation
        if 'security' in source or 'alert' in source:
            confidence += 0.3
        elif 'twitter' in source:
            confidence += 0.2
        elif 'reddit' in source:
            confidence += 0.1
        
        # Content analysis
        content_lower = content.lower()
        
        # High confidence indicators
        if any(word in content_lower for word in ['confirmed', 'verified', 'official']):
            confidence += 0.3
        
        # Medium confidence indicators
        if any(word in content_lower for word in ['reported', 'multiple', 'evidence']):
            confidence += 0.2
        
        # Address or specific details
        if self._extract_solana_addresses(content):
            confidence += 0.2
        
        return min(confidence, 1.0)

    async def _add_threat_intelligence(self, threat: ThreatIntelligence):
        """Add new threat intelligence to database"""
        try:
            threat_data = {
                'threat_type': threat.threat_type,
                'content': threat.content,
                'source': threat.source,
                'confidence': threat.confidence,
                'addresses': json.dumps(threat.addresses),
                'tokens': json.dumps(threat.tokens),
                'discovered_at': threat.discovered_at.isoformat(),
                'severity': threat.severity
            }
            
            # Save to database (you'll need to implement this in your DB interface)
            self.db.insert_threat_intelligence(threat_data)
            
        except Exception as e:
            logger.error(f"❌ Error adding threat intelligence: {e}")

    async def _add_blacklisted_wallet(self, address: str, threat_type: str, source: str):
        """Add wallet to blacklist"""
        try:
            if address not in self.blacklisted_wallets:
                wallet = BlacklistedWallet(
                    address=address,
                    threat_type=threat_type,
                    last_activity=None,
                    activity_count=0,
                    confidence=0.8,
                    sources=[source]
                )
                
                self.blacklisted_wallets[address] = wallet
                
                # Save to database
                self.db.insert_blacklisted_wallet({
                    'wallet_address': address,
                    'threat_type': threat_type,
                    'evidence': f'Discovered via {source}',
                    'community_reports': 1,
                    'is_confirmed': False,
                    'created_at': datetime.now().isoformat()
                })
                
                logger.warning(f"🚫 Added {address[:8]}... to blacklist ({threat_type})")
                self.stats['wallets_tracked'] += 1
            
        except Exception as e:
            logger.error(f"❌ Error adding blacklisted wallet: {e}")

    async def _update_statistics(self):
        """Update monitoring statistics"""
        try:
            stats_data = {
                'threats_discovered': self.stats['threats_discovered'],
                'wallets_tracked': len(self.blacklisted_wallets),
                'social_media_scans': self.stats['social_media_scans'],
                'database_updates': self.stats['database_updates'],
                'last_update': self.stats['last_update'].isoformat(),
                'monitoring_active': self.monitoring_active
            }
            
            # Save statistics (implement in your DB)
            self.db.update_monitoring_statistics(stats_data)
            
        except Exception as e:
            logger.error(f"❌ Error updating statistics: {e}")

    # ========== PUBLIC API METHODS ==========

    async def get_monitoring_status(self) -> Dict:
        """Get current monitoring status"""
        return {
            'monitoring_active': self.monitoring_active,
            'tasks_running': len([t for t in self.monitoring_tasks if not t.done()]),
            'blacklisted_wallets': len(self.blacklisted_wallets),
            'statistics': self.stats,
            'configuration': self.config,
            'api_clients': {
                'twitter': self.twitter_client is not None,
                'reddit': self.reddit_client is not None
            }
        }

    async def add_manual_threat(self, threat_data: Dict) -> bool:
        """Manually add threat intelligence"""
        try:
            threat = ThreatIntelligence(
                threat_type=threat_data.get('threat_type', 'manual'),
                content=threat_data.get('content', ''),
                source='manual_input',
                confidence=threat_data.get('confidence', 0.8),
                addresses=threat_data.get('addresses', []),
                tokens=threat_data.get('tokens', []),
                discovered_at=datetime.now(),
                severity=threat_data.get('severity', 'medium')
            )
            
            await self._add_threat_intelligence(threat)
            return True
            
        except Exception as e:
            logger.error(f"❌ Error adding manual threat: {e}")
            return False

    async def blacklist_wallet(self, address: str, threat_type: str, evidence: str) -> bool:
        """Manually blacklist a wallet"""
        try:
            await self._add_blacklisted_wallet(address, threat_type, 'manual_input')
            return True
            
        except Exception as e:
            logger.error(f"❌ Error blacklisting wallet: {e}")
            return False


# ========== INTEGRATION WITH MAIN SYSTEM ==========

async def start_background_monitor(db: SQLiteDB, rag: RAGClient) -> BackgroundIntelligenceMonitor:
    """Start the background intelligence monitor"""
    monitor = BackgroundIntelligenceMonitor(db, rag)
    await monitor.initialize()
    await monitor.start_monitoring()
    return monitor


if __name__ == "__main__":
    async def test_monitor():
        """Test the background monitor"""
        from src.db import SQLiteDB
        from src.client.rag import RAGClient
        
        db = SQLiteDB("./test_security.db")
        rag = RAGClient("http://localhost:8080")
        
        monitor = await start_background_monitor(db, rag)
        
        # Run for 60 seconds
        await asyncio.sleep(60)
        
        await monitor.stop_monitoring()
        
        status = await monitor.get_monitoring_status()
        print(json.dumps(status, indent=2))
    
    asyncio.run(test_monitor())