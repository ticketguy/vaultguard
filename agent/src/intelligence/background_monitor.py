
import asyncio
import json
import os
import re
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from pathlib import Path
import logging
import aiohttp

# Twitter API
try:
    import tweepy
except ImportError:
    tweepy = None

# Reddit API
try:
    import praw
except ImportError:
    praw = None

# Database and RAG integration
from src.db import SQLiteDB
from src.client.rag import RAGClient
from src.intelligence.edge_learning_engine import EdgeLearningEngine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("EnhancedBackgroundMonitor")

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

class EnhancedBackgroundIntelligenceMonitor:
    """
    Enhanced Background Intelligence Monitor - Integrated with EdgeLearningEngine
    Feeds fresh threat intelligence directly to the cache for instant transaction analysis
    """
    
    def __init__(self, db: SQLiteDB, rag: RAGClient, edge_learning_engine: Optional[EdgeLearningEngine] = None):
        self.db = db
        self.rag = rag
        self.edge_learning_engine = edge_learning_engine
        self.security_sensor = None  # Will be injected
        self.network_analyzer = None  # Will be set when sensor connects
        
        self.config = {
            'monitor_interval': int(os.getenv('MONITOR_INTERVAL', 600)),  # 10 minutes
            'social_media_interval': int(os.getenv('SOCIAL_INTERVAL', 7200)),  # 2 hours
            'wallet_tracking_interval': int(os.getenv('WALLET_INTERVAL', 1800)),  # 30 minutes
            'threat_update_interval': int(os.getenv('THREAT_UPDATE_INTERVAL', 10800)),  # 3 hours
            'cache_update_interval': int(os.getenv('CACHE_UPDATE_INTERVAL', 300)),  # 5 minutes
        }
        
        self.blacklisted_wallets: Dict[str, BlacklistedWallet] = {}
        self.threat_keywords = ['solana scam', 'sol drain', 'solana hack']
        self._twitter_keyword_index = 0
        self._reddit_subreddit_index = 0
        self.twitter_client = None
        self.reddit_client = None
        self.monitoring_active = False
        self.monitoring_tasks = []
        self.cache_update_queue = asyncio.Queue(maxsize=1000)
        
        self.stats = {
            'threats_discovered': 0,
            'wallets_tracked': 0,
            'social_media_scans': 0,
            'database_updates': 0,
            'cache_updates_sent': 0,
            'edge_learning_integration': edge_learning_engine is not None,
            'last_update': datetime.now(),
            'twitter_api_calls': 0,
            'reddit_api_calls': 0,
            'rate_limit_hits': 0
        }
        
        logger.info("🔍 Enhanced Background Intelligence Monitor initialized")
        if edge_learning_engine:
            logger.info("🧠 EdgeLearningEngine integration active!")
        else:
            logger.warning("⚠️ EdgeLearningEngine not available - limited functionality")

    async def initialize(self):
        """Initialize API clients and load existing data"""
        logger.info("🚀 Initializing Enhanced Background Intelligence Monitor...")
        
        await self._init_social_media_clients()
        await self._load_blacklisted_wallets()
        await self._load_threat_patterns()
        
        if self.edge_learning_engine:
            await self._integrate_with_edge_learning_engine()
        
        logger.info("✅ Enhanced Background Monitor initialization complete")

    async def _integrate_with_edge_learning_engine(self):
        """Integrate with EdgeLearningEngine for cached intelligence"""
        try:
            if hasattr(self.edge_learning_engine, 'background_monitor'):
                self.edge_learning_engine.background_monitor = self
                logger.info("🔗 EdgeLearningEngine ↔ BackgroundMonitor connected")
            
            await self._preload_blacklist_cache()
            
            logger.info("✅ EdgeLearningEngine integration complete")
        except Exception as e:
            logger.error(f"❌ EdgeLearningEngine integration failed: {e}")

    def set_security_sensor(self, security_sensor):
        """Connect background monitor to SecuritySensor for network analysis"""
        self.security_sensor = security_sensor
        self.network_analyzer = security_sensor.network_analyzer if security_sensor else None
        if self.network_analyzer:
            logger.info("🕸️ Background monitor connected to NetworkAnalyzer")

    async def _feed_threat_to_network_analyzer(self, threat_address: str, threat_data: Dict):
        """Feed discovered threats to NetworkAnalyzer for risk propagation"""
        if self.network_analyzer:
            try:
                # Create fake transaction data to feed the network
                fake_transaction = {
                    'from_address': threat_address,
                    'to_address': 'THREAT_SOURCE',  # Marker for threat origin
                    'timestamp': datetime.now(),
                    'value': 0,
                    'threat_type': threat_data.get('threat_type', 'unknown'),
                    'source': threat_data.get('source', 'background_monitor')
                }
                
                await self.network_analyzer.analyze_address_network(threat_address, fake_transaction)
                logger.info(f"🕸️ Fed threat {threat_address[:8]}... to network analysis")
                
            except Exception as e:
                logger.warning(f"⚠️ Failed to feed threat to NetworkAnalyzer: {e}")

    async def _preload_blacklist_cache(self):
        """Preload existing blacklisted wallets into EdgeLearningEngine cache - ENHANCED"""
        if not self.edge_learning_engine:
            return
        
        try:
            preload_count = 0
            
            for address, wallet in self.blacklisted_wallets.items():
                # 🆕 ENHANCED: More comprehensive intelligence data
                intelligence = {
                    'threat_patterns': [f'Blacklisted: {wallet.threat_type}'],
                    'analysis_suggestions': ['comprehensive_analysis', 'behavior_analysis', 'blacklist_check'],
                    'confidence_boost': wallet.confidence,
                    'risk_indicators': {
                        'blacklisted': True,
                        'threat_type': wallet.threat_type,
                        'confidence': wallet.confidence,
                        'activity_count': wallet.activity_count,
                        'sources': wallet.sources,
                        'last_activity': wallet.last_activity.isoformat() if wallet.last_activity else None,
                        'added_by': 'background_monitor'
                    },
                    # 🆕 ADD: Instant block indicators
                    'instant_block': True,
                    'block_reason': f"Address is blacklisted: {wallet.threat_type}",
                    'user_explanation': f"🚫 BLOCKED: This address is known for {wallet.threat_type.replace('_', ' ')}"
                }
                
                cache_key = f"address_{address}"
                self.edge_learning_engine.intelligence_cache.set(
                    cache_key,
                    intelligence,
                    source='background_monitor_preload',
                    ttl_seconds=86400  # 24 hours
                )
                
                preload_count += 1
            
            logger.info(f"🧠 Preloaded {preload_count} blacklisted wallets into EdgeLearningEngine cache")
            
            # 🆕 ADD: Preload blacklist summary for general access
            summary_intelligence = {
                'blacklist_summary': self.get_blacklist_summary(),
                'total_blacklisted_addresses': len(self.blacklisted_wallets),
                'cache_type': 'blacklist_summary'
            }
            
            self.edge_learning_engine.intelligence_cache.set(
                "blacklist_summary",
                summary_intelligence,
                source='background_monitor_summary',
                ttl_seconds=3600  # 1 hour
            )
            
        except Exception as e:
            logger.error(f"❌ Cache preload error: {e}")

    async def _init_social_media_clients(self):
        """Initialize Twitter and Reddit API clients with rate limiting"""
        if tweepy and os.getenv('TWITTER_BEARER_TOKEN'):
            try:
                self.twitter_client = tweepy.Client(
                    bearer_token=os.getenv('TWITTER_BEARER_TOKEN'),
                    wait_on_rate_limit=False  # Use custom rate limiting
                )
                logger.info("🐦 Twitter client initialized")
            except Exception as e:
                logger.warning(f"⚠️ Twitter client failed: {e}")
                self.twitter_client = None
        else:
            logger.info("🐦 Twitter client not configured (no TWITTER_BEARER_TOKEN)")
        
        if praw and os.getenv('REDDIT_CLIENT_ID'):
            try:
                self.reddit_client = praw.Reddit(
                    client_id=os.getenv('REDDIT_CLIENT_ID'),
                    client_secret=os.getenv('REDDIT_CLIENT_SECRET'),
                    user_agent='EnhancedSecurityMonitor/2.0'
                )
                logger.info("🔴 Reddit client initialized")
            except Exception as e:
                logger.warning(f"⚠️ Reddit client failed: {e}")
                self.reddit_client = None
        else:
            logger.info("🔴 Reddit client not configured")

    async def _load_blacklisted_wallets(self):
        """Load existing blacklisted wallets from database"""
        try:
            if hasattr(self.db, 'fetch_blacklisted_wallets'):
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
            else:
                logger.info("📋 No blacklisted wallets method in database, starting fresh")
                self.blacklisted_wallets = {}
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
                    self.threat_keywords = patterns.get('keywords', self.threat_keywords)
                    logger.info(f"📚 Loaded {len(self.threat_keywords)} threat keywords")
            else:
                logger.info(f"📚 Using default threat keywords: {len(self.threat_keywords)} keywords")
        except Exception as e:
            logger.warning(f"⚠️ Failed to load threat patterns: {e}")

    async def start_monitoring(self):
        """Start all background monitoring tasks"""
        if self.monitoring_active:
            logger.warning("⚠️ Background monitoring already active")
            return
        
        self.monitoring_active = True
        logger.info("🛡️ Starting enhanced background intelligence monitoring...")
        
        self.monitoring_tasks = [
            asyncio.create_task(self._social_media_monitor()),
            asyncio.create_task(self._wallet_activity_tracker()),
            asyncio.create_task(self._threat_database_updater()),
            asyncio.create_task(self._cache_update_processor()),
        ]
        
        logger.info(f"📡 Started {len(self.monitoring_tasks)} monitoring tasks")
        logger.info("⏰ Social media: every 2 hours | Wallets: every 30 min | Cache: every 5 min")

    async def stop_monitoring(self):
        """Stop all monitoring tasks"""
        self.monitoring_active = False
        
        for task in self.monitoring_tasks:
            if not task.done():
                task.cancel()
        
        await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
        
        logger.info("🛑 Enhanced background monitoring stopped")

    async def _cache_update_processor(self):
        """Process cache updates for EdgeLearningEngine"""
        while self.monitoring_active:
            try:
                if not self.edge_learning_engine:
                    await asyncio.sleep(self.config['cache_update_interval'])
                    continue
                
                logger.debug("🧠 Processing cache updates for EdgeLearningEngine...")
                
                updates_processed = 0
                while not self.cache_update_queue.empty():
                    try:
                        cache_update = await asyncio.wait_for(
                            self.cache_update_queue.get(),
                            timeout=1.0
                        )
                        
                        await self._apply_cache_update(cache_update)
                        updates_processed += 1
                        
                    except asyncio.TimeoutError:
                        break
                    except Exception as e:
                        logger.warning(f"⚠️ Cache update error: {e}")
                
                if updates_processed > 0:
                    logger.info(f"🧠 Applied {updates_processed} cache updates")
                    self.stats['cache_updates_sent'] += updates_processed
                
                await asyncio.sleep(self.config['cache_update_interval'])
                
            except Exception as e:
                logger.error(f"❌ Cache update processor error: {e}")
                self.stats['rate_limit_hits'] += 1
                await asyncio.sleep(self.config['cache_update_interval'])

    async def _apply_cache_update(self, cache_update: Dict):
        """Apply a cache update to EdgeLearningEngine - ENHANCED for instant blocking"""
        try:
            update_type = cache_update.get('type')
            data = cache_update.get('data', {})
            
            if update_type == 'blacklist_wallet':
                address = data.get('address')
                threat_type = data.get('threat_type', 'unknown')
                confidence = data.get('confidence', 0.8)
                source = data.get('source', 'background_monitor')
                
                # 🆕 ENHANCED: More comprehensive cache data for instant blocking
                intelligence = {
                    'threat_patterns': [f'Blacklisted: {threat_type}'],
                    'analysis_suggestions': ['comprehensive_analysis', 'behavior_analysis', 'immediate_block'],
                    'confidence_boost': confidence,
                    'risk_indicators': {
                        'blacklisted': True,
                        'threat_type': threat_type,
                        'discovered_by': source,
                        'timestamp': datetime.now().isoformat(),
                        'confidence': confidence
                    },
                    # 🆕 ADD: Instant block data for SecurityAgent
                    'instant_block': True,
                    'block_reason': f"Address blacklisted for {threat_type}",
                    'user_explanation': f"🚫 BLOCKED: This address is a known {threat_type.replace('_', ' ')} - transaction blocked for your safety",
                    'risk_score_override': 1.0,  # Maximum risk
                    'action_override': 'BLOCK'
                }
                
                cache_key = f"address_{address}"
                self.edge_learning_engine.intelligence_cache.set(
                    cache_key,
                    intelligence,
                    source='background_monitor_live',
                    ttl_seconds=86400
                )
                
                logger.info(f"🧠 Updated cache for blacklisted address: {address[:8]}... (instant block enabled)")
                
            elif update_type == 'threat_intelligence':
                addresses = data.get('addresses', [])
                tokens = data.get('tokens', [])
                threat_type = data.get('threat_type', 'unknown')
                confidence = data.get('confidence', 0.6)
                
                intelligence = {
                    'threat_patterns': [f'Social media threat: {threat_type}'],
                    'analysis_suggestions': ['social_media_analysis', 'comprehensive_analysis'],
                    'confidence_boost': confidence,
                    'risk_indicators': {
                        'social_media_threat': True,
                        'threat_type': threat_type,
                        'source': data.get('source', 'unknown'),
                        'discovered_at': data.get('discovered_at', datetime.now().isoformat()),
                        'confidence': confidence
                    },
                    # 🆕 ADD: Enhanced user explanations
                    'user_explanation': f"⚠️ WARNING: This address was mentioned in social media threats related to {threat_type.replace('_', ' ')}"
                }
                
                # Apply to addresses
                for address in addresses:
                    cache_key = f"address_{address}"
                    self.edge_learning_engine.intelligence_cache.set(
                        cache_key,
                        intelligence,
                        source='background_monitor_threat',
                        ttl_seconds=43200  # 12 hours
                    )
                
                # Apply to tokens
                for token in tokens:
                    cache_key = f"token_{token.lower()}"
                    self.edge_learning_engine.intelligence_cache.set(
                        cache_key,
                        intelligence,
                        source='background_monitor_threat',
                        ttl_seconds=43200
                    )
                
                logger.info(f"🧠 Updated cache for threat: {threat_type} ({len(addresses)} addresses, {len(tokens)} tokens)")
            
        except Exception as e:
            logger.error(f"❌ Cache update application error: {e}")

    async def _social_media_monitor(self):
        """Monitor social media for new threat intelligence"""
        async with aiohttp.ClientSession() as session:
            while self.monitoring_active:
                try:
                    logger.info("🔍 Scanning social media for threats...")
                    
                    if self.twitter_client:
                        await self._monitor_twitter_enhanced(session)
                        await asyncio.sleep(30)
                    
                    if self.reddit_client:
                        await self._monitor_reddit_enhanced(session)
                    
                    self.stats['social_media_scans'] += 1
                    
                    next_scan_hours = self.config['social_media_interval'] / 3600
                    logger.info(f"⏰ Waiting {next_scan_hours:.1f} hours before next social media scan...")
                    await asyncio.sleep(self.config['social_media_interval'])
                    
                except Exception as e:
                    logger.error(f"❌ Social media monitoring error: {e}")
                    self.stats['rate_limit_hits'] += 1
                    await asyncio.sleep(self.config['social_media_interval'])

    async def _monitor_twitter_enhanced(self, session: aiohttp.ClientSession):
        """Enhanced Twitter monitoring with cache updates and rate limiting"""
        if not self.twitter_client:
            logger.info("🐦 Twitter client not available - skipping")
            return
            
        try:
            if not self.threat_keywords:
                return
                
            keyword = self.threat_keywords[self._twitter_keyword_index % len(self.threat_keywords)]
            self._twitter_keyword_index += 1
            
            logger.info(f"🐦 Checking Twitter for: '{keyword}'")
            
            try:
                tweets = await asyncio.wait_for(
                    self.twitter_client.search_recent_tweets(
                        query=f'"{keyword}" -is:retweet',
                        max_results=5,
                        tweet_fields=['created_at', 'author_id']
                    ),
                    timeout=10
                )
                
                self.stats['twitter_api_calls'] += 1
                
                if tweets and tweets.data:
                    logger.info(f"📝 Found {len(tweets.data)} tweets for '{keyword}'")
                    for tweet in tweets.data:
                        await self._process_social_media_threat_enhanced(
                            content=tweet.text,
                            source='twitter',
                            created_at=tweet.created_at,
                            url=f"https://twitter.com/i/status/{tweet.id}"
                        )
                else:
                    logger.info(f"📝 No tweets found for '{keyword}'")
                
                logger.info(f"✅ Twitter check complete for '{keyword}'")
                
            except asyncio.TimeoutError:
                logger.warning(f"⏸️ Twitter request timeout for '{keyword}'")
                self.stats['rate_limit_hits'] += 1
                await self._fallback_to_reddit(session, keyword)
            except Exception as e:
                if "rate limit" in str(e).lower():
                    logger.warning(f"⏸️ Twitter rate limit reached, backing off for 60s")
                    self.stats['rate_limit_hits'] += 1
                    await asyncio.sleep(60)
                    await self._fallback_to_reddit(session, keyword)
                else:
                    logger.warning(f"⚠️ Twitter search error for '{keyword}': {e}")
            
        except Exception as e:
            logger.error(f"❌ Twitter monitoring error: {e}")

    async def _fallback_to_reddit(self, session: aiohttp.ClientSession, keyword: str):
        """Fallback to Reddit search on Twitter rate limit"""
        if not self.reddit_client:
            logger.info("🔴 Reddit client not available - skipping fallback")
            return
            
        try:
            subreddit = self.reddit_client.subreddit('solana')
            logger.info(f"🔴 Falling back to Reddit for keyword: {keyword}")
            
            posts_found = 0
            for submission in subreddit.hot(limit=5):
                title_lower = submission.title.lower()
                if keyword.lower() in title_lower:
                    await self._process_social_media_threat_enhanced(
                        content=f"{submission.title}\n{submission.selftext[:300]}",
                        source='reddit_fallback',
                        created_at=datetime.fromtimestamp(submission.created_utc),
                        url=f"https://reddit.com{submission.permalink}"
                    )
                    posts_found += 1
            
            self.stats['reddit_api_calls'] += 1
            logger.info(f"✅ Reddit fallback complete - {posts_found} relevant posts")
            await asyncio.sleep(2)
            
        except Exception as e:
            logger.warning(f"⚠️ Reddit fallback error: {e}")

    async def _monitor_reddit_enhanced(self, session: aiohttp.ClientSession):
        """Enhanced Reddit monitoring with cache updates"""
        if not self.reddit_client:
            logger.info("🔴 Reddit client not available - skipping")
            return
            
        try:
            subreddits = ['solana', 'SolanaScams']
            subreddit_name = subreddits[self._reddit_subreddit_index % len(subreddits)]
            self._reddit_subreddit_index += 1
            
            logger.info(f"🔴 Checking r/{subreddit_name}")
            
            try:
                subreddit = self.reddit_client.subreddit(subreddit_name)
                
                posts_found = 0
                for submission in subreddit.hot(limit=10):
                    title_lower = submission.title.lower()
                    
                    threat_found = False
                    for keyword in self.threat_keywords:
                        keyword_parts = keyword.split()
                        if any(part in title_lower for part in keyword_parts):
                            threat_found = True
                            break
                    
                    if threat_found:
                        await self._process_social_media_threat_enhanced(
                            content=f"{submission.title}\n{submission.selftext[:300]}",
                            source=f'reddit_{subreddit_name}',
                            created_at=datetime.fromtimestamp(submission.created_utc),
                            url=f"https://reddit.com{submission.permalink}"
                        )
                        posts_found += 1
                
                self.stats['reddit_api_calls'] += 1
                logger.info(f"✅ Reddit check complete for r/{subreddit_name} - {posts_found} relevant posts")
                await asyncio.sleep(2)
                
            except Exception as e:
                logger.warning(f"⚠️ Reddit error for r/{subreddit_name}: {e}")
                
        except Exception as e:
            logger.error(f"❌ Reddit monitoring error: {e}")

    async def _process_social_media_threat_enhanced(self, content: str, source: str, created_at: datetime, url: str):
        """Enhanced threat processing with immediate cache updates"""
        try:
            addresses = self._extract_solana_addresses(content)
            tokens = self._extract_token_names(content)
            
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
                
                await self._add_threat_intelligence(threat)
                
                if self.edge_learning_engine:
                    cache_update = {
                        'type': 'threat_intelligence',
                        'data': {
                            'threat_type': threat_type,
                            'addresses': addresses,
                            'tokens': tokens,
                            'confidence': confidence,
                            'source': source,
                            'discovered_at': created_at.isoformat()
                        }
                    }
                    
                    try:
                        self.cache_update_queue.put_nowait(cache_update)
                        logger.debug(f"🧠 Queued cache update for threat: {threat_type}")
                    except asyncio.QueueFull:
                        logger.warning("⚠️ Cache update queue full - dropping update")
                
                for address in addresses:
                    await self._add_blacklisted_wallet_enhanced(address, threat_type, source)

                                # feed directly to NetworkAnalyzer
                await self._feed_threat_to_network_analyzer(address, {
                    'threat_type': threat_type,
                    'source': f'social_media_{source}',
                    'confidence': 0.7,
                    'content': threat_content
                })
                
                logger.info(f"🚨 New threat discovered from {source}: {threat_type}")
                self.stats['threats_discovered'] += 1
                
        except Exception as e:
            logger.error(f"❌ Error processing social media threat: {e}")

    async def _add_blacklisted_wallet_enhanced(self, address: str, threat_type: str, source: str):
        """Enhanced wallet blacklisting with immediate cache updates"""
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
                
                if hasattr(self.db, 'insert_blacklisted_wallet'):
                    self.db.insert_blacklisted_wallet({
                        'wallet_address': address,
                        'threat_type': threat_type,
                        'evidence': f'Discovered via {source}',
                        'community_reports': 1,
                        'is_confirmed': False,
                        'created_at': datetime.now().isoformat()
                    })
                
                if self.edge_learning_engine:
                    cache_update = {
                        'type': 'blacklist_wallet',
                        'data': {
                            'address': address,
                            'threat_type': threat_type,
                            'confidence': 0.8,
                            'source': source
                        }
                    }
                    
                    try:
                        self.cache_update_queue.put_nowait(cache_update)
                        logger.debug(f"🧠 Queued cache update for blacklisted wallet: {address[:8]}...")
                    except asyncio.QueueFull:
                        logger.warning("⚠️ Cache update queue full - dropping wallet update")
                
                            # 🕸️ NEW: Feed to NetworkAnalyzer
                await self._feed_threat_to_network_analyzer(address, {
                    'threat_type': threat_type,
                    'source': source,
                    'confidence': 0.8
                })


                logger.warning(f"🚫 Added {address[:8]}... to blacklist ({threat_type})")
                self.stats['wallets_tracked'] += 1
            
        except Exception as e:
            logger.error(f"❌ Error adding blacklisted wallet: {e}")

    async def _wallet_activity_tracker(self):
        """Track activity of blacklisted wallets"""
        async with aiohttp.ClientSession() as session:
            while self.monitoring_active:
                try:
                    logger.info(f"👁️ Tracking {len(self.blacklisted_wallets)} blacklisted wallets...")
                    
                    for address, wallet in self.blacklisted_wallets.items():
                        try:
                            activity = await self._check_wallet_activity(session, address)
                            
                            if activity['has_new_activity']:
                                wallet.last_activity = datetime.now()
                                wallet.activity_count += activity['new_transactions']
                                
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
                                
                                if self.edge_learning_engine:
                                    cache_update = {
                                        'type': 'blacklist_wallet',
                                        'data': {
                                            'address': address,
                                            'threat_type': 'active_blacklisted_wallet',
                                            'confidence': 0.9,
                                            'source': 'wallet_tracker_activity'
                                        }
                                    }
                                    
                                    try:
                                        self.cache_update_queue.put_nowait(cache_update)
                                    except asyncio.QueueFull:
                                        logger.warning("⚠️ Cache update queue full - dropping activity update")
                                
                                logger.warning(f"⚠️ Blacklisted wallet {address[:8]}... is active!")
                            
                            await asyncio.sleep(1)
                            
                        except Exception as e:
                            logger.warning(f"⚠️ Error tracking wallet {address}: {e}")
                    
                    next_check_minutes = self.config['wallet_tracking_interval'] / 60
                    logger.info(f"⏰ Next wallet check in {next_check_minutes:.0f} minutes")
                    await asyncio.sleep(self.config['wallet_tracking_interval'])
                    
                except Exception as e:
                    logger.error(f"❌ Wallet tracking error: {e}")
                    self.stats['rate_limit_hits'] += 1
                    await asyncio.sleep(self.config['wallet_tracking_interval'])

    async def _check_wallet_activity(self, session: aiohttp.ClientSession, address: str) -> Dict:
        """Check if wallet has new activity using Solana RPC"""
        try:
            url = os.getenv('SOLANA_RPC_URL', 'https://api.mainnet-beta.solana.com')
            headers = {'Content-Type': 'application/json'}
            payload = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'getSignaturesForAddress',
                'params': [address, {'limit': 5}]
            }
            
            async with session.post(url, json=payload, timeout=10) as response:
                if response.status != 200:
                    logger.warning(f"Solana RPC returned status {response.status}")
                    return {'has_new_activity': False}
                
                data = await response.json()
                signatures = data.get('result', [])
                
                if not signatures:
                    return {'has_new_activity': False}
                
                # Fetch transaction details to identify tokens
                tokens_involved = []
                for sig in signatures[:1]:  # Limit to one for performance
                    tx_payload = {
                        'jsonrpc': '2.0',
                        'id': 1,
                        'method': 'getTransaction',
                        'params': [sig['signature'], {'encoding': 'json'}]
                    }
                    async with session.post(url, json=tx_payload, timeout=10) as tx_response:
                        if tx_response.status == 200:
                            tx_data = await tx_response.json()
                            accounts = tx_data.get('result', {}).get('transaction', {}).get('message', {}).get('accountKeys', [])
                            tokens_involved.extend([account for account in accounts if len(account) == 44])  # Solana mint addresses
                        
                return {
                    'has_new_activity': True,
                    'new_transactions': len(signatures),
                    'activity_summary': f"Detected {len(signatures)} recent transactions",
                    'tokens_involved': list(set(tokens_involved))
                }
                
        except Exception as e:
            logger.error(f"❌ Activity check error for {address}: {e}")
            return {'has_new_activity': False}

    async def _threat_database_updater(self):
        """Update threat database and RAG system"""
        while self.monitoring_active:
            try:
                logger.info("📚 Updating threat intelligence database...")
                
                await self._update_rag_with_threats()
                await self._cleanup_old_threats()
                await self._update_statistics()
                
                self.stats['database_updates'] += 1
                self.stats['last_update'] = datetime.now()
                
                next_update_hours = self.config['threat_update_interval'] / 3600
                logger.info(f"⏰ Next database update in {next_update_hours:.1f} hours")
                await asyncio.sleep(self.config['threat_update_interval'])
                
            except Exception as e:
                logger.error(f"❌ Database update error: {e}")
                self.stats['rate_limit_hits'] += 1
                await asyncio.sleep(self.config['threat_update_interval'])

    async def _update_rag_with_threats(self):
        """Update RAG system with new threat intelligence"""
        try:
            recent_threats = await self._get_recent_threats(hours=3)
            
            for threat in recent_threats:
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
                
                context = f"Threat Intelligence: {threat.threat_type} - {threat.content[:200]}..."
                await self.rag.save_context("background_threat_intelligence", context)
                
            if recent_threats:
                logger.info(f"📝 Updated RAG with {len(recent_threats)} new threats")
                
        except Exception as e:
            logger.error(f"❌ RAG update error: {e}")

    async def _get_recent_threats(self, hours: int = 3) -> List[ThreatIntelligence]:
        """Get threats discovered in the last N hours"""
        try:
            if hasattr(self.db, 'get_recent_threats'):
                return self.db.get_recent_threats(hours=hours)
            return []
        except Exception as e:
            logger.error(f"Failed to get recent threats: {e}")
            return []

    async def _cleanup_old_threats(self):
        """Clean up old threat intelligence data"""
        try:
            cutoff_date = datetime.now() - timedelta(days=30)
            if hasattr(self.db, 'delete_old_threats'):
                deleted = self.db.delete_old_threats(cutoff_date)
                logger.debug(f"🧹 Cleaned {deleted} threats older than {cutoff_date}")
        except Exception as e:
            logger.error(f"❌ Cleanup error: {e}")

    def _extract_solana_addresses(self, text: str) -> List[str]:
        """Extract Solana addresses from text"""
        pattern = r'\b[A-HJ-NP-Z1-9]{32,44}\b'
        addresses = re.findall(pattern, text)
        
        valid_addresses = []
        for addr in addresses:
            if len(addr) >= 32 and not addr.isdigit():
                valid_addresses.append(addr)
        
        return valid_addresses

    def _extract_token_names(self, text: str) -> List[str]:
        """Extract token names from text"""
        patterns = [
            r'\$([A-Z]{2,10})',
            r'\b([A-Z]{2,10})\s+token',
            r'token\s+([A-Z]{2,10})',
        ]
        
        tokens = []
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            tokens.extend(matches)
        
        return list(set(tokens))

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
        confidence = 0.3
        
        if 'security' in source or 'alert' in source:
            confidence += 0.3
        elif 'twitter' in source:
            confidence += 0.2
        elif 'reddit' in source:
            confidence += 0.1
        
        content_lower = content.lower()
        if any(word in content_lower for word in ['confirmed', 'verified', 'official']):
            confidence += 0.3
        if any(word in content_lower for word in ['reported', 'multiple', 'evidence']):
            confidence += 0.2
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
            
            if hasattr(self.db, 'insert_threat_intelligence'):
                self.db.insert_threat_intelligence(threat_data)
            else:
                logger.debug(f"📝 Would save threat intelligence: {threat.threat_type}")
            
        except Exception as e:
            logger.error(f"❌ Error adding threat intelligence: {e}")

    async def _update_statistics(self):
        """Update monitoring statistics"""
        try:
            stats_data = {
                'threats_discovered': self.stats['threats_discovered'],
                'wallets_tracked': len(self.blacklisted_wallets),
                'social_media_scans': self.stats['social_media_scans'],
                'database_updates': self.stats['database_updates'],
                'cache_updates_sent': self.stats['cache_updates_sent'],
                'edge_learning_integration': self.stats['edge_learning_integration'],
                'twitter_api_calls': self.stats['twitter_api_calls'],
                'reddit_api_calls': self.stats['reddit_api_calls'],
                'rate_limit_hits': self.stats['rate_limit_hits'],
                'last_update': self.stats['last_update'].isoformat(),
                'monitoring_active': self.monitoring_active
            }
            
            if hasattr(self.db, 'update_monitoring_statistics'):
                self.db.update_monitoring_statistics(stats_data)
            else:
                logger.debug(f"📊 Statistics: {self.stats['threats_discovered']} threats, {len(self.blacklisted_wallets)} blacklisted")
            
        except Exception as e:
            logger.error(f"❌ Error updating statistics: {e}")

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
            },
            'edge_learning_integration': {
                'available': self.edge_learning_engine is not None,
                'cache_updates_queued': self.cache_update_queue.qsize() if hasattr(self, 'cache_update_queue') else 0,
                'cache_updates_sent': self.stats['cache_updates_sent']
            },
            'rate_limiting': {
                'twitter_calls_made': self.stats['twitter_api_calls'],
                'reddit_calls_made': self.stats['reddit_api_calls'],
                'rate_limit_hits': self.stats['rate_limit_hits'],
                'current_keyword_index': self._twitter_keyword_index,
                'current_subreddit_index': self._reddit_subreddit_index
            }
        }

    async def add_manual_threat(self, threat_data: Dict) -> bool:
        """Manually add threat intelligence with cache updates"""
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
            
            if self.edge_learning_engine and (threat.addresses or threat.tokens):
                cache_update = {
                    'type': 'threat_intelligence',
                    'data': {
                        'threat_type': threat.threat_type,
                        'addresses': threat.addresses,
                        'tokens': threat.tokens,
                        'confidence': threat.confidence,
                        'source': 'manual_input',
                        'discovered_at': threat.discovered_at.isoformat()
                    }
                }
                
                try:
                    self.cache_update_queue.put_nowait(cache_update)
                    logger.info(f"🧠 Queued cache update for manual threat: {threat.threat_type}")
                except asyncio.QueueFull:
                    logger.warning("⚠️ Cache update queue full - manual threat may not be cached immediately")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error adding manual threat: {e}")
            return False

    async def blacklist_wallet_manual(self, address: str, threat_type: str, evidence: str) -> bool:
        """Manually blacklist a wallet with immediate cache update"""
        try:
            await self._add_blacklisted_wallet_enhanced(address, threat_type, 'manual_input')
            logger.info(f"✅ Manually blacklisted wallet: {address[:8]}... ({threat_type})")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error blacklisting wallet manually: {e}")
            return False

    async def integrate_with_edge_learning_engine(self, edge_learning_engine):
        """Set EdgeLearningEngine reference after initialization"""
        self.edge_learning_engine = edge_learning_engine
        self.stats['edge_learning_integration'] = True
        
        if not hasattr(self, 'cache_update_queue'):
            self.cache_update_queue = asyncio.Queue(maxsize=1000)
        
        await self._preload_blacklist_cache()
        
        logger.info("🔗 EdgeLearningEngine integrated with EnhancedBackgroundMonitor")

    def get_cache_update_queue_status(self) -> Dict[str, Any]:
        """Get status of cache update queue for debugging"""
        if not hasattr(self, 'cache_update_queue'):
            return {'queue_available': False}
        
        return {
            'queue_available': True,
            'queue_size': self.cache_update_queue.qsize(),
            'queue_max_size': self.cache_update_queue.maxsize,
            'cache_updates_sent': self.stats['cache_updates_sent'],
            'edge_learning_available': self.edge_learning_engine is not None
        }

    async def force_cache_sync(self) -> Dict[str, Any]:
        """Force immediate cache synchronization for debugging"""
        if not self.edge_learning_engine:
            return {'error': 'EdgeLearningEngine not available'}
        
        try:
            updates_processed = 0
            
            while not self.cache_update_queue.empty():
                cache_update = await self.cache_update_queue.get()
                await self._apply_cache_update(cache_update)
                updates_processed += 1
            
            logger.info(f"🧠 Force sync: processed {updates_processed} cache updates")
            
            return {
                'success': True,
                'updates_processed': updates_processed,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"❌ Force cache sync error: {e}")
            return {'error': str(e)}

    async def add_external_threat_source(self, source_config: Dict[str, Any]) -> bool:
        """Add external threat intelligence source"""
        try:
            source_name = source_config.get('name', 'unknown')
            source_url = source_config.get('url')
            source_type = source_config.get('type', 'json')
            
            logger.info(f"🔌 Adding external threat source: {source_name}")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(source_url, timeout=10) as response:
                    if response.status != 200:
                        logger.warning(f"External source {source_name} returned status {response.status}")
                        return False
                    logger.info(f"📡 External source configured: {source_name} ({source_type})")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error adding external threat source: {e}")
            return False

    def get_blacklisted_wallets(self) -> Dict[str, BlacklistedWallet]:
        """Get all blacklisted wallets for SecurityAgent access"""
        return self.blacklisted_wallets.copy()

    def is_address_blacklisted(self, address: str) -> Dict[str, Any]:
        """Check if specific address is blacklisted - for SecurityAgent integration"""
        if address in self.blacklisted_wallets:
            wallet = self.blacklisted_wallets[address]
            return {
                'is_blacklisted': True,
                'threat_type': wallet.threat_type,
                'confidence': wallet.confidence,
                'sources': wallet.sources,
                'activity_count': wallet.activity_count,
                'last_activity': wallet.last_activity.isoformat() if wallet.last_activity else None
            }
        return {'is_blacklisted': False}

    def get_blacklist_summary(self) -> Dict[str, Any]:
        """Get blacklist summary for SecurityAgent cache integration"""
        return {
            'total_blacklisted': len(self.blacklisted_wallets),
            'threat_types': list(set(w.threat_type for w in self.blacklisted_wallets.values())),
            'high_confidence_count': len([w for w in self.blacklisted_wallets.values() if w.confidence >= 0.8]),
            'recent_additions': len([w for w in self.blacklisted_wallets.values() 
                                if w.last_activity and w.last_activity > datetime.now() - timedelta(hours=24)]),
            'last_updated': datetime.now().isoformat()
        }

    async def sync_with_community_database(self, community_db_api_url: str) -> Dict[str, Any]:
        """Sync with external community database API"""
        try:
            logger.info(f"🌐 Syncing with community database: {community_db_api_url}")
            
            sync_data = {
                'blacklisted_wallets': [
                    {
                        'address': wallet.address,
                        'threat_type': wallet.threat_type,
                        'confidence': wallet.confidence,
                        'sources': wallet.sources
                    } for wallet in self.blacklisted_wallets.values()
                ],
                'threats_discovered': self.stats['threats_discovered'],
                'last_sync': datetime.now().isoformat()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{community_db_api_url}/sync", json=sync_data, timeout=10) as response:
                    if response.status != 200:
                        logger.warning(f"Community DB API returned status {response.status}")
                        return {'success': False, 'error': f"API error: {response.status}"}
                    remote_data = await response.json()
                    
                    # Update local blacklist with remote data
                    for remote_wallet in remote_data.get('blacklisted_wallets', []):
                        address = remote_wallet['address']
                        if address not in self.blacklisted_wallets:
                            self.blacklisted_wallets[address] = BlacklistedWallet(
                                address=address,
                                threat_type=remote_wallet.get('threat_type', 'general_scam'),
                                last_activity=None,
                                activity_count=0,
                                confidence=remote_wallet.get('confidence', 0.8),
                                sources=remote_wallet.get('sources', ['community_db'])
                            )
                    
                    logger.info(f"✅ Community database sync complete: {len(self.blacklisted_wallets)} wallets")
                    return {
                        'success': True,
                        'sync_data': sync_data,
                        'remote_wallets': len(remote_data.get('blacklisted_wallets', [])),
                        'timestamp': datetime.now().isoformat()
                    }
            
        except Exception as e:
            logger.error(f"❌ Community database sync error: {e}")
            return {'success': False, 'error': str(e)}

async def start_enhanced_background_monitor(db: SQLiteDB, rag: RAGClient, 
                                        edge_learning_engine=None) -> EnhancedBackgroundIntelligenceMonitor:
    """Start the enhanced background intelligence monitor with EdgeLearningEngine integration"""
    monitor = EnhancedBackgroundIntelligenceMonitor(db, rag, edge_learning_engine)
    await monitor.initialize()
    await monitor.start_monitoring()
    return monitor

async def start_background_monitor(db: SQLiteDB, rag: RAGClient) -> EnhancedBackgroundIntelligenceMonitor:
    """Backward compatibility wrapper"""
    logger.info("🔄 Using enhanced background monitor for backward compatibility")
    return await start_enhanced_background_monitor(db, rag, None)
