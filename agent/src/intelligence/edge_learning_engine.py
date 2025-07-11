import os
import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import threading
from collections import defaultdict
import aiohttp
import logging

# Core system imports
from src.client.rag import RAGClient
from src.db import DBInterface
from src.analysis.adaptive_community_database import AdaptiveCommunityDatabase

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("EdgeLearningEngine")

@dataclass
class LearningTask:
    """Structure for background learning tasks"""
    task_id: str
    task_type: str  # 'user_feedback', 'intelligence_refresh', 'external_data', 'cache_update'
    priority: str   # 'high', 'normal', 'low'
    data: Dict[str, Any]
    created_at: datetime
    attempts: int = 0
    max_attempts: int = 3

@dataclass
class CachedIntelligence:
    """Structure for cached intelligence data"""
    cache_key: str
    threat_patterns: List[str]
    analysis_suggestions: List[str]
    confidence_boost: float
    risk_indicators: Dict[str, float]
    source: str  # 'community_db', 'rag', 'external_api', 'user_feedback'
    cached_at: datetime
    expires_at: datetime
    access_count: int = 0

class IntelligenceCache:
    """
    High-performance intelligence cache for instant transaction analysis.
    Manages threat intelligence data with expiry and access patterns.
    """
    
    def __init__(self, max_size: int = 10000, default_ttl_seconds: int = 3600):
        self.cache: Dict[str, CachedIntelligence] = {}
        self.max_size = max_size
        self.default_ttl_seconds = default_ttl_seconds
        self.access_stats = defaultdict(int)
        self._lock = threading.RLock()
    
    def get(self, cache_key: str) -> Optional[CachedIntelligence]:
        """Get cached intelligence instantly (thread-safe)"""
        with self._lock:
            if cache_key in self.cache:
                cached_data = self.cache[cache_key]
                
                # Check if expired
                if datetime.now() > cached_data.expires_at:
                    del self.cache[cache_key]
                    if cache_key in self.access_stats:
                        del self.access_stats[key]
                    return None
                
                # Update access stats
                cached_data.access_count += 1
                self.access_stats[cache_key] += 1
                return cached_data
        
        return None
    
    def set(self, cache_key: str, intelligence: Dict[str, Any], 
            source: str = "unknown", ttl_seconds: Optional[int] = None) -> None:
        """Set cached intelligence (thread-safe)"""
        ttl = ttl_seconds or self.default_ttl_seconds
        expires_at = datetime.now() + timedelta(seconds=ttl)
        
        cached_intel = CachedIntelligence(
            cache_key=cache_key,
            threat_patterns=intelligence.get('threat_patterns', []),
            analysis_suggestions=intelligence.get('analysis_suggestions', []),
            confidence_boost=intelligence.get('confidence_boost', 0.0),
            risk_indicators=intelligence.get('risk_indicators', {}),
            source=source,
            cached_at=datetime.now(),
            expires_at=expires_at
        )
        
        with self._lock:
            # Remove expired entries if cache is full
            if len(self.cache) >= self.max_size:
                self._cleanup_expired()
            
            # If still full, remove least accessed items
            if len(self.cache) >= self.max_size:
                self._evict_least_accessed()
            
            self.cache[cache_key] = cached_intel
    
    def _cleanup_expired(self) -> int:
        """Remove expired cache entries"""
        now = datetime.now()
        expired_keys = [
            key for key, data in self.cache.items() 
            if now > data.expires_at
        ]
        
        for key in expired_keys:
            del self.cache[key]
            if key in self.access_stats:
                del self.access_stats[key]
        
        return len(expired_keys)
    
    def _evict_least_accessed(self) -> None:
        """Remove least accessed cache entries when cache is full"""
        sorted_items = sorted(
            self.cache.items(), 
            key=lambda x: x[1].access_count
        )
        
        evict_count = max(1, len(sorted_items) // 10)
        for key, _ in sorted_items[:evict_count]:
            del self.cache[key]
            if key in self.access_stats:
                del self.access_stats[key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            now = datetime.now()
            expired_count = sum(
                1 for data in self.cache.values() 
                if now > data.expires_at
            )
            
            return {
                'total_entries': len(self.cache),
                'expired_entries': expired_count,
                'cache_hit_rate': sum(self.access_stats.values()) / max(len(self.cache), 1),
                'most_accessed': sorted(
                    self.access_stats.items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:5]
            }

class ExternalDataIntegrator:
    """
    Plugin system for integrating external data sources.
    Handles Jupiter, DeFiLlama, CoinGecko, and custom APIs.
    """
    
    def __init__(self):
        self.integrations = {}
        self.rate_limits = {}
        self.last_requests = {}
    
    def register_integration(self, name: str, config: Dict[str, Any]) -> None:
        """Register a new external data integration"""
        self.integrations[name] = {
            'config': config,
            'enabled': config.get('enabled', True),
            'api_url': config.get('api_url'),
            'api_key': config.get('api_key'),
            'rate_limit': config.get('rate_limit', 60),  # requests per minute
            'timeout': config.get('timeout', 10),
            'data_normalizer': config.get('data_normalizer'),
        }
        self.rate_limits[name] = []
    
    async def fetch_external_data(self, source: str, data_type: str, params: Dict[str, Any]) -> Optional[Dict]:
        """Fetch data from external source with rate limiting"""
        if source not in self.integrations:
            logger.warning(f"Source {source} not registered")
            return None
        
        integration = self.integrations[source]
        if not integration['enabled']:
            logger.info(f"Source {source} disabled")
            return None
        
        if not self._check_rate_limit(source):
            logger.warning(f"Rate limit exceeded for {source}")
            return None
        
        try:
            self._record_request(source)
            async with aiohttp.ClientSession() as session:
                if source == 'jupiter':
                    return await self._fetch_jupiter_data(session, data_type, params)
                elif source == 'defi_llama':
                    return await self._fetch_defi_llama_data(session, data_type, params)
                elif source == 'coingecko':
                    return await self._fetch_coingecko_data(session, data_type, params)
                else:
                    return await self._fetch_custom_api_data(session, source, data_type, params)
        
        except Exception as e:
            logger.error(f"❌ External data fetch error ({source}): {e}")
            return None
    
    def _check_rate_limit(self, source: str) -> bool:
        """Check if we can make a request to this source"""
        now = datetime.now()
        cutoff = now - timedelta(minutes=1)
        
        self.rate_limits[source] = [
            req_time for req_time in self.rate_limits[source] 
            if req_time > cutoff
        ]
        
        integration = self.integrations[source]
        return len(self.rate_limits[source]) < integration['rate_limit']
    
    def _record_request(self, source: str) -> None:
        """Record a request for rate limiting"""
        self.rate_limits[source].append(datetime.now())
    
    async def _fetch_jupiter_data(self, session: aiohttp.ClientSession, data_type: str, params: Dict[str, Any]) -> Optional[Dict]:
        """Fetch data from Jupiter API"""
        if data_type == 'popular_routes':
            try:
                url = f"{self.integrations['jupiter']['api_url']}/v6/quote"
                headers = {'Authorization': f"Bearer {self.integrations['jupiter']['api_key']}"}
                async with session.get(url, params=params, headers=headers, timeout=self.integrations['jupiter']['timeout']) as response:
                    if response.status != 200:
                        logger.warning(f"Jupiter API returned status {response.status}")
                        return None
                    data = await response.json()
                    return {
                        'routes': data.get('data', []),
                        'source': 'jupiter_api',
                        'timestamp': datetime.now().isoformat()
                    }
            except Exception as e:
                logger.error(f"Jupiter API fetch error: {e}")
                return None
        return None
    
    async def _fetch_defi_llama_data(self, session: aiohttp.ClientSession, data_type: str, params: Dict[str, Any]) -> Optional[Dict]:
        """Fetch data from DeFiLlama API"""
        if data_type == 'protocols':
            try:
                url = f"{self.integrations['defi_llama']['api_url']}/protocols"
                async with session.get(url, params=params, timeout=self.integrations['defi_llama']['timeout']) as response:
                    if response.status != 200:
                        logger.warning(f"DeFiLlama API returned status {response.status}")
                        return None
                    data = await response.json()
                    return {
                        'protocols': data,
                        'source': 'defi_llama',
                        'timestamp': datetime.now().isoformat()
                    }
            except Exception as e:
                logger.error(f"DeFiLlama API fetch error: {e}")
                return None
        return None
    
    async def _fetch_coingecko_data(self, session: aiohttp.ClientSession, data_type: str, params: Dict[str, Any]) -> Optional[Dict]:
        """Fetch data from CoinGecko API"""
        if data_type == 'tokens':
            try:
                url = f"{self.integrations['coingecko']['api_url']}/coins/markets"
                params = {**params, 'vs_currency': 'usd', 'sparkline': 'false'}
                async with session.get(url, params=params, timeout=self.integrations['coingecko']['timeout']) as response:
                    if response.status != 200:
                        logger.warning(f"CoinGecko API returned status {response.status}")
                        return None
                    data = await response.json()
                    return {
                        'tokens': data,
                        'source': 'coingecko',
                        'timestamp': datetime.now().isoformat()
                    }
            except Exception as e:
                logger.error(f"CoinGecko API fetch error: {e}")
                return None
        return None
    
    async def _fetch_custom_api_data(self, session: aiohttp.ClientSession, source: str, data_type: str, params: Dict[str, Any]) -> Optional[Dict]:
        """Fetch data from custom API"""
        try:
            url = f"{self.integrations[source]['api_url']}/{data_type}"
            headers = {'Authorization': f"Bearer {self.integrations[source]['api_key']}"} if self.integrations[source].get('api_key') else {}
            async with session.get(url, params=params, headers=headers, timeout=self.integrations[source]['timeout']) as response:
                if response.status != 200:
                    logger.warning(f"Custom API {source} returned status {response.status}")
                    return None
                data = await response.json()
                return {
                    'data': data,
                    'source': source,
                    'timestamp': datetime.now().isoformat()
                }
        except Exception as e:
            logger.error(f"Custom API {source} fetch error: {e}")
            return None

class EdgeLearningEngine:
    """
    Main edge learning engine that orchestrates all background intelligence.
    Processes learning tasks, manages cache, and integrates external data.
    """
    
    def __init__(self, rag: RAGClient, db: DBInterface, community_db: AdaptiveCommunityDatabase):
        self.rag = rag
        self.db = db
        self.community_db = community_db
        
        # Core components
        self.intelligence_cache = IntelligenceCache()
        self.external_integrator = ExternalDataIntegrator()
        
        # Background processing
        self.learning_queue = asyncio.Queue(maxsize=5000)
        self.is_running = False
        self.background_tasks = []
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Configuration
        self.config = {
            'queue_process_interval': 5,     # Process queue every 5 seconds
            'cache_cleanup_interval': 300,   # Clean cache every 5 minutes
            'rag_update_interval': 600,      # Update RAG every 10 minutes
            'external_data_interval': 1800,  # Fetch external data every 30 minutes
            'community_sync_interval': 900,  # Sync community DB every 15 minutes
            'max_queue_size': 5000,
            'batch_process_size': 20
        }
        
        # Metrics and monitoring
        self.metrics = {
            'tasks_processed': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'rag_updates': 0,
            'external_api_calls': 0,
            'errors': 0
        }
    
    async def start(self) -> None:
        """Start the edge learning engine background processes"""
        if self.is_running:
            return
        
        self.is_running = True
        logger.info("🧠 Starting Edge Learning Engine...")
        
        # Initialize external integrations
        await self._initialize_external_integrations()
        
        # Start background tasks
        self.background_tasks = [
            asyncio.create_task(self._queue_processor()),
            asyncio.create_task(self._cache_manager()),
            asyncio.create_task(self._rag_updater()),
            asyncio.create_task(self._external_data_fetcher()),
            asyncio.create_task(self._community_db_syncer()),
            asyncio.create_task(self._metrics_reporter())
        ]
        
        logger.info("✅ Edge Learning Engine started")
    
    async def stop(self) -> None:
        """Stop the edge learning engine"""
        self.is_running = False
        
        # Cancel all background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        # Shutdown thread pool
        self.executor.shutdown(wait=True)
        
        logger.info("🛑 Edge Learning Engine stopped")
    
    # ========== PUBLIC API FOR SECURITY AGENT ==========
    
    async def get_cached_intelligence(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached intelligence for instant transaction analysis"""
        cached = self.intelligence_cache.get(cache_key)
        
        if cached:
            self.metrics['cache_hits'] += 1
            return {
                'cache_available': True,
                'threat_patterns': cached.threat_patterns,
                'analysis_suggestions': cached.analysis_suggestions,
                'confidence_boost': cached.confidence_boost,
                'risk_indicators': cached.risk_indicators,
                'source': cached.source,
                'cache_age_seconds': int((datetime.now() - cached.cached_at).total_seconds())
            }
        else:
            self.metrics['cache_misses'] += 1
            return {
                'cache_available': False,
                'threat_patterns': [],
                'analysis_suggestions': [],
                'confidence_boost': 0.0,
                'risk_indicators': {},
                'source': 'no_cache'
            }
    
    def queue_learning_task(self, task_type: str, data: Dict[str, Any], priority: str = 'normal') -> bool:
        """Queue a learning task for background processing (non-blocking)"""
        task = LearningTask(
            task_id=f"{task_type}_{int(time.time())}_{id(data)}",
            task_type=task_type,
            priority=priority,
            data=data,
            created_at=datetime.now()
        )
        
        try:
            self.learning_queue.put_nowait(task)
            return True
        except asyncio.QueueFull:
            logger.warning("⚠️ Learning queue full, dropping task")
            self.metrics['errors'] += 1
            return False
    
    def learn_from_user_decision(self, target_data: Dict, user_decision: str, 
                               user_reasoning: str = "", confidence: float = 0.8) -> None:
        """Learn from user decisions (approve/quarantine) - non-blocking"""
        learning_data = {
            'target_data': target_data,
            'user_decision': user_decision,
            'user_reasoning': user_reasoning,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat()
        }
        
        if self.queue_learning_task('user_feedback', learning_data, priority='high'):
            # Update cache immediately for instant effect
            self._update_cache_from_user_decision(target_data, user_decision, confidence)
    
    def trigger_intelligence_refresh(self, target_data: Dict, cache_keys: List[str]) -> None:
        """Trigger background intelligence refresh for future transactions"""
        refresh_data = {
            'target_data': target_data,
            'cache_keys': cache_keys,
            'refresh_type': 'transaction_analysis'
        }
        
        self.queue_learning_task('intelligence_refresh', refresh_data, priority='normal')
    
    # ========== BACKGROUND PROCESSING LOOPS ==========
    
    async def _queue_processor(self) -> None:
        """Main background task processor"""
        logger.info("🔄 Starting queue processor...")
        
        while self.is_running:
            try:
                tasks_batch = []
                
                for _ in range(self.config['batch_process_size']):
                    try:
                        task = await asyncio.wait_for(
                            self.learning_queue.get(),
                            timeout=self.config['queue_process_interval']
                        )
                        tasks_batch.append(task)
                    except asyncio.TimeoutError:
                        break
                
                if not tasks_batch:
                    await asyncio.sleep(1)
                    continue
                
                await self._process_task_batch(tasks_batch)
                
            except Exception as e:
                logger.error(f"❌ Queue processor error: {e}")
                self.metrics['errors'] += 1
                await asyncio.sleep(10)
    
    async def _process_task_batch(self, tasks: List[LearningTask]) -> None:
        """Process a batch of learning tasks"""
        logger.info(f"📚 Processing {len(tasks)} learning tasks")
        
        grouped_tasks = defaultdict(list)
        for task in tasks:
            if task.attempts < task.max_attempts:
                grouped_tasks[task.task_type].append(task)
            else:
                logger.warning(f"Task {task.task_id} exceeded max attempts ({task.max_attempts})")
        
        for task_type, task_list in grouped_tasks.items():
            try:
                if task_type == 'user_feedback':
                    await self._process_user_feedback_batch(task_list)
                elif task_type == 'intelligence_refresh':
                    await self._process_intelligence_refresh_batch(task_list)
                elif task_type == 'external_data':
                    await self._process_external_data_batch(task_list)
                elif task_type == 'cache_update':
                    await self._process_cache_update_batch(task_list)
                
                self.metrics['tasks_processed'] += len(task_list)
                
            except Exception as e:
                logger.error(f"❌ Error processing {task_type} tasks: {e}")
                self.metrics['errors'] += 1
    
    async def _process_user_feedback_batch(self, tasks: List[LearningTask]) -> None:
        """Process user feedback learning tasks"""
        for task in tasks:
            try:
                data = task.data
                target_data = data['target_data']
                user_decision = data['user_decision']
                user_reasoning = data.get('user_reasoning', '')
                
                await self.community_db.learn_from_user_feedback({
                    'address': target_data.get('from_address', ''),
                    'token_symbol': target_data.get('token_name', ''),
                    'user_decision': user_decision,
                    'user_reasoning': user_reasoning,
                    'timestamp': data['timestamp'],
                    'confidence': data['confidence']
                })
                
                context = self._create_rag_context_from_feedback(data)
                await self.rag.save_context("user_feedback_learning", context)
            except Exception as e:
                task.attempts += 1
                logger.warning(f"Failed to process user feedback task {task.task_id}: {e}")
    
    async def _process_intelligence_refresh_batch(self, tasks: List[LearningTask]) -> None:
        """Process intelligence refresh tasks"""
        for task in tasks:
            try:
                data = task.data
                target_data = data['target_data']
                cache_keys = data['cache_keys']
                
                intelligence = await self._gather_fresh_intelligence(target_data)
                
                for cache_key in cache_keys:
                    self.intelligence_cache.set(
                        cache_key, 
                        intelligence, 
                        source='background_refresh'
                    )
            except Exception as e:
                task.attempts += 1
                logger.warning(f"Failed to process intelligence refresh task {task.task_id}: {e}")
    
    async def _process_external_data_batch(self, tasks: List[LearningTask]) -> None:
        """Process external data integration tasks"""
        for task in tasks:
            try:
                data = task.data
                source = data.get('source')
                data_type = data.get('data_type')
                params = data.get('params', {})
                
                external_data = await self.external_integrator.fetch_external_data(
                    source, data_type, params
                )
                
                if external_data:
                    await self._process_external_data_result(source, external_data)
                    self.metrics['external_api_calls'] += 1
            except Exception as e:
                task.attempts += 1
                logger.warning(f"Failed to process external data task {task.task_id}: {e}")
    
    async def _process_cache_update_batch(self, tasks: List[LearningTask]) -> None:
        """Process cache update tasks"""
        for task in tasks:
            try:
                data = task.data
                cache_key = data['cache_key']
                intelligence = data['intelligence']
                source = data.get('source', 'manual_update')
                
                self.intelligence_cache.set(cache_key, intelligence, source)
            except Exception as e:
                task.attempts += 1
                logger.warning(f"Failed to process cache update task {task.task_id}: {e}")
    
    async def _cache_manager(self) -> None:
        """Background cache management task"""
        logger.info("🗄️ Starting cache manager...")
        
        while self.is_running:
            try:
                cleaned = self.intelligence_cache._cleanup_expired()
                if cleaned > 0:
                    logger.info(f"🧹 Cleaned {cleaned} expired cache entries")
                
                await self._preload_popular_cache_entries()
                
                await asyncio.sleep(self.config['cache_cleanup_interval'])
                
            except Exception as e:
                logger.error(f"❌ Cache manager error: {e}")
                self.metrics['errors'] += 1
                await asyncio.sleep(60)
    
    async def _rag_updater(self) -> None:
        """Background RAG system updater"""
        logger.info("📝 Starting RAG updater...")
        
        while self.is_running:
            try:
                accumulated_intelligence = await self._gather_accumulated_intelligence()
                
                for intel_item in accumulated_intelligence:
                    context = self._create_rag_context_from_intelligence(intel_item)
                    await self.rag.save_context("community_intelligence", context)
                
                if accumulated_intelligence:
                    logger.info(f"📝 Updated RAG with {len(accumulated_intelligence)} intelligence items")
                    self.metrics['rag_updates'] += len(accumulated_intelligence)
                
                await asyncio.sleep(self.config['rag_update_interval'])
                
            except Exception as e:
                logger.error(f"❌ RAG updater error: {e}")
                self.metrics['errors'] += 1
                await asyncio.sleep(120)
    
    async def _external_data_fetcher(self) -> None:
        """Background external data fetcher"""
        logger.info("🌐 Starting external data fetcher...")
        
        while self.is_running:
            try:
                self.queue_learning_task('external_data', {
                    'source': 'jupiter',
                    'data_type': 'popular_routes',
                    'params': {'inputMint': 'So11111111111111111111111111111111111111112', 'outputMint': 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'}
                })
                
                self.queue_learning_task('external_data', {
                    'source': 'defi_llama',
                    'data_type': 'protocols',
                    'params': {}
                })
                
                self.queue_learning_task('external_data', {
                    'source': 'coingecko',
                    'data_type': 'tokens',
                    'params': {'ids': 'solana,usd-coin'}
                })
                
                await asyncio.sleep(self.config['external_data_interval'])
                
            except Exception as e:
                logger.error(f"❌ External data fetcher error: {e}")
                self.metrics['errors'] += 1
                await asyncio.sleep(300)
    
    async def _community_db_syncer(self) -> None:
        """Background community database syncer"""
        logger.info("👥 Starting community DB syncer...")
        
        while self.is_running:
            try:
                await self.community_db.update_consensus_scores()
                await self._sync_community_intelligence_to_cache()
                
                await asyncio.sleep(self.config['community_sync_interval'])
                
            except Exception as e:
                logger.error(f"❌ Community DB syncer error: {e}")
                self.metrics['errors'] += 1
                await asyncio.sleep(180)
    
    async def _metrics_reporter(self) -> None:
        """Background metrics reporter"""
        while self.is_running:
            try:
                await asyncio.sleep(300)  # Report every 5 minutes
                
                cache_stats = self.intelligence_cache.get_stats()
                logger.info(f"📊 Metrics: Tasks={self.metrics['tasks_processed']}, "
                           f"Cache={cache_stats['total_entries']}, "
                           f"Hits={self.metrics['cache_hits']}, "
                           f"Misses={self.metrics['cache_misses']}")
                
            except Exception as e:
                logger.error(f"❌ Metrics reporter error: {e}")
                self.metrics['errors'] += 1
    
    # ========== HELPER METHODS ==========
    
    async def _initialize_external_integrations(self) -> None:
        """Initialize external data integrations"""
        self.external_integrator.register_integration('jupiter', {
            'enabled': True,
            'api_url': 'https://quote-api.jup.ag',
            'api_key': os.getenv('JUPITER_API_KEY', ''),
            'rate_limit': 30,
            'timeout': 10
        })
        
        self.external_integrator.register_integration('defi_llama', {
            'enabled': True,
            'api_url': 'https://api.llama.fi',
            'rate_limit': 60,
            'timeout': 15
        })
        
        self.external_integrator.register_integration('coingecko', {
            'enabled': True,
            'api_url': 'https://api.coingecko.com/api/v3',
            'rate_limit': 50,
            'timeout': 10
        })
    
    def _update_cache_from_user_decision(self, target_data: Dict, user_decision: str, confidence: float) -> None:
        """Update cache immediately based on user decision"""
        cache_keys = self._generate_cache_keys(target_data)
        
        for cache_key in cache_keys:
            existing_intel = self.intelligence_cache.get(cache_key)
            
            if existing_intel:
                if user_decision == 'quarantined':
                    existing_intel.confidence_boost = min(existing_intel.confidence_boost + 0.2, 1.0)
                    existing_intel.threat_patterns.append(f"User quarantined: {datetime.now().strftime('%Y-%m-%d')}")
                else:
                    existing_intel.confidence_boost = max(existing_intel.confidence_boost - 0.1, 0.0)
                    existing_intel.threat_patterns.append(f"User approved: {datetime.now().strftime('%Y-%m-%d')}")
                
                self.intelligence_cache.set(
                    cache_key,
                    {
                        'threat_patterns': existing_intel.threat_patterns,
                        'analysis_suggestions': existing_intel.analysis_suggestions,
                        'confidence_boost': existing_intel.confidence_boost,
                        'risk_indicators': existing_intel.risk_indicators
                    },
                    source='user_feedback_immediate'
                )
    
    def _generate_cache_keys(self, target_data: Dict) -> List[str]:
        """Generate cache keys from transaction data"""
        cache_keys = []
        
        if target_data.get('from_address'):
            cache_keys.append(f"address_{target_data['from_address']}")
        
        if target_data.get('token_name'):
            cache_keys.append(f"token_{target_data['token_name'].lower()}")
        
        if target_data.get('program_id'):
            cache_keys.append(f"program_{target_data['program_id']}")
        
        return cache_keys
    
    def _create_rag_context_from_feedback(self, feedback_data: Dict) -> str:
        """Create RAG context from user feedback"""
        target_data = feedback_data['target_data']
        decision = feedback_data['user_decision']
        reasoning = feedback_data.get('user_reasoning', '')
        
        address = target_data.get('from_address', 'unknown')
        token = target_data.get('token_name', 'unknown')
        
        if decision == 'approved':
            context = f"User approved token {token} from address {address} as legitimate."
        else:
            context = f"User quarantined token {token} from address {address} as suspicious."
        
        if reasoning:
            context += f" User reasoning: {reasoning}"
        
        context += f" Confidence: {feedback_data['confidence']}"
        
        return context
    
    def _create_rag_context_from_intelligence(self, intel_item: Dict) -> str:
        """Create RAG context from intelligence data"""
        return f"Community intelligence: {intel_item.get('summary', 'Unknown intelligence item')}"
    
    async def _gather_fresh_intelligence(self, target_data: Dict) -> Dict[str, Any]:
        """Gather fresh intelligence from community database"""
        address = target_data.get('from_address', '')
        token_name = target_data.get('token_name', '')
        
        legitimacy_data = await self.community_db.check_legitimacy(address, token_name, token_name)
        threat_data = await self.community_db.check_threat_level(address, token_name)
        
        intelligence = {
            'threat_patterns': [],
            'analysis_suggestions': ['comprehensive_analysis'],
            'confidence_boost': 0.0,
            'risk_indicators': {}
        }
        
        if legitimacy_data.get('is_legitimate'):
            intelligence['confidence_boost'] = 0.1
            intelligence['threat_patterns'].append("Community verified as legitimate")
        
        if threat_data.get('is_threat'):
            intelligence['confidence_boost'] = 0.3
            intelligence['threat_patterns'].append(f"Community threat level: {threat_data.get('threat_level', 'unknown')}")
            intelligence['analysis_suggestions'].extend(['behavior_analysis', 'contract_analysis'])
        
        return intelligence
    
    async def _gather_accumulated_intelligence(self) -> List[Dict]:
        """Gather accumulated intelligence for RAG updates"""
        try:
            recent_updates = await self._get_recent_community_updates()
            return [update['intelligence'] for update in recent_updates]
        except Exception as e:
            logger.error(f"Failed to gather accumulated intelligence: {e}")
            return []
    
    async def _preload_popular_cache_entries(self) -> None:
        """Preload cache with popular addresses/tokens"""
        try:
            # Example: Fetch popular tokens from community database
            popular_tokens = await self.db.get_popular_tokens(limit=100) if hasattr(self.db, 'get_popular_tokens') else []
            for token in popular_tokens:
                intelligence = await self._gather_fresh_intelligence({'token_name': token})
                self.intelligence_cache.set(
                    f"token_{token.lower()}",
                    intelligence,
                    source='popular_preload'
                )
        except Exception as e:
            logger.error(f"Failed to preload cache: {e}")
    
    async def _sync_community_intelligence_to_cache(self) -> None:
        """Sync latest community intelligence to cache"""
        try:
            recent_updates = await self._get_recent_community_updates()
            
            for update in recent_updates:
                cache_key = update['cache_key']
                intelligence = update['intelligence']
                
                self.intelligence_cache.set(
                    cache_key,
                    intelligence,
                    source='community_consensus',
                    ttl_seconds=7200
                )
        except Exception as e:
            logger.error(f"❌ Community sync error: {e}")
    
    async def _get_recent_community_updates(self) -> List[Dict]:
        """Get recent community database updates"""
        try:
            if hasattr(self.db, 'get_recent_consensus_updates'):
                return self.db.get_recent_consensus_updates(hours=1)
            return []
        except Exception as e:
            logger.error(f"Failed to get community updates: {e}")
            return []
    
    async def _process_external_data_result(self, source: str, external_data: Dict) -> None:
        """Process results from external API calls"""
        try:
            if source == 'jupiter':
                await self._process_jupiter_data(external_data)
            elif source == 'defi_llama':
                await self._process_defi_llama_data(external_data)
            elif source == 'coingecko':
                await self._process_coingecko_data(external_data)
        except Exception as e:
            logger.error(f"❌ External data processing error ({source}): {e}")
    
    async def _process_jupiter_data(self, jupiter_data: Dict) -> None:
        """Process Jupiter route data for token legitimacy learning"""
        routes = jupiter_data.get('routes', [])
        
        for route in routes:
            input_mint = route.get('inputMint')
            output_mint = route.get('outputMint')
            confidence = route.get('confidence', 0.8)
            
            if input_mint:
                self.intelligence_cache.set(
                    f"token_address_{input_mint}",
                    {
                        'threat_patterns': ['Seen in Jupiter legitimate routes'],
                        'analysis_suggestions': ['dust_analysis'],
                        'confidence_boost': 0.1,
                        'risk_indicators': {'jupiter_route_seen': confidence}
                    },
                    source='jupiter_routes',
                    ttl_seconds=86400
                )
            
            if output_mint:
                self.intelligence_cache.set(
                    f"token_address_{output_mint}",
                    {
                        'threat_patterns': ['Seen in Jupiter legitimate routes'],
                        'analysis_suggestions': ['dust_analysis'],
                        'confidence_boost': 0.1,
                        'risk_indicators': {'jupiter_route_seen': confidence}
                    },
                    source='jupiter_routes',
                    ttl_seconds=86400
                )
    
    async def _process_defi_llama_data(self, defi_data: Dict) -> None:
        """Process DeFiLlama protocol data"""
        protocols = defi_data.get('protocols', [])
        
        for protocol in protocols:
            protocol_name = protocol.get('name', '').lower()
            if protocol_name:
                self.intelligence_cache.set(
                    f"protocol_{protocol_name}",
                    {
                        'threat_patterns': ['Verified DeFi protocol'],
                        'analysis_suggestions': ['contract_analysis'],
                        'confidence_boost': 0.2,
                        'risk_indicators': {'defi_llama_verified': True}
                    },
                    source='defi_llama',
                    ttl_seconds=604800
                )
    
    async def _process_coingecko_data(self, coingecko_data: Dict) -> None:
        """Process CoinGecko market data"""
        tokens = coingecko_data.get('tokens', [])
        
        for token in tokens:
            token_symbol = token.get('symbol', '').lower()
            if token_symbol:
                self.intelligence_cache.set(
                    f"token_{token_symbol}",
                    {
                        'threat_patterns': ['Listed on CoinGecko'],
                        'analysis_suggestions': ['comprehensive_analysis'],
                        'confidence_boost': 0.15,
                        'risk_indicators': {'coingecko_listed': True}
                    },
                    source='coingecko',
                    ttl_seconds=43200
                )
    
    # ========== PUBLIC MONITORING METHODS ==========
    
    def get_engine_status(self) -> Dict[str, Any]:
        """Get current engine status and metrics"""
        cache_stats = self.intelligence_cache.get_stats()
        
        return {
            'is_running': self.is_running,
            'queue_size': self.learning_queue.qsize(),
            'cache_stats': cache_stats,
            'metrics': self.metrics.copy(),
            'active_tasks': len(self.background_tasks),
            'external_integrations': {
                name: integration['enabled'] 
                for name, integration in self.external_integrator.integrations.items()
            }
        }
    
    def get_cache_intelligence_for_keys(self, cache_keys: List[str]) -> Dict[str, Any]:
        """Get cached intelligence for multiple keys (for debugging)"""
        results = {}
        
        for key in cache_keys:
            cached = self.intelligence_cache.get(key)
            if cached:
                results[key] = {
                    'available': True,
                    'source': cached.source,
                    'threat_patterns': cached.threat_patterns[:3],
                    'confidence_boost': cached.confidence_boost,
                    'cache_age_seconds': int((datetime.now() - cached.cached_at).total_seconds())
                }
            else:
                results[key] = {'available': False}
        
        return results
    
    async def force_intelligence_refresh(self, target_data: Dict) -> Dict[str, Any]:
        """Force immediate intelligence refresh for debugging/testing"""
        cache_keys = self._generate_cache_keys(target_data)
        
        fresh_intelligence = await self._gather_fresh_intelligence(target_data)
        
        for cache_key in cache_keys:
            self.intelligence_cache.set(
                cache_key,
                fresh_intelligence,
                source='forced_refresh'
            )
        
        return {
            'refreshed_keys': cache_keys,
            'intelligence': fresh_intelligence,
            'timestamp': datetime.now().isoformat()
        }
    
    def clear_cache(self) -> Dict[str, Any]:
        """Clear all cached intelligence (for testing/debugging)"""
        with self.intelligence_cache._lock:
            cleared_count = len(self.intelligence_cache.cache)
            self.intelligence_cache.cache.clear()
            self.intelligence_cache.access_stats.clear()
        
        return {
            'cleared_entries': cleared_count,
            'timestamp': datetime.now().isoformat()
        }
    
    # ========== INTEGRATION METHODS FOR OTHER COMPONENTS ==========
    
    async def integrate_with_security_agent(self, security_agent) -> None:
        """
        Integrate with SecurityAgent for seamless background learning
        
        This integration allows EdgeLearningEngine to work with SecurityAgent without
        overriding the SecurityAgent's _get_cached_intelligence method, which was
        causing the "unhashable type: 'dict'" error.
        """
        # Set the intelligence cache reference so SecurityAgent can access it
        security_agent.intelligence_cache = self.intelligence_cache
        
        # Set up background learning integration
        security_agent._trigger_background_learning = self._trigger_background_learning_from_agent
        security_agent.learn_from_user_decision = self.learn_from_user_decision
        
        logger.info("🔗 EdgeLearningEngine integrated with SecurityAgent")
        logger.info("✅ SecurityAgent will use its own _get_cached_intelligence method")
        logger.info("✅ EdgeLearningEngine provides background learning and cache storage")
    
    def _trigger_background_learning_from_agent(self, target_data: Dict, analysis_result: Dict) -> None:
        """Trigger background learning from SecurityAgent analysis results"""
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
        
        self.queue_learning_task('analysis_learning', learning_data, priority='normal')
    
    async def integrate_with_community_db(self, community_db: AdaptiveCommunityDatabase) -> None:
        """Enhanced integration with community database"""
        self.community_db = community_db
        community_db.set_edge_learning_engine_reference(self)
        
        logger.info("🔗 EdgeLearningEngine integrated with AdaptiveCommunityDatabase")
    
    # ========== EXTERNAL API CONFIGURATION ==========
    
    def configure_jupiter_integration(self, api_config: Dict[str, Any]) -> None:
        """Configure Jupiter API integration"""
        self.external_integrator.register_integration('jupiter', {
            'enabled': api_config.get('enabled', True),
            'api_url': api_config.get('api_url', 'https://quote-api.jup.ag'),
            'api_key': api_config.get('api_key', os.getenv('JUPITER_API_KEY', '')),
            'rate_limit': api_config.get('rate_limit', 30),
            'timeout': api_config.get('timeout', 10)
        })
        
        logger.info("🪐 Jupiter integration configured")
    
    def configure_custom_api(self, name: str, config: Dict[str, Any]) -> None:
        """Configure custom external API integration"""
        self.external_integrator.register_integration(name, config)
        logger.info(f"🔌 Custom API '{name}' configured")
    
    # ========== ADVANCED FEATURES ==========
    
    async def bulk_cache_preload(self, addresses: List[str], tokens: List[str]) -> Dict[str, int]:
        """Bulk preload cache with intelligence for multiple addresses/tokens"""
        preloaded = {'addresses': 0, 'tokens': 0}
        
        for address in addresses:
            target_data = {'from_address': address}
            intelligence = await self._gather_fresh_intelligence(target_data)
            
            self.intelligence_cache.set(
                f"address_{address}",
                intelligence,
                source='bulk_preload'
            )
            preloaded['addresses'] += 1
        
        for token in tokens:
            target_data = {'token_name': token}
            intelligence = await self._gather_fresh_intelligence(target_data)
            
            self.intelligence_cache.set(
                f"token_{token.lower()}",
                intelligence,
                source='bulk_preload'
            )
            preloaded['tokens'] += 1
        
        return preloaded
    
    def set_cache_ttl_policy(self, source: str, ttl_seconds: int) -> None:
        """Set custom TTL policy for specific intelligence sources"""
        if source == 'community_consensus':
            self.intelligence_cache.default_ttl_seconds = max(ttl_seconds, 7200)
        elif source == 'external_api':
            self.intelligence_cache.default_ttl_seconds = max(ttl_seconds, 3600)
        elif source == 'user_feedback':
            self.intelligence_cache.default_ttl_seconds = max(ttl_seconds, 1800)
    
    async def export_intelligence_data(self, format_type: str = 'json') -> Dict[str, Any]:
        """Export cached intelligence data for analysis/backup"""
        with self.intelligence_cache._lock:
            exported_data = {
                'timestamp': datetime.now().isoformat(),
                'total_entries': len(self.intelligence_cache.cache),
                'intelligence_data': []
            }
            
            for key, cached_intel in self.intelligence_cache.cache.items():
                exported_data['intelligence_data'].append({
                    'cache_key': key,
                    'source': cached_intel.source,
                    'threat_patterns': cached_intel.threat_patterns,
                    'analysis_suggestions': cached_intel.analysis_suggestions,
                    'confidence_boost': cached_intel.confidence_boost,
                    'cached_at': cached_intel.cached_at.isoformat(),
                    'access_count': cached_intel.access_count
                })
        
        return exported_data

def create_edge_learning_engine(rag: RAGClient, db: DBInterface, 
                               community_db: AdaptiveCommunityDatabase) -> EdgeLearningEngine:
    """Factory function to create and configure EdgeLearningEngine"""
    engine = EdgeLearningEngine(rag, db, community_db)
    
    engine.configure_jupiter_integration({
        'enabled': True,
        'rate_limit': 30,
        'timeout': 10
    })
    
    return engine

async def start_edge_learning_system(rag: RAGClient, db: DBInterface, 
                                   community_db: AdaptiveCommunityDatabase) -> EdgeLearningEngine:
    """Start the complete edge learning system"""
    engine = create_edge_learning_engine(rag, db, community_db)
    await engine.start()
    return engine