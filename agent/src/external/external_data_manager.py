
import aiohttp
import os
from typing import Dict, Optional, Any
from datetime import datetime, timedelta
from loguru import logger
import tweepy
import praw
from src.external.jupiter_connector import JupiterConnector

class ExternalDataIntegrator:
    """Handles external API integrations for real-time data."""
    
    def __init__(self):
        """Initialize API clients for Jupiter, Twitter, and Reddit."""
        self.jupiter_connector = JupiterConnector(
            api_url=os.getenv('JUPITER_API_URL', 'https://quote-api.jup.ag'),
            api_key=os.getenv('JUPITER_API_KEY', ''),
            rate_limit=int(os.getenv('JUPITER_RATE_LIMIT', 30)),
            timeout=int(os.getenv('JUPITER_TIMEOUT', 10))
        )
        self.twitter_client = None
        self.reddit_client = None
        self.initialize_social_media_clients()
    
    def initialize_social_media_clients(self):
        """Initialize Twitter and Reddit clients if credentials are available."""
        twitter_bearer_token = os.getenv('TWITTER_BEARER_TOKEN')
        if twitter_bearer_token:
            try:
                self.twitter_client = tweepy.Client(bearer_token=twitter_bearer_token)
                logger.info("✅ Twitter client initialized")
            except Exception as e:
                logger.warning(f"⚠️ Failed to initialize Twitter client: {e}")
        
        reddit_client_id = os.getenv('REDDIT_CLIENT_ID')
        reddit_client_secret = os.getenv('REDDIT_CLIENT_SECRET')
        if reddit_client_id and reddit_client_secret:
            try:
                self.reddit_client = praw.Reddit(
                    client_id=reddit_client_id,
                    client_secret=reddit_client_secret,
                    user_agent='security-agent/1.0'
                )
                logger.info("✅ Reddit client initialized")
            except Exception as e:
                logger.warning(f"⚠️ Failed to initialize Reddit client: {e}")
    
    async def fetch_external_data(self, data_type: str, params: Dict[str, Any]) -> Optional[Dict]:
        """
        Fetch data from external APIs based on data type.
        
        Args:
            data_type (str): Type of data to fetch ('popular_routes', 'social_media_sentiment')
            params (Dict): Parameters for the API request
        
        Returns:
            Optional[Dict]: Fetched data or None if request fails
        """
        async with aiohttp.ClientSession() as session:
            if data_type == 'popular_routes':
                return await self._fetch_jupiter_data(session, data_type, params)
            elif data_type == 'social_media_sentiment':
                return await self._fetch_social_media_data(session, params)
            logger.warning(f"Unsupported data type: {data_type}")
            return None
    
    async def _fetch_jupiter_data(self, session: aiohttp.ClientSession, data_type: str, params: Dict[str, Any]) -> Optional[Dict]:
        """Fetch data from Jupiter API."""
        if data_type == 'popular_routes':
            return await self.jupiter_connector.fetch_popular_routes(params)
        return None
    
    async def _fetch_social_media_data(self, session: aiohttp.ClientSession, params: Dict[str, Any]) -> Optional[Dict]:
        """Fetch social media sentiment from Twitter and Reddit."""
        token_symbol = params.get('token_symbol', '')
        if not token_symbol:
            logger.warning("No token symbol provided for social media fetch")
            return None
        
        sentiment_data = {'twitter': {}, 'reddit': {}}
        
        if self.twitter_client:
            try:
                tweets = self.twitter_client.search_recent_tweets(
                    query=f"{token_symbol} crypto",
                    max_results=10
                )
                sentiment_data['twitter'] = {
                    'tweets_found': len(tweets.data) if tweets.data else 0,
                    'sentiment': 'neutral',  # Placeholder; real NLP could be added
                    'timestamp': datetime.now().isoformat()
                }
            except Exception as e:
                logger.warning(f"Twitter fetch error: {e}")
                sentiment_data['twitter']['error'] = str(e)
        
        if self.reddit_client:
            try:
                subreddit = self.reddit_client.subreddit('cryptocurrency')
                posts = subreddit.search(f"{token_symbol}", limit=10)
                sentiment_data['reddit'] = {
                    'posts_found': sum(1 for _ in posts),
                    'sentiment': 'neutral',  # Placeholder; real NLP could be added
                    'timestamp': datetime.now().isoformat()
                }
            except Exception as e:
                logger.warning(f"Reddit fetch error: {e}")
                sentiment_data['reddit']['error'] = str(e)
        
        return sentiment_data
