
from datetime import datetime
import json
from loguru import logger
import aiohttp
from src.datatypes import StrategyData
from typing import List, Tuple, TypedDict, Any
import dataclasses

class RAGInsertData(TypedDict):
    """
    Type definition for data to be inserted into the RAG system.
    """
    strategy_id: str
    summarized_desc: str

class Metadata(TypedDict):
    """
    Type definition for metadata associated with RAG content.
    """
    created_at: str
    reference_id: str
    strategy_data: str

class PageContent(TypedDict):
    """
    Type definition for a page of content in the RAG system.
    """
    metadata: Metadata
    page_content: str

class PageContentV2(TypedDict):
    """
    Type definition for a page of content in the RAG system v2.
    """
    metadata: "MetadataV2"
    page_content: str

class MetadataV2(TypedDict):
    """
    Type definition for metadata associated with RAG content for v2 endpoint.
    """
    created_at: str
    reference_id: str
    strategy_data: str
    similarity: float

class StrategyResponse(TypedDict):
    """
    Type definition for the response from the RAG API when retrieving strategies.
    """
    data: List[Any]
    message: str
    status: str

class RAGClient:
    """
    Client for interacting with the Retrieval-Augmented Generation (RAG) API.
    Supports strategy data storage/retrieval and context management for security system.
    """
    
    def __init__(self, agent_id: str, session_id: str, base_url: str):
        """
        Initialize the RAG client with agent and session information.
        
        Args:
            agent_id (str): Identifier for the agent
            session_id (str): Identifier for the session
            base_url (str): Base URL for the RAG API
        """
        self.base_url = base_url.rstrip('/')
        self.agent_id = agent_id
        self.session_id = session_id

    async def save_context(self, context_type: str, context: str):
        """
        Save a single context entry to the RAG system.
        
        Args:
            context_type (str): Type of context (e.g., 'user_feedback', 'community_reports')
            context (str): Content to save
        """
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "strategy": context,
                    "strategy_data": json.dumps({"context_type": context_type}),
                    "reference_id": f"context_{context_type}_{int(datetime.now().timestamp())}",
                    "agent_id": self.agent_id,
                    "session_id": self.session_id,
                    "created_at": datetime.now().isoformat()
                }
                async with session.post(f"{self.base_url}/context", json=payload, timeout=10) as response:
                    if response.status != 200:
                        logger.warning(f"RAG API /context returned status {response.status}")
                        return
                    logger.info(f"Saved context type {context_type}")
        except Exception as e:
            logger.error(f"RAG save_context error: {e}")

    async def save_context_batch(self, contexts: List[Dict[str, str]]):
        """
        Save a batch of context entries to the RAG system.
        
        Args:
            contexts (List[Dict[str, str]]): List of context entries with 'type' and 'content'
        """
        try:
            async with aiohttp.ClientSession() as session:
                payload = [
                    {
                        "strategy": ctx["content"],
                        "strategy_data": json.dumps({"context_type": ctx["type"]}),
                        "reference_id": f"context_{ctx['type']}_{int(datetime.now().timestamp())}_{i}",
                        "agent_id": self.agent_id,
                        "session_id": self.session_id,
                        "created_at": datetime.now().isoformat()
                    }
                    for i, ctx in enumerate(contexts)
                ]
                async with session.post(f"{self.base_url}/context/batch", json=payload, timeout=15) as response:
                    if response.status != 200:
                        logger.warning(f"RAG batch API returned status {response.status}")
                        return
                    logger.info(f"Saved {len(contexts)} contexts")
        except Exception as e:
            logger.error(f"RAG save_context_batch error: {e}")

    async def query(self, query: str) -> str:
        """
        Query the RAG system for relevant content.
        
        Args:
            query (str): Search query
        
        Returns:
            str: Query response
        """
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "query": query,
                    "agent_id": self.agent_id,
                    "session_id": self.session_id,
                    "top_k": 5,
                    "threshold": 0.7
                }
                async with session.post(f"{self.base_url}/query", json=payload, timeout=10) as response:
                    if response.status != 200:
                        logger.warning(f"RAG query API returned status {response.status}")
                        return ""
                    return await response.text()
        except Exception as e:
            logger.error(f"RAG query error: {e}")
            return ""

    def save_result_batch(self, batch_data: List[StrategyData]) -> dict:
        """
        Save a batch of strategy data to the RAG system (deprecated).
        """
        logger.warning("USING DEPRECTED ENDPOINT")
        url = f"{self.base_url}/save_result_batch"
        payload = [
            {
                "strategy": data.summarized_desc,
                "strategy_data": json.dumps(dataclasses.asdict(data)),
                "reference_id": data.strategy_id,
                "agent_id": self.agent_id,
                "session_id": self.session_id,
                "created_at": data.created_at.isoformat() if isinstance(data.created_at, datetime) else data.created_at
            }
            for data in batch_data
        ]
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error saving result batch: {e}")
            return {"status": "error", "message": str(e)}

    def save_result_batch_v4(self, batch_data: List[StrategyData]) -> dict:
        """
        Save a batch of strategy data to the RAG system (v4).
        """
        url = f"{self.base_url}/save_result_batch_v4"
        payload = []
        missing_keys = 0
        for data in batch_data:
            if isinstance(data.created_at, datetime):
                data.created_at = data.created_at.isoformat()
            if isinstance(data.parameters, str):
                parsed_once = json.loads(data.parameters)
                data_params = json.loads(parsed_once) if isinstance(parsed_once, str) else parsed_once
            else:
                data_params = data.parameters
            if "notif_str" not in data_params:
                missing_keys += 1
                continue
            payload.append(
                {
                    "notification_key": data_params["notif_str"],
                    "strategy_data": json.dumps(dataclasses.asdict(data)),
                    "reference_id": data.strategy_id,
                    "agent_id": self.agent_id,
                    "session_id": self.session_id,
                    "created_at": data.created_at
                }
            )
        if missing_keys > 0:
            logger.info(f"{missing_keys} StrategyData(s) with missing 'notif_str' keys are skipped")
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error saving result batch v4: {e}")
            return {"status": "error", "message": str(e)}

    def relevant_strategy_raw(self, query: str | None) -> List[StrategyData]:
        """
        Retrieve strategies relevant to the given query (deprecated).
        """
        logger.warning("USING DEPRECTED ENDPOINT")
        if query is None:
            return []
        url = f"{self.base_url}/relevant_strategy_raw"
        payload = {
            "query": query,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "top_k": 5,
            "threshold": 0.7
        }
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            r: StrategyResponse = response.json()
            strategy_datas = []
            for subdata in r["data"]:
                strategy_data = json.loads(subdata["metadata"]["strategy_data"])
                strategy_data["created_at"] = strategy_data.get("created_at", subdata["metadata"]["created_at"])
                strategy_data = StrategyData(**strategy_data)
                strategy_datas.append(strategy_data)
            return strategy_datas
        except Exception as e:
            logger.error(f"Error on /relevant_strategy_raw: {e}")
            return []

    def relevant_strategy_raw_v2(self, query: str) -> List[Tuple[StrategyData, float]]:
        """
        Retrieve strategies relevant to the given query using v2 endpoint (deprecated).
        """
        logger.warning("USING DEPRECTED ENDPOINT")
        if not query.strip():
            return []
        url = f"{self.base_url}/relevant_strategy_raw_v2"
        payload = {
            "query": query,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "top_k": 1
        }
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            r: StrategyResponse = response.json()
            strategy_data_tuples = []
            for subdata in r["data"]:
                strategy_data = json.loads(subdata["metadata"]["strategy_data"])
                strategy_data["created_at"] = strategy_data.get("created_at", subdata["metadata"]["created_at"])
                strategy_data_obj = StrategyData(**strategy_data)
                similarity_score = subdata["metadata"]["similarity"]
                strategy_data_tuples.append((strategy_data_obj, similarity_score))
            return strategy_data_tuples
        except Exception as e:
            logger.error(f"Error on /relevant_strategy_raw_v2: {e}")
            return []

    def relevant_strategy_raw_v4(self, query: str) -> List[Tuple[StrategyData, float]]:
        """
        Retrieve strategies relevant to the given query using v4 endpoint.
        """
        if not query.strip():
            return []
        url = f"{self.base_url}/relevant_strategy_raw_v4"
        payload = {
            "query": query,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "top_k": 1
        }
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            r: StrategyResponse = response.json()
            strategy_data_tuples = []
            for subdata in r["data"]:
                strategy_data = json.loads(subdata["metadata"]["strategy_data"])
                strategy_data["created_at"] = strategy_data.get("created_at", subdata["metadata"]["created_at"])
                strategy_data_obj = StrategyData(**strategy_data)
                similarity_score = subdata["metadata"]["distance"]
                strategy_data_tuples.append((strategy_data_obj, similarity_score))
            return strategy_data_tuples
        except Exception as e:
            logger.error(f"Error on /relevant_strategy_raw_v4: {e}")
            return []
