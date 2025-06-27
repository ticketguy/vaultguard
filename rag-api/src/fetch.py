"""
Enhanced RAG System - Threat Intelligence Functions
Extends existing RAG with specialized threat intelligence search capabilities
"""

from glob import glob
import os
from typing import List, Tuple, Dict, Optional
import json
from datetime import datetime

from dotenv import load_dotenv
from langchain_community.vectorstores.faiss import FAISS
from langchain_core.documents import Document
from loguru import logger

from src.store import get_embeddings

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
THRESHOLD = 0.7


# ========== EXISTING FUNCTIONS (Keep as-is) ==========

def convert_threshold(threshold_0_to_1: float) -> float:
    """Convert threshold from 0-1 range to -1 to 1 range."""
    if not 0 <= threshold_0_to_1 <= 1:
        raise ValueError("Threshold must be between 0 and 1")
    return (2 * threshold_0_to_1) - 1


def get_context_from_kb(vectorstore: FAISS, query: str, num_chunks: int, threshold: float):
    """Get context from knowledge base with threshold"""
    vector_retriever = vectorstore.as_retriever(
        search_type="similarity_score_threshold",
        search_kwargs={
            "k": num_chunks,
            "score_threshold": convert_threshold(threshold),
        },
    )
    result_docs = vector_retriever.invoke(query)
    return result_docs


def get_context_from_kb_with_top_k(vectorstore: FAISS, query: str, num_chunks: int):
    """Get top-k results from knowledge base"""
    results_with_scores = vectorstore.similarity_search_with_score(query, k=num_chunks)
    logger.info(f"`len(results_with_scores)`: {len(results_with_scores)}")
    return results_with_scores


def get_data_raw_v4(notification_query: str, agent_id: str, top_k: int) -> List[Tuple[Document, float]]:
    """Backward compatible KBs getter for multiple KBs based on agent_id"""
    pattern = f"pkl/v4/{agent_id}*.pkl"
    matching_files = glob(pattern)

    if not matching_files:
        logger.error(f"No vector database exists for {agent_id} yet. Please insert at least one strategy")
        return []

    base_name = os.path.basename(matching_files[0]).replace(".pkl", "")
    logger.info(f"Initializing vectorstore with `base_name` = {base_name}")

    vectorstore = FAISS.load_local(
        "pkl/v4/",
        get_embeddings(),
        base_name,
        allow_dangerous_deserialization=True,
        distance_strategy="COSINE",
    )

    for file_path in matching_files[1:]:
        base_name = os.path.basename(file_path).replace(".pkl", "")
        logger.info(f"Merging the initialized vectorstore with `base_name` = {base_name}")

        additional_index = FAISS.load_local(
            "pkl/v4/",
            get_embeddings(),
            base_name,
            allow_dangerous_deserialization=True,
            distance_strategy="COSINE",
        )
        vectorstore.merge_from(additional_index)

    return get_context_from_kb_with_top_k(vectorstore, notification_query, top_k)


# ========== NEW THREAT INTELLIGENCE FUNCTIONS ==========

async def search_threat_intelligence(query: str, threat_type: str = "general", top_k: int = 10) -> List[Dict]:
    """
    NEW FUNCTION: Search for specific threat intelligence
    Used by SecurityAgent for AI code generation
    """
    logger.info(f"🔍 Searching threat intelligence: {query} (type: {threat_type})")
    
    try:
        # Enhanced query with threat-specific context
        enhanced_query = f"{threat_type} {query} security threat analysis patterns"
        
        # Search across all available knowledge bases
        threat_results = []
        
        # Search v4 knowledge bases (your existing approach)
        pattern = "pkl/v4/*.pkl"
        matching_files = glob(pattern)
        
        if matching_files:
            # Use first available KB for threat intelligence
            base_name = os.path.basename(matching_files[0]).replace(".pkl", "")
            
            vectorstore = FAISS.load_local(
                "pkl/v4/",
                get_embeddings(),
                base_name,
                allow_dangerous_deserialization=True,
                distance_strategy="COSINE",
            )
            
            # Get threat intelligence results
            results_with_scores = vectorstore.similarity_search_with_score(enhanced_query, k=top_k)
            
            for doc, score in results_with_scores:
                threat_results.append({
                    'content': doc.page_content,
                    'metadata': doc.metadata,
                    'relevance_score': float(1.0 - score),  # Convert distance to relevance
                    'source': 'threat_intelligence_kb',
                    'threat_type': threat_type,
                    'search_query': query
                })
        
        # Add threat patterns from community database if available
        community_threats = await search_community_threat_patterns(query, threat_type)
        threat_results.extend(community_threats)
        
        # Sort by relevance score
        threat_results.sort(key=lambda x: x['relevance_score'], reverse=True)
        
        logger.info(f"✅ Found {len(threat_results)} threat intelligence results")
        return threat_results[:top_k]
        
    except Exception as e:
        logger.error(f"❌ Error searching threat intelligence: {e}")
        return []


async def search_dapp_reputation(dapp_name: str, dapp_url: str = "") -> Dict:
    """
    NEW FUNCTION: Get DApp reputation from community intelligence
    """
    logger.info(f"🔍 Searching DApp reputation: {dapp_name}")
    
    try:
        # Search for DApp mentions in threat intelligence
        dapp_query = f"dapp {dapp_name} {dapp_url} reputation safety scam"
        threat_results = await search_threat_intelligence(dapp_query, "dapp_analysis", top_k=5)
        
        reputation_data = {
            'dapp_name': dapp_name,
            'dapp_url': dapp_url,
            'safety_status': 'unknown',
            'confidence_score': 0.0,
            'community_reports': [],
            'threat_indicators': [],
            'verification_status': 'unverified',
            'last_updated': datetime.now().isoformat()
        }
        
        # Analyze results for reputation indicators
        positive_indicators = 0
        negative_indicators = 0
        
        for result in threat_results:
            content = result['content'].lower()
            
            # Check for negative indicators
            if any(word in content for word in ['scam', 'fraud', 'drain', 'rug', 'honeypot']):
                negative_indicators += 1
                reputation_data['threat_indicators'].append({
                    'type': 'negative',
                    'evidence': result['content'][:200] + "...",
                    'confidence': result['relevance_score']
                })
            
            # Check for positive indicators
            elif any(word in content for word in ['safe', 'verified', 'legitimate', 'trusted']):
                positive_indicators += 1
                reputation_data['community_reports'].append({
                    'type': 'positive',
                    'evidence': result['content'][:200] + "...",
                    'confidence': result['relevance_score']
                })
        
        # Calculate safety status
        if negative_indicators > positive_indicators and negative_indicators >= 2:
            reputation_data['safety_status'] = 'risky'
            reputation_data['confidence_score'] = min(0.8, negative_indicators * 0.3)
        elif positive_indicators > negative_indicators and positive_indicators >= 2:
            reputation_data['safety_status'] = 'safe'
            reputation_data['confidence_score'] = min(0.8, positive_indicators * 0.3)
        else:
            reputation_data['safety_status'] = 'unknown'
            reputation_data['confidence_score'] = 0.1
        
        logger.info(f"✅ DApp reputation analysis complete: {reputation_data['safety_status']}")
        return reputation_data
        
    except Exception as e:
        logger.error(f"❌ Error analyzing DApp reputation: {e}")
        return {
            'dapp_name': dapp_name,
            'safety_status': 'error',
            'confidence_score': 0.0,
            'error': str(e)
        }


async def search_similar_scam_patterns(pattern_data: Dict) -> List[Dict]:
    """
    NEW FUNCTION: Find similar scam patterns based on transaction characteristics
    """
    logger.info("🔍 Searching for similar scam patterns")
    
    try:
        # Build search query from pattern characteristics
        search_terms = []
        
        if pattern_data.get('token_name'):
            search_terms.append(f"token {pattern_data['token_name']}")
        
        if pattern_data.get('transaction_value'):
            value = float(pattern_data['transaction_value'])
            if value < 0.001:
                search_terms.append("dust attack small value")
            elif value > 1000:
                search_terms.append("large value drain")
        
        if pattern_data.get('contract_address'):
            search_terms.append(f"contract {pattern_data['contract_address']}")
        
        if pattern_data.get('sender_address'):
            search_terms.append(f"address {pattern_data['sender_address']}")
        
        # Default search if no specific patterns
        if not search_terms:
            search_terms = ["scam pattern exploit fraud"]
        
        query = " ".join(search_terms)
        
        # Search for similar patterns
        similar_patterns = await search_threat_intelligence(query, "pattern_analysis", top_k=15)
        
        # Filter and enhance results
        pattern_matches = []
        for result in similar_patterns:
            if result['relevance_score'] > 0.6:  # Only high-confidence matches
                pattern_matches.append({
                    'pattern_type': 'similar_scam',
                    'description': result['content'][:300] + "...",
                    'similarity_score': result['relevance_score'],
                    'source': result['source'],
                    'metadata': result.get('metadata', {})
                })
        
        logger.info(f"✅ Found {len(pattern_matches)} similar scam patterns")
        return pattern_matches
        
    except Exception as e:
        logger.error(f"❌ Error searching scam patterns: {e}")
        return []


async def search_community_threat_patterns(query: str, threat_type: str) -> List[Dict]:
    """
    NEW FUNCTION: Search community-reported threat patterns
    """
    try:
        # Load community threat database if exists
        community_db_path = "data/community_threats.json"
        
        if os.path.exists(community_db_path):
            with open(community_db_path, 'r') as f:
                community_data = json.load(f)
            
            community_results = []
            query_lower = query.lower()
            
            # Search through community reports
            for threat_id, threat_info in community_data.get('threats', {}).items():
                threat_content = str(threat_info).lower()
                
                # Simple relevance scoring
                relevance = 0.0
                for word in query_lower.split():
                    if word in threat_content:
                        relevance += 0.2
                
                if relevance > 0.4:  # Minimum relevance threshold
                    community_results.append({
                        'content': json.dumps(threat_info, indent=2),
                        'metadata': {'threat_id': threat_id, 'source': 'community'},
                        'relevance_score': relevance,
                        'source': 'community_database',
                        'threat_type': threat_type
                    })
            
            return community_results
        
        return []
        
    except Exception as e:
        logger.error(f"❌ Error searching community threats: {e}")
        return []


async def update_community_intelligence(new_data: Dict) -> bool:
    """
    NEW FUNCTION: Add new threat intelligence to RAG system
    """
    logger.info("📝 Updating community intelligence database")
    
    try:
        # Load existing community data
        community_db_path = "data/community_threats.json"
        
        if os.path.exists(community_db_path):
            with open(community_db_path, 'r') as f:
                community_data = json.load(f)
        else:
            community_data = {
                'threats': {},
                'last_updated': datetime.now().isoformat(),
                'version': '1.0'
            }
        
        # Add new threat data
        threat_id = f"threat_{int(datetime.now().timestamp())}"
        community_data['threats'][threat_id] = {
            **new_data,
            'added_at': datetime.now().isoformat(),
            'status': 'active'
        }
        
        # Update metadata
        community_data['last_updated'] = datetime.now().isoformat()
        
        # Ensure data directory exists
        os.makedirs("data", exist_ok=True)
        
        # Save updated data
        with open(community_db_path, 'w') as f:
            json.dump(community_data, f, indent=2)
        
        logger.info(f"✅ Added new threat intelligence: {threat_id}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error updating community intelligence: {e}")
        return False


async def search_address_intelligence(address: str) -> Dict:
    """
    NEW FUNCTION: Search for intelligence on specific address
    """
    logger.info(f"🔍 Searching address intelligence: {address[:8]}...")
    
    try:
        # Search for address mentions in threat intelligence
        address_query = f"address {address} scammer blacklist malicious"
        threat_results = await search_threat_intelligence(address_query, "address_analysis", top_k=10)
        
        address_intel = {
            'address': address,
            'reputation': 'unknown',
            'confidence': 0.0,
            'threat_reports': [],
            'activity_patterns': [],
            'risk_factors': [],
            'last_analyzed': datetime.now().isoformat()
        }
        
        # Analyze threat intelligence results
        threat_count = 0
        for result in threat_results:
            content = result['content'].lower()
            
            # Check for threat indicators
            if any(word in content for word in ['scammer', 'blacklist', 'malicious', 'drain', 'exploit']):
                threat_count += 1
                address_intel['threat_reports'].append({
                    'evidence': result['content'][:200] + "...",
                    'confidence': result['relevance_score'],
                    'source': result['source']
                })
        
        # Determine reputation
        if threat_count >= 3:
            address_intel['reputation'] = 'malicious'
            address_intel['confidence'] = min(0.9, threat_count * 0.3)
        elif threat_count >= 1:
            address_intel['reputation'] = 'suspicious'
            address_intel['confidence'] = min(0.6, threat_count * 0.2)
        else:
            address_intel['reputation'] = 'unknown'
            address_intel['confidence'] = 0.1
        
        logger.info(f"✅ Address intelligence: {address_intel['reputation']}")
        return address_intel
        
    except Exception as e:
        logger.error(f"❌ Error analyzing address intelligence: {e}")
        return {
            'address': address,
            'reputation': 'error',
            'confidence': 0.0,
            'error': str(e)
        }


async def search_token_intelligence(token_name: str, token_address: str = "") -> Dict:
    """
    NEW FUNCTION: Search for intelligence on specific token
    """
    logger.info(f"🔍 Searching token intelligence: {token_name}")
    
    try:
        # Search for token mentions in threat intelligence
        token_query = f"token {token_name} {token_address} honeypot scam fake"
        threat_results = await search_threat_intelligence(token_query, "token_analysis", top_k=10)
        
        token_intel = {
            'token_name': token_name,
            'token_address': token_address,
            'legitimacy': 'unknown',
            'confidence': 0.0,
            'scam_reports': [],
            'honeypot_indicators': [],
            'community_sentiment': 'neutral',
            'last_analyzed': datetime.now().isoformat()
        }
        
        # Analyze results for token reputation
        scam_indicators = 0
        positive_indicators = 0
        
        for result in threat_results:
            content = result['content'].lower()
            
            # Check for scam indicators
            if any(word in content for word in ['honeypot', 'scam', 'fake', 'rug']):
                scam_indicators += 1
                token_intel['scam_reports'].append({
                    'evidence': result['content'][:200] + "...",
                    'confidence': result['relevance_score']
                })
            
            # Check for positive indicators
            elif any(word in content for word in ['legitimate', 'verified', 'safe']):
                positive_indicators += 1
        
        # Determine legitimacy
        if scam_indicators > positive_indicators and scam_indicators >= 2:
            token_intel['legitimacy'] = 'scam'
            token_intel['confidence'] = min(0.9, scam_indicators * 0.3)
            token_intel['community_sentiment'] = 'negative'
        elif positive_indicators > scam_indicators and positive_indicators >= 2:
            token_intel['legitimacy'] = 'legitimate'
            token_intel['confidence'] = min(0.8, positive_indicators * 0.3)
            token_intel['community_sentiment'] = 'positive'
        else:
            token_intel['legitimacy'] = 'unknown'
            token_intel['confidence'] = 0.1
        
        logger.info(f"✅ Token intelligence: {token_intel['legitimacy']}")
        return token_intel
        
    except Exception as e:
        logger.error(f"❌ Error analyzing token intelligence: {e}")
        return {
            'token_name': token_name,
            'legitimacy': 'error',
            'confidence': 0.0,
            'error': str(e)
        }


# ========== LEGACY COMPATIBILITY ==========

def get_data_raw(query: str, agent_id: str, session_id: str, top_k: int, threshold: float):
    """Legacy function for backward compatibility"""
    kb_id = f"{agent_id}_{session_id}"
    if not os.path.exists(f"pkl/{kb_id}.pkl"):
        raise Exception("No vector database has been made. Please run the agent at least one time")

    vectorstore = FAISS.load_local(
        "pkl/",
        get_embeddings(),
        kb_id,
        allow_dangerous_deserialization=True,
        distance_strategy="COSINE",
    )
    documents = get_context_from_kb(vectorstore, query, top_k, threshold)

    format_docs = [
        {
            "page_content": doc.page_content,
            "metadata": doc.metadata,
        }
        for doc in documents
    ]

    return format_docs


def get_data_raw_v2(query: str, agent_id: str, session_id: str, top_k: int) -> List[Tuple[Document, float]]:
    """Legacy function for backward compatibility"""
    kb_id = f"{agent_id}_{session_id}"

    if not os.path.exists(f"pkl/{kb_id}.pkl"):
        raise Exception("No vector database has been made. Please run the agent at least one time")

    vectorstore = FAISS.load_local(
        "pkl/",
        get_embeddings(),
        kb_id,
        allow_dangerous_deserialization=True,
        distance_strategy="COSINE",
    )

    return get_context_from_kb_with_top_k(vectorstore, query, top_k)


def get_data_raw_v3(query: str, agent_id: str, top_k: int) -> List[Tuple[Document, float]]:
    """Legacy function for backward compatibility"""
    pattern = f"pkl/{agent_id}*.pkl"
    matching_files = glob(pattern)

    if not matching_files:
        logger.error("No vector database has exists for {agent_id} yet. Please insert atleast one strategy")
        return []

    logger.info(f"`len(matching_files)` = {len(matching_files)}")

    base_name = os.path.basename(matching_files[0]).replace(".pkl", "")
    logger.info(f"Initializing vectorstore with `base_name` = {base_name}")

    vectorstore = FAISS.load_local(
        "pkl/",
        get_embeddings(),
        base_name,
        allow_dangerous_deserialization=True,
        distance_strategy="COSINE",
    )

    for file_path in matching_files[1:]:
        base_name = os.path.basename(file_path).replace(".pkl", "")
        logger.info(f"Merging the initialized vectorstore with `base_name` = {base_name}")

        additional_index = FAISS.load_local(
            "pkl/",
            get_embeddings(),
            base_name,
            allow_dangerous_deserialization=True,
            distance_strategy="COSINE",
        )
        vectorstore.merge_from(additional_index)

    return get_context_from_kb_with_top_k(vectorstore, query, top_k)