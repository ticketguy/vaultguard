from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import List, Dict, Any
import sqlite3
import json
from datetime import datetime
import os
import logging

# Configure logging for tracking API operations and debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CommunityDBAPI")

# FastAPI application instance for the centralized community intelligence service
app = FastAPI(title="Community DB API")

# Database connection manager with SQLite row factory for dict-like access
def get_db():
    """
    Creates a new SQLite database connection for each request.
    Uses row_factory to return dict-like objects instead of tuples.
    Automatically closes connection after request completes.
    """
    conn = sqlite3.connect('community.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row  # Enables column access by name
    try:
        yield conn
    finally:
        conn.close()

# Pydantic models for request validation and API documentation
class ReportRequest(BaseModel):
    """
    Data structure for submitting community threat/legitimacy reports.
    Used when edge agents want to share intelligence about addresses/tokens.
    """
    address: str           # Solana wallet address being reported
    token_symbol: str      # Token symbol (e.g., "SOL", "USDC") 
    report_type: str       # Either 'threat' or 'legitimate'
    evidence: List[str]    # List of evidence strings (e.g., ["suspicious_pattern", "user_complaint"])
    description: str       # Human-readable description of the finding

class SyncRequest(BaseModel):
    """
    Data structure for synchronizing consensus data between edge agents.
    Contains local intelligence that needs to be merged with community data.
    """
    local_patterns: int              # Number of patterns learned locally
    local_consensus: Dict[str, Any]  # Local consensus data to merge
    last_sync: str                   # ISO timestamp of last synchronization

# Database schema initialization
def init_db():
    """
    Creates the SQLite database tables if they don't exist.
    
    reports table: Stores individual threat/legitimacy reports from edge agents
    consensus_data table: Stores aggregated community consensus by key
    """
    with sqlite3.connect('community.db') as conn:
        cursor = conn.cursor()
        
        # Table for storing individual community reports
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT,                    -- Wallet address being reported
                token_symbol TEXT,              -- Associated token symbol
                report_type TEXT,               -- 'threat' or 'legitimate'
                evidence TEXT,                  -- JSON array of evidence strings
                description TEXT,               -- Human description
                submitted_at TEXT               -- ISO timestamp
            )
        """)
        
        # Table for storing aggregated consensus data
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS consensus_data (
                key TEXT PRIMARY KEY,           -- Unique identifier (e.g., "address_token")
                data TEXT                       -- JSON object with consensus metrics
            )
        """)
        conn.commit()

# Initialize database on startup
init_db()

@app.post("/report")
async def submit_report(request: ReportRequest, db: sqlite3.Connection = Depends(get_db)):
    """
    Endpoint for edge agents to submit community reports about addresses/tokens.
    
    When an edge agent detects a threat or verifies legitimacy, it calls this endpoint
    to share that intelligence with the community. Other agents will receive this
    information during their next sync operation.
    
    Flow:
    1. Edge agent analyzes transaction/address
    2. Determines threat level or legitimacy  
    3. Submits report to this endpoint
    4. Report is stored in community database
    5. Other agents sync and receive this intelligence
    """
    try:
        cursor = db.cursor()
        
        # Insert the report into the database
        # Evidence is stored as JSON string for flexible data structure
        cursor.execute(
            "INSERT INTO reports (address, token_symbol, report_type, evidence, description, submitted_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                request.address, 
                request.token_symbol, 
                request.report_type, 
                json.dumps(request.evidence),  # Convert list to JSON string
                request.description, 
                datetime.now().isoformat()
            )
        )
        db.commit()
        
        # Log successful report submission for monitoring
        logger.info(f"Submitted report for {request.address}: {request.report_type}")
        
        # Return success response with the new report ID
        return {"status": "success", "report_id": cursor.lastrowid}
        
    except Exception as e:
        # Log error and return HTTP 500 if database operation fails
        logger.error(f"Failed to submit report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit report: {str(e)}")

@app.get("/query/reputation/{address}")
async def query_reputation(address: str, db: sqlite3.Connection = Depends(get_db)):
    """
    Endpoint for edge agents to query the community reputation of an address.
    
    Calculates reputation score based on all community reports for the given address.
    Returns aggregated statistics and detailed report history.
    
    Used when edge agents need to make instant decisions about address safety
    based on collective community intelligence.
    
    Reputation calculation:
    - Score = positive_reports / total_reports
    - Includes detailed breakdown of all reports
    - Provides evidence trail for transparency
    """
    try:
        cursor = db.cursor()
        
        # Retrieve all reports for the specified address
        cursor.execute("SELECT * FROM reports WHERE address = ?", (address,))
        reports = [dict(row) for row in cursor.fetchall()]
        
        # Parse JSON evidence back to list format for each report
        for report in reports:
            report['evidence'] = json.loads(report['evidence'])
        
        # Calculate reputation metrics
        positive_reports = sum(1 for r in reports if r['report_type'] == 'legitimate')
        negative_reports = sum(1 for r in reports if r['report_type'] == 'threat')
        total_reports = len(reports)
        
        # Calculate reputation score (0.0 to 1.0, where 1.0 is fully legitimate)
        # Default to neutral 0.5 if no reports exist
        reputation_score = (positive_reports / total_reports) if total_reports > 0 else 0.5
        
        # Log reputation query for monitoring API usage
        logger.info(f"Queried reputation for {address}: {total_reports} reports")
        
        # Return comprehensive reputation data
        return {
            "status": "success",
            "reputation": {
                "score": reputation_score,      # 0.0 = threat, 1.0 = legitimate
                "reports": total_reports,       # Total number of reports
                "positive": positive_reports,   # Number of 'legitimate' reports
                "negative": negative_reports,   # Number of 'threat' reports
                "details": reports             # Full report history with evidence
            }
        }
        
    except Exception as e:
        # Log error and return HTTP 500 if query fails
        logger.error(f"Failed to query reputation: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to query reputation: {str(e)}")

@app.post("/sync")
async def sync_data(request: SyncRequest, db: sqlite3.Connection = Depends(get_db)):
    """
    Endpoint for edge agents to synchronize their local consensus data with community data.
    
    This is the core intelligence sharing mechanism that enables the network effect.
    Edge agents periodically call this endpoint to:
    1. Upload their local consensus findings
    2. Merge with existing community consensus
    3. Download updated community intelligence
    
    Consensus data structure:
    - Key: Unique identifier (e.g., "address_token" or "pattern_hash")
    - Data: JSON object containing voting metrics, confidence scores, timestamps
    
    Merging strategy:
    - Combines vote counts from multiple agents
    - Aggregates confidence scores
    - Updates timestamps to latest sync
    """
    try:
        cursor = db.cursor()
        
        # Retrieve existing consensus data from database
        cursor.execute("SELECT * FROM consensus_data")
        local_consensus = {row['key']: json.loads(row['data']) for row in cursor.fetchall()}
        
        # Merge incoming consensus data with existing community data
        for key, data in request.local_consensus.items():
            if key in local_consensus:
                # If consensus key already exists, aggregate the metrics
                local_consensus[key]['total_votes'] += data.get('total_votes', 0)
                local_consensus[key]['positive_votes'] += data.get('positive_votes', 0)
                local_consensus[key]['negative_votes'] += data.get('negative_votes', 0)
                
                # Update timestamp to latest sync
                local_consensus[key]['last_updated'] = datetime.now().isoformat()
            else:
                # If new consensus key, add it to community database
                local_consensus[key] = data
        
        # Update the database with merged consensus data
        for key, data in local_consensus.items():
            cursor.execute(
                "INSERT OR REPLACE INTO consensus_data (key, data) VALUES (?, ?)",
                (key, json.dumps(data))  # Store as JSON string
            )
        db.commit()
        
        # Log successful sync operation
        logger.info(f"Synced {len(local_consensus)} consensus items")
        
        # Return updated consensus data for edge agent to update local cache
        return {"status": "success", "consensus_data": local_consensus}
        
    except Exception as e:
        # Log error and return HTTP 500 if sync operation fails
        logger.error(f"Failed to sync data: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to sync data: {str(e)}")

@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring service availability.
    
    Used by edge agents to verify community DB API is operational
    before attempting intelligence sync operations.
    """
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}