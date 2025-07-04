
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import List, Dict, Any
import sqlite3
import json
from datetime import datetime
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CommunityDBAPI")

app = FastAPI(title="Community DB API")

# API key authentication
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(x_api_key: str = Depends(api_key_header)):
    valid_api_keys = os.getenv("VALID_API_KEYS", "").split(",")
    if x_api_key not in valid_api_keys:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return x_api_key

# Database connection
def get_db():
    conn = sqlite3.connect('community.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# Pydantic models
class ReportRequest(BaseModel):
    address: str
    token_symbol: str
    report_type: str  # 'threat' or 'legitimate'
    evidence: List[str]
    description: str

class SyncRequest(BaseModel):
    local_patterns: int
    local_consensus: Dict[str, Any]
    last_sync: str

# Database initialization
def init_db():
    with sqlite3.connect('community.db') as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT,
                token_symbol TEXT,
                report_type TEXT,
                evidence TEXT,
                description TEXT,
                submitted_at TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS consensus_data (
                key TEXT PRIMARY KEY,
                data TEXT
            )
        """)
        conn.commit()

init_db()

@app.post("/report")
async def submit_report(request: ReportRequest, db: sqlite3.Connection = Depends(get_db), api_key: str = Depends(verify_api_key)):
    """
    Submit a community report for an address or token
    """
    try:
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO reports (address, token_symbol, report_type, evidence, description, submitted_at) VALUES (?, ?, ?, ?, ?, ?)",
            (request.address, request.token_symbol, request.report_type, json.dumps(request.evidence), request.description, datetime.now().isoformat())
        )
        db.commit()
        logger.info(f"Submitted report for {request.address}: {request.report_type}")
        return {"status": "success", "report_id": cursor.lastrowid}
    except Exception as e:
        logger.error(f"Failed to submit report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit report: {str(e)}")

@app.get("/query/reputation/{address}")
async def query_reputation(address: str, db: sqlite3.Connection = Depends(get_db), api_key: str = Depends(verify_api_key)):
    """
    Query reputation for an address
    """
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM reports WHERE address = ?", (address,))
        reports = [dict(row) for row in cursor.fetchall()]
        for report in reports:
            report['evidence'] = json.loads(report['evidence'])
        
        positive_reports = sum(1 for r in reports if r['report_type'] == 'legitimate')
        negative_reports = sum(1 for r in reports if r['report_type'] == 'threat')
        total_reports = len(reports)
        
        reputation_score = (positive_reports / total_reports) if total_reports > 0 else 0.5
        
        logger.info(f"Queried reputation for {address}: {total_reports} reports")
        return {
            "status": "success",
            "reputation": {
                "score": reputation_score,
                "reports": total_reports,
                "positive": positive_reports,
                "negative": negative_reports,
                "details": reports
            }
        }
    except Exception as e:
        logger.error(f"Failed to query reputation: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to query reputation: {str(e)}")

@app.post("/sync")
async def sync_data(request: SyncRequest, db: sqlite3.Connection = Depends(get_db), api_key: str = Depends(verify_api_key)):
    """
    Sync consensus data with local instances
    """
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM consensus_data")
        local_consensus = {row['key']: json.loads(row['data']) for row in cursor.fetchall()}
        
        for key, data in request.local_consensus.items():
            if key in local_consensus:
                local_consensus[key]['total_votes'] += data.get('total_votes', 0)
                local_consensus[key]['positive_votes'] += data.get('positive_votes', 0)
                local_consensus[key]['negative_votes'] += data.get('negative_votes', 0)
            else:
                local_consensus[key] = data
        
        for key, data in local_consensus.items():
            cursor.execute(
                "INSERT OR REPLACE INTO consensus_data (key, data) VALUES (?, ?)",
                (key, json.dumps(data))
            )
        db.commit()
        
        logger.info(f"Synced {len(local_consensus)} consensus items")
        return {"status": "success", "consensus_data": local_consensus}
    except Exception as e:
        logger.error(f"Failed to sync data: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to sync data: {str(e)}")

@app.get("/health")
async def health_check():
    """
    Health check endpoint
    """
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}
