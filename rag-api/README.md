# RAG API

Vector database API for storing and retrieving agent strategies using FAISS embeddings.

## What it does

The RAG API provides intelligent search capabilities for VaultGuard agents by:

- Storing strategy data as vector embeddings in FAISS databases
- Searching for relevant strategies using semantic similarity
- Supporting multiple agent sessions and knowledge bases
- Providing background context for AI decision making

## API Endpoints

### Health Check

"""
GET /health
"""

Returns service status

### Search for Strategies

"""
POST /relevant_strategy_raw
"""

Store new strategy data for future searches

## How it works

1. **Storage**: Agent strategies are converted to vector embeddings using OpenAI embeddings
2. **Database**: FAISS vector database stores embeddings with metadata
3. **Search**: Similarity search finds relevant past strategies for context
4. **Context**: Results help agents make better decisions based on historical data

## Environment Variables

"""
OPENAI_API_KEY=your_openai_api_key
PORT=8080
HOST=0.0.0.0
"""

## Quick Start

### Using Docker

"""
docker compose up --build
"""

### Local Development

"""
pip install -e .
python scripts/api.py
"""

## File Structure

"""
rag-api/
├── src/
│   ├── fetch.py      # Search and retrieval functions
│   └── store.py      # Storage and embedding functions
├── scripts/
│   └── api.py        # FastAPI server
├── pkl/              # FAISS database files
└── requirements.txt
"""

## Usage by VaultGuard

The VaultGuard security agent uses this API to:

- Store learned threat patterns
- Search for similar security scenarios
- Build context for AI analysis
- Improve decision accuracy over time

The API runs on port 8080 and integrates with the main VaultGuard system for background intelligence gathering.
