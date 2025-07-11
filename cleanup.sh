#!/bin/bash

echo "🧹 VaultGuard Cache Cleanup Script"
echo "=================================="

# Stop any running processes
echo "1. Stopping any running VaultGuard processes..."
pkill -f "python scripts/starter.py" 2>/dev/null || true
pkill -f "python scripts/api.py" 2>/dev/null || true

# Navigate to project root
cd "$(dirname "$0")"

echo "2. Clearing EdgeLearningEngine cache..."
# Clear agent cache
cd agent 2>/dev/null || true
rm -rf cache/ pkl/ *.pkl *.cache temp/ tmp/ 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

echo "3. Clearing database files..."
rm -rf db/ *.db *.sqlite 2>/dev/null || true

echo "4. Clearing RAG API cache..."
cd ../rag-api 2>/dev/null || true
rm -rf pkl/ cache/ *.pkl temp/ tmp/ 2>/dev/null || true

echo "5. Clearing container volumes (if any)..."
cd .. 2>/dev/null || true
docker system prune -f 2>/dev/null || true
docker volume prune -f 2>/dev/null || true

echo "6. Clearing Python cache..."
find . -name "*.pyc" -delete 2>/dev/null || true
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

echo ""
echo "✅ Cache cleanup complete!"
echo ""
echo "🚀 To restart VaultGuard:"
echo "   cd agent"
echo "   python scripts/starter.py"
echo ""
echo "📊 To start RAG API (if needed):"
echo "   cd rag-api" 
echo "   python scripts/api.py"