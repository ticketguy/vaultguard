#!/bin/bash

echo "🏗️ Initializing VaultGuard directory structure..."

# Create required directories
mkdir -p db
mkdir -p cache  
mkdir -p temp
mkdir -p pkl
mkdir -p logs

# Set proper permissions
chmod -R 755 db cache temp pkl logs

echo "✅ Directory structure created:"
echo "   📁 db/     - Database files"
echo "   📁 cache/  - EdgeLearning cache"  
echo "   📁 temp/   - Temporary files"
echo "   📁 pkl/    - Pickle files"
echo "   📁 logs/   - Log files"

echo ""
echo "🚀 Ready to start VaultGuard!"
echo "   python scripts/starter.py"