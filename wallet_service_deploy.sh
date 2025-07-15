#!/bin/bash

# VaultGuard Wallet Service Deployment Script - Windows Compatible
# Creates and manages isolated wallet provider security services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICES_DIR="$SCRIPT_DIR/services"
LOGS_DIR="$SCRIPT_DIR/logs"

# Ensure required directories exist
mkdir -p "$SERVICES_DIR" "$LOGS_DIR"

show_usage() {
    echo -e "${BLUE}VaultGuard Wallet Service Manager${NC}"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  create <wallet_name>     Create new wallet service"
    echo "  start <wallet_name>      Start existing wallet service"
    echo "  stop <wallet_name>       Stop running wallet service"
    echo "  status                   Show all services status"
    echo "  logs <wallet_name>       Show logs for service"
    echo "  remove <wallet_name>     Remove service completely"
    echo ""
    echo "Examples:"
    echo "  $0 create phantom        # Create Phantom wallet service"
    echo "  $0 start phantom         # Start Phantom service"
    echo "  $0 status               # Show all services"
}

check_dependencies() {
    echo -e "${BLUE}🔍 Checking dependencies...${NC}"
    
    # Check Python
    if ! command -v python &> /dev/null; then
        echo -e "${RED}❌ Python not found${NC}"
        exit 1
    fi
    
    # Check if in VaultGuard directory
    if [ ! -f "agent/scripts/starter.py" ]; then
        echo -e "${RED}❌ Please run from VaultGuard root directory${NC}"
        exit 1
    fi
    
    # Check virtual environment (Windows compatible)
    if [ ! -d "venv" ] && [ ! -d "agent-venv" ] && [ ! -d ".venv" ]; then
        echo -e "${YELLOW}⚠️ Virtual environment not found. Run bootstrap.sh first${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Dependencies OK${NC}"
}

activate_venv() {
    # Windows-compatible virtual environment activation
    if [ -d "venv" ]; then
        if [ -f "venv/Scripts/activate" ]; then
            # Windows venv
            source venv/Scripts/activate
        elif [ -f "venv/bin/activate" ]; then
            # Linux venv
            source venv/bin/activate
        fi
    elif [ -d "agent-venv" ]; then
        if [ -f "agent-venv/Scripts/activate" ]; then
            # Windows agent-venv
            source agent-venv/Scripts/activate
        elif [ -f "agent-venv/bin/activate" ]; then
            # Linux agent-venv
            source agent-venv/bin/activate
        fi
    elif [ -d ".venv" ]; then
        if [ -f ".venv/Scripts/activate" ]; then
            # Windows .venv
            source .venv/Scripts/activate
        elif [ -f ".venv/bin/activate" ]; then
            # Linux .venv
            source .venv/bin/activate
        fi
    else
        echo -e "${RED}❌ No virtual environment found${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Virtual environment activated${NC}"
}

create_service() {
    local wallet_name="$1"
    
    if [ -z "$wallet_name" ]; then
        echo -e "${RED}❌ Wallet name required${NC}"
        show_usage
        exit 1
    fi
    
    echo -e "${BLUE}🏗️ Creating $wallet_name security service...${NC}"
    
    activate_venv
    
    # Check if wallet_service_template.py exists
    if [ ! -f "agent/wallet_service_template.py" ]; then
        echo -e "${RED}❌ wallet_service_template.py not found in agent/ directory${NC}"
        echo -e "${YELLOW}Please create agent/wallet_service_template.py first${NC}"
        exit 1
    fi
    
    # Create service using template
    cd agent
    
    echo -e "${YELLOW}Running Python service generator...${NC}"
    python -c "
import asyncio
import sys
import os
sys.path.append('.')

try:
    from wallet_service_template import WalletServiceGenerator
    
    async def create():
        generator = WalletServiceGenerator()
        await generator.create_wallet_service('$wallet_name')
        print('✅ Service created successfully!')
    
    asyncio.run(create())
    
except ImportError as e:
    print(f'❌ Import error: {e}')
    print('Make sure wallet_service_template.py exists and has no syntax errors')
    sys.exit(1)
except Exception as e:
    print(f'❌ Error creating service: {e}')
    sys.exit(1)
"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ $wallet_name security service created successfully!${NC}"
        echo -e "${YELLOW}📁 Service directory: services/$wallet_name/${NC}"
        echo -e "${YELLOW}🗄️ Database: db/${wallet_name}_security.db${NC}"
        echo -e "${YELLOW}🚀 Start with: $0 start $wallet_name${NC}"
    else
        echo -e "${RED}❌ Failed to create $wallet_name service${NC}"
        exit 1
    fi
}

start_service() {
    local wallet_name="$1"
    
    if [ -z "$wallet_name" ]; then
        echo -e "${RED}❌ Wallet name required${NC}"
        show_usage
        exit 1
    fi
    
    local service_dir="$SERVICES_DIR/$wallet_name"
    
    if [ ! -d "$service_dir" ]; then
        echo -e "${RED}❌ Service for $wallet_name not found. Create it first with: $0 create $wallet_name${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}🚀 Starting $wallet_name security service...${NC}"
    
    activate_venv
    
    # Check if service is already running
    local pid_file="$service_dir/${wallet_name}.pid"
    if [ -f "$pid_file" ]; then
        local existing_pid=$(cat "$pid_file")
        if tasklist //FI "PID eq $existing_pid" 2>/dev/null | grep -q "$existing_pid"; then
            echo -e "${YELLOW}⚠️ Service already running (PID: $existing_pid)${NC}"
            exit 1
        else
            # Clean up stale PID file
            rm -f "$pid_file"
        fi
    fi
    
    # Start service in background (Windows compatible)
    cd agent
    
    # For Windows, we'll use a different approach to run in background
    python -c "
import asyncio
import sys
import os
sys.path.append('.')

try:
    from wallet_service_template import WalletServiceGenerator
    
    async def start():
        generator = WalletServiceGenerator()
        print('🚀 Starting $wallet_name service...')
        await generator.start_service('$wallet_name')
    
    asyncio.run(start())
    
except Exception as e:
    print(f'❌ Error starting service: {e}')
    sys.exit(1)
" > "$LOGS_DIR/${wallet_name}.log" 2>&1 &
    
    local service_pid=$!
    echo $service_pid > "$pid_file"
    
    # Wait a moment and check if service started successfully
    sleep 3
    if tasklist //FI "PID eq $service_pid" 2>/dev/null | grep -q "$service_pid"; then
        local config_file="$service_dir/${wallet_name}_config.json"
        if [ -f "$config_file" ]; then
            local port=$(python -c "import json; print(json.load(open('$config_file'))['api_config']['port'])" 2>/dev/null || echo "8001")
        else
            local port="8001"
        fi
        
        echo -e "${GREEN}✅ $wallet_name security service started!${NC}"
        echo -e "${YELLOW}🌐 API: http://localhost:$port/api/v1/$wallet_name/health${NC}"
        echo -e "${YELLOW}📊 Status: $0 status${NC}"
        echo -e "${YELLOW}📝 Logs: $0 logs $wallet_name${NC}"
    else
        echo -e "${RED}❌ Failed to start $wallet_name service${NC}"
        echo -e "${YELLOW}📝 Check logs: $0 logs $wallet_name${NC}"
        rm -f "$pid_file"
        exit 1
    fi
}

stop_service() {
    local wallet_name="$1"
    
    if [ -z "$wallet_name" ]; then
        echo -e "${RED}❌ Wallet name required${NC}"
        show_usage
        exit 1
    fi
    
    local service_dir="$SERVICES_DIR/$wallet_name"
    local pid_file="$service_dir/${wallet_name}.pid"
    
    if [ ! -f "$pid_file" ]; then
        echo -e "${YELLOW}⚠️ Service $wallet_name not running${NC}"
        exit 1
    fi
    
    local pid=$(cat "$pid_file")
    
    echo -e "${BLUE}🛑 Stopping $wallet_name security service...${NC}"
    
    # Windows-compatible process termination
    if tasklist //FI "PID eq $pid" 2>/dev/null | grep -q "$pid"; then
        taskkill //PID $pid //F 2>/dev/null
        echo -e "${GREEN}✅ $wallet_name service stopped${NC}"
        rm -f "$pid_file"
    else
        echo -e "${YELLOW}⚠️ Service process not found, cleaning up PID file${NC}"
        rm -f "$pid_file"
    fi
}

show_status() {
    echo -e "${BLUE}📊 VaultGuard Services Status${NC}"
    echo ""
    
    if [ ! -d "$SERVICES_DIR" ] || [ -z "$(ls -A $SERVICES_DIR 2>/dev/null)" ]; then
        echo -e "${YELLOW}No services created yet${NC}"
        echo "Create a service with: $0 create <wallet_name>"
        return
    fi
    
    printf "%-12s %-8s %-6s %-25s %s\n" "SERVICE" "STATUS" "PORT" "API ENDPOINT" "PID"
    echo "────────────────────────────────────────────────────────────────────────"
    
    for service_dir in "$SERVICES_DIR"/*; do
        if [ -d "$service_dir" ]; then
            local wallet_name=$(basename "$service_dir")
            local config_file="$service_dir/${wallet_name}_config.json"
            local pid_file="$service_dir/${wallet_name}.pid"
            
            if [ -f "$config_file" ]; then
                local port=$(python -c "import json; print(json.load(open('$config_file'))['api_config']['port'])" 2>/dev/null || echo "N/A")
                local endpoint="localhost:$port/api/v1/$wallet_name"
                local status="STOPPED"
                local pid="N/A"
                
                if [ -f "$pid_file" ]; then
                    local service_pid=$(cat "$pid_file")
                    if tasklist //FI "PID eq $service_pid" 2>/dev/null | grep -q "$service_pid"; then
                        status="RUNNING"
                        pid="$service_pid"
                    else
                        rm -f "$pid_file"  # Clean up stale PID file
                    fi
                fi
                
                printf "%-12s %-8s %-6s %-25s %s\n" "$wallet_name" "$status" "$port" "$endpoint" "$pid"
            fi
        fi
    done
}

show_logs() {
    local wallet_name="$1"
    
    if [ -z "$wallet_name" ]; then
        echo -e "${RED}❌ Wallet name required${NC}"
        show_usage
        exit 1
    fi
    
    local log_file="$LOGS_DIR/${wallet_name}.log"
    
    if [ ! -f "$log_file" ]; then
        echo -e "${YELLOW}⚠️ No logs found for $wallet_name service${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}📝 Logs for $wallet_name service${NC}"
    echo "────────────────────────────────────────────"
    
    # Windows-compatible tail equivalent
    if command -v tail &> /dev/null; then
        tail -f "$log_file"
    else
        # Fallback for Windows without tail
        echo "Showing last 20 lines of log file:"
        cat "$log_file" | tail -20
    fi
}

remove_service() {
    local wallet_name="$1"
    
    if [ -z "$wallet_name" ]; then
        echo -e "${RED}❌ Wallet name required${NC}"
        show_usage
        exit 1
    fi
    
    local service_dir="$SERVICES_DIR/$wallet_name"
    
    if [ ! -d "$service_dir" ]; then
        echo -e "${YELLOW}⚠️ Service $wallet_name not found${NC}"
        exit 1
    fi
    
    # Stop service if running
    local pid_file="$service_dir/${wallet_name}.pid"
    if [ -f "$pid_file" ]; then
        echo -e "${YELLOW}🛑 Stopping service first...${NC}"
        stop_service "$wallet_name"
    fi
    
    echo -e "${BLUE}🗑️ Removing $wallet_name security service...${NC}"
    
    # Ask for confirmation
    read -p "Are you sure you want to remove $wallet_name service? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}❌ Cancelled${NC}"
        exit 1
    fi
    
    # Remove service directory
    rm -rf "$service_dir"
    
    # Remove database
    local db_file="db/${wallet_name}_security.db"
    if [ -f "$db_file" ]; then
        rm -f "$db_file"
        echo -e "${GREEN}🗄️ Database removed${NC}"
    fi
    
    # Remove logs
    local log_file="$LOGS_DIR/${wallet_name}.log"
    if [ -f "$log_file" ]; then
        rm -f "$log_file"
        echo -e "${GREEN}📝 Logs removed${NC}"
    fi
    
    echo -e "${GREEN}✅ $wallet_name service removed completely${NC}"
}

# Main command handling
case "$1" in
    create)
        check_dependencies
        create_service "$2"
        ;;
    start)
        check_dependencies
        start_service "$2"
        ;;
    stop)
        stop_service "$2"
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "$2"
        ;;
    remove)
        remove_service "$2"
        ;;
    *)
        show_usage
        exit 1
        ;;
esac