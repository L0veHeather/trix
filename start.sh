#!/bin/bash
#
# Strix One-Click Launcher
# Starts both the backend server and desktop UI
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "  ╔═══════════════════════════════════════════════════════════╗"
    echo "  ║                                                           ║"
    echo "  ║   🐯 Trix - Autonomous AI Security Agent                 ║"
    echo "  ║                                                           ║"
    echo "  ╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    # Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed."
        exit 1
    fi
    
    # Node.js
    if ! command -v node &> /dev/null; then
        log_error "Node.js is required but not installed."
        exit 1
    fi
    
    # pnpm
    if ! command -v pnpm &> /dev/null; then
        log_warn "pnpm not found, installing..."
        npm install -g pnpm
    fi
    
    log_info "All core dependencies satisfied."
}

check_security_tools() {
    # List of optional security tools
    local tools=("nuclei" "httpx" "ffuf" "katana" "sqlmap")
    local installed=()
    local missing=()
    
    # Check which tools are available
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            installed+=("$tool")
        else
            missing+=("$tool")
        fi
    done
    
    if [ ${#installed[@]} -gt 0 ]; then
        log_info "Security tools available: ${installed[*]}"
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_warn "Optional tools not found: ${missing[*]}"
        log_warn "To install, run: ./start.sh tools"
    fi
}

setup_python_env() {
    log_info "Setting up Python environment..."
    
    # Use Python 3.12 if available, otherwise use system python3
    PYTHON_BIN=""
    if command -v /opt/homebrew/bin/python3.12 &> /dev/null; then
        PYTHON_BIN="/opt/homebrew/bin/python3.12"
    elif command -v python3.12 &> /dev/null; then
        PYTHON_BIN="python3.12"
    else
        PYTHON_BIN="python3"
    fi
    
    log_info "Using Python: $($PYTHON_BIN --version)"
    
    # Check if existing venv is valid (Python executable exists and works)
    VENV_VALID=false
    if [ -d ".venv" ] && [ -f ".venv/bin/python" ]; then
        if .venv/bin/python --version &> /dev/null; then
            VENV_VALID=true
        else
            log_warn "Virtual environment is broken (Python not executable), recreating..."
            rm -rf .venv
        fi
    fi
    
    # Create venv if not exists or was invalid
    if [ "$VENV_VALID" = false ]; then
        log_info "Creating virtual environment..."
        $PYTHON_BIN -m venv .venv
    fi
    
    # Install core dependencies (matching pyproject.toml)
    log_info "Installing Python dependencies..."
    .venv/bin/pip install --upgrade pip -q
    .venv/bin/pip install --timeout 120 -q \
        fastapi uvicorn pydantic httpx litellm sqlalchemy \
        pyyaml rich textual requests aiofiles websockets \
        tenacity openai playwright docker gql \
        xmltodict pyte libtmux jinja2 \
        2>/dev/null || log_warn "Some optional deps may have failed"
    
    # Install playwright browsers (required for browser automation)
    if [ ! -d "$HOME/.cache/ms-playwright" ]; then
        log_info "Installing Playwright browsers (first time only)..."
        .venv/bin/playwright install chromium 2>/dev/null || log_warn "Playwright browser install may have failed"
    fi
    
    log_info "Python dependencies installed."
}

setup_frontend() {
    log_info "Setting up frontend..."
    
    cd desktop
    if [ ! -d "node_modules" ]; then
        pnpm install
    fi
    cd ..
}

start_backend() {
    log_info "Starting backend server on port 8000..."
    
    # Kill existing server if running
    pkill -f "uvicorn trix.server.app:app" 2>/dev/null || true
    
    # Start server in background using venv
    cd "$SCRIPT_DIR"
    mkdir -p logs
    nohup .venv/bin/python -m uvicorn trix.server.app:app --host 0.0.0.0 --port 8000 > logs/backend.log 2>&1 &
    echo $! > .backend.pid
    
    # Wait for server to start
    sleep 3
    
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        log_info "Backend server started successfully."
    else
        log_warn "Backend may still be starting... Check logs/backend.log for details."
    fi
}

start_frontend() {
    log_info "Starting frontend on port 5173..."
    
    cd desktop
    
    # Kill existing dev server if running
    pkill -f "vite" 2>/dev/null || true
    
    # Start frontend in background
    nohup pnpm dev > ../logs/frontend.log 2>&1 &
    echo $! > ../.frontend.pid
    
    cd ..
    
    sleep 3
    log_info "Frontend started successfully."
}

start_tauri() {
    log_info "Starting Tauri desktop app..."
    
    cd desktop
    pnpm tauri:dev
}

open_browser() {
    local url="http://localhost:5173"
    
    sleep 2
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open "$url"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open "$url" 2>/dev/null || true
    fi
    
    log_info "Opened browser at $url"
}

stop_all() {
    log_info "Stopping all services..."
    
    if [ -f .backend.pid ]; then
        kill $(cat .backend.pid) 2>/dev/null || true
        rm .backend.pid
    fi
    
    if [ -f .frontend.pid ]; then
        kill $(cat .frontend.pid) 2>/dev/null || true
        rm .frontend.pid
    fi
    
    pkill -f "uvicorn trix.server.app:app" 2>/dev/null || true
    pkill -f "vite" 2>/dev/null || true
    
    log_info "All services stopped."
}

show_help() {
    echo "Usage: ./start.sh [command]"
    echo ""
    echo "Commands:"
    echo "  dev       Start in development mode (backend + frontend)"
    echo "  desktop   Start Tauri desktop app"
    echo "  backend   Start only the backend server"
    echo "  frontend  Start only the frontend dev server"
    echo "  stop      Stop all services"
    echo "  status    Show service status"
    echo "  tools     Install security tools"
    echo "  help      Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  STRIX_LLM          LLM model to use (default: openai/gpt-4o)"
    echo "  OPENAI_API_KEY     OpenAI API key"
    echo "  ANTHROPIC_API_KEY  Anthropic API key"
}

show_status() {
    echo ""
    echo "Service Status:"
    echo "---------------"
    
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo -e "Backend:  ${GREEN}Running${NC} (http://localhost:8000)"
    else
        echo -e "Backend:  ${RED}Stopped${NC}"
    fi
    
    if curl -s http://localhost:5173 > /dev/null 2>&1; then
        echo -e "Frontend: ${GREEN}Running${NC} (http://localhost:5173)"
    else
        echo -e "Frontend: ${RED}Stopped${NC}"
    fi
    
    echo ""
}

install_tools() {
    log_info "安装安全工具..."
    
    # 优先使用 Homebrew (macOS 最可靠的方式)
    if command -v brew &> /dev/null; then
        log_info "使用 Homebrew 安装工具..."
        
        # ProjectDiscovery 工具 (nuclei, httpx, katana)
        if ! command -v nuclei &> /dev/null; then
            log_info "  安装 nuclei..."
            brew install nuclei 2>/dev/null || log_warn "nuclei 安装失败"
        fi
        
        if ! command -v httpx &> /dev/null; then
            log_info "  安装 httpx..."
            brew install httpx 2>/dev/null || log_warn "httpx 安装失败"
        fi
        
        if ! command -v katana &> /dev/null; then
            log_info "  安装 katana..."
            brew install katana 2>/dev/null || log_warn "katana 安装失败"
        fi
        
        if ! command -v ffuf &> /dev/null; then
            log_info "  安装 ffuf..."
            brew install ffuf 2>/dev/null || log_warn "ffuf 安装失败"
        fi
        
        if ! command -v sqlmap &> /dev/null; then
            log_info "  安装 sqlmap..."
            brew install sqlmap 2>/dev/null || log_warn "sqlmap 安装失败"
        fi
        
        log_info "Homebrew 工具安装完成！"
    else
        log_warn "未找到 Homebrew，请先安装: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        log_info "或者手动下载工具："
        log_info "  nuclei: https://github.com/projectdiscovery/nuclei/releases"
        log_info "  httpx:  https://github.com/projectdiscovery/httpx/releases"
        log_info "  katana: https://github.com/projectdiscovery/katana/releases"
        log_info "  ffuf:   https://github.com/ffuf/ffuf/releases"
        log_info "  sqlmap: pip install sqlmap"
    fi
    
    log_info "工具安装完成。"
}

# Create logs directory
mkdir -p logs

# Main
print_banner

case "${1:-dev}" in
    dev)
        check_dependencies
        check_security_tools
        setup_python_env
        setup_frontend
        start_backend
        start_frontend
        open_browser
        
        echo ""
        log_info "Trix is running!"
        log_info "Backend URL: http://localhost:8000"
        log_info "Frontend URL: http://localhost:5173"
        echo "  📖 Docs:    http://localhost:8000/docs"
        echo ""
        echo "Press Ctrl+C to stop..."
        
        # Wait for interrupt
        trap stop_all EXIT
        wait
        ;;
    desktop)
        check_dependencies
        setup_python_env
        setup_frontend
        start_backend
        start_tauri
        ;;
    backend)
        setup_python_env
        start_backend
        ;;
    frontend)
        setup_frontend
        start_frontend
        open_browser
        ;;
    stop)
        stop_all
        ;;
    status)
        show_status
        ;;
    tools)
        install_tools
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
