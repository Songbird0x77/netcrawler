#!/usr/bin/env bash
set -e
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }

echo -e "${CYAN}NetCrawler Setup${NC}"
echo "=========================="

info "Creating Python virtual environment..."
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip -q
pip install rich typer wafw00f -q
success "Python dependencies installed"

info "Installing system tools..."
sudo apt-get update -qq
sudo apt-get install -y -qq nmap whatweb dnsutils curl git golang-go
success "System tools installed"

info "Installing theHarvester..."
pip install theHarvester -q 2>/dev/null || warning "theHarvester install failed — install manually"

if command -v go &>/dev/null; then
    info "Installing Go tools..."
    export PATH=$PATH:~/go/bin
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && success "Subfinder installed" || warning "Subfinder failed"
    go install github.com/ffuf/ffuf/v2@latest 2>/dev/null && success "ffuf installed" || warning "ffuf failed"
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && success "Nuclei installed" || warning "Nuclei failed"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null && success "httpx installed" || warning "httpx failed"
    grep -q 'go/bin' ~/.bashrc || echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
    nuclei -update-templates -silent 2>/dev/null && success "Nuclei templates updated" || warning "Nuclei template update failed"
else
    warning "Go not found — skipping Go tools. Install: sudo apt install golang-go"
fi

info "Checking Ollama..."
if curl -s "http://localhost:11434/api/tags" &>/dev/null; then
    success "Ollama is running"
else
    warning "Ollama not detected — install from https://ollama.com"
    warning "Then run: ollama pull deepseek-r1:14b"
fi

echo ""
echo -e "${GREEN}Setup complete!${NC}"
echo "  source .venv/bin/activate"
echo "  python3 main.py example.com"
