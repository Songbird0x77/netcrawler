# NetCrawler — AI Pentesting Agent

An AI-driven reconnaissance and vulnerability scanning agent powered by a local Ollama LLM. The agent reasons about your target, decides which tools to run, interprets their output, and produces a structured report.

---
<img width="1157" height="359" alt="image" src="https://github.com/user-attachments/assets/b3281145-cac3-44fc-a2bb-a266b02387c8" />

## Architecture

```
main.py
├── tui/app.py          — Rich terminal interface
├── agent/
│   ├── loop.py         — Observe → think → act cycle
│   └── ollama.py       — Local LLM reasoning via Ollama
├── core/
│   └── context.py      — Shared scan state
├── modules/
│   ├── passive_recon.py   — Subfinder + theHarvester
│   ├── web_fingerprint.py — WhatWeb + wafw00f
│   ├── port_scan.py       — Nmap
│   ├── vuln_scan.py       — Nuclei
│   └── dir_fuzz.py        — ffuf
└── output/
    └── reporter.py     — Markdown + JSON reports
```

---

## Setup

### 1. Python dependencies
```bash
pip install -r requirements.txt
```

### 2. Ollama (local LLM)
```bash
# Install Ollama: https://ollama.com
ollama pull llama3       # recommended — good reasoning, fast
# alternatives:
ollama pull mistral
ollama pull deepseek-r1:7b

ollama serve             # start the server (runs on :11434)
```

### 3. Recon tools (install what you need)
```bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# theHarvester
pip install theHarvester

# WhatWeb
sudo apt install whatweb   # or: gem install whatweb

# wafw00f
pip install wafw00f

# Nmap
sudo apt install nmap

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# ffuf
go install github.com/ffuf/ffuf/v2@latest
```

---

## Usage

```bash
# Domain / website
python main.py example.com
python main.py https://example.com

# IP address
python main.py 192.168.1.1

# CIDR range
python main.py 192.168.1.0/24

# Choose model
python main.py example.com --model mistral

# Verbose (show raw tool output)
python main.py example.com --verbose
```

---

## How the agent works

1. **Target intake** — normalises IP / domain / URL into `ScanContext`
2. **Ollama reasoning** — LLM receives current state, decides next tool
3. **Tool dispatch** — the chosen module runs, output stored in context
4. **Interpretation** — LLM interprets raw output into human findings
5. **Loop** — repeat until LLM decides scan is complete (max 12 iterations)
6. **Report** — Markdown + JSON saved to `~/netcrawler_reports/`

---

## Adding new modules

1. Create `modules/your_module.py` with signature:
   ```python
   def run_your_module(ctx: ScanContext, status: Callable[[str], None]) -> str:
       ...
   ```
2. Register it in `agent/loop.py`:
   ```python
   TOOL_MAP["your_module"] = run_your_module
   ```
3. Add a description to the system prompt in `agent/ollama.py`

The LLM will automatically learn to use it from the description.

---

## Reports

Reports are saved to `~/netcrawler_reports/<host>_<timestamp>/`:
- `report.md` — human-readable Markdown
- `report.json` — machine-readable, importable to other tools

---

## Legal

This tool is for authorised penetration testing only. Always obtain written permission before scanning any target you do not own.
