# Conpot Log Analyser

A command-line tool for parsing, merging, and AI-analysing [Conpot](https://github.com/mushorg/conpot) honeypot logs. Entries are automatically deduplicated by response, source IPs are consolidated, and optional LLM-powered analysis via [OpenRouter](https://openrouter.ai) can identify individual attack patterns or full campaign correlations. \
Yes this was vibe-coded and yes it wasnt orrigenally intended to be used by someone other than myself. I use it for my [tpotce](https://github.com/telekom-security/tpotce) logs.

---

## Features

- Reads plain `.json` and compressed `.json.gz` Conpot log files
- Merges entries **by response** — all IPs and requests that produced the same response are grouped
- Optional **per-pattern AI analysis** (`-i`) with a structured, consistent output schema
- Optional **deep context analysis** (`-d`) — sends the full timeline to a stronger model to detect campaigns, correlate IPs, and assess overall risk
- Output to console and/or file (`-f`)
- Fully localised UI and LLM prompts (`de` / `en`, easily extensible)
- Pure Python

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/GomorrhaDev/ConpotLogAnalyser.git
cd ConpotLogAnalyser
```

### 2. Configure environment

```bash
cp .env.example .env
```

Then open `.env` and fill in your values:

```env
OPENROUTER_API_KEY=sk-or-your-key-here
OPENROUTER_MODEL=inception/mercury-2
OPENROUTER_MODEL_DEEP=minimax/minimax-m2.7
LOG_DIR=blabla
LANG=en
```

Get a OpenRouter API key at [openrouter.ai/keys](https://openrouter.ai/keys).

### 3. Run

No `pip install` required.

```bash
python parse_conpot.py
```

---

## Usage

```
python parse_conpot.py [OPTIONS]
```

| Flag | Description |
|------|-------------|
| *(none)* | Parse and display merged log entries |
| `-i` / `--interpret` | Analyse each pattern with LLM (uses `OPENROUTER_MODEL`) |
| `-d` / `--deep` | Deep context: full campaign & IP correlation analysis (uses `OPENROUTER_MODEL_DEEP`) |
| `-f FILE` / `--file FILE` | Also write output to a file |

### Examples

```bash
# Basic merged output
python parse_conpot.py

# Per-pattern AI analysis
python parse_conpot.py -i

# Deep correlation analysis
python parse_conpot.py -d

# Full analysis, saved to report
python parse_conpot.py -i -d -f report.txt
```
---

## Output

### Merged pattern block

```
──────────────────────────────────────────────────────────────────────
  Pattern 1/2  –  observed 3x
──────────────────────────────────────────────────────────────────────
  First seen   : 2026-04-05T00:59:02
  Last seen    : 2026-04-05T02:56:22
  Source IPs   : 71.6.199.23, 204.48.25.130  (2 unique)
  Source files : conpot_guardian_ast.json, conpot_guardian_ast.json.1.gz
  Requests     : (2 unique)
                 b'\x01I20100'
                 b'\x01I20100\n'
  Response     :
                 I20100
                 04/05/2026 00:59
                 ...
```

### AI analysis block (`-i`)

```
  ┌─ AI Analysis ─────────────────────────────────────────────────────
  │  🔵 ACTION   : The command I20100 was sent via the Guardian-AST protocol.
  │  🎯 GOAL     : Reading tank inventory data from a fuel management system.
  │  📋 FINDING  : The response reveals an AVIA gas station system with 4 fuel tanks.
  │  🌐 IPs      : Coordinated – two IPs sent the same command 2 hours apart.
  │  ⚠️  RISK     : HIGH – unauthorized access to fuel infrastructure would be dangerous in real time.
  └───────────────────────────────────────────────────────────────────
```

### Deep context block (`-d`)

```
══════════════════════════════════════════════════════════════════════
  🔍 DEEP CONTEXT ANALYSIS  (Model: openai/gpt-4o)
══════════════════════════════════════════════════════════════════════

  🎯  CAMPAIGNS:
    - Two IPs executed the same ATG query within a short time frame ...

  🌐  IP PROFILES:
    - 71.6.199.23: targeted attacker – structured protocol commands, no port scan pattern
    - 147.185.132.204: scanner – connects and disconnects without sending commands

  🕐  TIME PATTERNS:
    - Activity is concentrated during nighttime hours (00:59–02:58 UTC) ...

  🔗  CORRELATIONS:
    - The IP ranges 71.6.x and 204.48.x may belong to the same scanning campaign ...

  ⚠️   OVERALL RISK : HIGH – multiple IPs with protocol knowledge active

  💡  RECOMMENDATIONS:
    - Do not expose port 10001 publicly
    - Block source IPs via firewall
```
---
## Localisation

UI labels and LLM prompts are stored in `lang/`:

```
lang/
  de.json   ← Deutsch 
  en.json   ← English (Default)
```

To add a new language, copy `lang/en.json`, translate both the `ui` and `prompts` sections, and set `LANG=xx` in your `.env`.

---

## Project structure

```
conpot-parser/
├── parse_conpot.py     ← main script
├── .env                ← your local config (not committed)
├── .env.example        ← template
├── .gitignore
├── README.md
└── lang/
    ├── de.json         ← German UI + prompts
    └── en.json         ← English UI + prompts
```

---

## Requirements

- Python 3.9+
- No external packages (uses only stdlib: `json`, `gzip`, `glob`, `os`, `argparse`, `urllib`)
- An [OpenRouter](https://openrouter.ai) API key (only needed for `-i` and `-d`)

---

## License

MIT
