"""
Conpot Log Parser
-----------------
Parses Conpot honeypot JSON logs, merges entries by response,
and optionally analyses them with an LLM via OpenRouter.

Usage:
  python parse_conpot.py                  # merged output
  python parse_conpot.py -i               # + per-pattern AI analysis
  python parse_conpot.py -d               # + deep context / campaign analysis
  python parse_conpot.py -i -d -f out.txt # everything, saved to file
"""

import json
import gzip
import glob
import os
import argparse
import urllib.request
from collections import defaultdict
from pathlib import Path


# ── Load .env ─────────────────────────────────────────────────────────────────

def load_env(env_path: str = ".env") -> None:
    """Minimal .env loader — sets os.environ for KEY=VALUE lines."""
    path = Path(env_path)
    if not path.exists():
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


load_env()

OPENROUTER_API_KEY    = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL      = os.environ.get("OPENROUTER_MODEL", "openai/gpt-4o-mini")
OPENROUTER_MODEL_DEEP = os.environ.get("OPENROUTER_MODEL_DEEP", "openai/gpt-4o")
LOG_DIR               = os.environ.get("LOG_DIR", r"C:\Programmieren\logs_honeypot\conpot\log")
LANG                  = os.environ.get("LANG", "de")


# ── Load language file ─────────────────────────────────────────────────────────

def load_lang(lang: str) -> dict:
    """Load the language JSON from the lang/ folder next to this script."""
    script_dir = Path(__file__).parent
    lang_file  = script_dir / "lang" / f"{lang}.json"

    if not lang_file.exists():
        fallback = script_dir / "lang" / "en.json"
        print(f"[WARN] Language '{lang}' not found, falling back to 'en'.")
        lang_file = fallback

    with open(lang_file, encoding="utf-8") as f:
        return json.load(f)


L = load_lang(LANG)
UI = L["ui"]
PROMPTS = L["prompts"]


# ── File reading ───────────────────────────────────────────────────────────────

def read_file(filepath: str) -> list[str]:
    if filepath.endswith(".gz"):
        with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    else:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return f.readlines()


def parse_entries(lines: list[str]) -> list[dict]:
    """Return only log entries that contain a non-empty response."""
    results = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            if entry.get("response"):
                results.append(entry)
        except json.JSONDecodeError:
            pass
    return results


# ── Merging ────────────────────────────────────────────────────────────────────

def merge_entries(all_hits: list[tuple]) -> list[dict]:
    """
    Group entries exclusively by response content.
    Merges source IPs, all requests, timestamps, and source filenames.
    """
    groups = defaultdict(lambda: {
        "ips":        set(),
        "timestamps": [],
        "quellen":    [],
        "event_type": "",
        "data_type":  "",
        "requests":   set(),
        "response":   "",
        "dst_ip":     "",
        "dst_port":   "",
        "sensorid":   "",
    })

    for filename, hits in all_hits:
        for entry in hits:
            key = str(entry.get("response"))
            g   = groups[key]
            g["ips"].add(entry.get("src_ip", "N/A"))
            g["timestamps"].append(entry.get("timestamp", ""))
            g["quellen"].append(filename)
            g["event_type"] = entry.get("event_type", "")
            g["data_type"]  = entry.get("data_type", "")
            if entry.get("request"):
                g["requests"].add(str(entry.get("request")))
            g["response"] = entry.get("response", "")
            g["dst_ip"]   = entry.get("dst_ip", "")
            g["dst_port"] = entry.get("dst_port", "")
            g["sensorid"] = entry.get("sensorid", "")

    return list(groups.values())


# ── OpenRouter ─────────────────────────────────────────────────────────────────

def ki_request(prompt: str, model: str, timeout: int = 60) -> str:
    if not OPENROUTER_API_KEY or OPENROUTER_API_KEY.startswith("sk-or-your"):
        return "[Error] OPENROUTER_API_KEY not set. Check your .env file."

    payload = json.dumps({
        "model":    model,
        "messages": [{"role": "user", "content": prompt}]
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type":  "application/json",
            "HTTP-Referer":  "https://github.com/conpot-parser",
            "X-Title":       "Conpot Log Analyser",
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"[AI Error] {e}"


def analyse_single(group: dict) -> str:
    ips_str  = ", ".join(sorted(group["ips"]))
    ts_first = min(group["timestamps"]) if group["timestamps"] else "N/A"
    ts_last  = max(group["timestamps"]) if group["timestamps"] else "N/A"
    count    = len(group["timestamps"])
    quellen  = ", ".join(sorted(set(group["quellen"])))
    requests = ", ".join(sorted(group.get("requests", set()))) or "none"

    prompt = PROMPTS["analyse_single"].format(
        count      = count,
        ts_first   = ts_first,
        ts_last    = ts_last,
        ips_str    = ips_str,
        quellen    = quellen,
        event_type = group["event_type"],
        data_type  = group["data_type"],
        requests   = requests,
        response   = group["response"],
    )
    return ki_request(prompt, OPENROUTER_MODEL)


def analyse_deep(all_hits: list[tuple], groups: list[dict]) -> str:
    ip_timeline: dict = defaultdict(list)
    for filename, hits in all_hits:
        for entry in hits:
            ip = entry.get("src_ip", "N/A")
            ip_timeline[ip].append({
                "ts":        entry.get("timestamp", ""),
                "event":     entry.get("event_type", ""),
                "data_type": entry.get("data_type", ""),
                "request":   str(entry.get("request", "")),
                "dst_port":  entry.get("dst_port", ""),
                "file":      filename,
            })

    ip_blocks = []
    for ip, events in sorted(ip_timeline.items()):
        events_sorted = sorted(events, key=lambda e: e["ts"])
        lines = [f"  IP: {ip}  ({len(events)} events)"]
        for ev in events_sorted:
            lines.append(
                f"    [{ev['ts']}] {ev['event']} | Port {ev['dst_port']} | "
                f"Type: {ev['data_type']} | Request: {ev['request'][:60]}"
            )
        ip_blocks.append("\n".join(lines))

    pattern_lines = []
    for i, g in enumerate(groups, 1):
        pattern_lines.append(
            f"  Pattern {i}: {len(g['timestamps'])}x | IPs: {', '.join(sorted(g['ips']))} | "
            f"Type: {g['data_type']} | Requests: {', '.join(sorted(g['requests'])) or 'none'}"
        )

    prompt = PROMPTS["analyse_deep"].format(
        total_events    = sum(len(h) for _, h in all_hits),
        unique_ips      = len(ip_timeline),
        unique_patterns = len(groups),
        ip_summary      = "\n\n".join(ip_blocks),
        pattern_summary = "\n".join(pattern_lines),
    )
    return ki_request(prompt, OPENROUTER_MODEL_DEEP, timeout=120)


# ── Output ─────────────────────────────────────────────────────────────────────

def print_groups(groups: list[dict], out, interpret: bool) -> None:
    for i, group in enumerate(groups, 1):
        ips_str  = ", ".join(sorted(group["ips"]))
        ts_first = min(group["timestamps"]) if group["timestamps"] else "N/A"
        ts_last  = max(group["timestamps"]) if group["timestamps"] else "N/A"
        count    = len(group["timestamps"])
        quellen  = ", ".join(sorted(set(group["quellen"])))

        out(f"\n{'─'*70}")
        out(f"  {UI['pattern_header'].format(i=i, total=len(groups), count=count)}")
        out(f"{'─'*70}")
        out(f"  {UI['first_hit']:<15}: {ts_first}")
        out(f"  {UI['last_hit']:<15}: {ts_last}")
        out(f"  {UI['source_ips']:<15}: {ips_str}  ({len(group['ips'])} {UI['unique']})")
        out(f"  {UI['source_files']:<15}: {quellen}")
        out(f"  {UI['sensor']:<15}: {group['sensorid']}")
        out(f"  {UI['event']:<15}: {group['event_type']}")
        out(f"  {UI['data_type']:<15}: {group['data_type']}")
        out(f"  {UI['target']:<15}: {group['dst_ip']}:{group['dst_port']}")

        requests = group.get("requests", set())
        if requests:
            out(f"  {UI['requests']:<15}: ({len(requests)} {UI['unique']})")
            for req in sorted(requests):
                out(f"                   {req}")

        out(f"  {UI['response']:<15}:")
        for line in str(group["response"]).splitlines():
            out(f"                 {line}")

        if interpret:
            print(f"  {UI['ki_analysing'].format(i=i, total=len(groups))}", end="\r")
            result = analyse_single(group)
            out(f"\n  ┌─ {UI['ki_header']} {'─'*49}")
            ki_fields = UI.get("ki_fields", {})
            for line in result.splitlines():
                line = line.strip()
                if not line:
                    continue
                matched = False
                for keyword, icon in ki_fields.items():
                    if line.startswith(keyword):
                        out(f"  │  {icon} {line}")
                        matched = True
                        break
                if not matched:
                    out(f"  │  {line}")
            out(f"  └{'─'*63}")


def print_deep(result: str, out) -> None:
    out(f"\n{'═'*70}")
    out(f"  🔍 {UI['deep_header'].format(model=OPENROUTER_MODEL_DEEP)}")
    out(f"{'═'*70}")

    section_icons = UI.get("deep_sections", {})

    for line in result.splitlines():
        stripped = line.strip()
        if not stripped:
            out()
            continue
        matched = False
        for keyword, icon in section_icons.items():
            if stripped.upper().startswith(keyword.upper()):
                out(f"\n  {icon}  {stripped}")
                matched = True
                break
        if not matched:
            out(f"  {line}")

    out(f"\n{'═'*70}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Conpot Log Parser – merged honeypot log analysis with optional LLM"
    )
    parser.add_argument("-f", "--file",      metavar="FILE",
                        help="Also write output to a file")
    parser.add_argument("-i", "--interpret", action="store_true",
                        help="Analyse each pattern with LLM via OpenRouter")
    parser.add_argument("-d", "--deep",      action="store_true",
                        help="Deep context: send all data to LLM for campaign/IP correlation analysis")
    args = parser.parse_args()

    outfile = open(args.file, "w", encoding="utf-8") if args.file else None

    def out(text: str = "") -> None:
        print(text)
        if outfile:
            outfile.write(text + "\n")

    # ── Find and read log files ────────────────────────────────────────────────
    patterns = [
        os.path.join(LOG_DIR, "*.json"),
        os.path.join(LOG_DIR, "*.json.*.gz"),
    ]
    files = []
    for pattern in patterns:
        files.extend(glob.glob(pattern))

    if not files:
        out(UI["no_files_found"].format(log_dir=LOG_DIR))
        if outfile:
            outfile.close()
        return

    files.sort()
    all_hits = []

    for filepath in files:
        filename = os.path.basename(filepath)
        try:
            lines = read_file(filepath)
            hits  = parse_entries(lines)
            if hits:
                all_hits.append((filename, hits))
        except Exception as e:
            out(UI["file_error"].format(filename=filename, error=e))

    if not all_hits:
        out(UI["no_hits"])
        if outfile:
            outfile.close()
        return

    # ── Merge & print ──────────────────────────────────────────────────────────
    total  = sum(len(h) for _, h in all_hits)
    groups = merge_entries(all_hits)

    flags = []
    if args.interpret:
        flags.append(UI["flag_interpret"])
    if args.deep:
        flags.append(UI["flag_deep"])
    flag_str = f"  [{' + '.join(flags)}]" if flags else ""

    out(f"{'='*70}")
    out(f"  {UI['header_found'].format(total=total, groups=len(groups), flags=flag_str)}")
    out(f"  {UI['header_merged']}")
    out(f"{'='*70}")

    print_groups(groups, out, args.interpret)

    suffix = UI["footer_analysed"].format(groups=len(groups)) if args.interpret else ""
    out(f"\n{'='*70}")
    out(f"  {UI['footer'].format(total=total, groups=len(groups), suffix=suffix)}")
    out(f"{'='*70}")

    # ── Deep context ───────────────────────────────────────────────────────────
    if args.deep:
        print(f"\n  {UI['deep_running']}", end="\r")
        result = analyse_deep(all_hits, groups)
        print_deep(result, out)

    if outfile:
        outfile.close()
        print(f"\n{UI['saved_to'].format(file=args.file)}")


if __name__ == "__main__":
    main()
