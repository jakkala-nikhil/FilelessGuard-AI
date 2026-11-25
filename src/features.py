"""Feature extraction: turns one raw process record into numeric behaviour features.

A raw record is a dict with:
  name, parent_name, cmdline, cpu_percent, memory_mb, num_children, chain_depth
The same function is used for training and for live monitoring, so the model
always sees identical features.
"""
import math
import re
from collections import Counter

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe"}
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "cmd.exe", "wmic.exe", "rundll32.exe", "regsvr32.exe"}
POWERSHELL = {"powershell.exe", "pwsh.exe"}

RE_ENC = re.compile(r"(\s-(e|ec|en|enc|enco|encod\w*)\s+[A-Za-z0-9+/=]{8,})|-encodedcommand", re.I)
RE_HIDDEN = re.compile(r"-w(indowstyle)?\s+hidden|-win\s+hidden", re.I)
RE_BYPASS = re.compile(r"-ep\s+bypass|-executionpolicy\s+bypass|-exec\s+bypass", re.I)
RE_NOPROFILE = re.compile(r"\s-nop(rofile)?\b", re.I)
RE_CRADLE = re.compile(r"\biex\b|invoke-expression|downloadstring|downloadfile|invoke-webrequest|"
                       r"net\.webclient|frombase64string|reflection\.assembly", re.I)
RE_B64 = re.compile(r"[A-Za-z0-9+/=]{40,}")

FEATURES = [
    "is_powershell", "is_script_host", "parent_is_office", "parent_is_script_host",
    "cmd_len", "has_encoded_cmd", "hidden_window", "bypass_policy", "no_profile",
    "download_cradle", "longest_b64_blob", "cmd_entropy",
    "cpu_percent", "memory_mb", "num_children", "chain_depth",
]

# Human-readable text for the alert "indicator" column.
INDICATOR_TEXT = {
    "parent_is_office": "Office program spawned a child process",
    "has_encoded_cmd": "Encoded command-line",
    "hidden_window": "Hidden window requested",
    "bypass_policy": "Execution policy bypass",
    "no_profile": "Profile loading skipped (-NoProfile)",
    "download_cradle": "In-memory download/execute pattern",
    "longest_b64_blob": "Long Base64-like blob in command line",
    "parent_is_script_host": "Launched by a script host",
}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def extract_features(rec: dict) -> dict:
    name = str(rec.get("name", "")).lower()
    parent = str(rec.get("parent_name", "")).lower()
    cmd = str(rec.get("cmdline", "") or "")
    blobs = RE_B64.findall(cmd)
    return {
        "is_powershell": int(name in POWERSHELL),
        "is_script_host": int(name in SCRIPT_HOSTS),
        "parent_is_office": int(parent in OFFICE),
        "parent_is_script_host": int(parent in SCRIPT_HOSTS),
        "cmd_len": len(cmd),
        "has_encoded_cmd": int(bool(RE_ENC.search(cmd))),
        "hidden_window": int(bool(RE_HIDDEN.search(cmd))),
        "bypass_policy": int(bool(RE_BYPASS.search(cmd))),
        "no_profile": int(bool(RE_NOPROFILE.search(cmd))),
        "download_cradle": int(bool(RE_CRADLE.search(cmd))),
        "longest_b64_blob": max((len(b) for b in blobs), default=0),
        "cmd_entropy": round(_entropy(cmd), 3),
        "cpu_percent": float(rec.get("cpu_percent", 0) or 0),
        "memory_mb": float(rec.get("memory_mb", 0) or 0),
        "num_children": int(rec.get("num_children", 0) or 0),
        "chain_depth": int(rec.get("chain_depth", 0) or 0),
    }


def reasons(feats: dict) -> list:
    """Rule-based explanation shown next to an alert (which indicators fired)."""
    out = []
    for key, text in INDICATOR_TEXT.items():
        v = feats.get(key, 0)
        if (key == "longest_b64_blob" and v >= 40) or (key != "longest_b64_blob" and v):
            out.append(text)
    return out
