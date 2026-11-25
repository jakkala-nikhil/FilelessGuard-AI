"""Process collector (Monitor + Extract stages).

Reads every running process with psutil and returns raw records:
  pid, name, parent_name, cmdline, cpu_percent, memory_mb, num_children, chain_depth
"""
import os
import time

import psutil


def _norm(name: str) -> str:
    """On Linux/macOS binaries have no '.exe'; add it so name-based features
    (powershell.exe, winword.exe ...) behave the same during a demo. No-op on Windows."""
    name = name or ""
    if os.name != "nt" and "." not in name:
        return name + ".exe"
    return name


def snapshot(interval: float = 0.4, max_cmd: int = 2000) -> list:
    procs = list(psutil.process_iter())
    for p in procs:                       # prime CPU counters
        try:
            p.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    time.sleep(interval)

    names, ppid_of, children = {}, {}, {}
    rows = []
    for p in procs:
        try:
            with p.oneshot():
                pid, ppid = p.pid, p.ppid()
                name = _norm(p.name())
                try:
                    cmd = " ".join(p.cmdline())[:max_cmd]
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    cmd = ""
                rows.append(dict(pid=pid, ppid=ppid, name=name, cmdline=cmd,
                                 cpu_percent=p.cpu_percent(None),
                                 memory_mb=round(p.memory_info().rss / 1048576, 1)))
                names[pid], ppid_of[pid] = name, ppid
                children[ppid] = children.get(ppid, 0) + 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    for r in rows:
        r["parent_name"] = names.get(r["ppid"], "")
        r["num_children"] = children.get(r["pid"], 0)
        depth, cur, seen = 0, r["pid"], set()
        while cur in ppid_of and cur not in seen and depth < 15:
            seen.add(cur)
            cur = ppid_of[cur]
            depth += 1
        r["chain_depth"] = depth
    return rows
