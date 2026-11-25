"""Optional Sysmon source (Windows only).

Reads recent Sysmon 'Process Create' events (Event ID 1) with the built-in
wevtutil tool and converts them to the same raw records the collector produces.
Needs Sysmon installed and an elevated (Administrator) prompt.
"""
import os
import subprocess
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _base(path: str) -> str:
    return (path or "").replace("/", "\\").split("\\")[-1]


def parse_events(xml_text: str) -> list:
    """Parse wevtutil XML output (one <Event> per element) into raw records."""
    wrapped = f"<Events>{xml_text}</Events>"
    records = []
    for ev in ET.fromstring(wrapped).iter(f"{NS}Event"):
        data = {d.get("Name"): (d.text or "") for d in ev.iter(f"{NS}Data")}
        records.append(dict(
            pid=int(data.get("ProcessId", 0) or 0),
            name=_base(data.get("Image")),
            parent_name=_base(data.get("ParentImage")),
            cmdline=data.get("CommandLine", ""),
            cpu_percent=0.0, memory_mb=0.0, num_children=0, chain_depth=2,
        ))
    return records


def read_recent(count: int = 50) -> list:
    if os.name != "nt":
        raise RuntimeError("Sysmon source is only available on Windows.")
    cmd = ["wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
           "/q:*[System[(EventID=1)]]", f"/c:{count}", "/rd:true", "/f:xml"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return parse_events(out)
