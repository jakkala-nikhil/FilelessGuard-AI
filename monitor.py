"""Command-line monitor: Monitor -> Extract -> Analyze -> Alert loop.

Examples:
    python monitor.py --once                 # one scan of the live system
    python monitor.py --simulate --once      # also inject safe simulated events
    python monitor.py --interval 5           # continuous monitoring (Ctrl+C to stop)
    python monitor.py --sysmon --once        # add Sysmon process-creation events (Windows)
"""
import argparse
import time

from src.collector import snapshot
from src.detector import AlertLog, Detector
from src.samples import SIMULATED_EVENTS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=5.0, help="seconds between scans")
    ap.add_argument("--once", action="store_true", help="scan once and exit")
    ap.add_argument("--simulate", action="store_true", help="inject safe simulated suspicious events")
    ap.add_argument("--sysmon", action="store_true", help="also read Sysmon events (Windows)")
    args = ap.parse_args()

    det, alerts = Detector(), AlertLog()
    print("Monitoring started. Press Ctrl+C to stop.\n")
    try:
        while True:
            records = snapshot()
            if args.sysmon:
                from src.sysmon_source import read_recent
                records += read_recent()
            if args.simulate:
                records += SIMULATED_EVENTS
            scored = det.score(records)
            new = alerts.add(scored)
            stamp = time.strftime("%H:%M:%S")
            n_bad = int((scored.verdict != "BENIGN").sum())
            print(f"[{stamp}] scanned {len(scored)} processes | flagged {n_bad} | new alerts {len(new)}")
            for r in new.to_dict("records"):
                print(f"  ALERT [{r['verdict']}] p={r['probability']:.2f} {r['name']} "
                      f"(PID {r['pid']}, parent {r['parent_name']}) -> {r['indicator']}")
            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
