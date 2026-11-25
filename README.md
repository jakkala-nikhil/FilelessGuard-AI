# Intelligent Fileless Malware Detection and Suspicious Process Monitoring System

Capstone project – ITA1438 Ethical Hacking, SIMATS Engineering
Team: Jakkala Nikhil (192312001), Baranidharan V (192312019) | Guide: Gunasundari B

A behaviour-based detector: it watches running processes, extracts behaviour
features (parent–child chain, command line, CPU/memory), classifies each process
with a Random Forest and raises alerts on a Streamlit dashboard.
It is a **defensive** tool. It contains no malware and executes nothing malicious.

## Project structure

| File | Role in the pipeline |
|---|---|
| `src/collector.py` | **Monitor / Extract** – reads processes with psutil (PID, name, parent, CPU, memory, command line) |
| `src/sysmon_source.py` | Optional Sysmon Event ID 1 reader (Windows, Administrator) |
| `src/features.py` | Feature extraction (encoded command, hidden window, Office parent, download cradle, entropy …) |
| `src/data_gen.py` | Synthetic training data for the demo (text records only) |
| `train.py` | Trains the Random Forest, writes metrics, confusion matrix, feature-importance chart |
| `src/detector.py` | **Analyze** (Random Forest verdict) and **Alert** (writes `logs/alerts.csv`) |
| `monitor.py` | Command-line monitor |
| `app.py` | Streamlit dashboard |
| `src/samples.py` | Safe simulated suspicious events for the live demo |
| `tests/` | Unit tests |

## Setup (Windows, Python 3.10+)

```
pip install -r requirements.txt
python train.py
streamlit run app.py
```

Command line alternative: `python monitor.py --simulate --once` or `python monitor.py --interval 5`.
Run tests: `python -m unittest discover tests`.

For Sysmon events, install Sysmon (Microsoft Sysinternals), open an Administrator
prompt and add `--sysmon` to `monitor.py`.

## Demo script for the faculty (about 5 minutes)

1. Show the architecture diagram, then `python train.py` and the metrics.
2. Start `streamlit run app.py`. The *Live processes* tab lists every process with a verdict.
3. Keep **Inject simulated suspicious events** on: Office → PowerShell with an encoded,
   hidden command appears as MALICIOUS with the indicators that fired.
4. Open *Alert history* (also saved in `logs/alerts.csv`) and *Model & evaluation*.
5. Move the threshold sliders to show the false-negative / false-positive trade-off.

## Important: be honest about the results

The bundled model is trained on **synthetic** data, so the displayed accuracy
(about 98 %) only shows that the pipeline works. It is **not** real-world performance.
For your report:

* Train on a real labelled dataset: `python train.py --csv mydata.csv`
  (columns: `name, parent_name, cmdline, cpu_percent, memory_mb, num_children, chain_depth, label`).
* Report the metrics that `train.py` prints for the held-out test set, and state the dataset used.
* Safe testing only: use your own machine or an isolated virtual machine.

## Known limitations

* Accuracy depends on training data; unseen techniques may be missed.
* On Linux/macOS process names are mapped to `.exe` only for demonstration; the tool targets Windows.
* API-call sequences (listed in the slides) are not collected; features use process metadata and command lines.
* `sysmon_source.py` and the Streamlit dashboard were written to run on your Windows machine; the XML parser
  and the rest of the pipeline were tested, the live dashboard UI should be checked on your system.
