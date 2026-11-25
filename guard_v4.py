"""Local research helpers. No execution of sampled commands."""
import os, subprocess, json
from datetime import datetime
from pathlib import Path

def hybrid(result, records):
    from src.features import extract_features
    by_pid={r['pid']:r for r in records}
    result=result.copy()
    result['model_verdict']=result.verdict
    for i,r in result.iterrows():
        f=extract_features(by_pid[r.pid]); strong=[]
        for key,label in [('has_encoded_cmd','Encoded command'),('download_cradle','Download/execute pattern'),('bypass_policy','Policy bypass'),('hidden_window','Hidden window')]:
            if f['is_script_host'] and f[key]: strong.append(label)
        if f['parent_is_office'] and f['is_script_host']: strong.append('Office launched script host')
        p=r.probability
        verdict='MALICIOUS' if p>=.8 and len(strong)>=2 else 'SUSPICIOUS' if p>=.5 or strong else 'BENIGN'
        result.at[i,'verdict']=verdict
        result.at[i,'indicator']=('; '.join(strong) if strong else 'Model score only; no corroborating rule') if verdict!='BENIGN' else 'Low model score; no corroborating rule'
    return result

def save_event(df):
    p=Path('logs/guard_v4_history.jsonl'); p.parent.mkdir(exist_ok=True)
    event={'Time':datetime.now().isoformat(timespec='seconds'),'Needs review':int((df.verdict=='SUSPICIOUS').sum()),'High risk':int((df.verdict=='MALICIOUS').sum()),'Checked':len(df)}
    with p.open('a',encoding='utf8') as f: f.write(json.dumps(event)+'\n')

def history():
    p=Path('logs/guard_v4_history.jsonl')
    if not p.exists(): return []
    return [json.loads(x) for x in p.read_text(encoding='utf8').splitlines() if x.strip()][-200:]

def publisher(pid):
    if os.name!='nt': return 'Windows only'
    import psutil
    path=psutil.Process(int(pid)).exe()
    env=os.environ.copy(); env['GUARD_VERIFY_PATH']=path
    script='$s=Get-AuthenticodeSignature -LiteralPath $env:GUARD_VERIFY_PATH; [pscustomobject]@{Status=[string]$s.Status; Publisher=$s.SignerCertificate.Subject} | ConvertTo-Json -Compress'
    p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],env=env,capture_output=True,text=True,timeout=20,check=True)
    return p.stdout.strip()

def notify(count):
    if os.name!='nt': return
    import ctypes, threading
    threading.Thread(target=lambda:ctypes.windll.user32.MessageBoxW(0,f'{count} high-risk records need review. Not confirmed malware.','FilelessGuard AI',0x40),daemon=True).start()
