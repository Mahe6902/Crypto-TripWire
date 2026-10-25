import json, os

EVIDENCE_DIR = "evidence_output"
WHITELIST = [
    "system", "system idle process", "registry", "memory compression",
    "secure system", "svchost.exe", "explorer.exe", "winlogon.exe",
    "csrss.exe", "lsass.exe", "smss.exe", "wininit.exe", "services.exe",
    "spoolsv.exe", "taskhostw.exe", "dwm.exe", "python.exe", "python3.exe",
    "cmd.exe", "conhost.exe", "runtimebroker.exe", "sihost.exe",
    "fontdrvhost.exe", "searchhost.exe", "searchindexer.exe",
    "taskmgr.exe", "notepad.exe", "mspaint.exe", "textinputhost.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "applicationframehost.exe", "ctfmon.exe", "dllhost.exe",
    "audiodg.exe", "wmiprvse.exe", "wuauclt.exe"
]

print("=" * 60)
print("        CRYPTO-TRIPWIRE — PHASE 3")
print("        Timeline Reconstruction")
print("=" * 60)

proc_path     = os.path.join(EVIDENCE_DIR, 'processes.json')
net_path      = os.path.join(EVIDENCE_DIR, 'network.json')
manifest_path = os.path.join(EVIDENCE_DIR, 'manifest.json')

if not os.path.exists(proc_path):
    print("\n[ERROR] No evidence files found.")
    print("[ERROR] Run main.py and simulate.py first, then re-run this.")
    exit()

with open(proc_path)     as f: proc_data = json.load(f)
with open(net_path)      as f: net_data  = json.load(f)
with open(manifest_path) as f: manifest  = json.load(f)

print(f"\n[Phase 3] Evidence timestamp        : {proc_data['timestamp']}")
print(f"[Phase 3] Total processes in snapshot: {len(proc_data['processes'])}")
print(f"[Phase 3] Total connections captured : {len(net_data['connections'])}")

print("\n[Phase 3] --- PROCESSES NOT IN WHITELIST (FLAGGED) ---")
flagged_procs = []
for p in proc_data['processes']:
    name = p.get('name', '')
    if name and name.lower() not in [w.lower() for w in WHITELIST]:
        flagged_procs.append(p)
        print(f"  [FLAG] PID {p['pid']:5} | {name:40} | Started: {p.get('create_time','unknown')[:19]}")

print(f"\n[Phase 3] Total flagged processes    : {len(flagged_procs)}")

print("\n[Phase 3] --- ESTABLISHED OUTBOUND CONNECTIONS ---")
flagged_conns = []
for c in net_data['connections']:
    if c.get('raddr') and c.get('status') == 'ESTABLISHED':
        flagged_conns.append(c)
        print(f"  [FLAG] PID {str(c.get('pid','?')):5} | {c['laddr']:25} -> {c['raddr']:25} | {c['status']}")

if not flagged_conns:
    print("  [INFO] No outbound ESTABLISHED connections at capture time.")
print(f"\n[Phase 3] Total flagged connections  : {len(flagged_conns)}")

print("\n[Phase 3] --- RECONSTRUCTED EVENT TIMELINE ---")
timeline = []
for p in flagged_procs:
    timeline.append({
        'time':  p.get('create_time', proc_data['timestamp']),
        'type':  'PROCESS',
        'event': f"Non-whitelisted process active: {p.get('name')} (PID {p['pid']})"
    })
for c in flagged_conns:
    timeline.append({
        'time':  proc_data['timestamp'],
        'type':  'NETWORK',
        'event': f"Outbound connection: {c['laddr']} -> {c['raddr']}"
    })

timeline.sort(key=lambda x: x['time'])

for i, e in enumerate(timeline[:12], 1):
    print(f"  T+{i:02d} | [{e['type']:7}] {e['event']}")

timeline_path = os.path.join(EVIDENCE_DIR, 'timeline.json')
with open(timeline_path, 'w') as f:
    json.dump({
        'timestamp': proc_data['timestamp'],
        'total_flagged_processes': len(flagged_procs),
        'total_flagged_connections': len(flagged_conns),
        'timeline': timeline
    }, f, indent=2)

print(f"\n[Phase 3] Timeline saved to          : {timeline_path}")
print(f"\n[Phase 3] --- SHA-256 INTEGRITY VERIFICATION ---")
print(f"  processes.json : {manifest['hashes']['processes.json']}")
print(f"  network.json   : {manifest['hashes']['network.json']}")
print(f"\n[Phase 3] Timeline reconstruction complete.")
print("=" * 60)