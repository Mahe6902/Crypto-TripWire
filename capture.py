import psutil, json, hashlib, datetime, os

def capture_evidence(output_dir="evidence_output"):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"[Phase 2] Capture timestamp    : {ts}")

    procs = []
    for p in psutil.process_iter(['pid', 'name', 'ppid', 'create_time']):
        try:
            info = p.info
            info['create_time'] = datetime.datetime.fromtimestamp(
                info['create_time']).isoformat()
            procs.append(info)
        except:
            pass

    conns = []
    for c in psutil.net_connections(kind='inet'):
        try:
            conns.append({
                'laddr': f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                'raddr': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                'status': c.status,
                'pid': c.pid
            })
        except:
            pass

    proc_path = os.path.join(output_dir, 'processes.json')
    net_path  = os.path.join(output_dir, 'network.json')

    with open(proc_path, 'w') as f:
        json.dump({'timestamp': ts, 'processes': procs}, f, indent=2)
    with open(net_path, 'w') as f:
        json.dump({'timestamp': ts, 'connections': conns}, f, indent=2)

    manifest = {'timestamp': ts, 'hashes': {}}
    for label, path in [('processes.json', proc_path), ('network.json', net_path)]:
        with open(path, 'rb') as f:
            manifest['hashes'][label] = hashlib.sha256(f.read()).hexdigest()

    manifest_path = os.path.join(output_dir, 'manifest.json')
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f"[Phase 2] Processes captured   : {len(procs)}")
    print(f"[Phase 2] Connections captured : {len(conns)}")
    print(f"[Phase 2] SHA-256 manifest     : saved to {manifest_path}")
    print(f"\n[Phase 2] Integrity Hashes:")
    for k, v in manifest['hashes'].items():
        print(f"          {k} : {v}")
    print(f"\n[Phase 2] Evidence location    : {os.path.abspath(output_dir)}")
    return manifest