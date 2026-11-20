"""RedHat Windows defensive monitoring core. Python standard library only."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

BASE = Path(os.environ.get('LOCALAPPDATA') or (Path.home() / 'AppData' / 'Local')) / 'RedHat'
STATE = BASE / 'state.json'
EVENTS = BASE / 'events.jsonl'
DECISIONS = BASE / 'decisions.jsonl'
ALERT = BASE / 'alert.lock'
QUARANTINE = BASE / 'Quarantine'
DANGEROUS = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse', '.wsf', '.hta', '.msi', '.jar', '.com', '.lnk', '.iso'}
PARTIAL = {'.crdownload', '.part', '.download', '.tmp'}
MAX_HASH_BYTES = 1024 * 1024 * 1024

def prepare():
    BASE.mkdir(parents=True, exist_ok=True)
    QUARANTINE.mkdir(exist_ok=True)

def now():
    return datetime.now(timezone.utc).isoformat()

def log_event(category, severity, message, path=None, **details):
    prepare()
    event = {'id': f'{time.time_ns()}', 'time': now(), 'category': category,
             'severity': severity, 'message': message, 'path': str(path) if path else None, **details}
    with EVENTS.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(event, ensure_ascii=False) + '\n')
    return event

def last_events(limit=30):
    if not EVENTS.exists():
        return []
    from collections import deque
    with EVENTS.open(encoding='utf-8') as f:
        lines = list(deque(f, maxlen=limit))
    result = []
    for line in lines:
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return result

def load_state():
    try:
        return json.loads(STATE.read_text(encoding='utf-8'))
    except (FileNotFoundError, ValueError):
        return {'seen': {}, 'defender_ids': []}

def save_state(state):
    prepare()
    tmp = STATE.with_suffix('.tmp')
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding='utf-8')
    tmp.replace(STATE)

def ps(command, timeout=25):
    if os.name != 'nt':
        raise RuntimeError('O Microsoft Defender requer Windows.')
    cp = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                         "$ErrorActionPreference='Stop'; " + command],
                        capture_output=True, text=True, timeout=timeout, creationflags=0x08000000)
    if cp.returncode:
        raise RuntimeError((cp.stderr or cp.stdout).strip()[:800])
    return cp.stdout.strip()

def ps_json(command):
    raw = ps(command + ' | ConvertTo-Json -Depth 5 -Compress')
    return json.loads(raw) if raw else None

def defender_status():
    return ps_json('Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated')

def defender_threats():
    data = ps_json('Get-MpThreatDetection | Select-Object ThreatID,ThreatStatusID,Resources,InitialDetectionTime')
    return data if isinstance(data, list) else ([data] if data else [])

def scan_file(path):
    quoted = "'" + str(Path(path).resolve()).replace("'", "''") + "'"
    return ps('Start-MpScan -ScanType CustomScan -ScanPath ' + quoted, timeout=180)

def sha256(path):
    p = Path(path)
    if p.stat().st_size > MAX_HASH_BYTES:
        return None
    digest = hashlib.sha256()
    with p.open('rb') as fd:
        for block in iter(lambda: fd.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()

def inspect(path, defender_scan=False):
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(path)
    st = p.stat()
    ext = p.suffix.lower()
    score = 0
    reasons = []
    if ext in DANGEROUS:
        score += 35
        reasons.append('tipo de arquivo executável ou script')
    if any(p.name.lower().endswith(x) for x in ('.pdf.exe', '.jpg.exe', '.png.exe', '.txt.exe', '.docx.exe')):
        score += 45
        reasons.append('extensão dupla usada para disfarçar executável')
    if p.name.startswith('.') and ext in DANGEROUS:
        score += 10
        reasons.append('nome oculto incomum')
    if st.st_size == 0:
        reasons.append('arquivo vazio')
    fingerprint = sha256(p)
    result = {'file': str(p), 'sha256': fingerprint, 'size': st.st_size,
              'score': min(score, 100), 'reasons': reasons,
              'classification': 'suspeito' if score >= 60 else 'atenção' if score else 'informativo'}
    if defender_scan:
        try:
            scan_file(p)
            result['defender_scan'] = 'concluído; confira o histórico de ameaças'
        except Exception as exc:
            result['defender_scan'] = 'falhou: ' + str(exc)
    return result

def download_folder():
    return Path.home() / 'Downloads'

def process_downloads(state):
    seen = state.setdefault('seen', {})
    folder = download_folder()
    if not folder.exists():
        return
    try:
        files = [p for p in folder.iterdir() if p.is_file() and p.suffix.lower() not in PARTIAL]
    except OSError as exc:
        log_event('monitor', 'warning', f'Não foi possível listar Downloads: {exc}')
        files = []
    for p in files:
        try:
            stat = p.stat()
            identity = f'{stat.st_size}:{stat.st_mtime_ns}'
            key = str(p)
            if seen.get(key) == identity:
                continue
            if time.time() - stat.st_mtime < 4:
                continue
            result = inspect(p)
            # Trigger the actual Windows malware scanner for downloaded executable content.
            if p.suffix.lower() in DANGEROUS:
                try:
                    scan_file(p)
                    result['defender_scan'] = 'completed'
                except Exception as exc:
                    result['defender_scan'] = 'failed: ' + str(exc)
                    log_event('defender', 'warning', 'A varredura do download falhou', p, error=str(exc))
            seen[key] = identity
            if result['score']:
                log_event('download', 'warning' if result['score'] < 60 else 'high',
                          'Arquivo exige análise adicional', p, **{k:v for k,v in result.items() if k!='file'})
            else:
                log_event('download', 'info', 'Arquivo observado; nenhum indicador heurístico simples', p, sha256=result['sha256'])
        except (OSError, PermissionError) as exc:
            log_event('monitor', 'warning', f'Falha ao verificar arquivo: {exc}', p)
    if len(seen) > 3000:
        state['seen'] = {k:v for k,v in seen.items() if Path(k).exists()}

def process_defender(state):
    previous = set(str(x) for x in state.setdefault('defender_ids', []))
    detections = defender_threats()
    # First run: baseline historic detections; only notify about newly observed records.
    if not state.get('defender_initialized'):
        state['defender_ids'] = [hashlib.sha256(json.dumps(item, sort_keys=True, default=str).encode()).hexdigest() for item in detections][-500:]
        state['defender_initialized'] = True
        return
    for item in detections:
        marker = json.dumps(item, sort_keys=True, default=str)
        identity = hashlib.sha256(marker.encode()).hexdigest()
        if identity not in previous:
            log_event('defender', 'critical', 'Microsoft Defender registrou uma detecção', detection=item)
            previous.add(identity)
    state['defender_ids'] = list(previous)[-500:]

def severe_unhandled_events():
    acknowledged = set()
    if DECISIONS.exists():
        with DECISIONS.open(encoding='utf-8') as f:
            for line in f:
                try:
                    acknowledged.add(json.loads(line)['event_id'])
                except (KeyError, ValueError):
                    pass
    return [e for e in last_events(200) if e['severity'] in ('high','critical') and e['id'] not in acknowledged]

def prompt_window():
    if os.name != 'nt':
        return
    if ALERT.exists():
        try:
            if time.time() - ALERT.stat().st_mtime < 90:
                return
        except OSError:
            pass
    ALERT.write_text(str(os.getpid()), encoding='utf-8')
    python = sys.executable
    if Path(python).name.lower() == 'pythonw.exe':
        python = str(Path(python).with_name('python.exe'))
    args = f'"{python}" -m redhat.cli alerts'
    subprocess.Popen(['cmd.exe', '/c', args], cwd=str(Path(__file__).resolve().parent.parent),
                     creationflags=subprocess.CREATE_NEW_CONSOLE)

def daemon(interval=8):
    prepare()
    state = load_state()
    log_event('service', 'info', 'Monitor RedHat iniciado')
    last_defender = 0
    while True:
        try:
            process_downloads(state)
            if time.monotonic() - last_defender > 45:
                last_defender = time.monotonic()
                try:
                    process_defender(state)
                except Exception as exc:
                    log_event('defender', 'warning', 'Não foi possível consultar Microsoft Defender: ' + str(exc))
            save_state(state)
            if severe_unhandled_events():
                prompt_window()
        except Exception as exc:
            log_event('service', 'warning', 'Erro recuperável no monitor: ' + repr(exc))
        time.sleep(interval)

def quarantine_file(path):
    src = Path(path).resolve(strict=True)
    if not src.is_file() or src.is_symlink():
        raise ValueError('Apenas arquivos regulares podem ser isolados.')
    if QUARANTINE.resolve() in src.parents:
        raise ValueError('O arquivo já está em quarentena.')
    if download_folder().resolve() not in src.parents:
        raise ValueError('Quarentena via CLI permitida somente na pasta Downloads.')
    prepare()
    digest = hashlib.sha256((str(src) + now()).encode()).hexdigest()[:16]
    target = QUARANTINE / (digest + '.isolated')
    shutil.move(str(src), str(target))
    manifest = {'source': str(src), 'isolated': str(target), 'time': now()}
    (QUARANTINE / (digest + '.json')).write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    log_event('response', 'info', 'Arquivo colocado em quarentena por autorização do usuário', src, isolated=str(target))
    return str(target)

def acknowledge(event_id, action):
    prepare()
    with DECISIONS.open('a', encoding='utf-8') as f:
        f.write(json.dumps({'event_id': event_id, 'action': action, 'time': now()}) + '\n')
