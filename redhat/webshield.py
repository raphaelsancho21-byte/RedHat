"""Passive DNS cache monitoring and consent-based Tor Browser launcher."""
import json, os, re, subprocess
from pathlib import Path
from . import core
RULES = core.BASE / 'blocked-domains.json'
def check(state):
    core.prepare()
    if not RULES.exists():
        RULES.write_text(json.dumps({'domains':['example-malware.invalid']},indent=2))
    try:
        blocked={x.lower().strip('.') for x in json.loads(RULES.read_text()).get('domains',[]) if isinstance(x,str)}
    except (OSError,ValueError):
        blocked=set()
    if os.name!='nt': return
    result=subprocess.run(['ipconfig','/displaydns'],capture_output=True,text=True,errors='replace',timeout=20,creationflags=0x08000000)
    seen=set(state.get('web_alerted',[]))
    for line in result.stdout.splitlines():
        if ':' not in line: continue
        key,value=line.split(':',1)
        if 'Record Name' not in key and 'Nome do Registro' not in key and 'Nome do registro' not in key: continue
        domain=value.strip().rstrip('.').lower()
        if not re.fullmatch(r'[a-z0-9_.-]{1,253}',domain): continue
        if domain not in seen and any(domain==x or domain.endswith('.'+x) for x in blocked):
            core.log_event('web','high','Domínio presente na lista local apareceu no cache DNS; não comprova ataque',domain)
            seen.add(domain)
    state['web_alerted']=list(seen)[-500:]
def open_tor():
    home=Path.home()
    roots=[home/'Desktop'/'Tor Browser',home/'Downloads'/'Tor Browser',Path(os.environ.get('PROGRAMFILES','C:/Program Files'))/'Tor Browser',Path(os.environ.get('LOCALAPPDATA',str(home)))/'Tor Browser']
    tor=next((p/'Browser'/'firefox.exe' for p in roots if (p/'Browser'/'firefox.exe').is_file()),None)
    if tor is None:
        print('Instale o Tor Browser oficial: https://www.torproject.org/download/')
        return
    print('Tor protege apenas a navegação dentro do Tor Browser, não todo o Windows.')
    if input('Abrir Tor Browser? (s/N): ').strip().lower()=='s':
        subprocess.Popen([str(tor)],cwd=str(tor.parent))
