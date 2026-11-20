"""Interactive RedHat CLI; never removes threats without explicit approval."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from . import __version__
from . import core

BANNER = r'''
  ____          _ _   _       _
 |  _ \ ___  __| | | | | __ _| |_
 | |_) / _ \/ _` | |_| |/ _` | __|
 |  _ <  __/ (_| |  _  | (_| | |_
 |_| \_\___|\__,_|_| |_|\__,_|\__|
       WINDOWS DEFENSE CONSOLE
'''

def status():
    print('\nRedHat', __version__)
    try:
        print('Defender:', json.dumps(core.defender_status(), ensure_ascii=False, indent=2))
    except Exception as e:
        print('Defender indisponível:', e)
    print('Pasta de eventos:', core.EVENTS)
    print('Downloads monitorados:', core.download_folder())
    print('Alertas pendentes:', len(core.severe_unhandled_events()))

def alerts():
    try:
        pending = core.severe_unhandled_events()
        if not pending:
            print('Nenhum alerta crítico pendente.')
            return
        for ev in pending:
            print('\n' + '=' * 65)
            print('ALERTA', ev['severity'].upper(), '|', ev['category'])
            print(ev['message'])
            if ev.get('path'):
                print('Arquivo:', ev['path'])
            if ev.get('reasons'):
                print('Indicadores:', ', '.join(ev['reasons']))
            if ev['category'] == 'download' and ev.get('path'):
                print('[1] Isolar em quarentena (requer confirmação)')
            print('[2] Registrar como revisado | [Enter] Deixar pendente')
            choice = input('Ação: ').strip()
            if choice == '1' and ev['category'] == 'download' and ev.get('path'):
                print('IMPORTANTE: heurística não prova que um arquivo é malware.')
                confirm = input('Digite ISOLAR para mover o arquivo: ').strip()
                if confirm == 'ISOLAR':
                    try:
                        print('Quarentena:', core.quarantine_file(ev['path']))
                        core.acknowledge(ev['id'], 'quarantined')
                    except Exception as exc:
                        print('Não foi possível isolar:', exc)
            elif choice == '2':
                core.acknowledge(ev['id'], 'reviewed')
    finally:
        try:
            core.ALERT.unlink(missing_ok=True)
        except OSError:
            pass

def history():
    for ev in core.last_events(40):
        print(f"[{ev['time']}] {ev['severity']:<8} {ev['category']:<9} {ev['message']} {ev.get('path') or ''}")

def do_scan(path):
    p = Path(path).expanduser()
    result = core.inspect(p, defender_scan=True)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print('Aviso: análise heurística não é um veredito; consulte histórico do Defender.')

def menu():
    while True:
        print(BANNER)
        print('1 Status | 2 Alertas | 3 Histórico | 4 Verificar arquivo | 5 Sair')
        c = input('redhat> ').strip()
        if c == '1': status()
        elif c == '2': alerts()
        elif c == '3': history()
        elif c == '4':
            try: do_scan(input('Caminho do arquivo: ').strip().strip('"'))
            except Exception as e: print('Erro:', e)
        elif c == '5': break
        else: print('Escolha uma opção válida.')
        input('\nEnter para continuar...')

def main():
    ap = argparse.ArgumentParser(description='RedHat defensive Windows CLI')
    ap.add_argument('command', nargs='?', choices=['status','alerts','history','scan','daemon'])
    ap.add_argument('path', nargs='?')
    ns = ap.parse_args()
    if ns.command == 'status': status()
    elif ns.command == 'alerts': alerts()
    elif ns.command == 'history': history()
    elif ns.command == 'scan':
        if not ns.path: ap.error('scan requer caminho de arquivo')
        do_scan(ns.path)
    elif ns.command == 'daemon': core.daemon()
    else: menu()

if __name__ == '__main__':
    main()
