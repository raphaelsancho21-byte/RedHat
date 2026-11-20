# RedHat 0.1 — Windows Security CLI + background monitor

Protótipo defensivo **em desenvolvimento** para Windows 10/11. CLI e observador são processos separados: fechar o terminal de controle não encerra o monitor instalado. O monitor verifica a pasta Downloads a cada ~8 segundos, consulta novas detecções do Microsoft Defender a cada ~45 segundos, mantém logs JSONL e abre outro CMD quando encontra alertas de risco alto para pedir uma decisão. Nenhum arquivo é colocado em quarentena sem aprovação explícita.

> **IMPORTANTE:** RedHat 0.1 **não substitui um antivírus**, não examina pacotes de rede nem intercepta a navegação, não impede a execução antes do primeiro scan, não prova a segurança de um arquivo e não oferece proteção completa contra phishing em todos os navegadores. Para páginas perigosas, mantenha SmartScreen e a proteção do navegador ligados. A detecção de malware é do Microsoft Defender; o score interno é apenas heurística e pode gerar falsos positivos/negativos.

## Instalar (PowerShell)

```powershell
git clone https://github.com/raphaelsancho21-byte/RedHat.git
cd RedHat
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Instalador verifica Python, pergunta **antes de usar winget**, copia para `%LOCALAPPDATA%\RedHat\app` e pede autorização para criar a tarefa `RedHat Monitor` no logon. O Microsoft Defender já vem integrado ao Windows compatível e não é baixado pelo instalador. Para executar a CLI sem instalar, a partir do repositório:

```powershell
py -3 -m redhat
py -3 -m redhat status
py -3 -m redhat alerts
py -3 -m redhat history
py -3 -m redhat scan "C:\Users\Usuario\Downloads\arquivo.exe"
py -3 -m redhat daemon
```

Se Python não estiver no PATH após instalá-lo, abra outro terminal. A execução sem Python compatível falhará explicitamente.

## Arquitetura

- `redhat/core.py`: monitor, hashes SHA-256, pontuação heurística, eventos, consultas ao Defender, isolamento autorizado.
- `redhat/cli.py`: interface textual, histórico, decisões e varredura manual do Microsoft Defender.
- `install.ps1`: detecção e instalação autorizada de dependências e criação da tarefa de logon.
- `uninstall.ps1`: remoção da tarefa mediante confirmação; preserva logs e quarentena.
- `tests/`: testes unitários.

### Segurança e limitações

- Arquivos `.crdownload`, `.part` e outros temporários são ignorados até conclusão.
- O arquivo suspeito é **apenas sinalizado** até o usuário digitar `ISOLAR`; isolamento só é permitido para arquivos regulares da pasta Downloads.
- Os registros estão em `%LOCALAPPDATA%\RedHat`; não contêm uploads para serviços externos.
- O monitor não instala drivers, não desativa Defender, não cria exclusões, não modifica navegador e pode ser removido.
- O aviso abre um CMD separado; dependendo das políticas do Windows, esse comportamento pode não funcionar em sessões não interativas.
- O mecanismo interno heurístico alerta sobre **extensões executáveis** e extensões duplas, não identifica famílias específicas de malware.
- A proteção de sites depende de tecnologias do Windows/navegador já instaladas. Documentação: [Microsoft Defender SmartScreen](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/) e [Defender PowerShell](https://learn.microsoft.com/en-us/powershell/module/defender/).

## Próximos marcos

- Monitor robusto com watchdog de eventos do Windows e detecções sem duplicar.
- Avaliação de assinatura Authenticode e reputação opcional com consentimento.
- Notificação nativa Windows em vez de apenas janela CMD.
- Integração de extensão de navegador para inspeção de URLs de forma transparente e com consentimento.
- Empacotamento `.exe` assinado e instalador com desinstalação completa.
