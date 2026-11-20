# RedHat 0.2 — Windows Security CLI + background monitor

Protótipo defensivo **em desenvolvimento** para Windows 10/11. CLI e observador são processos separados: fechar o terminal de controle não encerra o monitor instalado. O monitor verifica a pasta Downloads a cada ~8 segundos, solicita análise do Microsoft Defender para novos downloads de tipos executáveis e consulta novas detecções do Defender a cada ~45 segundos, mantém logs JSONL e abre outro CMD quando encontra alertas de risco alto para pedir uma decisão. Nenhum arquivo é colocado em quarentena sem aprovação explícita.

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
- O mecanismo interno heurístico alerta sobre **extensões executáveis** e extensões duplas, não identifica famílias específicas de malware. Apenas alertas de risco alto abrem a CLI automaticamente; outros resultados ficam no histórico.\n- A varredura pode atrasar ou falhar caso o Defender esteja desativado ou o arquivo esteja bloqueado. O alerta não bloqueia preventivamente a execução do download.
- A proteção de sites depende de tecnologias do Windows/navegador já instaladas. Documentação: [Microsoft Defender SmartScreen](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/) e [Defender PowerShell](https://learn.microsoft.com/en-us/powershell/module/defender/).

## Próximos marcos

- Monitor robusto com watchdog de eventos do Windows e detecções sem duplicar.
- Avaliação de assinatura Authenticode e reputação opcional com consentimento.
- Notificação nativa Windows em vez de apenas janela CMD.
- Integração de extensão de navegador para inspeção de URLs de forma transparente e com consentimento.
- Empacotamento `.exe` assinado e instalador com desinstalação completa.

## V0.2: comando global, Web Shield experimental e Tor

Depois de executar novamente `install.ps1`, **abra um novo CMD** e digite `redhat` para abrir o painel, `redhat web` para verificar o cache DNS, ou `redhat tor` para localizar e abrir o Tor Browser após confirmação.

O monitor consulta periodicamente o cache DNS do Windows e compara os nomes com `%LOCALAPPDATA%\\RedHat\\blocked-domains.json`. A lista padrão contém apenas um domínio fictício de exemplo: **adicione indicadores confiáveis para obter alertas úteis**. Isto não é proteção integral em tempo real: o cache DNS não contém necessariamente todas as URLs, não inspeciona HTTPS, não bloqueia tráfego e pode perder resoluções feitas por DNS-over-HTTPS. Não detecta quem está tentando obter seu IP. Um site normalmente recebe seu IP ao estabelecer uma conexão.

Tor Browser **não** é ativado automaticamente por mera exposição de IP: o usuário pode optar por abri-lo pelo comando `redhat tor`, caso já esteja instalado. Ele protege somente as conexões feitas dentro do Tor Browser. O programa não identifica atacantes, não executa retaliação e não garante anonimato.

Para proteção real contra sites perigosos, mantenha Microsoft Defender SmartScreen e os filtros antiphishing do navegador ativados. Uma extensão própria com interceptação de navegação e um serviço de reputação são trabalhos futuros.
