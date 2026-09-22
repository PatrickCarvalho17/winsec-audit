# WinSecAudit

Ferramenta de auditoria de postura de segurança para endpoints Windows. Analisa **39 vetores de segurança** em 5 categorias, gera score de postura (0-100), e exporta laudo HTML, JSON e CSV.

Cada check é mapeado para **CIS Controls v8** e **NIST Cybersecurity Framework**.

## 📸 Preview

![Preview do relatório](Capturas%20de%20tela/report-preview.png)

## ✨ Features

- **38 checagens** em 5 categorias: Endpoint Protection, Data Protection, Network Security, Identity & Access, Compliance & Hygiene
- **Score global (0-100)** + score individual por categoria
- **Mapeamento CIS v8 + NIST CSF** em cada check
- **Export triplo:** HTML (visual), JSON (integração), CSV (Excel)
- **Modo comparativo:** compara com scan anterior e mostra delta de score
- **Execution Policy GPO-aware:** diferencia política local de política corporativa
- **Auto-elevação UAC** — sem precisar rodar "como admin" manualmente

## 🛡️ O que é verificado

### Endpoint Protection
Antivírus/EDR, Defender RTP, assinaturas, exclusões, ASR Rules, Network Protection, Controlled Folder Access, Patch Management, Secure Boot, HVCI, SmartScreen, saúde do disco, Kernel DMA, TPM, itens de inicialização, scheduled tasks suspeitas.

### Data Protection
Backup (detecção de sync vs backup imutável), BitLocker.

### Network Security
Windows Firewall (3 perfis), portas expostas, SMBv1, SMB Signing, LLMNR, NetBIOS, RDP, shares, DNS.

### Identity & Access
UAC, conta Guest, admins locais, política de senha, senhas sem expiração, Credential Guard, LSA Protection, WDigest.

### Compliance & Hygiene
PowerShell Execution Policy (GPO-aware), ScriptBlock Logging, telemetria.

## 🚀 Como usar

### Requisitos
- Windows 10/11 ou Windows Server 2019+
- PowerShell 5.1+
- Privilégios administrativos (o script se auto-eleva via UAC)

### Execução básica

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\WinSecAudit.ps1
```

Ao final, abre automaticamente o laudo HTML no navegador.

### Parâmetros disponíveis

| Parâmetro | Descrição |
|---|---|
| `-OutputPath <path>` | Diretório de saída (default: Desktop) |
| `-Silent` | Sem mensagens no console (útil para agendamento) |
| `-SkipNetwork` | Pula consulta externa de IP |
| `-NoOpen` | Não abre o HTML ao final |
| `-ComparePath <json>` | Compara com scan anterior |

### Exemplos

```powershell
# Comparar com o último scan
.\WinSecAudit.ps1 -ComparePath ".\WinSecAudit_Data_PC01.json"

# Rodar silencioso (para agendador de tarefas)
.\WinSecAudit.ps1 -Silent -NoOpen -SkipNetwork
```

## 📊 Output

- `WinSecAudit_<HOSTNAME>.html` — laudo visual (print-friendly, exportável para PDF)
- `WinSecAudit_Data_<HOSTNAME>.json` — dados estruturados
- `WinSecAudit_Report_<HOSTNAME>.csv` — matriz para análise em planilha

## ⚠️ Falsos positivos conhecidos

- **Scheduled Tasks Suspeitas:** scripts legítimos de TI podem usar `-enc` ou `FromBase64String`. Requer validação manual.
- **Admins Locais:** em domínio, grupos de AD aparecem como admins — comportamento esperado.

## 🗺️ Roadmap

- [ ] Modularização em `WinSecAudit.psm1`
- [ ] Suporte a execução remota via WinRM
- [ ] Testes Pester
- [ ] Export PDF nativo

## 📜 Licença

MIT — veja [LICENSE](LICENSE).
