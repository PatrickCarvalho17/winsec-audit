<#
.SYNOPSIS
    WinSecAudit - Analise de Postura de Seguranca para endpoints Windows.

.DESCRIPTION
    Ferramenta de auditoria local que avalia 39 vetores de seguranca em 5 categorias,
    gera score de postura (0-100), exporta laudo HTML, JSON e CSV.
    Cada check e mapeado para CIS Controls v8 e NIST CSF.

.PARAMETER OutputPath
    Diretorio de saida. Default: Desktop (fallback: Documents/TEMP).

.PARAMETER Silent
    Executa sem mensagens de progresso no console.

.PARAMETER Anonymize
    Substitui hostname, dominio, IP e ISP por valores genericos de demonstracao.
    Use ao gerar relatorios para compartilhamento publico.

.PARAMETER NoOpen
    Nao abre o HTML automaticamente ao final.

.PARAMETER ComparePath
    Caminho para JSON de scan anterior. Exibe diff e delta de score.

.EXAMPLE
    .\WinSecAudit.ps1
    Roda com dados reais (uso oficial).

.EXAMPLE
    .\WinSecAudit.ps1 -Anonymize
    Roda com dados ficticios (uso demo/portfolio).

.NOTES
    Requer privilegios administrativos (auto-elevacao via UAC).
    Autor: [Seu Nome] | Licenca: MIT
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$Silent,
    [switch]$Anonymize,
    [switch]$NoOpen,
    [string]$ComparePath
)

$ErrorActionPreference = 'SilentlyContinue'

# --- 0. TRAVA DE PRIVILEGIO ADMINISTRATIVO ---
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Silent) { $args += " -Silent" }
    if ($Anonymize) { $args += " -Anonymize" }
    if ($NoOpen) { $args += " -NoOpen" }
    if ($OutputPath) { $args += " -OutputPath `"$OutputPath`"" }
    if ($ComparePath) { $args += " -ComparePath `"$ComparePath`"" }
    Write-Host "Elevando privilegios para auditoria profunda..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList $args -Verb RunAs
    Exit
}

function Write-Progress-Msg ($msg, $color = 'Cyan') {
    if (-not $Silent) { Write-Host $msg -ForegroundColor $color }
}

function Get-OutputPath {
    if ($OutputPath -and (Test-Path $OutputPath)) { return $OutputPath }
    $candidates = @(
        [Environment]::GetFolderPath('Desktop'),
        "$env:USERPROFILE\Documents",
        $env:TEMP,
        $PWD.Path
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $env:TEMP
}

function Get-CloudStatus {
    $Status = @{ Nome="Nenhum"; Tipo="Inexistente"; Cor="#ef4444"; Msg="Sem solucao de backup off-site identificada." }

    $SyncEngines = @("OneDrive", "GoogleDriveFS", "googledrivesync", "Dropbox", "Box", "BoxSync", "iCloudServices", "MEGAsync", "Nextcloud", "owncloud", "SugarSync", "Tresorit", "Amazon Drive", "AdobeCollabSync")
    $ImmutableEngines = @("VeeamAgent", "veeam", "ShadowProtect", "mms", "CoveDataProtection", "BackupExec", "NBU")

    $ProcessosAtivos = Get-Process | Select-Object -ExpandProperty Name
    $SyncDetectado = $ProcessosAtivos | Where-Object { $SyncEngines -contains $_ -or $_ -match "sync" } | Select-Object -Unique
    $ImutavelDetectado = $ProcessosAtivos | Where-Object { $ImmutableEngines -contains $_ } | Select-Object -Unique

    if ($ImutavelDetectado) {
        $Status.Nome = ($ImutavelDetectado -join ", ")
        $Status.Tipo = "BACKUP IMUTAVEL"
        $Status.Cor  = "#10b981"
        $Status.Msg  = "Solucao de backup com imutabilidade ativa. Ambiente resiliente a Ransomware."
        return $Status
    }

    $S_Backup = Get-Service -Name "mms", "VeeamBackupSvc" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }
    if ($S_Backup) {
        $Status.Nome = ($S_Backup.DisplayName -join ", ")
        $Status.Tipo = "BACKUP IMUTAVEL"
        $Status.Cor  = "#10b981"
        $Status.Msg  = "Solucao de backup com imutabilidade ativa. Ambiente resiliente a Ransomware."
        return $Status
    }

    if ($SyncDetectado) {
        $Status.Nome = ($SyncDetectado -join ", ")
        $Status.Tipo = "SINCRONIZACAO"
        $Status.Cor  = "#f59e0b"
        $Status.Msg  = "Apenas sincronizacao detectada. Este modelo espelha infeccoes de Ransomware para a nuvem em segundos."
        return $Status
    }

    return $Status
}

function New-Check {
    param(
        [string]$Categoria,
        [string]$Vetor,
        [string]$Severidade,
        [string]$Status,
        [string]$Analise,
        [string]$Acao,
        [string]$CIS = "-",
        [string]$NIST = "-",
        [int]$Penalidade = 0
    )
    [PSCustomObject]@{
        Categoria  = $Categoria
        Vetor      = $Vetor
        Severidade = $Severidade
        Status     = $Status
        Analise    = $Analise
        Acao       = $Acao
        CIS        = $CIS
        NIST       = $NIST
        Penalidade = $Penalidade
    }
}

# --- 2. COLETA DE DADOS ---
Write-Progress-Msg ">>> INICIANDO WINSECAUDIT (SCAN DE ALTA PREVISAO)..." 'Cyan'

if ($Anonymize) {
    $PC  = "CORP-WKS-042"
    $DOM = "CORP"
    $IP  = "10.42.0.187"
    $ISP = "Corporate Network (LAN)"
    Write-Progress-Msg ">>> MODO ANONIMIZADO ATIVO (dados de identidade substituidos)" 'Yellow'
} else {
    $PC  = $env:COMPUTERNAME
    $DOM = $env:USERDOMAIN
    $IP  = "Local/Oculto"
    $ISP = "Privado"
    try {
        $Geo = Invoke-RestMethod -Uri "https://ipinfo.io/json" -TimeoutSec 4 -ErrorAction Stop
        $IP = $Geo.ip; $ISP = $Geo.org
    } catch {}
}

$OS = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$RAM = 0
try { $RAM = [math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB) } catch {}
$Disco = Get-PhysicalDisk -ErrorAction SilentlyContinue | Select -First 1
$DiasLigado = 0
if ($OS) { $DiasLigado = ((Get-Date) - $OS.LastBootUpTime).Days }
$RebootPending = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"

$DNS = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses
$ListaDNS = if ($DNS) { ($DNS | Select-Object -Unique) -join ", " } else { "Nao detectado" }
$DNSConfiaveis = @('1.1.1.1', '8.8.8.8', '9.9.9.9', '208.67.222.222')
$DNSSeguro = if ($DNS | Where-Object { $DNSConfiaveis -contains $_ }) { $true } else { $false }

$PortasPerigo = @(3389, 445, 21, 23, 80, 4444, 3306, 1433)
$PortasAbertas = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object {
    $PortasPerigo -contains $_.LocalPort -and $_.LocalAddress -ne '127.0.0.1' -and $_.LocalAddress -ne '::1'
}
if ($PortasAbertas) {
    $ListaPortas = ($PortasAbertas.LocalPort | Select-Object -Unique) -join ", "
    $StatusFirewall = "EXPOSTO (Portas: $ListaPortas)"
    $RiscoFirewall = $true
} else {
    $StatusFirewall = "SEGURO"
    $RiscoFirewall = $false
}

$FWProfiles = @{}
try { $FWProfiles = Get-NetFirewallProfile -ErrorAction Stop } catch {}
$FW_Domain  = ($FWProfiles | Where-Object Name -eq 'Domain').Enabled
$FW_Private = ($FWProfiles | Where-Object Name -eq 'Private').Enabled
$FW_Public  = ($FWProfiles | Where-Object Name -eq 'Public').Enabled

$Bit = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
$BitStatus = if ($Bit -and $Bit.ProtectionStatus -eq 'On') { $true } else { $false }

$Cloud = Get-CloudStatus

$DMAProt = $false
try { $DMAProt = (Get-ComputerInfo -Property DeviceGuardDmaProtectionEnabled -ErrorAction Stop).DeviceGuardDmaProtectionEnabled } catch {}

$AdID = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -ErrorAction SilentlyContinue
$Spying = if ($AdID -and $AdID.Enabled -eq 1) { $true } else { $false }

$Shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin 'C$', 'IPC$', 'ADMIN$' }
$ListaShares = if ($Shares) { ($Shares.Name -join ", ") } else { "Nenhuma" }
$HasShares = if ($Shares) { $true } else { $false }

$AV = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
$NomeAV = if($AV) { ($AV.displayName | Select-Object -Unique) -join " + " } else { 'NENHUM DETECTADO' }

$Admins = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue
$CountAdmins = if ($Admins) { $Admins.Count } else { 1 }

$SecureBoot = $null
try { $SecureBoot = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $SecureBoot = $null }

$TPMPresent = $false; $TPMReady = $false
try {
    $TPMData = Get-Tpm -ErrorAction Stop
    $TPMPresent = $TPMData.TpmPresent
    $TPMReady   = $TPMData.TpmReady
} catch {}

$UACEnabled = $null; $UACLevel = $null
try {
    $UACKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop
    $UACEnabled = $UACKey.EnableLUA
    $UACLevel   = $UACKey.ConsentPromptBehaviorAdmin
} catch {}

$SMB1Enabled = $null
try { $SMB1Enabled = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}

$SMBSigning = $null
try { $SMBSigning = (Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature } catch {}

$DefenderRTP = $null
$DefenderSigAge = -1
$DefenderExclusions = @()
$DefenderASR = $null
$DefenderNetworkProt = $null
$DefenderCFA = $null
try {
    $MpStatus = Get-MpComputerStatus -ErrorAction Stop
    $DefenderRTP = $MpStatus.RealTimeProtectionEnabled
    if ($MpStatus.AntivirusSignatureLastUpdated) {
        $DefenderSigAge = ((Get-Date) - $MpStatus.AntivirusSignatureLastUpdated).Days
    }
} catch {}
try {
    $MpPref = Get-MpPreference -ErrorAction Stop
    $DefenderExclusions = @($MpPref.ExclusionPath) + @($MpPref.ExclusionProcess) + @($MpPref.ExclusionExtension) | Where-Object { $_ }
    $DefenderASR = $MpPref.AttackSurfaceReductionRules_Ids
    $DefenderNetworkProt = $MpPref.EnableNetworkProtection
    $DefenderCFA = $MpPref.EnableControlledFolderAccess
} catch {}

$GuestEnabled = $false
try {
    $Guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($Guest) { $GuestEnabled = $Guest.Enabled }
} catch {}

$ContasSemExpira = @()
try {
    $todosUsuarios = Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -eq $true -and $_.Name -notin @('DefaultAccount','WDAGUtilityAccount') }
    foreach ($u in $todosUsuarios) {
        $semExpira = $false
        try { $semExpira = (net user $u.Name 2>$null | Select-String 'Expira.*Nunca|Expires.*Never') -ne $null } catch {}
        if ($semExpira) { $ContasSemExpira += $u.Name }
    }
} catch {}

$RDPEnabled = $false
try {
    $RDPKey = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction Stop
    $RDPEnabled = ($RDPKey.fDenyTSConnections -eq 0)
} catch {}

$ExecPolicy = Get-ExecutionPolicy
$ExecPolicyGPO = $false
$ExecPolicyGPOOrigem = ""
try {
    $ExecPolicyList = Get-ExecutionPolicy -List
    foreach ($escopo in $ExecPolicyList) {
        if ($escopo.Scope -in @('MachinePolicy','UserPolicy') -and $escopo.ExecutionPolicy -ne 'Undefined') {
            $ExecPolicyGPO = $true
            $ExecPolicyGPOOrigem = "$($escopo.Scope): $($escopo.ExecutionPolicy)"
            break
        }
    }
} catch {}

$DiasDesdePatch = -1
try {
    $UltimoPatch = Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($UltimoPatch -and $UltimoPatch.InstalledOn) {
        $DiasDesdePatch = ((Get-Date) - $UltimoPatch.InstalledOn).Days
    }
} catch {}

$StartupCount = 0
$StartupPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($p in $StartupPaths) {
    if (Test-Path $p) {
        $props = (Get-ItemProperty $p -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }
        if ($props) { $StartupCount += $props.Count }
    }
}

$MinPwdLen = 0
$NetAccounts = net accounts 2>$null
if ($NetAccounts) {
    foreach ($linha in $NetAccounts) {
        if ($linha -match '(Comprimento m[ií]nimo da senha|Minimum password length):\s+(\d+)') {
            $MinPwdLen = [int]$matches[2]
            break
        }
    }
}

$LLMNRDisabled = $false
try {
    $LLMNR = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction Stop
    $LLMNRDisabled = ($LLMNR.EnableMulticast -eq 0)
} catch {}

$NetBIOSDisabled = $false
try {
    $interfaces = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction Stop
    $allDisabled = $true
    foreach ($i in $interfaces) {
        $val = (Get-ItemProperty $i.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions
        if ($val -ne 2) { $allDisabled = $false; break }
    }
    $NetBIOSDisabled = $allDisabled -and ($interfaces.Count -gt 0)
} catch {}

$CredGuard = $false
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $CredGuard = ($dg.SecurityServicesRunning -contains 1)
} catch {}

$LSAPPL = $false
try {
    $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction Stop
    $LSAPPL = ($lsa.RunAsPPL -ge 1)
} catch {}

$WDigest = $null
try {
    $wd = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -ErrorAction Stop
    $WDigest = $wd.UseLogonCredential
} catch { $WDigest = 0 }

$HVCI = $false
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $HVCI = ($dg.SecurityServicesRunning -contains 2)
} catch {}

$SmartScreen = $null
try {
    $ss = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name SmartScreenEnabled -ErrorAction Stop
    $SmartScreen = $ss.SmartScreenEnabled
} catch {}

$ScriptBlockLogging = $false
try {
    $sbl = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction Stop
    $ScriptBlockLogging = ($sbl.EnableScriptBlockLogging -eq 1)
} catch {}

$TasksSuspeitas = @()
try {
    $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' }
    foreach ($t in $tasks) {
        foreach ($action in $t.Actions) {
            $exec = "$($action.Execute) $($action.Arguments)"
            if ($exec -match '-enc\s' -or $exec -match '-EncodedCommand' -or $exec -match 'FromBase64String' -or $exec -match 'IEX\s*\(|Invoke-Expression' -or $exec -match 'DownloadString|DownloadFile|WebClient|Invoke-WebRequest.*-OutFile') {
                $TasksSuspeitas += "$($t.TaskName)"
                break
            }
        }
    }
} catch {}
$TasksSuspeitasCount = $TasksSuspeitas.Count

# --- 3. MOTOR DE SCORING (39 CHECKS EM 5 CATEGORIAS) ---
$Checks = @()

if ($NomeAV -match "Defender" -or $NomeAV -eq 'NENHUM DETECTADO') {
    $Checks += New-Check "Endpoint Protection" "Antivirus / EDR" "ALTO" "BASICO ($NomeAV)" "Sem heuristica avancada. Nao detecta ataques Zero-Day nem possui Rollback nativo." "Adotar EDR com capacidade de Rollback automatico." "CIS 10.1" "PR.PT-1" 10
} else {
    $Checks += New-Check "Endpoint Protection" "Antivirus / EDR" "OK" "GERENCIADO ($NomeAV)" "Motor de seguranca ativo. Verificar se a ferramenta possui Rollback contra Ransomware." "Validar eficacia com teste de simulacao." "CIS 10.1" "PR.PT-1" 0
}

if ($DefenderRTP -eq $false) {
    $Checks += New-Check "Endpoint Protection" "Protecao em Tempo Real" "ALTO" "DESATIVADA" "Real-Time Protection desligada expoe o sistema a malware em execucao." "Reativar RTP ou instalar EDR ativo." "CIS 10.1" "PR.PT-1" 10
} elseif ($DefenderRTP -eq $true) {
    $Checks += New-Check "Endpoint Protection" "Protecao em Tempo Real" "OK" "ATIVA" "Monitoramento em tempo real ativo." "Manter." "CIS 10.1" "PR.PT-1" 0
} else {
    $Checks += New-Check "Endpoint Protection" "Protecao em Tempo Real" "BAIXO" "NAO DETECTADO" "Windows Defender nao instalado/gerenciado por outro produto." "Confirmar cobertura do EDR instalado." "CIS 10.1" "PR.PT-1" 0
}

if ($DefenderSigAge -eq -1) {
    $Checks += New-Check "Endpoint Protection" "Assinaturas Defender" "BAIXO" "NAO VERIFICAVEL" "Nao foi possivel determinar a idade das assinaturas." "Verificar manualmente via Get-MpComputerStatus." "CIS 10.1" "PR.PT-1" 0
} elseif ($DefenderSigAge -gt 7) {
    $Checks += New-Check "Endpoint Protection" "Assinaturas Defender" "ALTO" "DESATUALIZADAS ($DefenderSigAge dias)" "Assinaturas com mais de 7 dias nao detectam novas variantes de malware." "Forcar update de assinaturas (Update-MpSignature)." "CIS 10.1" "PR.PT-1" 10
} elseif ($DefenderSigAge -gt 3) {
    $Checks += New-Check "Endpoint Protection" "Assinaturas Defender" "MEDIO" "IDADE $DefenderSigAge DIAS" "Assinaturas com mais de 3 dias. Atualizacao diaria e recomendada." "Verificar agendamento de updates de assinatura." "CIS 10.1" "PR.PT-1" 5
} else {
    $Checks += New-Check "Endpoint Protection" "Assinaturas Defender" "OK" "ATUALIZADAS ($DefenderSigAge dias)" "Assinaturas recentes." "Manter." "CIS 10.1" "PR.PT-1" 0
}

if ($DefenderExclusions.Count -gt 0) {
    $exclList = ($DefenderExclusions | Select-Object -First 5) -join ", "
    $Checks += New-Check "Endpoint Protection" "Exclusoes Defender" "ALTO" "$($DefenderExclusions.Count) EXCLUSAO(OES)" "Exclusoes de scan podem ser abusadas por atacantes para persistir malware sem deteccao. Exemplos: $exclList" "Auditar e remover exclusoes nao justificadas." "CIS 10.1" "PR.PT-1" 10
} else {
    $Checks += New-Check "Endpoint Protection" "Exclusoes Defender" "OK" "NENHUMA" "Sem exclusoes de scan configuradas." "Manter." "CIS 10.1" "PR.PT-1" 0
}

$asrCount = 0
if ($DefenderASR) { $asrCount = $DefenderASR.Count }
if ($asrCount -eq 0) {
    $Checks += New-Check "Endpoint Protection" "ASR Rules" "ALTO" "NAO CONFIGURADAS" "Nenhuma regra de Attack Surface Reduction ativa. Office macros, scripts e execucoes suspeitas nao estao bloqueadas." "Habilitar regras ASR essenciais (block Office child, block script exe)." "CIS 10.1" "PR.PT-1" 10
} elseif ($asrCount -lt 8) {
    $Checks += New-Check "Endpoint Protection" "ASR Rules" "MEDIO" "$asrCount REGRA(S)" "Cobertura ASR parcial. Recomendado 8+ regras essenciais em modo Block." "Expandir conjunto de regras ASR." "CIS 10.1" "PR.PT-1" 5
} else {
    $Checks += New-Check "Endpoint Protection" "ASR Rules" "OK" "$asrCount REGRAS" "Cobertura ASR adequada." "Manter." "CIS 10.1" "PR.PT-1" 0
}

if ($DefenderNetworkProt -eq 1) {
    $Checks += New-Check "Endpoint Protection" "Network Protection" "OK" "ATIVO" "Bloqueio de conexoes maliciosas a nivel de rede ativo." "Manter." "CIS 10.1" "PR.PT-1" 0
} else {
    $Checks += New-Check "Endpoint Protection" "Network Protection" "MEDIO" "INATIVO" "Sem bloqueio de IPs/dominios maliciosos a nivel de rede." "Habilitar Network Protection em modo Block." "CIS 10.1" "PR.PT-1" 5
}

if ($DefenderCFA -eq 1) {
    $Checks += New-Check "Endpoint Protection" "Controlled Folder Access" "OK" "ATIVO" "Protecao anti-Ransomware ativa (bloqueio de alteracao em pastas criticas)." "Manter." "CIS 10.1" "PR.DS-1" 0
} else {
    $Checks += New-Check "Endpoint Protection" "Controlled Folder Access" "ALTO" "INATIVO" "Sem protecao anti-Ransomware nativa. Documentos podem ser cifrados livremente." "Habilitar Controlled Folder Access." "CIS 10.1" "PR.DS-1" 10
}

if ($RebootPending -or $DiasLigado -gt 15) {
    $Checks += New-Check "Endpoint Protection" "Patch Management" "ALTO" "PENDENTE ($DiasLigado dias ligado)" "Sistema vulneravel a exploits conhecidos por falta de reboot." "Reiniciar sistema e implantar ciclo de patch management." "CIS 7.1" "PR.MA-1" 10
} else {
    $Checks += New-Check "Endpoint Protection" "Patch Management" "OK" "ATUALIZADO" "Sistema em conformidade de ciclo de reinicio." "Manter politica de reinicio semanal." "CIS 7.1" "PR.MA-1" 0
}

if ($DiasDesdePatch -eq -1) {
    $Checks += New-Check "Endpoint Protection" "Ultima Atualizacao Windows" "BAIXO" "NAO DETECTADO" "Nao foi possivel identificar a ultima atualizacao instalada." "Verificar historico de updates manualmente." "CIS 7.1" "PR.MA-1" 0
} elseif ($DiasDesdePatch -gt 60) {
    $Checks += New-Check "Endpoint Protection" "Ultima Atualizacao Windows" "ALTO" "HA $DiasDesdePatch DIAS" "Sistema sem atualizacoes ha mais de 60 dias. Vulnerabilidades conhecidas expostas." "Aplicar todas as atualizacoes pendentes." "CIS 7.1" "PR.MA-1" 10
} elseif ($DiasDesdePatch -gt 30) {
    $Checks += New-Check "Endpoint Protection" "Ultima Atualizacao Windows" "MEDIO" "HA $DiasDesdePatch DIAS" "Ciclo de atualizacao acima do ideal." "Aplicar atualizacoes pendentes." "CIS 7.1" "PR.MA-1" 5
} else {
    $Checks += New-Check "Endpoint Protection" "Ultima Atualizacao Windows" "OK" "HA $DiasDesdePatch DIAS" "Ciclo de atualizacao em conformidade." "Manter rotina." "CIS 7.1" "PR.MA-1" 0
}

if ($SecureBoot -eq $true) {
    $Checks += New-Check "Endpoint Protection" "Secure Boot (UEFI)" "OK" "ATIVO" "Boot chaveado por UEFI. Impede bootkits e rootkits persistentes." "Manter." "CIS 1.4" "PR.PT-3" 0
} elseif ($SecureBoot -eq $false) {
    $Checks += New-Check "Endpoint Protection" "Secure Boot (UEFI)" "ALTO" "DESABILITADO" "Bootloader sem assinatura pode ser carregado, permitindo bootkits persistentes." "Habilitar Secure Boot no firmware UEFI." "CIS 1.4" "PR.PT-3" 10
} else {
    $Checks += New-Check "Endpoint Protection" "Secure Boot (UEFI)" "BAIXO" "LEGACY BIOS" "Firmware legado (BIOS). Sem protecao de cadeia de boot." "Migrar para UEFI e habilitar Secure Boot." "CIS 1.4" "PR.PT-3" 5
}

if ($HVCI) {
    $Checks += New-Check "Endpoint Protection" "Memory Integrity (HVCI)" "OK" "ATIVO" "Hypervisor-enforced Code Integrity ativo. Bloqueia drivers maliciosos." "Manter." "CIS 10.1" "PR.PT-3" 0
} else {
    $Checks += New-Check "Endpoint Protection" "Memory Integrity (HVCI)" "MEDIO" "INATIVO" "Sem HVCI, drivers maliciosos com assinatura podem ser carregados no kernel." "Habilitar Memory Integrity em Windows Security." "CIS 10.1" "PR.PT-3" 5
}

if ($SmartScreen -eq 'RequireAdmin' -or $SmartScreen -eq 'Block' -or $SmartScreen -eq 'Warn') {
    $Checks += New-Check "Endpoint Protection" "SmartScreen" "OK" "ATIVO ($SmartScreen)" "Bloqueio de executaveis e sites maliciosos ativo." "Manter." "CIS 10.1" "PR.PT-1" 0
} elseif ($SmartScreen -eq 'Off') {
    $Checks += New-Check "Endpoint Protection" "SmartScreen" "ALTO" "DESATIVADO" "SmartScreen desligado. Downloads maliciosos nao sao bloqueados." "Reativar SmartScreen nas configuracoes do Windows." "CIS 10.1" "PR.PT-1" 10
} else {
    $Checks += New-Check "Endpoint Protection" "SmartScreen" "BAIXO" "NAO VERIFICAVEL" "Estado do SmartScreen nao pode ser determinado." "Verificar manualmente em Configuracoes > Privacidade." "CIS 10.1" "PR.PT-1" 0
}

if ($Disco -and $Disco.HealthStatus -ne 'Healthy') {
    $Checks += New-Check "Endpoint Protection" "Saude do Disco" "CRITICO" "FALHA IMINENTE" "Degradacao fisica identificada na unidade de armazenamento." "Substituir hardware e validar backup." "CIS 11.1" "PR.IP-4" 10
} else {
    $Checks += New-Check "Endpoint Protection" "Saude do Disco" "OK" "SAUDAVEL" "SMART reporta disco saudavel. Monitorar anualmente a vida util." "Manter monitoramento SMART." "CIS 11.1" "PR.IP-4" 0
}

if (!$DMAProt) {
    $Checks += New-Check "Endpoint Protection" "Kernel DMA Protection" "MEDIO" "AUSENTE" "Acesso direto a RAM possivel via portas externas (Thunderbolt, PCIe)." "Habilitar Kernel DMA Protection no firmware." "CIS 1.4" "PR.PT-3" 5
} else {
    $Checks += New-Check "Endpoint Protection" "Kernel DMA Protection" "OK" "ATIVO" "Protecao Kernel DMA ativa." "Manter." "CIS 1.4" "PR.PT-3" 0
}

if ($TPMPresent -and $TPMReady) {
    $Checks += New-Check "Endpoint Protection" "TPM (Trusted Platform)" "OK" "PRESENTE E ATIVO" "Modulo criptografico disponivel. Base para BitLocker e Windows Hello." "Manter." "CIS 1.4" "PR.PT-3" 0
} elseif ($TPMPresent -and -not $TPMReady) {
    $Checks += New-Check "Endpoint Protection" "TPM (Trusted Platform)" "MEDIO" "PRESENTE / NAO PRONTO" "TPM detectado mas nao inicializado no firmware." "Inicializar TPM no BIOS/UEFI." "CIS 1.4" "PR.PT-3" 5
} else {
    $Checks += New-Check "Endpoint Protection" "TPM (Trusted Platform)" "ALTO" "AUSENTE" "Sem TPM, nao ha suporte nativo a BitLocker nem credenciais baseadas em hardware." "Avaliar upgrade de hardware." "CIS 1.4" "PR.PT-3" 10
}

if ($StartupCount -gt 15) {
    $Checks += New-Check "Endpoint Protection" "Itens de Inicializacao" "MEDIO" "$StartupCount ITENS" "Muitos itens na inicializacao aumentam superficie de ataque e tempo de boot." "Auditar e remover itens desnecessarios." "CIS 2.1" "PR.IP-1" 5
} elseif ($StartupCount -gt 0) {
    $Checks += New-Check "Endpoint Protection" "Itens de Inicializacao" "OK" "$StartupCount ITENS" "Quantidade dentro do esperado." "Revisar periodicamente." "CIS 2.1" "PR.IP-1" 0
} else {
    $Checks += New-Check "Endpoint Protection" "Itens de Inicializacao" "OK" "NENHUM" "Nenhum item na inicializacao registrado nas chaves Run." "Manter." "CIS 2.1" "PR.IP-1" 0
}

if ($TasksSuspeitasCount -gt 0) {
    $listaT = ($TasksSuspeitas | Select-Object -First 3) -join " | "
    $Checks += New-Check "Endpoint Protection" "Scheduled Tasks Suspeitas" "CRITICO" "$TasksSuspeitasCount TAREFA(S)" "Tarefas agendadas com comandos ofuscados/encoded - padrao classico de persistencia maliciosa. Exemplos: $listaT" "Investigar imediatamente. Pode indicar comprometimento ativo." "CIS 2.1" "DE.CM-1" 15
} else {
    $Checks += New-Check "Endpoint Protection" "Scheduled Tasks Suspeitas" "OK" "NENHUMA" "Nenhuma tarefa agendada com padroes suspeitos." "Manter." "CIS 2.1" "DE.CM-1" 0
}

if ($Cloud.Tipo -like "*IMUTAVEL*") {
    $Checks += New-Check "Data Protection" "Cloud & Backup" "OK" $Cloud.Nome "Solucao com imutabilidade ativa. Ambiente resiliente a Ransomware." "Manter e testar restore periodicamente." "CIS 11.1" "PR.IP-4" 0
} elseif ($Cloud.Tipo -like "*SINCRONIZACAO*") {
    $Checks += New-Check "Data Protection" "Cloud & Backup" "MEDIO" "$($Cloud.Nome) (Apenas Sync)" "Sincronizacao apenas espelha dados. Ransomware propaga para a nuvem em segundos." "Implantar backup com imutabilidade e Air-Gap." "CIS 11.1" "PR.IP-4" 15
} else {
    $Checks += New-Check "Data Protection" "Cloud & Backup" "CRITICO" "INEXISTENTE" "Sem protecao off-site. Risco extremo de perda total em ataque ou desastre fisico." "Implantar estrategia 3-2-1 com imutabilidade." "CIS 11.1" "PR.IP-4" 25
}

if (!$BitStatus) {
    $Checks += New-Check "Data Protection" "Criptografia de Disco" "CRITICO" "DADOS EXPOSTOS" "Ausencia de criptografia. Roubo do disco resulta em violacao direta da LGPD." "Habilitar BitLocker e guardar Recovery Key em cofre externo." "CIS 3.6" "PR.DS-1" 15
} else {
    $Checks += New-Check "Data Protection" "Criptografia de Disco" "OK" "ATIVO (BitLocker)" "Disco protegido. Garantir o backup da Recovery Key em cofre externo." "Auditar acesso a Recovery Key." "CIS 3.6" "PR.DS-1" 0
}

if ($FW_Domain -eq $false -or $FW_Private -eq $false -or $FW_Public -eq $false) {
    $perfisOff = @()
    if ($FW_Domain -eq $false)  { $perfisOff += "Domain" }
    if ($FW_Private -eq $false) { $perfisOff += "Private" }
    if ($FW_Public -eq $false)  { $perfisOff += "Public" }
    $Checks += New-Check "Network Security" "Windows Firewall" "CRITICO" "DESATIVADO: $($perfisOff -join ', ')" "Perfil(is) de Firewall desabilitado(s). Sistema exposto a conexoes de entrada." "Habilitar todos os perfis de Firewall do Windows." "CIS 4.1" "PR.PT-4" 15
} else {
    $Checks += New-Check "Network Security" "Windows Firewall" "OK" "ATIVO (3 perfis)" "Firewall habilitado em Domain, Private e Public." "Manter." "CIS 4.1" "PR.PT-4" 0
}

if ($RiscoFirewall) {
    $Checks += New-Check "Network Security" "Portas Expostas" "CRITICO" $StatusFirewall "Portas abertas expoem a maquina a exploracao remota (Brute-force, exploits SMB)." "Bloquear portas e revisar regras de Firewall." "CIS 4.8" "PR.PT-4" 15
} else {
    $Checks += New-Check "Network Security" "Portas Expostas" "OK" "SEGURO" "Portas criticas isoladas ou filtradas." "Manter monitoramento." "CIS 4.8" "PR.PT-4" 0
}

if ($SMB1Enabled -eq $true) {
    $Checks += New-Check "Network Security" "Protocolo SMBv1" "CRITICO" "HABILITADO" "SMBv1 e o vetor do WannaCry/EternalBlue. Protocolo obsoleto e intrinsecamente inseguro." "Desabilitar SMBv1 imediatamente." "CIS 4.8" "PR.PT-4" 15
} elseif ($SMB1Enabled -eq $false) {
    $Checks += New-Check "Network Security" "Protocolo SMBv1" "OK" "DESABILITADO" "Protocolo legado desativado." "Manter." "CIS 4.8" "PR.PT-4" 0
} else {
    $Checks += New-Check "Network Security" "Protocolo SMBv1" "BAIXO" "NAO VERIFICAVEL" "Nao foi possivel verificar o estado do SMBv1." "Verificar manualmente." "CIS 4.8" "PR.PT-4" 0
}

if ($SMBSigning -eq $true) {
    $Checks += New-Check "Network Security" "SMB Signing" "OK" "OBRIGATORIO" "Assinatura SMB obrigatoria. Protege contra ataques MITM em SMB." "Manter." "CIS 4.8" "PR.DS-2" 0
} elseif ($SMBSigning -eq $false) {
    $Checks += New-Check "Network Security" "SMB Signing" "MEDIO" "NAO OBRIGATORIO" "Assinatura SMB nao obrigatoria. Vulneravel a SMB Relay e MITM." "Habilitar assinatura SMB obrigatoria." "CIS 4.8" "PR.DS-2" 5
} else {
    $Checks += New-Check "Network Security" "SMB Signing" "BAIXO" "NAO VERIFICAVEL" "Nao foi possivel verificar SMB Signing." "Verificar via Get-SmbServerConfiguration." "CIS 4.8" "PR.DS-2" 0
}

if ($LLMNRDisabled) {
    $Checks += New-Check "Network Security" "LLMNR" "OK" "DESABILITADO" "LLMNR desabilitado. Mitiga ataques de poisoning (Responder)." "Manter." "CIS 4.8" "PR.PT-4" 0
} else {
    $Checks += New-Check "Network Security" "LLMNR" "MEDIO" "HABILITADO" "LLMNR permite captura de hashes NTLMv2 via Responder em rede local." "Desabilitar LLMNR via GPO." "CIS 4.8" "PR.PT-4" 5
}

if ($NetBIOSDisabled) {
    $Checks += New-Check "Network Security" "NetBIOS over TCP/IP" "OK" "DESABILITADO" "NetBIOS desabilitado em todas as interfaces." "Manter." "CIS 4.8" "PR.PT-4" 0
} else {
    $Checks += New-Check "Network Security" "NetBIOS over TCP/IP" "MEDIO" "HABILITADO" "NetBIOS legado expoe nomes de maquina e facilita poisoning." "Desabilitar NetBIOS nas interfaces de rede." "CIS 4.8" "PR.PT-4" 5
}

if ($RDPEnabled) {
    $Checks += New-Check "Network Security" "RDP (Area de Trabalho Remota)" "ALTO" "HABILITADO" "RDP exposto e alvo de Brute-Force e exploits como BlueKeep." "Desabilitar RDP ou colocar atras de VPN com MFA." "CIS 4.8" "PR.AC-3" 10
} else {
    $Checks += New-Check "Network Security" "RDP (Area de Trabalho Remota)" "OK" "DESABILITADO" "RDP desabilitado." "Manter." "CIS 4.8" "PR.AC-3" 0
}

if ($HasShares) {
    $Checks += New-Check "Network Security" "Pastas Compartilhadas" "MEDIO" "EXPOSTO: $ListaShares" "Compartilhamentos SMB abertos criam rotas laterais para Ransomware." "Remover compartilhamentos desnecessarios ou aplicar ACLs restritivas." "CIS 3.3" "PR.AC-4" 5
} else {
    $Checks += New-Check "Network Security" "Pastas Compartilhadas" "OK" "SEGURO" "Sem compartilhamentos de risco." "Manter." "CIS 3.3" "PR.AC-4" 0
}

if (!$DNSSeguro) {
    $Checks += New-Check "Network Security" "DNS Security" "MEDIO" "INSEGURO ($ListaDNS)" "DNS padrao de operadora. Facilita interceptacao e DNS Spoofing." "Adotar DNS Filtering com bloqueio de categorias maliciosas." "CIS 4.9" "PR.PT-4" 5
} else {
    $Checks += New-Check "Network Security" "DNS Security" "OK" "SEGURO" "Resolucao de DNS confiavel." "Manter." "CIS 4.9" "PR.PT-4" 0
}

if ($UACEnabled -eq 0) {
    $Checks += New-Check "Identity & Access" "Controle de Conta (UAC)" "CRITICO" "DESABILITADO" "UAC desligado permite escalonamento silencioso de privilegios." "Habilitar UAC imediatamente." "CIS 5.4" "PR.AC-4" 15
} elseif ($UACEnabled -eq 1 -and $UACLevel -eq 0) {
    $Checks += New-Check "Identity & Access" "Controle de Conta (UAC)" "ALTO" "ELEVACAO SILENCIOSA" "UAC ativo mas configurado para elevar sem solicitar consentimento." "Configurar UAC para 'Perguntar sempre'." "CIS 5.4" "PR.AC-4" 10
} else {
    $Checks += New-Check "Identity & Access" "Controle de Conta (UAC)" "OK" "ATIVO" "UAC ativo e configurado corretamente." "Manter." "CIS 5.4" "PR.AC-4" 0
}

if ($GuestEnabled) {
    $Checks += New-Check "Identity & Access" "Conta Guest" "ALTO" "HABILITADA" "Conta Guest ativa permite acesso anonimo ao sistema." "Desabilitar conta Guest imediatamente." "CIS 5.1" "PR.AC-1" 10
} else {
    $Checks += New-Check "Identity & Access" "Conta Guest" "OK" "DESABILITADA" "Conta Guest desabilitada." "Manter." "CIS 5.1" "PR.AC-1" 0
}

if ($CountAdmins -gt 3) {
    $Checks += New-Check "Identity & Access" "Administradores Locais" "MEDIO" "$CountAdmins CONTAS" "Excesso de contas administrativas viola principio do menor privilegio." "Reduzir a 1-2 contas com elevacao sob demanda." "CIS 5.2" "PR.AC-4" 5
} else {
    $Checks += New-Check "Identity & Access" "Administradores Locais" "OK" "$CountAdmins CONTA(S)" "Quantidade de admins dentro do aceitavel." "Manter." "CIS 5.2" "PR.AC-4" 0
}

if ($MinPwdLen -eq 0) {
    $Checks += New-Check "Identity & Access" "Politica de Senha" "ALTO" "SEM MINIMO" "Nenhum comprimento minimo configurado. Senhas fracas permitidas." "Definir minimo de 12 caracteres via GPO." "CIS 5.2" "PR.AC-1" 10
} elseif ($MinPwdLen -lt 8) {
    $Checks += New-Check "Identity & Access" "Politica de Senha" "ALTO" "MINIMO $MinPwdLen CHARS" "Comprimento minimo abaixo do recomendado (NIST: 12+)." "Elevar para 12 caracteres ou mais." "CIS 5.2" "PR.AC-1" 10
} elseif ($MinPwdLen -lt 12) {
    $Checks += New-Check "Identity & Access" "Politica de Senha" "MEDIO" "MINIMO $MinPwdLen CHARS" "Politica aceitavel, porem abaixo da recomendacao NIST." "Considerar elevar para 12+ caracteres." "CIS 5.2" "PR.AC-1" 5
} else {
    $Checks += New-Check "Identity & Access" "Politica de Senha" "OK" "MINIMO $MinPwdLen CHARS" "Politica de senha em conformidade com NIST." "Manter." "CIS 5.2" "PR.AC-1" 0
}

if ($ContasSemExpira.Count -gt 0) {
    $listaC = ($ContasSemExpira | Select-Object -First 5) -join ", "
    $Checks += New-Check "Identity & Access" "Senhas sem Expiracao" "MEDIO" "$($ContasSemExpira.Count) CONTA(S)" "Contas com senha 'nunca expira': $listaC. Aumentam janela de exposicao em caso de vazamento." "Definir expiracao ou usar gestor de credenciais." "CIS 5.2" "PR.AC-1" 5
} else {
    $Checks += New-Check "Identity & Access" "Senhas sem Expiracao" "OK" "NENHUMA" "Todas as contas com expiracao de senha configurada." "Manter." "CIS 5.2" "PR.AC-1" 0
}

if ($CredGuard) {
    $Checks += New-Check "Identity & Access" "Credential Guard" "OK" "ATIVO" "Credenciais isoladas via virtualizacao. Bloqueia Pass-the-Hash." "Manter." "CIS 5.4" "PR.AC-4" 0
} else {
    $Checks += New-Check "Identity & Access" "Credential Guard" "MEDIO" "INATIVO" "Sem Credential Guard, hashes NTLM podem ser capturados e reusados (Pass-the-Hash)." "Habilitar Credential Guard em ambiente com UEFI+TPM." "CIS 5.4" "PR.AC-4" 5
}

if ($LSAPPL) {
    $Checks += New-Check "Identity & Access" "LSA Protection (RunAsPPL)" "OK" "ATIVO" "LSA protegido contra injecao (Mimikatz bloqueado)." "Manter." "CIS 5.4" "PR.AC-4" 0
} else {
    $Checks += New-Check "Identity & Access" "LSA Protection (RunAsPPL)" "MEDIO" "INATIVO" "LSA sem RunAsPPL permite dumping de credenciais (Mimikatz, ProcDump)." "Habilitar RunAsPPL no registro + reboot." "CIS 5.4" "PR.AC-4" 5
}

if ($WDigest -eq 1) {
    $Checks += New-Check "Identity & Access" "WDigest" "CRITICO" "HABILITADO" "WDigest armazena senhas em texto claro na memoria (LSASS). Vetor do Mimikatz." "Definir UseLogonCredential=0 e reiniciar." "CIS 5.4" "PR.AC-4" 15
} else {
    $Checks += New-Check "Identity & Access" "WDigest" "OK" "DESABILITADO" "WDigest nao armazena credenciais em texto claro." "Manter." "CIS 5.4" "PR.AC-4" 0
}

if ($ExecPolicyGPO) {
    if ($ExecPolicy -in @('Bypass','Unrestricted')) {
        $Checks += New-Check "Compliance & Hygiene" "PowerShell Execution Policy" "ALTO" "$ExecPolicy (GPO)" "Politica definida por GPO corporativa ($ExecPolicyGPOOrigem) permite execucao irrestrita. Alteracao local sera sobrescrita." "Avaliar com time de infraestrutura." "CIS 2.5" "PR.IP-1" 0
    } else {
        $Checks += New-Check "Compliance & Hygiene" "PowerShell Execution Policy" "OK" "$ExecPolicy (GPO)" "Politica gerenciada por GPO corporativa." "Manter conforme GPO." "CIS 2.5" "PR.IP-1" 0
    }
} else {
    switch ($ExecPolicy) {
        'Unrestricted' { $Checks += New-Check "Compliance & Hygiene" "PowerShell Execution Policy" "ALTO" "UNRESTRICTED" "Scripts arbitrarios podem ser executados sem bloqueio." "Definir como RemoteSigned ou AllSigned." "CIS 2.5" "PR.IP-1" 10 }
        'Bypass'       { $Checks += New-Check "Compliance & Hygiene" "PowerShell Execution Policy" "CRITICO" "BYPASS" "Execution Policy totalmente contornada. Nenhum controle sobre scripts." "Redefinir imediatamente para RemoteSigned." "CIS 2.5" "PR.IP-1" 15 }
        'RemoteSigned' { $Checks += New-Check "Compliance & Hygiene" "PowerShell Execution Policy" "OK" "REMOTESIGNED" "Politica equilibrada entre seguranca e usabilidade." "Manter." "CIS 2.5" "PR.IP-1" 0 }
        'AllSigned'    { $Checks += New-Check "Compliance & Hygiene" "PowerShell Execution Policy" "OK" "ALLSIGNED" "Todos os scripts precisam ser assinados." "Manter." "CIS 2.5" "PR.IP-1" 0 }
        'Restricted'   { $Checks += New-Check "Compliance & Hygiene" "PowerShell Execution Policy" "OK" "RESTRICTED" "Scripts PowerShell bloqueados por padrao." "Manter." "CIS 2.5" "PR.IP-1" 0 }
        default        { $Checks += New-Check "Compliance & Hygiene" "PowerShell Execution Policy" "BAIXO" "$ExecPolicy" "Politica incomum." "Avaliar politica corporativa." "CIS 2.5" "PR.IP-1" 0 }
    }
}

if ($ScriptBlockLogging) {
    $Checks += New-Check "Compliance & Hygiene" "PowerShell Logging" "OK" "ATIVO" "ScriptBlock Logging ativo. Permite deteccao de comandos ofuscados." "Manter." "CIS 8.2" "DE.AE-3" 0
} else {
    $Checks += New-Check "Compliance & Hygiene" "PowerShell Logging" "MEDIO" "INATIVO" "ScriptBlock Logging desativado. Comandos ofuscados nao ficam registrados para deteccao." "Habilitar via GPO para visibilidade de ameacas." "CIS 8.2" "DE.AE-3" 5
}

if ($Spying) {
    $Checks += New-Check "Compliance & Hygiene" "Privacidade / Telemetria" "BAIXO" "TELEMETRIA ATIVA" "Sistema Operacional enviando dados rastreaveis externamente." "Aplicar hardening de telemetria." "CIS 18.9" "PR.DS-5" 5
} else {
    $Checks += New-Check "Compliance & Hygiene" "Privacidade / Telemetria" "OK" "PRIVADO" "ID de Anuncios e Telemetria bloqueados." "Manter." "CIS 18.9" "PR.DS-5" 0
}

# --- 4. CALCULO FINAL DE SCORE ---
$Score = 100
foreach ($c in $Checks) {
    if ($c.Penalidade -gt 0) { $Score -= $c.Penalidade }
}
if ($Score -lt 0) { $Score = 0 }
if ($Score -gt 100) { $Score = 100 }

$CountCritico = ($Checks | Where-Object { $_.Severidade -eq 'CRITICO' }).Count
$CountAlto    = ($Checks | Where-Object { $_.Severidade -eq 'ALTO' }).Count
$CountMedio   = ($Checks | Where-Object { $_.Severidade -eq 'MEDIO' }).Count
$CountBaixo   = ($Checks | Where-Object { $_.Severidade -eq 'BAIXO' }).Count
$CountOk      = ($Checks | Where-Object { $_.Severidade -eq 'OK' }).Count

if ($Score -lt 60) { $CorScore="#ef4444"; $Nivel="RISCO CRITICO" }
elseif ($Score -lt 85) { $CorScore="#f59e0b"; $Nivel="RISCO MODERADO" }
else { $CorScore="#10b981"; $Nivel="AMBIENTE SEGURO" }

$Categorias = @('Endpoint Protection','Data Protection','Network Security','Identity & Access','Compliance & Hygiene')
$ScorePorCategoria = @{}
foreach ($cat in $Categorias) {
    $checksCat = $Checks | Where-Object { $_.Categoria -eq $cat }
    $penalCat = ($checksCat | Measure-Object -Property Penalidade -Sum).Sum
    $scoreCat = 100 - $penalCat
    if ($scoreCat -lt 0) { $scoreCat = 0 }
    $ScorePorCategoria[$cat] = @{
        Score = $scoreCat
        Total = $checksCat.Count
        Criticos = ($checksCat | Where-Object { $_.Severidade -eq 'CRITICO' }).Count
    }
}

$Comparativo = $null
if ($ComparePath -and (Test-Path $ComparePath)) {
    try {
        $Anterior = Get-Content $ComparePath -Raw | ConvertFrom-Json
        $Comparativo = @{
            Data = $Anterior.Data_Scan
            ScoreAnterior = $Anterior.Score_Global
            Delta = $Score - $Anterior.Score_Global
        }
    } catch {}
}

$Dados = @{
    Data_Scan    = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    Computador   = $PC
    IP_Externo   = $IP
    ISP          = $ISP
    Anonimizado  = $Anonymize.IsPresent
    Score_Global = $Score
    Avaliacao    = $Nivel
    Severidades  = @{
        Critico = $CountCritico
        Alto    = $CountAlto
        Medio   = $CountMedio
        Baixo   = $CountBaixo
        Ok      = $CountOk
    }
    Score_Por_Categoria = $ScorePorCategoria
    Checks = $Checks | Select-Object Categoria, Vetor, Severidade, Status, Analise, Acao, CIS, NIST
}

$Path = Get-OutputPath
$JsonFile = Join-Path $Path "WinSecAudit_Data_$PC.json"
$CsvFile  = Join-Path $Path "WinSecAudit_Report_$PC.csv"
$Dados | ConvertTo-Json -Depth 6 | Out-File $JsonFile -Encoding UTF8
$Checks | Select-Object Categoria, Vetor, Severidade, Status, Analise, Acao, CIS, NIST | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8

function Get-CatColor ($score) {
    if ($score -lt 60) { return '#ef4444' }
    elseif ($score -lt 85) { return '#f59e0b' }
    else { return '#10b981' }
}

function Get-RowsForCategoria ($cat) {
    $rows = ""
    $checksCat = $Checks | Where-Object { $_.Categoria -eq $cat }
    foreach ($c in $checksCat) {
        $sevClass = switch ($c.Severidade) {
            'CRITICO' { 'sev-critico' }
            'ALTO'    { 'sev-alto' }
            'MEDIO'   { 'sev-medio' }
            'BAIXO'   { 'sev-baixo' }
            default   { 'sev-ok' }
        }
        $rows += "<tr><td class='item'>$($c.Vetor)</td><td><span class='badge $sevClass'>$($c.Severidade)</span></td><td class='status-cell'>$($c.Status)</td><td class='analise'>$($c.Analise)</td><td class='acao'>$($c.Acao)</td><td class='compliance'><span class='tag'>$($c.CIS)</span><br><span class='tag nist'>$($c.NIST)</span></td></tr>"
    }
    return $rows
}

$CategoriasHTML = ""
foreach ($cat in $Categorias) {
    $scoreCat = $ScorePorCategoria[$cat].Score
    $totalCat = $ScorePorCategoria[$cat].Total
    $critCat  = $ScorePorCategoria[$cat].Criticos
    $corCat   = Get-CatColor $scoreCat
    $openAttr = if ($critCat -gt 0) { " open" } else { "" }
    $CategoriasHTML += @"
<details class='cat-block'$openAttr>
    <summary>
        <div class='cat-summary'>
            <div class='cat-name'>$cat <span class='cat-count'>($totalCat checagens)</span></div>
            <div class='cat-score' style='color:$corCat'>$scoreCat/100</div>
        </div>
    </summary>
    <table>
        <thead>
            <tr>
                <th>Vetor Analisado</th>
                <th>Severidade</th>
                <th>Status Tecnico</th>
                <th>Analise de Risco</th>
                <th>Acao Recomendada</th>
                <th>CIS / NIST</th>
            </tr>
        </thead>
        <tbody>
            $(Get-RowsForCategoria $cat)
        </tbody>
    </table>
</details>
"@
}

$CategoriasBarsHTML = ""
foreach ($cat in $Categorias) {
    $sc = $ScorePorCategoria[$cat].Score
    $cc = Get-CatColor $sc
    $CategoriasBarsHTML += @"
<div class='cat-bar-item'>
    <div class='cat-bar-label'><span>$cat</span><strong style='color:$cc'>$sc</strong></div>
    <div class='cat-bar-track'><div class='cat-bar-fill' style='width:$sc%;background:$cc'></div></div>
</div>
"@
}

$ComparativoHTML = ""
if ($Comparativo) {
    $delta = $Comparativo.Delta
    $corDelta = if ($delta -gt 0) { '#10b981' } elseif ($delta -lt 0) { '#ef4444' } else { '#94a3b8' }
    $simbolo = if ($delta -gt 0) { "+" } else { "" }
    $ComparativoHTML = @"
<div class='compare-box'>
    <div class='compare-item'><small>Score Anterior</small><strong>$($Comparativo.ScoreAnterior)</strong></div>
    <div class='compare-arrow'>→</div>
    <div class='compare-item'><small>Score Atual</small><strong style='color:$CorScore'>$Score</strong></div>
    <div class='compare-delta' style='color:$corDelta'>$simbolo$delta</div>
</div>
"@
}

$AnonBannerHTML = ""
if ($Anonymize) {
    $AnonBannerHTML = "<div style='background:rgba(245,158,11,0.15);border-bottom:1px solid #f59e0b;padding:12px 40px;color:#fcd34d;font-size:11px;text-transform:uppercase;letter-spacing:1.5px;font-weight:800;text-align:center'>Relatorio Anonimizado - Dados de Identidade de Rede Substituidos para Compartilhamento Publico</div>"
}

$HTML = @"
<!DOCTYPE html>
<html lang='pt-br'>
<head>
<meta charset='UTF-8'>
<title>WinSecAudit - $PC</title>
<style>
    * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; color-adjust: exact !important; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Roboto, Helvetica, sans-serif; background-color: #070a12 !important; color: #e2e8f0 !important; margin: 0; padding: 24px; }
    .container { max-width: 1320px; margin: 0 auto; background-color: #0f1524 !important; border-radius: 16px; border: 1px solid #1e293b !important; overflow: hidden; box-shadow: 0 20px 60px rgba(0,0,0,0.6); }
    .header { background: linear-gradient(135deg, #0b1220 0%, #131c30 55%, #1a2540 100%) !important; padding: 36px 40px; border-bottom: 1px solid #1e293b !important; display: flex; justify-content: space-between; align-items: center; gap: 30px; }
    .brand-block { display: flex; align-items: center; gap: 20px; }
    .brand-mark { width: 60px; height: 60px; border-radius: 14px; background: linear-gradient(135deg, #3b82f6 0%, #6366f1 100%); display: flex; align-items: center; justify-content: center; font-weight: 900; font-size: 22px; color: #fff !important; letter-spacing: -1px; box-shadow: 0 8px 24px rgba(59,130,246,0.35); }
    .brand h1 { margin: 0; color: #fff !important; text-transform: uppercase; letter-spacing: 3px; font-size: 26px; font-weight: 800; }
    .brand h1 span { color: #60a5fa !important; }
    .brand p { margin: 6px 0 0; color: #94a3b8 !important; font-size: 11px; letter-spacing: 1.5px; text-transform: uppercase; }
    .brand .target-line { margin-top: 8px; font-size: 10px; color: #64748b !important; letter-spacing: 1px; font-family: 'Consolas', monospace; }
    .score-ring { width: 150px; height: 150px; border-radius: 50%; background: conic-gradient($CorScore 0% $Score%, #1e293b $Score% 100%); display: flex; align-items: center; justify-content: center; position: relative; flex-shrink: 0; box-shadow: 0 0 40px rgba(0,0,0,0.5); }
    .score-ring::before { content: ''; position: absolute; inset: 12px; background: #0f1524; border-radius: 50%; }
    .score-inner { position: relative; z-index: 1; text-align: center; }
    .score-val { font-size: 46px; font-weight: 900; color: $CorScore !important; line-height: 1; letter-spacing: -2px; }
    .score-tag { font-size: 9px; color: #94a3b8 !important; text-transform: uppercase; letter-spacing: 1.5px; margin-top: 4px; font-weight: 700; }
    .score-nivel { font-size: 10px; color: $CorScore !important; font-weight: 800; margin-top: 6px; letter-spacing: 0.5px; }
    .intel-bar { display: grid; grid-template-columns: repeat(5, 1fr); background-color: #0a0f1c !important; border-bottom: 1px solid #1e293b !important; }
    .intel-item { padding: 18px 12px; text-align: center; border-right: 1px solid #1e293b !important; }
    .intel-item:last-child { border-right: none; }
    .intel-item small { display: block; color: #64748b !important; font-size: 9px; text-transform: uppercase; margin-bottom: 6px; font-weight: 700; letter-spacing: 1px; }
    .intel-item strong { color: #f8fafc !important; font-size: 13px; font-weight: 700; word-break: break-word; }
    .exec-summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; padding: 24px 40px; background-color: #0b1018 !important; border-bottom: 1px solid #1e293b !important; }
    .exec-card { background-color: #131a29 !important; border-radius: 10px; padding: 14px; border-left: 4px solid #334155 !important; }
    .exec-card .exec-num { font-size: 24px; font-weight: 900; line-height: 1; }
    .exec-card .exec-lbl { font-size: 10px; color: #94a3b8 !important; text-transform: uppercase; letter-spacing: 1px; margin-top: 6px; font-weight: 700; }
    .exec-critico { border-left-color: #ef4444 !important; } .exec-critico .exec-num { color: #ef4444 !important; }
    .exec-alto    { border-left-color: #f97316 !important; } .exec-alto .exec-num { color: #f97316 !important; }
    .exec-medio   { border-left-color: #f59e0b !important; } .exec-medio .exec-num { color: #f59e0b !important; }
    .exec-baixo   { border-left-color: #3b82f6 !important; } .exec-baixo .exec-num { color: #3b82f6 !important; }
    .exec-ok      { border-left-color: #10b981 !important; } .exec-ok .exec-num { color: #10b981 !important; }
    .cat-scores { padding: 24px 40px; background-color: #0a0f1c !important; border-bottom: 1px solid #1e293b !important; display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; }
    .cat-bar-item { display: flex; flex-direction: column; gap: 8px; }
    .cat-bar-label { display: flex; justify-content: space-between; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: #94a3b8 !important; font-weight: 700; }
    .cat-bar-label strong { font-size: 13px; }
    .cat-bar-track { height: 6px; background: #1e293b; border-radius: 3px; overflow: hidden; }
    .cat-bar-fill { height: 100%; border-radius: 3px; }
    .content { padding: 32px 40px; }
    h3 { color: #60a5fa !important; text-transform: uppercase; font-size: 13px; border-bottom: 1px solid #1e293b !important; padding-bottom: 12px; margin: 0 0 24px; letter-spacing: 2px; font-weight: 800; }
    details.cat-block { border: 1px solid #1e293b !important; border-radius: 10px; margin-bottom: 18px; overflow: hidden; background: #0b1018 !important; }
    details.cat-block > summary { padding: 16px 20px; cursor: pointer; list-style: none; background: #131a29 !important; border-bottom: 1px solid #1e293b !important; user-select: none; }
    details.cat-block > summary::-webkit-details-marker { display: none; }
    details.cat-block > summary::after { content: 'v'; float: right; color: #64748b !important; font-size: 10px; }
    .cat-summary { display: flex; justify-content: space-between; align-items: center; }
    .cat-name { color: #f8fafc !important; font-weight: 800; font-size: 13px; letter-spacing: 1px; text-transform: uppercase; }
    .cat-count { color: #64748b !important; font-weight: 500; font-size: 11px; margin-left: 6px; letter-spacing: 0; text-transform: none; }
    .cat-score { font-weight: 900; font-size: 15px; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; color: #64748b !important; font-size: 9px; text-transform: uppercase; padding: 12px; border-bottom: 1px solid #1e293b !important; letter-spacing: 1px; font-weight: 800; background: #0a0f1c !important; }
    td { padding: 14px 12px; border-bottom: 1px solid #131a29 !important; vertical-align: top; }
    .item { font-weight: 700; color: #f1f5f9 !important; font-size: 12px; width: 14%; }
    .status-cell { font-size: 11px; color: #e2e8f0 !important; font-weight: 600; width: 14%; }
    .analise { font-size: 11px; color: #94a3b8 !important; width: 30%; line-height: 1.5; }
    .acao { font-size: 11px; color: #60a5fa !important; font-weight: 700; width: 20%; line-height: 1.5; text-transform: uppercase; letter-spacing: 0.3px; }
    .compliance { font-size: 10px; color: #94a3b8 !important; width: 8%; font-family: 'Consolas', monospace; }
    .tag { display: inline-block; background: #1e293b !important; color: #93c5fd !important; padding: 2px 6px; border-radius: 3px; font-size: 9px; margin-bottom: 3px; }
    .tag.nist { color: #a78bfa !important; }
    .badge { display: inline-block; padding: 4px 8px; border-radius: 5px; font-size: 9px; font-weight: 900; letter-spacing: 0.8px; text-align: center; min-width: 60px; }
    .sev-critico { background: rgba(239,68,68,0.15) !important; color: #fca5a5 !important; border: 1px solid #ef4444 !important; }
    .sev-alto    { background: rgba(249,115,22,0.15) !important; color: #fdba74 !important; border: 1px solid #f97316 !important; }
    .sev-medio   { background: rgba(245,158,11,0.15) !important; color: #fcd34d !important; border: 1px solid #f59e0b !important; }
    .sev-baixo   { background: rgba(59,130,246,0.15) !important; color: #93c5fd !important; border: 1px solid #3b82f6 !important; }
    .sev-ok      { background: rgba(16,185,129,0.15) !important; color: #6ee7b7 !important; border: 1px solid #10b981 !important; }
    .footer-cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 18px; margin-top: 40px; }
    .card { background-color: #0a0f1c !important; padding: 22px; border-radius: 10px; border: 1px solid #1e293b !important; border-top: 3px solid #ef4444 !important; }
    .card.warning { border-top-color: #f59e0b !important; }
    .card.info { border-top-color: #3b82f6 !important; }
    .card h4 { margin: 0 0 10px 0; color: #f8fafc !important; font-size: 12px; text-transform: uppercase; letter-spacing: 1.5px; font-weight: 800; }
    .card p { margin: 0; color: #94a3b8 !important; font-size: 12px; line-height: 1.6; }
    .btn { display: block; width: 300px; margin: 40px auto 0; background: linear-gradient(135deg, #3b82f6 0%, #6366f1 100%) !important; color: #ffffff !important; text-align: center; padding: 16px; border-radius: 8px; text-decoration: none; font-weight: 800; text-transform: uppercase; font-size: 12px; letter-spacing: 1.5px; border: none; cursor: pointer; }
    .report-footer { text-align: center; padding: 24px; color: #475569 !important; font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; font-family: 'Consolas', monospace; }
    @media print { body { padding: 0; } .btn { display: none !important; } details.cat-block { break-inside: avoid; } details.cat-block > summary::after { display: none; } @page { margin: 0.5cm; } }
</style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <div class='brand-block'>
                <div class='brand-mark'>WS</div>
                <div class='brand'>
                    <h1>WinSec <span>Audit</span></h1>
                    <p>Analise de Postura de Seguranca em Endpoints Windows</p>
                    <div class='target-line'>TARGET: $PC &nbsp;|&nbsp; DATA: $(Get-Date -Format 'dd/MM/yyyy HH:mm') &nbsp;|&nbsp; DOMINIO: $DOM &nbsp;|&nbsp; CHECKS: $($Checks.Count)</div>
                </div>
            </div>
            <div class='score-ring'>
                <div class='score-inner'>
                    <div class='score-val'>$Score</div>
                    <div class='score-tag'>Score</div>
                    <div class='score-nivel'>$Nivel</div>
                </div>
            </div>
        </div>
        $AnonBannerHTML
        <div class='intel-bar'>
            <div class='intel-item'><small>IP Publico</small><strong>$IP</strong></div>
            <div class='intel-item'><small>Provedor</small><strong>$ISP</strong></div>
            <div class='intel-item'><small>Memoria RAM</small><strong>$RAM GB</strong></div>
            <div class='intel-item'><small>Admins Locais</small><strong>$CountAdmins Usuario(s)</strong></div>
            <div class='intel-item'><small>Tempo Ligado</small><strong>$DiasLigado Dias</strong></div>
        </div>
        <div class='exec-summary'>
            <div class='exec-card exec-critico'><div class='exec-num'>$CountCritico</div><div class='exec-lbl'>Criticos</div></div>
            <div class='exec-card exec-alto'><div class='exec-num'>$CountAlto</div><div class='exec-lbl'>Altos</div></div>
            <div class='exec-card exec-medio'><div class='exec-num'>$CountMedio</div><div class='exec-lbl'>Medios</div></div>
            <div class='exec-card exec-baixo'><div class='exec-num'>$CountBaixo</div><div class='exec-lbl'>Baixos</div></div>
            <div class='exec-card exec-ok'><div class='exec-num'>$CountOk</div><div class='exec-lbl'>Conformes</div></div>
        </div>
        <div class='cat-scores'>
            $CategoriasBarsHTML
        </div>
        $ComparativoHTML
        <div class='content'>
            <h3>Matriz de Vulnerabilidades por Categoria</h3>
            $CategoriasHTML
            <div class='footer-cards'>
                <div class='card'>
                    <h4>Parada Operacional</h4>
                    <p>Sem solucao de backup com imutabilidade, a recuperacao apos Ransomware pode levar dias ou semanas. Considere estrategia 3-2-1 com Air-Gap.</p>
                </div>
                <div class='card warning'>
                    <h4>Conformidade LGPD</h4>
                    <p>Discos sem criptografia e portas expostas configuram negligencia tecnica na protecao de dados pessoais. Multas podem chegar a 2% do faturamento.</p>
                </div>
                <div class='card info'>
                    <h4>Proximos Passos</h4>
                    <p>Priorizar itens CRITICO e ALTO. Revalidar o ambiente apos correcoes para emissao de novo relatorio comparativo.</p>
                </div>
            </div>
            <button onclick='window.print()' class='btn'>Imprimir Laudo Tecnico (PDF)</button>
        </div>
        <div class='report-footer'>
            WINSECAUDIT v2.0 &nbsp;&bull;&nbsp; GERADO EM $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss') &nbsp;&bull;&nbsp; CONFIDENCIAL
        </div>
    </div>
</body>
</html>
"@

$HtmlFile = Join-Path $Path "WinSecAudit_$PC.html"
$UTF8BOM = [System.Text.UTF8Encoding]::new($true)
[System.IO.File]::WriteAllText($HtmlFile, $HTML, $UTF8BOM)

Write-Progress-Msg ""
Write-Progress-Msg "=== AUDITORIA CONCLUIDA ===" 'Green'
Write-Progress-Msg "Modo............: $(if ($Anonymize) { 'ANONIMIZADO (demo)' } else { 'REAL (dados reais)' })" 'Cyan'
Write-Progress-Msg "Score...........: $Score / 100 ($Nivel)" 'Cyan'
Write-Progress-Msg "Total Checks....: $($Checks.Count)" 'White'
Write-Progress-Msg "Criticos........: $CountCritico" 'Red'
Write-Progress-Msg "Altos...........: $CountAlto" 'Magenta'
Write-Progress-Msg "Medios..........: $CountMedio" 'Yellow'
Write-Progress-Msg "Baixos..........: $CountBaixo" 'Blue'
Write-Progress-Msg "Conformes.......: $CountOk" 'Green'
Write-Progress-Msg ""
Write-Progress-Msg "JSON............: $JsonFile" 'White'
Write-Progress-Msg "CSV.............: $CsvFile" 'White'
Write-Progress-Msg "HTML............: $HtmlFile" 'White'
Write-Progress-Msg ""

if (-not $NoOpen) { Invoke-Item $HtmlFile }