# Detectar_tentativas_de_exfiltracao
Detectar tentativas de exfiltração de dados
# Data Exfiltration Detection Lab

> **Plataforma:** TryHackMe / LetsDefend  
> **Ferramentas:** Wireshark · Splunk (SPL)  
> **Protocolos analisados:** DNS Tunneling · FTP · HTTP · ICMP  
> **Objetivo:** Detectar e investigar tentativas de exfiltração de dados usando análise de tráfego de rede (PCAP) e correlação de logs em SIEM.

---
## O que é Exfiltração de Dados?

Exfiltração de dados é a **transferência não autorizada de informações sensíveis** de dentro de uma rede para um destino externo controlado pelo atacante. Pode ocorrer via malware, credenciais comprometidas ou ação de insider malicioso.

### Por que os atacantes fazem isso?

| Motivação | Descrição |
|---|---|
| Ganho financeiro | Dados de cartão, registros pessoais vendidos na dark web |
| Espionagem | Propriedade intelectual, segredos comerciais |
| Ransomware | Roubo de dados antes da criptografia — extorsão dupla |
| Sabotagem | Vazamento de dados internos para prejudicar a reputação |
| Persistência | Mapeamento do ambiente para ataques futuros |

---

## Fases de um Ataque de Exfiltração

```
[1] Descoberta/Coleta
    └── Atacante localiza arquivos sensíveis na rede

[2] Preparação/Compressão
    └── Agrega, comprime, criptografa ou codifica (ZIP, RAR, Base64, esteganografia)

[3] Transporte/Exfiltração
    └── Transferência via rede, mídia removível, nuvem ou canais secretos

[4] Comando e Controle (C2)
    └── Orquestra a transferência e confirma o recebimento dos dados
```

---

## DNS Tunneling

### Conceito
O DNS é um protocolo universalmente liberado em firewalls corporativos — quase todo host realiza pesquisas DNS na porta **UDP 53**. Exatamente por isso ele é um canal secreto atraente para atacantes.
No DNS Tunneling, dados são **fragmentados e codificados** (Base32/Base64) e inseridos dentro dos *labels* do subdomínio de cada consulta:

<img width="1206" height="210" alt="image" src="https://github.com/user-attachments/assets/e7bd864a-fa5d-47da-a9db-e8035b331fc8" />
Como;
```
[DADO_CODIFICADO_EM_BASE64].tunnelcorp.net
a3rWfuze7kctrf0e2ef5.tunnelcorp.net
```

O servidor DNS controlado pelo atacante recebe, remonta e decodifica os dados — sem que firewalls ou proxies percebam, pois o tráfego parece consultas DNS normais.

### Indicadores de Ataque (IoAs)

- Alto volume de consultas para um único domínio externo
- Labels de subdomínio excepcionalmente longos (> 60–100 caracteres)
- Padrões de alta entropia ou Base32/Base64 no nome da consulta
- Tipos de registro raros (TXT, NULL) com respostas grandes
- Consultas sem resposta (NXDOMAIN frequente)
- Comportamento de sinalização — consultas em intervalos regulares

---

### Wireshark — Análise do `dns_exfil.pcap`

**Passo 1 — Isolar todo tráfego DNS**
```
dns
```
> Exibe todas as consultas e respostas DNS. Ponto de partida para entender o volume e os destinos.
---
**Passo 2 — Filtrar apenas consultas sem resposta**
```
dns.flags.response == 0
```
> Consultas sem resposta são suspeitas: indicam que o atacante está apenas *enviando* dados codificados, sem precisar de resolução legítima. Em tunelamento DNS, o servidor C2 já sabe o que fazer com a consulta recebida.
---

**Passo 3 — Identificar consultas com subdomínios longos**
```
dns && frame.len > 70
```

<img width="1914" height="898" alt="image" src="https://github.com/user-attachments/assets/397f334a-1e6a-4de1-b627-c1558e47b22d" />

> Um nome de domínio legítimo raramente ultrapassa 30–40 caracteres. Consultas acima de 70 bytes no total indicam que o subdomínio está carregando um *payload* — fragmento de dado exfiltrado codificado em Base32/Base64.

---

**Passo 4 — Filtrar pelo domínio C2 identificado**
```
dns && dns.qry.name contains "tunnelcorp.net"
```

<img width="1908" height="898" alt="image" src="https://github.com/user-attachments/assets/4bcf55b2-5d47-4261-b4b4-d7886ba461cd" />

> Após identificar o domínio suspeito no passo anterior, este filtro confirma **quais hosts internos estão comprometidos** e comunicando com o C2.

---

### Splunk — Correlação de Logs DNS

**Passo 1 — Visão geral dos logs**
```
index=data_exfil sourcetype=DNS_logs
```

<img width="1907" height="759" alt="image" src="https://github.com/user-attachments/assets/9d4c6433-c65f-49c0-8466-a18414712895" />

> Carrega todos os eventos DNS indexados. Permite uma primeira visão do volume total e dos campos disponíveis (src_ip, query, dst_ip, protocol).

---

**Passo 2 — Contar consultas por IP de origem**
```
index="data_exfil" sourcetype="DNS_logs" | stats count by src_ip
```

<img width="1914" height="738" alt="image" src="https://github.com/user-attachments/assets/a21fd251-38e8-4cff-a25c-0048e4d73154" />

> Hosts legítimos fazem um volume normal de consultas DNS. Um host com volume **anormalmente alto** em relação aos demais é fortemente suspeito de estar sendo usado como canal de exfiltração.

---

**Passo 3 — Ordenar consultas por frequência e identificar nomes suspeitos**
```
index="data_exfil" sourcetype="dns_logs" | stats count by query | sort -count
```

<img width="1918" height="783" alt="image" src="https://github.com/user-attachments/assets/171f070e-484c-495f-a24a-c266925ffd47" />

> Domínios legítimos (google.com, microsoft.com) aparecem com contagens altas e nomes curtos. Domínios com nomes longos e aparência aleatória — mesmo com contagem baixa — são os alvos de investigação.

---

**Passo 4 — Filtrar consultas com comprimento suspeito**
```
index="data_exfil" sourcetype="DNS_logs" | where len(query) > 30
```

<img width="1922" height="797" alt="image" src="https://github.com/user-attachments/assets/fcc455e5-a487-444e-b6b5-c14cfab42df8" />

> Isola consultas cujo nome ultrapassa 30 caracteres. Estes são os subdomínios que carregam dados codificados. Aumentar o threshold (ex: `> 50`) refina ainda mais os resultados.

---
<img width="795" height="436" alt="image" src="https://github.com/user-attachments/assets/88c45f57-6f2a-4096-b005-f3455a76d3ea" />

### Findings

| Indicador | Valor |
|---|---|
| Domínio C2 | `tunnelcorp.net` |
| Total de registros suspeitos | 315 |
| Host com maior volume | `192.168.1.103` |
| Técnica confirmada | DNS Tunneling via subdomínio codificado |

---

## FTP Exfiltration

### Conceito

O FTP (File Transfer Protocol) é um dos protocolos mais antigos para transferência de arquivos via TCP/IP. Atacantes o utilizam para mover grandes volumes de dados para servidores externos, frequentemente via **credenciais comprometidas** ou servidores mal configurados.

O grande problema do FTP: **tudo trafega em texto puro** — usuários, senhas e conteúdo dos arquivos são visíveis a qualquer um com acesso ao tráfego de rede.

### Como atacantes usam FTP

- Servidores FTP públicos ou internos mal configurados como destino
- Credenciais comprometidas (contas de serviço, usuários com senhas fracas)
- Portas não padronizadas ou túneis para misturar ao tráfego legítimo
- Modo PASV (passivo) para abrir canais de dados em portas efêmeras

### Indicadores de Ataque (IoAs)

- Comandos `USER`/`PASS` com credenciais suspeitas (ex: `guest`, `admin`, `test`)
- Comando `STOR` — upload de arquivos do cliente para o servidor
- Transferências para IPs externos fora do horário comercial
- Arquivos com extensões sensíveis: `.csv`, `.pdf`, `.xlsx`, `.tar`, `.zip`
- Grande volume de dados em canais de dados PASV

---

### Wireshark — Análise do `ftp-lab.pcap`

**Passo 1 — Isolar sessões FTP completas**
```
ftp || ftp-data
```
<img width="1916" height="881" alt="image" src="https://github.com/user-attachments/assets/b229cfa5-82ba-4058-9e31-df7fcddef00d" />

> Captura tanto o canal de **controle FTP** (comandos: USER, PASS, STOR, RETR) quanto o canal de **dados** onde os arquivos são efetivamente transferidos. Necessário usar os dois para ter a visão completa da sessão.

---

**Passo 2 — Capturar credenciais em texto puro**
```
ftp.request.command == "USER" || ftp.request.command == "PASS"
```
<img width="1912" height="886" alt="image" src="https://github.com/user-attachments/assets/a58dd7cf-4557-42e4-9808-3433075713c4" />

> FTP não criptografa as credenciais. Este filtro exibe todos os logins em texto puro — usuários como `guest`, `test`, `admin` ou senhas fracas são red flags imediatos. No lab, foi identificado acesso com conta `guest` a um servidor externo suspeito.

---

**Passo 3 — Identificar uploads de arquivos**
```
ftp contains "STOR"
```
> O comando `STOR` indica que o cliente está **enviando um arquivo para o servidor** — o oposto de `RETR` (download). Em contexto de exfiltração, é o principal comando a monitorar.
---

**Passo 4 — Filtrar por tipo de arquivo sensível**
```
ftp contains "csv"
```
> Refina a busca para arquivos com extensões específicas. Substitua por `pdf`, `xlsx`, `tar`, `zip` para cobrir outros formatos sensíveis.

---

**Passo 5 — Isolar transferências com payload real**
```
ftp && frame.len > 90
```
> Filtra pacotes de controle (pequenos) e mantém apenas os que carregam dados reais. Combine com **Follow → TCP Stream** para visualizar o conteúdo completo do arquivo transferido.
<img width="1913" height="336" alt="image" src="https://github.com/user-attachments/assets/4f0ecbf8-5793-41ff-ae6e-9df76356dfe4" />
<img width="1234" height="481" alt="image" src="https://github.com/user-attachments/assets/42e16f79-4610-4601-b108-2505297bfecc" />

---

### Findings

| Indicador | Valor |
|---|---|
| IP comprometido | `192.168.1.103` |
| Credencial usada | `guest` (conta padrão não desabilitada) |
| Arquivo exfiltrado | `customer_data.xlsx` |
| Servidor de destino | IP externo suspeito |
| Evidência | Conteúdo visualizado via Follow → TCP Stream |

---

## Referências MITRE ATT&CK

| Técnica | ID | Descrição |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Uso do canal C2 existente para exfiltração |
| Exfiltration Over Alternative Protocol | [T1048](https://attack.mitre.org/techniques/T1048/) | DNS, ICMP, FTP como canais alternativos |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | DNS/ICMP tunneling |

---

##  Stack Utilizada

| Ferramenta | Uso |
|---|---|
| **Wireshark** | Análise de arquivos PCAP |
| **Splunk (SPL)** | Correlação de logs |
| **TryHackMe** | Ambiente de laboratório controlado |

---

*Documentado por Nicolas Farias — SOC Analyst | Cybersecurity Research & SOC Labs*
