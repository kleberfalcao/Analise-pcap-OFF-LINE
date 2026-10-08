# ============================================================
# ARQUIVO: Analise_pcap_OT_melhorado.py
# Multi-PCAP · timeline unificada · irregularidades · mapa com
# protocolos nas arestas · nós OT em losango · coluna Captura
# ============================================================
import hashlib
import html
import ipaddress
import math
import os
import re
import struct
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx
import pandas as pd
import plotly.express as px
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, IPv6, Raw, TCP, UDP
from scapy.utils import PcapNgReader, PcapReader


TAMANHO_MAXIMO_ARQUIVO_MB = 500
LIMITE_PACOTES_AMOSTRA = 5000
LIMITE_EVENTOS = 1000
LIMITE_NOS_MAPA = 60
LIMITE_ARESTAS_MAPA = 180
LIMITE_PAYLOAD = 8192
LIMITE_TRANSFERENCIA_OT = 1024
LIMITE_EVENTOS_OT = 1000

# Portas/protocolos OT reconhecidos por heurísticas de captura.
# A identificação não significa, por si só, que o tráfego seja malicioso.
PORTAS_OT = {
    102: "Siemens S7comm / ISO-TSAP",
    502: "Modbus TCP",
    2404: "IEC 60870-5-104",
    44818: "EtherNet/IP / CIP",
    4840: "OPC UA",
    20000: "DNP3",
    47808: "BACnet/IP",
    5000: "Mitsubishi MC / SLMP (candidato)",
    9600: "Omron FINS (candidato)",
    48898: "Beckhoff ADS (candidato)",
}

META_PROTOCOLOS_OT = {
    "Siemens S7comm / ISO-TSAP": ("Siemens", "S7 / S7comm"),
    "Modbus TCP": ("Schneider / múltiplos fabricantes", "Modbus TCP"),
    "IEC 60870-5-104": ("IEC / múltiplos fabricantes", "IEC-104"),
    "EtherNet/IP / CIP": ("Rockwell / múltiplos fabricantes", "EtherNet/IP / CIP"),
    "OPC UA": ("OPC Foundation / múltiplos fabricantes", "OPC UA"),
    "DNP3": ("DNP3 / múltiplos fabricantes", "DNP3"),
    "BACnet/IP": ("BACnet / múltiplos fabricantes", "BACnet/IP"),
    "Mitsubishi MC / SLMP (candidato)": ("Mitsubishi Electric", "MC / SLMP"),
    "Omron FINS (candidato)": ("Omron", "FINS"),
    "Beckhoff ADS (candidato)": ("Beckhoff", "ADS"),
}

PORTAS_TRANSFERENCIA_OT = {102, 502, 2404, 44818, 4840, 20000, 47808, 5000, 9600, 48898}

FUNCOES_MODBUS_ESCRITA = {5, 6, 15, 16, 22, 23}
FUNCOES_S7_TRANSFERENCIA_CANDIDATA = {0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}

st.set_page_config(
    page_title="Analisador OT de PCAP",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    /* Fontes do sistema — 100% offline (sem Google Fonts) */
    html, body, [class*="css"] {
      font-family: system-ui, -apple-system, "Segoe UI", Roboto, Ubuntu, Cantarell, "Noto Sans", sans-serif;
    }
    .stApp { background: linear-gradient(180deg, #0B1220 0%, #0F172A 40%, #111827 100%); }
    [data-testid="stSidebar"] {
        background: #0B1220;
        border-right: 1px solid #1E293B;
    }
    .block-container { padding-top: 1.2rem; max-width: 1400px; }
    div[data-testid="stMetric"] {
        background: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 12px;
        padding: 12px 16px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.25);
    }
    div[data-testid="stMetric"] label { color: #94A3B8 !important; }
    div[data-testid="stMetric"] [data-testid="stMetricValue"] { color: #F8FAFC !important; font-weight: 600; }
    .stTabs [data-baseweb="tab-list"] {
        gap: 6px;
        background: #0B1220;
        border-radius: 10px;
        padding: 6px;
        border: 1px solid #1E293B;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        color: #94A3B8;
        padding: 8px 14px;
    }
    .stTabs [aria-selected="true"] {
        background: #1E293B !important;
        color: #F1F5F9 !important;
    }
    h1, h2, h3 { color: #F1F5F9 !important; letter-spacing: -0.02em; }
    .stDataFrame { border-radius: 10px; overflow: hidden; border: 1px solid #1E293B; }
    div[data-testid="stFileUploader"] {
        background: #0F172A;
        border: 1px dashed #334155;
        border-radius: 12px;
        padding: 8px;
    }
    .footer-apackets {
        margin-top: 48px;
        padding: 28px 20px 36px;
        border-top: 1px solid #1E293B;
        color: #94A3B8;
        font-size: 0.88rem;
        line-height: 1.55;
    }
    .footer-apackets h4 {
        color: #E2E8F0 !important;
        font-size: 0.95rem;
        margin: 0 0 8px 0;
        letter-spacing: 0.02em;
    }
    .footer-apackets a { color: #38BDF8; text-decoration: none; }
    .footer-apackets .cols {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 20px;
        margin-top: 12px;
    }
    /* Título na mesma faixa do botão Deploy, no canto oposto (esquerda) */
    header[data-testid="stHeader"] {
        background: rgba(11, 18, 32, 0.92) !important;
    }
    header[data-testid="stHeader"]::before {
        content: "🔎 Analisador OT de PCAP";
        position: absolute;
        left: 1.1rem;
        top: 50%;
        transform: translateY(-50%);
        font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Ubuntu, sans-serif;
        font-weight: 600;
        font-size: 0.98rem;
        color: #F8FAFC;
        letter-spacing: -0.01em;
        white-space: nowrap;
        pointer-events: none;
        z-index: 10;
    }
    /* Esconde o título duplicado no corpo da página */
    h1#titulo-app { display: none !important; }
    section.main > div:first-child { padding-top: 1.6rem; }
    /* Empurra o uploader para baixo da faixa do título/Deploy */
    div[data-testid="stFileUploader"] { margin-top: 0.75rem; }
    .block-container { padding-top: 2rem !important; }
    </style>
    """,
    unsafe_allow_html=True,
)


def bytes_legivel(valor):
    for unidade in ["B", "KB", "MB", "GB", "TB"]:
        if valor < 1024 or unidade == "TB":
            return f"{valor:.2f} {unidade}"
        valor /= 1024


def data_utc(timestamp):
    try:
        return datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
    except Exception:
        return None


def texto_data(valor):
    return valor.strftime("%Y-%m-%d %H:%M:%S") if valor else "-"


def ip_interno(ip):
    try:
        endereco = ipaddress.ip_address(ip)
        return (
            endereco.is_private
            or endereco.is_loopback
            or endereco.is_link_local
        )
    except Exception:
        return False


def ip_publico(ip):
    try:
        endereco = ipaddress.ip_address(ip)

        return not (
            endereco.is_private
            or endereco.is_loopback
            or endereco.is_multicast
            or endereco.is_reserved
            or endereco.is_unspecified
            or endereco.is_link_local
        )
    except Exception:
        return False


def ips_pacote(pacote):
    if IP in pacote:
        return pacote[IP].src, pacote[IP].dst, "IPv4"

    if IPv6 in pacote:
        return pacote[IPv6].src, pacote[IPv6].dst, "IPv6"

    return None, None, None


def transporte_pacote(pacote):
    if TCP in pacote:
        return (
            "TCP",
            int(pacote[TCP].sport),
            int(pacote[TCP].dport),
            str(pacote[TCP].flags),
        )

    if UDP in pacote:
        return (
            "UDP",
            int(pacote[UDP].sport),
            int(pacote[UDP].dport),
            "",
        )

    if ICMP in pacote:
        return "ICMP", None, None, ""

    return "Outro", None, None, ""


def protocolo_pacote(pacote):
    if DNS in pacote:
        return "DNS"
    if TCP in pacote:
        return "TCP"
    if UDP in pacote:
        return "UDP"
    if ICMP in pacote:
        return "ICMP"
    if ARP in pacote:
        return "ARP"
    if IP in pacote:
        return "IPv4"
    if IPv6 in pacote:
        return "IPv6"

    return "Outro"


def nome_servico(porta):
    servicos = {
        20: "FTP Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP Submission",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1900: "SSDP",
        3128: "Proxy HTTP",
        8000: "HTTP Alternativo",
        8080: "HTTP Alternativo",
        8443: "HTTPS Alternativo",
    }

    return servicos.get(porta, f"Porta {porta}")


def chave_fluxo(origem, destino, transporte, porta_origem, porta_destino):
    if not origem or not destino:
        return None

    ponta_a, ponta_b = sorted(
        [
            (origem, porta_origem or 0),
            (destino, porta_destino or 0),
        ],
        key=lambda item: (item[0], item[1]),
    )

    return (
        transporte,
        ponta_a[0],
        ponta_a[1],
        ponta_b[0],
        ponta_b[1],
    )


def texto_fluxo(chave):
    transporte, ip_a, porta_a, ip_b, porta_b = chave
    return f"{transporte} | {ip_a}:{porta_a} ↔ {ip_b}:{porta_b}"


def id_usuario(usuario):
    if not usuario:
        return "Não identificado"

    valor_hash = hashlib.sha256(
        usuario.encode("utf-8", errors="ignore")
    ).hexdigest()

    return f"usuario_{valor_hash[:10]}"


def mascarar_arquivo(nome):
    nome = nome.replace("\\", "/").split("/")[-1].strip()

    if not nome:
        return "Arquivo não identificado"

    if "." in nome:
        base, extensao = nome.rsplit(".", 1)
        return f"{base[:3]}***.{extensao[:10]}"

    return f"{nome[:3]}***"


def payload_limitado(pacote):
    try:
        if Raw in pacote:
            return bytes(pacote[Raw].load)[:LIMITE_PAYLOAD]
    except Exception:
        pass

    return b""


def abrir_pcap(caminho):
    for leitor in (PcapReader, PcapNgReader):
        try:
            return leitor(caminho)
        except Exception:
            continue

    raise ValueError("Arquivo PCAP ou PCAPNG inválido ou não suportado.")


def salvar_upload(arquivo):
    extensao = Path(arquivo.name).suffix.lower()

    if extensao not in {".pcap", ".pcapng", ".cap"}:
        raise ValueError("Use um arquivo PCAP, PCAPNG ou CAP.")

    arquivo.seek(0)

    temporario = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=extensao,
    )

    sha256 = hashlib.sha256()

    try:
        while True:
            bloco = arquivo.read(1024 * 1024)

            if not bloco:
                break

            sha256.update(bloco)
            temporario.write(bloco)
    finally:
        temporario.close()

    return temporario.name, sha256.hexdigest()


def carregar_iocs(arquivo):
    ips = set()
    dominios = set()

    if arquivo is None:
        return ips, dominios

    conteudo = arquivo.getvalue().decode(
        "utf-8",
        errors="replace",
    )

    for linha in conteudo.splitlines():
        linha = linha.strip()

        if not linha or linha.startswith("#"):
            continue

        for valor in re.split(r"[,;\s]+", linha.lower()):
            valor = valor.strip().rstrip(".")

            if not valor:
                continue

            try:
                ipaddress.ip_address(valor)
                ips.add(valor)
            except ValueError:
                if "." in valor and len(valor) <= 253:
                    dominios.add(valor)

    return ips, dominios


def extrair_consulta_dns(pacote, instante):
    if DNS not in pacote or DNSQR not in pacote:
        return None

    if int(pacote[DNS].qr) != 0:
        return None

    try:
        dominio = pacote[DNSQR].qname.decode(
            "utf-8",
            errors="replace",
        ).rstrip(".")
    except Exception:
        dominio = str(pacote[DNSQR].qname).rstrip(".")

    origem, destino, _ = ips_pacote(pacote)

    return {
        "Data/hora UTC": texto_data(instante),
        "Origem": origem or "-",
        "Servidor DNS": destino or "-",
        "Domínio": dominio,
        "Tipo DNS": int(pacote[DNSQR].qtype),
    }


def adicionar_evento(eventos, chaves, evento):
    # Eventos de exposição usam "Protocolo"; eventos OT usam "Protocolo OT".
    # .get evita KeyError (que antes descartava todo evento OT como "erro").
    chave = (
        evento.get("Categoria"),
        evento.get("Protocolo", evento.get("Protocolo OT")),
        evento.get("Origem"),
        evento.get("Destino"),
        evento.get("Porta destino"),
        evento.get("Detalhe"),
        evento.get("Usuário identificado"),
        evento.get("Arquivo"),
        evento.get("Nº pacote"),
    )

    if chave not in chaves and len(eventos) < LIMITE_EVENTOS:
        chaves.add(chave)
        eventos.append(evento)


def detectar_exposicao(
    pacote,
    instante,
    origem,
    destino,
    porta_origem,
    porta_destino,
    fluxo,
    usuarios_fluxo,
    eventos,
    chaves_eventos,
    num_pacote=None,
):
    """
    Identifica exposição potencial em protocolos sem TLS.
    Senhas não são mostradas, exportadas ou armazenadas.
    """
    payload = payload_limitado(pacote)

    if not payload:
        return

    payload_maiusculo = payload.upper()

    base = {
        "Nº pacote": num_pacote if num_pacote is not None else "-",
        "Data/hora UTC": texto_data(instante),
        "Origem": origem or "-",
        "Destino": destino or "-",
        "Porta destino": porta_destino or "-",
        "Usuário identificado": "Não identificado",
        "Arquivo": "-",
    }

    if porta_destino == 21 or porta_origem == 21:
        usuario = re.search(
            rb"(?im)^\s*USER\s+([^\r\n\s]+)",
            payload,
        )

        if usuario and fluxo:
            usuarios_fluxo[fluxo] = id_usuario(
                usuario.group(1).decode(
                    "utf-8",
                    errors="replace",
                )
            )

        if re.search(rb"(?im)^\s*PASS\s+\S+", payload):
            adicionar_evento(
                eventos,
                chaves_eventos,
                {
                    **base,
                    "Categoria": "Possível credencial exposta",
                    "Protocolo": "FTP sem TLS",
                    "Usuário identificado": usuarios_fluxo.get(
                        fluxo,
                        "Não identificado",
                    ),
                    "Ação": "Autenticação FTP (PASS)",
                    "Detalhe": (
                        "Comando FTP PASS identificado. A senha não foi "
                        "exibida nem armazenada."
                    ),
                },
            )

        arquivo = re.search(
            rb"(?im)^\s*(RETR|STOR|APPE|STOU)\s+([^\r\n]+)",
            payload,
        )

        if arquivo:
            operacao = arquivo.group(1).decode(
                "utf-8",
                errors="replace",
            )

            nome = arquivo.group(2).decode(
                "utf-8",
                errors="replace",
            )

            if operacao.upper() in {"RETR"}:
                acao_ftp = f"Download FTP ({operacao})"
            elif operacao.upper() in {"STOR", "APPE", "STOU"}:
                acao_ftp = f"Upload FTP ({operacao})"
            else:
                acao_ftp = f"Transferência FTP ({operacao})"
            adicionar_evento(
                eventos,
                chaves_eventos,
                {
                    **base,
                    "Categoria": "Possível transferência de arquivo",
                    "Protocolo": "FTP sem TLS",
                    "Arquivo": mascarar_arquivo(nome),
                    "Ação": acao_ftp,
                    "Detalhe": f"Comando FTP {operacao} identificado — {acao_ftp}.",
                },
            )

    if porta_destino == 110 or porta_origem == 110:
        usuario = re.search(
            rb"(?im)^\s*USER\s+([^\r\n\s]+)",
            payload,
        )

        if usuario and fluxo:
            usuarios_fluxo[fluxo] = id_usuario(
                usuario.group(1).decode(
                    "utf-8",
                    errors="replace",
                )
            )

        if re.search(rb"(?im)^\s*PASS\s+\S+", payload):
            adicionar_evento(
                eventos,
                chaves_eventos,
                {
                    **base,
                    "Categoria": "Possível credencial exposta",
                    "Protocolo": "POP3 sem TLS",
                    "Usuário identificado": usuarios_fluxo.get(
                        fluxo,
                        "Não identificado",
                    ),
                    "Detalhe": (
                        "Comando POP3 PASS identificado. A senha não foi "
                        "exibida nem armazenada."
                    ),
                },
            )

    if porta_destino == 23 or porta_origem == 23:
        adicionar_evento(
            eventos,
            chaves_eventos,
            {
                **base,
                "Categoria": "Canal com risco de exposição",
                "Protocolo": "Telnet",
                "Ação": "Sessão Telnet (texto claro)",
                "Detalhe": (
                    "Tráfego Telnet identificado. O protocolo normalmente "
                    "não utiliza criptografia — comandos e credenciais podem trafegar em claro."
                ),
            },
        )

    if porta_destino in {25, 587} or porta_origem in {25, 587}:
        if b"AUTH LOGIN" in payload_maiusculo or b"AUTH PLAIN" in payload_maiusculo:
            adicionar_evento(
                eventos,
                chaves_eventos,
                {
                    **base,
                    "Categoria": "Possível credencial exposta",
                    "Protocolo": "SMTP sem TLS",
                    "Detalhe": (
                        "Comando SMTP AUTH identificado. Verifique se a "
                        "sessão utilizava STARTTLS."
                    ),
                },
            )

    if porta_destino == 143 or porta_origem == 143:
        if re.search(rb"(?im)^\S+\s+LOGIN\s+", payload):
            adicionar_evento(
                eventos,
                chaves_eventos,
                {
                    **base,
                    "Categoria": "Possível credencial exposta",
                    "Protocolo": "IMAP sem TLS",
                    "Detalhe": (
                        "Comando IMAP LOGIN identificado. Os valores não "
                        "foram exibidos."
                    ),
                },
            )

    portas_http = {80, 8000, 8080, 3128}
    parece_http = bool(re.match(rb"(?:GET|POST|PUT|HEAD|HTTP/1\.[01])[ /]", payload))

    if parece_http or porta_destino in portas_http or porta_origem in portas_http:
        basic = b"AUTHORIZATION: BASIC " in payload_maiusculo

        senha_formulario = bool(
            re.search(
                rb"(?i)(password|passwd|pwd|senha)\s*=",
                payload,
            )
        )

        usuario = re.search(
            rb"(?i)(username|user|login|email|usuario)\s*=\s*([^&\s\r\n]+)",
            payload,
        )

        usuario_hash = (
            id_usuario(
                usuario.group(2).decode(
                    "utf-8",
                    errors="replace",
                )
            )
            if usuario
            else "Não identificado"
        )

        if basic or senha_formulario:
            detalhe = (
                "Cabeçalho HTTP Basic Authorization identificado."
                if basic
                else "Campo de senha em possível formulário HTTP identificado."
            )

            adicionar_evento(
                eventos,
                chaves_eventos,
                {
                    **base,
                    "Categoria": "Possível credencial exposta",
                    "Protocolo": "HTTP sem TLS",
                    "Usuário identificado": usuario_hash,
                    "Detalhe": (
                        f"{detalhe} A senha não foi exibida nem armazenada."
                    ),
                },
            )

        arquivo = re.search(
            rb'(?i)content-disposition:\s*.*?filename="?([^"\r\n;]+)',
            payload,
        )

        if arquivo:
            adicionar_evento(
                eventos,
                chaves_eventos,
                {
                    **base,
                    "Categoria": "Possível transferência de arquivo",
                    "Protocolo": "HTTP sem TLS",
                    "Arquivo": mascarar_arquivo(
                        arquivo.group(1).decode(
                            "utf-8",
                            errors="replace",
                        )
                    ),
                    "Detalhe": (
                        "Cabeçalho HTTP Content-Disposition identificado "
                        "(possível upload/download de arquivo via HTTP)."
                    ),
                    "Ação": "Upload/download HTTP (Content-Disposition)",
                },
            )

    # SMB / CIFS (porta 445 ou 139) — heurística de comandos e nomes de arquivo
    if porta_destino in {445, 139} or porta_origem in {445, 139}:
        # Strings comuns em SMB (ASCII no payload)
        smb_cmds = []
        if re.search(rb"(?i)NT\s*Create|CreateAndX|CREATE", payload):
            smb_cmds.append("abertura/criação de arquivo (NT Create)")
        if re.search(rb"(?i)WRITE|WriteAndX", payload) and not re.search(
            rb"(?i)WriteAndX\s*Response", payload[:40]
        ):
            smb_cmds.append("escrita/cópia de dados (Write)")
        if re.search(rb"(?i)READ|ReadAndX", payload):
            smb_cmds.append("leitura de arquivo (Read)")
        if re.search(rb"(?i)DELETE|Delete\s*DIR", payload):
            smb_cmds.append("exclusão de arquivo/diretório")
        if re.search(rb"(?i)TREE\s*CONNECT|TreeConnect", payload):
            smb_cmds.append("conexão a compartilhamento (Tree Connect)")
        if re.search(rb"(?i)SESSION\s*SETUP|SessionSetup", payload):
            smb_cmds.append("autenticação de sessão SMB")
        if re.search(rb"(?i)TRANS2|FIND_FIRST|FIND_BOTH", payload):
            smb_cmds.append("listagem/busca de arquivos")

        # Nome de arquivo com extensão típica no payload SMB
        nome_smb = re.search(
            rb"([A-Za-z0-9_\-.]{3,40}\.(?:exe|dll|bat|ps1|txt|doc|docx|xls|xlsx|pdf|zip|rar|lnk))",
            payload,
        )
        arquivo_smb = (
            mascarar_arquivo(nome_smb.group(1).decode("utf-8", errors="replace"))
            if nome_smb
            else "-"
        )

        if smb_cmds or nome_smb:
            acao_smb = "; ".join(smb_cmds) if smb_cmds else "atividade SMB com nome de arquivo"
            adicionar_evento(
                eventos,
                chaves_eventos,
                {
                    **base,
                    "Categoria": "Ação SMB / compartilhamento",
                    "Protocolo": "SMB/CIFS",
                    "Arquivo": arquivo_smb,
                    "Ação": acao_smb,
                    "Detalhe": (
                        f"Tráfego SMB com indício de: {acao_smb}."
                        + (f" Arquivo observado: {arquivo_smb}." if arquivo_smb != "-" else "")
                    ),
                },
            )
        else:
            adicionar_evento(
                eventos,
                chaves_eventos,
                {
                    **base,
                    "Categoria": "Comunicação SMB",
                    "Protocolo": "SMB/CIFS",
                    "Ação": "Tráfego SMB observado",
                    "Detalhe": "Tráfego na porta SMB/CIFS (445/139) sem comando textual claro no payload amostrado.",
                },
            )


def classificar_protocolo_ot(porta_origem, porta_destino, payload=b"", transporte=None):
    """Identifica protocolo OT por porta e, quando possível, por assinatura."""
    portas = (porta_destino, porta_origem)

    # Conteúdo claramente HTTP ou executável não deve casar com assinaturas OT
    # (evita rotular o download de um binário como tráfego de PLC).
    if payload and (
        payload[:2] == b"MZ"
        or payload[:4] == b"\x7fELF"
        or payload[:5] == b"HTTP/"
        or REGEX_REQUISICAO_HTTP.match(payload)
    ):
        payload = b""

    # Assinaturas mais específicas primeiro.
    if transporte == "TCP" and payload:
        if analisar_s7_payload(payload):
            return "Siemens S7comm / ISO-TSAP"
        if analisar_modbus_payload(payload):
            return "Modbus TCP"
        if analisar_enip_payload(payload):
            return "EtherNet/IP / CIP"
        if analisar_opcua_payload(payload):
            return "OPC UA"
        if analisar_iec104_payload(payload):
            return "IEC 60870-5-104"
        if analisar_dnp3_payload(payload):
            return "DNP3"
        if analisar_mitsubishi_payload(payload):
            return "Mitsubishi MC / SLMP (candidato)"
        if analisar_ads_payload(payload):
            return "Beckhoff ADS (candidato)"

    if transporte == "UDP" and payload:
        if analisar_fins_payload(payload):
            return "Omron FINS (candidato)"
        if analisar_dnp3_payload(payload):
            return "DNP3"
        if analisar_bacnet_payload(payload):
            return "BACnet/IP"

    for porta in portas:
        if porta in PORTAS_OT:
            return PORTAS_OT[porta]

    return None


def direcao_cliente_servidor(
    origem,
    destino,
    porta_origem,
    porta_destino,
    fluxo,
    bytes_a,
    bytes_b,
):
    """Determina direção relativa ao serviço, sem afirmar o papel operacional do ativo."""
    porta_servico = None

    if porta_destino in PORTAS_TRANSFERENCIA_OT:
        porta_servico = porta_destino
        cliente = origem
        servidor = destino
        bytes_cliente_servidor = bytes_a
        bytes_servidor_cliente = bytes_b
    elif porta_origem in PORTAS_TRANSFERENCIA_OT:
        porta_servico = porta_origem
        cliente = destino
        servidor = origem
        bytes_cliente_servidor = bytes_b
        bytes_servidor_cliente = bytes_a
    else:
        return None

    protocolo = PORTAS_OT.get(porta_servico, "OT desconhecido")
    fabricante, familia = META_PROTOCOLOS_OT.get(
        protocolo, ("Não identificado", protocolo)
    )

    return {
        "Porta serviço": porta_servico,
        "Protocolo OT": protocolo,
        "Fabricante": fabricante,
        "Família": familia,
        "Cliente observado": cliente,
        "Servidor observado": servidor,
        "Bytes cliente→servidor": bytes_cliente_servidor,
        "Bytes servidor→cliente": bytes_servidor_cliente,
    }


def analisar_s7_payload(payload):
    """Identificação heurística de TPKT/COTP/S7comm."""
    if not payload or len(payload) < 12 or payload[0:2] != b"\x03\x00":
        return None

    for indice in range(4, min(len(payload) - 10, 32)):
        if payload[indice] != 0x32:
            continue
        rosctr = payload[indice + 1]
        if rosctr not in {0x01, 0x02, 0x03, 0x07}:
            continue
        try:
            tamanho_parametro = int.from_bytes(payload[indice + 6:indice + 8], "big")
            tamanho_dados = int.from_bytes(payload[indice + 8:indice + 10], "big")
        except Exception:
            continue
        inicio_parametro = indice + 10
        fim_parametro = inicio_parametro + tamanho_parametro
        if fim_parametro > len(payload):
            continue
        funcao = payload[inicio_parametro] if tamanho_parametro > 0 else None
        return {
            "S7comm": True,
            "ROSCTR": rosctr,
            "Função": funcao,
            "Tamanho parâmetro": tamanho_parametro,
            "Tamanho dados": tamanho_dados,
        }
    return None


def analisar_modbus_payload(payload):
    """Identificação heurística de Modbus TCP e função."""
    if not payload or len(payload) < 8:
        return None
    try:
        protocolo_id = int.from_bytes(payload[2:4], "big")
        tamanho = int.from_bytes(payload[4:6], "big")
        funcao = payload[7]
    except Exception:
        return None
    if protocolo_id != 0 or funcao == 0 or funcao > 0x7F:
        return None
    return {
        "Modbus": True,
        "Função": funcao,
        "Escrita": funcao in FUNCOES_MODBUS_ESCRITA,
        "Tamanho": tamanho,
    }


def analisar_enip_payload(payload):
    """Detecta EtherNet/IP encapsulation e serviços CIP quando presentes."""
    if not payload or len(payload) < 24:
        return None
    # EtherNet/IP encapsulation commands conhecidos.
    comando = int.from_bytes(payload[0:2], "little")
    comandos = {0x0001, 0x0004, 0x0065, 0x0066, 0x006F, 0x0070}
    if comando not in comandos:
        return None
    servico = None
    for i in range(24, min(len(payload) - 1, 96)):
        if payload[i] in {0x01, 0x02, 0x03, 0x04, 0x0E, 0x10, 0x4B, 0x4C, 0x4D, 0x4E, 0x52, 0x54, 0x55}:
            servico = payload[i]
            break
    escrita = servico in {0x04, 0x10, 0x4D, 0x4E, 0x4F, 0x52, 0x54, 0x55}
    return {"EtherNet/IP": True, "Comando": comando, "Serviço CIP": servico, "Escrita": escrita}


def analisar_opcua_payload(payload):
    """Detecta cabeçalhos OPC UA TCP: HEL/ACK/ERR/OPN/MSG/CLO."""
    if not payload or len(payload) < 8:
        return None
    tipo = payload[0:3]
    if tipo not in {b"HEL", b"ACK", b"ERR", b"OPN", b"MSG", b"CLO"}:
        return None
    return {"OPC UA": True, "Mensagem": tipo.decode("ascii", errors="ignore")}


def analisar_iec104_payload(payload):
    """Detecção básica de ASDU IEC-104 pelo formato APCI."""
    if not payload or len(payload) < 6 or payload[0] != 0x68:
        return None
    comprimento = payload[1]
    if comprimento < 4 or comprimento > len(payload) - 2:
        return None
    tipo = payload[2] & 0x03
    return {"IEC-104": True, "Tipo APCI": tipo, "ASDU": payload[6] if len(payload) > 6 else None}


def analisar_dnp3_payload(payload):
    """Detecta cabeçalho DNP3 05 64 e função de transporte/link."""
    if not payload or len(payload) < 10 or payload[0:2] != b"\x05\x64":
        return None
    return {
        "DNP3": True,
        "Controle": payload[3],
        "Função link": payload[10] if len(payload) > 10 else None,
    }


def analisar_bacnet_payload(payload):
    """Detecta BACnet/IP BVLL pelo cabeçalho 0x81."""
    if not payload or len(payload) < 4 or payload[0] != 0x81:
        return None
    return {"BACnet/IP": True, "Função BVLL": payload[1], "Comprimento": int.from_bytes(payload[2:4], "big")}


def analisar_mitsubishi_payload(payload):
    """Heurística conservadora para MC/SLMP; porta isolada não é prova de protocolo."""
    if not payload or len(payload) < 8:
        return None
    # 3E frame TCP: subheader 0x5000 little-endian; 4E começa com 0x5400.
    subheader = int.from_bytes(payload[0:2], "little")
    if subheader not in {0x0050, 0x0054}:
        return None
    return {"Mitsubishi": True, "Subheader": subheader, "Comando": int.from_bytes(payload[18:20], "little") if len(payload) >= 20 else None}


def analisar_fins_payload(payload):
    """Heurística FINS: cabeçalho IC FINS e campos de comando."""
    if not payload or len(payload) < 16:
        return None
    # FINS TCP começa normalmente com 'FINS' e FINS UDP usa cabeçalho binário.
    if payload[0:4] == b"FINS":
        return {"FINS": True, "Comando": payload[12:16].hex()}
    return None


def analisar_ads_payload(payload):
    """Detecção conservadora de ADS/TCP por porta; payload completo exige dissecação específica."""
    if not payload or len(payload) < 8:
        return None
    # AMS/TCP pode iniciar com NetID de 6 bytes seguido de port/command.
    # AMS/TCP: 2 bytes reservados (0) + 4 bytes de comprimento (little-endian)
    # que deve ser coerente com o restante da mensagem. Só checar bytes 6-7
    # gerava falso positivo em qualquer binário (ex.: cabeçalho MZ de um PE).
    if (
        len(payload) >= 38
        and payload[0:2] == b"\x00\x00"
        and int.from_bytes(payload[2:6], "little") == len(payload) - 6
    ):
        return {"ADS": True, "Evidência": "estrutura compatível com AMS/TCP"}
    return None

def adicionar_alerta(alertas, chave_alertas, alerta):
    chave = (
        alerta.get("Tipo"),
        alerta.get("Origem"),
        alerta.get("Destino"),
        alerta.get("Porta destino"),
        alerta.get("Detalhe"),
    )

    if chave not in chave_alertas and len(alertas) < LIMITE_EVENTOS_OT:
        chave_alertas.add(chave)
        alertas.append(alerta)


def detectar_ot_pacote(
    pacote,
    instante,
    origem,
    destino,
    porta_origem,
    porta_destino,
    fluxo,
    eventos_ot,
    chaves_eventos_ot,
    detalhes_ot,
    num_pacote=None,
):
    """Detecta protocolo/família OT e operações relevantes com evidência do payload."""
    transporte, _, _, _ = transporte_pacote(pacote)
    payload = payload_limitado(pacote)
    protocolo_ot = classificar_protocolo_ot(
        porta_origem,
        porta_destino,
        payload,
        transporte,
    )

    if not protocolo_ot:
        return

    detalhes_ot[protocolo_ot] += 1
    fabricante, familia = META_PROTOCOLOS_OT.get(
        protocolo_ot, ("Não identificado", protocolo_ot)
    )

    base = {
        "Nº pacote": num_pacote if num_pacote is not None else "-",
        "Data/hora UTC": texto_data(instante),
        "Origem": origem or "-",
        "Destino": destino or "-",
        "Porta destino": porta_destino or "-",
        "Transporte": transporte,
        "Fabricante": fabricante,
        "Família PLC/OT": familia,
        "Protocolo OT": protocolo_ot,
        "Categoria": "Comunicação OT",
        "Classificação": "Indicador comportamental",
        "Operação": "Não determinada",
        "Arquivo": "-",
    }

    detalhe = "Protocolo OT identificado por heurística de porta."
    categoria = "Comunicação OT"
    classificacao = "Protocolo OT observado"
    operacao = "Não determinada"

    if protocolo_ot == "Siemens S7comm / ISO-TSAP":
        s7 = analisar_s7_payload(payload)
        if s7:
            funcao = s7["Função"]
            operacao = f"Função S7 0x{funcao:02X}" if funcao is not None else "Mensagem S7comm"
            detalhe = (
                f"TPKT/COTP/S7comm; ROSCTR=0x{s7['ROSCTR']:02X}; "
                f"função={operacao}; parâmetro={s7['Tamanho parâmetro']} B; "
                f"dados={s7['Tamanho dados']} B."
            )
            if funcao in FUNCOES_S7_TRANSFERENCIA_CANDIDATA:
                categoria = "Transferência OT candidata"
                classificacao = "Transferência de bloco S7 candidata"

    elif protocolo_ot == "Modbus TCP":
        mb = analisar_modbus_payload(payload)
        if mb:
            operacao = f"Função Modbus {mb['Função']}"
            detalhe = f"MBAP válido; função={mb['Função']}; PDU={mb['Tamanho']} B."
            if mb["Escrita"]:
                categoria = "Alteração OT candidata"
                classificacao = "Escrita Modbus observada"
                detalhe += " A operação de escrita deve ser validada no contexto operacional."

    elif protocolo_ot == "EtherNet/IP / CIP":
        enip = analisar_enip_payload(payload)
        if enip:
            servico = enip.get("Serviço CIP")
            operacao = f"CIP 0x{servico:02X}" if servico is not None else "EtherNet/IP encapsulation"
            detalhe = f"EtherNet/IP comando 0x{enip['Comando']:04X}; serviço CIP={operacao}."
            if enip.get("Escrita"):
                categoria = "Alteração OT candidata"
                classificacao = "Escrita CIP candidata"

    elif protocolo_ot == "OPC UA":
        opc = analisar_opcua_payload(payload)
        if opc:
            operacao = f"OPC UA {opc['Mensagem']}"
            detalhe = f"Mensagem OPC UA TCP {opc['Mensagem']} identificada."

    elif protocolo_ot == "IEC 60870-5-104":
        iec = analisar_iec104_payload(payload)
        if iec:
            operacao = "APCI/ASDU IEC-104"
            detalhe = f"IEC-104; tipo APCI={iec['Tipo APCI']}; ASDU={iec['ASDU']}."

    elif protocolo_ot == "DNP3":
        dnp = analisar_dnp3_payload(payload)
        if dnp:
            operacao = "DNP3 link/application"
            detalhe = f"DNP3; controle=0x{dnp['Controle']:02X}; função link={dnp['Função link']}."

    elif protocolo_ot == "BACnet/IP":
        bac = analisar_bacnet_payload(payload)
        if bac:
            operacao = f"BVLL 0x{bac['Função BVLL']:02X}"
            detalhe = f"BACnet/IP BVLL; função=0x{bac['Função BVLL']:02X}."

    elif protocolo_ot == "Mitsubishi MC / SLMP (candidato)":
        mits = analisar_mitsubishi_payload(payload)
        if mits:
            operacao = "MC/SLMP"
            detalhe = f"Mitsubishi MC/SLMP; subheader=0x{mits['Subheader']:04X}."

    elif protocolo_ot == "Omron FINS (candidato)":
        fins = analisar_fins_payload(payload)
        if fins:
            operacao = "FINS"
            detalhe = f"Omron FINS; comando={fins['Comando']}."

    elif protocolo_ot == "Beckhoff ADS (candidato)":
        ads = analisar_ads_payload(payload)
        if ads:
            operacao = "ADS/AMS"
            detalhe = ads["Evidência"] + "."

    adicionar_evento(
        eventos_ot,
        chaves_eventos_ot,
        {
            **base,
            "Categoria": categoria,
            "Classificação": classificacao,
            "Operação": operacao,
            "Detalhe": detalhe,
        },
    )

def gerar_transferencias_ot(fluxos):
    """Classifica fluxos OT assimétricos como upload/download candidatos."""
    transferencias = []

    for chave, dados in fluxos.items():
        transporte, ip_a, porta_a, ip_b, porta_b = chave

        if transporte != "TCP":
            continue

        info = direcao_cliente_servidor(
            ip_a,
            ip_b,
            porta_a,
            porta_b,
            chave,
            dados.get("Bytes A→B", 0),
            dados.get("Bytes B→A", 0),
        )

        if not info:
            continue

        total = (
            info["Bytes cliente→servidor"]
            + info["Bytes servidor→cliente"]
        )

        if total < LIMITE_TRANSFERENCIA_OT:
            continue

        menor = max(
            min(
                info["Bytes cliente→servidor"],
                info["Bytes servidor→cliente"],
            ),
            1,
        )
        maior = max(
            info["Bytes cliente→servidor"],
            info["Bytes servidor→cliente"],
        )

        razao = maior / menor

        if razao < 3:
            continue

        if info["Bytes cliente→servidor"] > info["Bytes servidor→cliente"]:
            operacao = "Upload/download para o servidor OT — direção candidata: cliente→servidor"
            sentido = "Cliente → servidor OT"
        else:
            operacao = "Upload/download a partir do servidor OT — direção candidata: servidor→cliente"
            sentido = "Servidor OT → cliente"

        transferencias.append(
            {
                "Fabricante": info["Fabricante"],
                "Família PLC/OT": info["Família"],
                "Protocolo OT": info["Protocolo OT"],
                "Porta": info["Porta serviço"],
                "Cliente observado": info["Cliente observado"],
                "Servidor observado": info["Servidor observado"],
                "Sentido dominante": sentido,
                "Bytes cliente→servidor": info["Bytes cliente→servidor"],
                "Bytes servidor→cliente": info["Bytes servidor→cliente"],
                "Volume total": bytes_legivel(total),
                "Razão de assimetria": round(razao, 2),
                "Classificação": "Transferência OT candidata",
                "Interpretação": operacao,
            }
        )

    return pd.DataFrame(transferencias).sort_values(
        by=["Razão de assimetria", "Bytes cliente→servidor", "Bytes servidor→cliente"],
        ascending=False,
    ) if transferencias else pd.DataFrame()


def gerar_ativos_ot(fluxos):
    """Resume ativos que participaram de comunicações em portas OT."""
    ativos = defaultdict(lambda: {
        "Protocolos": set(),
        "Portas": set(),
        "Peers": set(),
        "Bytes": 0,
        "Fluxos": 0,
    })

    for chave, dados in fluxos.items():
        transporte, ip_a, porta_a, ip_b, porta_b = chave
        portas_ot = [p for p in (porta_a, porta_b) if p in PORTAS_OT]
        if not portas_ot:
            continue

        protocolo = ", ".join(sorted({PORTAS_OT[p] for p in portas_ot}))

        for ip, peer in ((ip_a, ip_b), (ip_b, ip_a)):
            ativos[ip]["Protocolos"].add(protocolo)
            ativos[ip]["Portas"].update(portas_ot)
            ativos[ip]["Peers"].add(peer)
            ativos[ip]["Bytes"] += dados["Bytes"]
            ativos[ip]["Fluxos"] += 1

    linhas = []
    for ip, dados in ativos.items():
        linhas.append({
            "Ativo": ip,
            "Protocolos OT": ", ".join(sorted(dados["Protocolos"])),
            "Portas OT": ", ".join(str(x) for x in sorted(dados["Portas"])),
            "Peers": len(dados["Peers"]),
            "Fluxos": dados["Fluxos"],
            "Volume": bytes_legivel(dados["Bytes"]),
        })

    return pd.DataFrame(linhas).sort_values(
        by=["Fluxos", "Peers"], ascending=False
    ) if linhas else pd.DataFrame()


def deduplicar_ativos_ot(df):
    """
    Conta cada IP de ativo OT uma única vez.
    Agrega protocolos, portas, peers, fluxos e bytes entre capturas.
    """
    if df is None or df.empty or "Ativo" not in df.columns:
        return pd.DataFrame() if df is None else df.copy()

    def _unir_texto(serie):
        partes = set()
        for v in serie.dropna():
            for p in str(v).split(","):
                p = p.strip()
                if p:
                    partes.add(p)
        return ", ".join(sorted(partes)) if partes else "-"

    def _soma_num(serie):
        total = 0
        for v in serie:
            try:
                total += int(v)
            except Exception:
                pass
        return total

    grupos = []
    for ativo, g in df.groupby("Ativo", sort=False):
        capturas = (
            ", ".join(sorted(set(g["Captura"].dropna().astype(str))))
            if "Captura" in g.columns
            else "-"
        )
        grupos.append({
            "Ativo": ativo,
            "Protocolos OT": _unir_texto(g["Protocolos OT"]) if "Protocolos OT" in g.columns else "-",
            "Portas OT": _unir_texto(g["Portas OT"]) if "Portas OT" in g.columns else "-",
            "Peers": _soma_num(g["Peers"]) if "Peers" in g.columns else 0,
            "Fluxos": _soma_num(g["Fluxos"]) if "Fluxos" in g.columns else 0,
            "Volume": g["Volume"].iloc[0] if "Volume" in g.columns else "-",
            "Capturas": capturas,
        })

    out = pd.DataFrame(grupos)
    if out.empty:
        return out
    return out.sort_values(by=["Fluxos", "Peers"], ascending=False).reset_index(drop=True)


def deduplicar_iocs(df, col_ioc="IOC candidato"):
    """Remove IOCs repetidos (mesmo Tipo + valor), preservando a primeira evidência."""
    if df is None or df.empty:
        return pd.DataFrame() if df is None else df.copy()

    col_tipo = "Tipo" if "Tipo" in df.columns else None
    if col_ioc not in df.columns and "IOC" in df.columns:
        col_ioc = "IOC"
    if col_ioc not in df.columns:
        return df.drop_duplicates().reset_index(drop=True)

    chaves = [c for c in [col_tipo, col_ioc] if c]
    return df.drop_duplicates(subset=chaves, keep="first").reset_index(drop=True)


def contar_ativos_ot_unicos(df):
    """Quantidade distinta de IPs que comunicaram em protocolos OT."""
    if df is None or df.empty or "Ativo" not in df.columns:
        return 0
    return int(df["Ativo"].nunique())


def contar_iocs_unicos(df):
    """Quantidade distinta de IOCs (por Tipo + valor)."""
    if df is None or df.empty:
        return 0
    col = "IOC candidato" if "IOC candidato" in df.columns else ("IOC" if "IOC" in df.columns else None)
    if not col:
        return len(df)
    if "Tipo" in df.columns:
        return int(df.drop_duplicates(subset=["Tipo", col]).shape[0])
    return int(df[col].nunique())


def gerar_iocs_candidatos(
    alertas,
    transferencias_ot,
    externos,
    eventos_ot,
    downloads=None,
):
    """
    Gera indicadores candidatos derivados da própria captura.

    Importante: isso não afirma que o indicador seja malicioso. Sem inteligência
    externa ou contexto operacional, o resultado é um candidato para investigação.
    """
    candidatos = []

    for alerta in alertas:
        if alerta.get("Tipo") in {
            "Possível varredura TCP",
            "Possível comunicação OT externa",
        }:
            origem = alerta.get("Origem", "-")
            destino = alerta.get("Destino", "-")
            candidatos.append({
                "Tipo": "IP",
                "IOC candidato": destino if destino != "-" else origem,
                "Motivo": alerta.get("Tipo"),
                "Evidência": alerta.get("Detalhe", ""),
                "Fonte": "Derivado da captura",
            })

    for _, linha in transferencias_ot.iterrows():
        servidor = linha.get("Servidor observado", "-")
        candidatos.append({
            "Tipo": "Endpoint OT",
            "IOC candidato": servidor,
            "Motivo": "Transferência OT candidata",
            "Evidência": linha.get("Interpretação", ""),
            "Fonte": "Derivado da captura",
        })

    for evento in eventos_ot:
        if evento.get("Categoria") in {
            "Alteração OT candidata",
            "Transferência OT candidata",
        }:
            candidatos.append({
                "Tipo": "Endpoint OT",
                "IOC candidato": evento.get("Destino", "-"),
                "Motivo": evento.get("Categoria"),
                "Evidência": evento.get("Detalhe", ""),
                "Fonte": "Derivado da captura",
            })

    for item in downloads or []:
        evidencia = f"{item['Tipo de arquivo']} baixado via HTTP de {item['URL']}"
        for tipo_ioc, valor in (
            ("Hash SHA-256", item["SHA-256"]),
            ("Hash MD5", item["MD5"]),
            ("URL", item["URL"]),
            ("IP servidor de payload", item["Servidor"]),
        ):
            if valor and valor != "-":
                candidatos.append({
                    "Tipo": tipo_ioc,
                    "IOC candidato": valor,
                    "Motivo": "Download de executável/payload via HTTP",
                    "Evidência": evidencia,
                    "Fonte": "Derivado da captura",
                })

    # Deduplicação preservando a evidência mais direta.
    vistos = set()
    resultado = []
    for item in candidatos:
        chave = (
            item["Tipo"],
            item["IOC candidato"],
            item["Motivo"],
        )
        if chave in vistos:
            continue
        vistos.add(chave)
        resultado.append(item)

    return pd.DataFrame(resultado)


def gerar_anomalias_ot(fluxos, transferencias_ot):
    """Detecta comportamentos OT relevantes sem exigir uma base de IOCs."""
    linhas = []

    destinos_por_origem = defaultdict(set)
    portas_por_origem = defaultdict(set)

    for chave, dados in fluxos.items():
        transporte, ip_a, porta_a, ip_b, porta_b = chave
        if porta_b in PORTAS_OT:
            destinos_por_origem[ip_a].add(f"{ip_b}:{porta_b}")
            portas_por_origem[ip_a].add(porta_b)
        if porta_a in PORTAS_OT:
            destinos_por_origem[ip_b].add(f"{ip_a}:{porta_a}")
            portas_por_origem[ip_b].add(porta_a)

    for origem, destinos in destinos_por_origem.items():
        if len(destinos) >= 5:
            linhas.append({
                "Severidade": "Média",
                "Tipo": "Comunicação OT one-to-many",
                "Origem": origem,
                "Destino": "-",
                "Evidência": (
                    f"Ativo iniciou/recebeu comunicação relacionada a "
                    f"{len(destinos)} destinos OT distintos."
                ),
                "Classificação": "Anomalia comportamental",
            })

    for _, linha in transferencias_ot.iterrows():
        linhas.append({
            "Severidade": "Média",
            "Tipo": "Transferência OT assimétrica",
            "Origem": linha["Cliente observado"],
            "Destino": linha["Servidor observado"],
            "Evidência": (
                f"{linha['Protocolo OT']} porta {linha['Porta']}; "
                f"assimetria {linha['Razão de assimetria']}x; "
                f"{linha['Interpretação']}"
            ),
            "Classificação": "Indicador comportamental",
        })

    return pd.DataFrame(linhas)


def tipo_no(ip, ips_dns):
    if ip in ips_dns:
        return "DNS"

    if ip_interno(ip):
        return "Interno"

    if ip_publico(ip):
        return "Externo"

    return "Outro"


def rotulo_aplicacao(porta_a, porta_b, transporte):
    """Rotula a aplicação dominante da aresta (inspirado em topologia estilo A-Packets)."""
    for p in (porta_a, porta_b):
        if p in PORTAS_OT:
            return PORTAS_OT[p]
        if p == 53:
            return "DNS"
        if p in {80, 8000, 8080, 3128}:
            return "HTTP"
        if p in {443, 8443}:
            return "HTTPS / TLS"
        if p in {20, 21}:
            return "FTP"
        if p == 22:
            return "SSH"
        if p == 23:
            return "Telnet"
        if p == 445:
            return "SMB"
        if p == 1900:
            return "SSDP"
    return transporte or "Outro"


def criar_grafo(fluxos):
    """Cria grafo com portas, protocolos de aplicação e direção de comunicação."""
    grafo = nx.Graph()
    volume_ip = Counter()
    ips_dns = set()

    for chave, dados in fluxos.items():
        transporte, ip_a, porta_a, ip_b, porta_b = chave

        volume_ip[ip_a] += dados["Bytes"]
        volume_ip[ip_b] += dados["Bytes"]

        if porta_a == 53:
            ips_dns.add(ip_a)

        if porta_b == 53:
            ips_dns.add(ip_b)

    ips_relevantes = {
        ip
        for ip, _ in volume_ip.most_common(LIMITE_NOS_MAPA)
    }

    for chave, dados in fluxos.items():
        transporte, ip_a, porta_a, ip_b, porta_b = chave

        if ip_a not in ips_relevantes or ip_b not in ips_relevantes:
            continue

        portas_fluxo = {
            porta
            for porta in [porta_a, porta_b]
            if porta and porta != 0
        }

        app = rotulo_aplicacao(porta_a, porta_b, transporte)
        bytes_fluxo = dados["Bytes"]

        if grafo.has_edge(ip_a, ip_b):
            dados_aresta = grafo[ip_a][ip_b]

            dados_aresta["Bytes"] += bytes_fluxo
            dados_aresta["Pacotes"] += dados["Pacotes"]
            dados_aresta["Fluxos"] += 1
            dados_aresta["AparaB"] += dados["A→B"]
            dados_aresta["BparaA"] += dados["B→A"]
            dados_aresta["Protocolos"].add(transporte)
            dados_aresta["Portas"].update(portas_fluxo)
            dados_aresta["Apps"][app] = dados_aresta["Apps"].get(app, 0) + bytes_fluxo

        else:
            grafo.add_edge(
                ip_a,
                ip_b,
                IP_A=ip_a,
                IP_B=ip_b,
                Bytes=bytes_fluxo,
                Pacotes=dados["Pacotes"],
                Fluxos=1,
                AparaB=dados["A→B"],
                BparaA=dados["B→A"],
                Protocolos={transporte},
                Portas=portas_fluxo,
                Apps={app: bytes_fluxo},
            )

    for ip in grafo.nodes:
        grafo.nodes[ip]["Volume"] = volume_ip[ip]
        grafo.nodes[ip]["Tipo"] = tipo_no(ip, ips_dns)

    return grafo


# Cores de aplicação/protocolo para arestas (estilo topologia A-Packets).
CORES_APP = {
    "Modbus TCP": "#EF4444",
    "Siemens S7comm / ISO-TSAP": "#DC2626",
    "IEC 60870-5-104": "#F97316",
    "EtherNet/IP / CIP": "#EA580C",
    "OPC UA": "#D97706",
    "DNP3": "#CA8A04",
    "BACnet/IP": "#A16207",
    "Mitsubishi MC / SLMP (candidato)": "#B45309",
    "Omron FINS (candidato)": "#92400E",
    "Beckhoff ADS (candidato)": "#78350F",
    "DNS": "#38BDF8",
    "HTTP": "#22C55E",
    "HTTPS / TLS": "#10B981",
    "FTP": "#A78BFA",
    "SSH": "#8B5CF6",
    "Telnet": "#F43F5E",
    "SMB": "#EAB308",
    "SSDP": "#94A3B8",
    "TCP": "#64748B",
    "UDP": "#475569",
    "Outro": "#334155",
}


def listar_apps_grafo(grafo):
    """Lista protocolos de aplicação presentes nas arestas do grafo."""
    apps = set()
    for _, _, dados in grafo.edges(data=True):
        apps_edge = dados.get("Apps") or {}
        if apps_edge:
            apps.update(apps_edge.keys())
        else:
            apps.update(dados.get("Protocolos") or [])
    return sorted(apps)


def desenhar_mapa_comunicacao(grafo, filtros_app=None):
    """
    Mapa de topologia interativo: nós por tipo de host, arestas coloridas por protocolo dominante.
    filtros_app: lista de nomes de aplicação; se None ou vazia, mostra todas.
    Retorna o HTML gerado (para download) ou None.
    """
    if not grafo.nodes:
        st.info("Não há dados suficientes para gerar o mapa.")
        return None

    arestas = sorted(
        grafo.edges(data=True),
        key=lambda item: item[2]["Bytes"],
        reverse=True,
    )[:LIMITE_ARESTAS_MAPA]

    grafo_visual = nx.Graph()
    for origem, destino, dados in arestas:
        apps_edge = dados.get("Apps") or {}
        if filtros_app:
            # Mantém aresta se algum app filtrado estiver presente (ou transporte se sem Apps).
            if apps_edge:
                if not any(a in filtros_app for a in apps_edge):
                    continue
            else:
                protos = dados.get("Protocolos") or set()
                if not any(p in filtros_app for p in protos):
                    continue
        grafo_visual.add_edge(origem, destino, **dados)

    if not grafo_visual.edges:
        st.warning(
            "Nenhuma aresta corresponde ao filtro de protocolo selecionado. "
            "Ajuste o filtro para ver o mapa."
        )
        return None

    for ip in grafo_visual.nodes:
        grafo_visual.nodes[ip]["Volume"] = grafo.nodes[ip].get("Volume", 0)
        grafo_visual.nodes[ip]["Tipo"] = grafo.nodes[ip].get("Tipo", "Outro")

    protocolos_por_ip = defaultdict(set)
    portas_por_ip = defaultdict(set)
    apps_por_ip = defaultdict(Counter)
    nos_ot = set()

    for origem, destino, dados in grafo_visual.edges(data=True):
        protocolos_por_ip[origem].update(dados.get("Protocolos") or set())
        protocolos_por_ip[destino].update(dados.get("Protocolos") or set())
        portas_por_ip[origem].update(dados.get("Portas") or set())
        portas_por_ip[destino].update(dados.get("Portas") or set())
        for app, vol in (dados.get("Apps") or {}).items():
            apps_por_ip[origem][app] += vol
            apps_por_ip[destino][app] += vol
            # Marca nós envolvidos em protocolo OT conhecido
            if app in PORTAS_OT.values() or "Modbus" in app or "S7" in app or "IEC" in app or "CIP" in app or "OPC" in app or "DNP" in app:
                nos_ot.add(origem)
                nos_ot.add(destino)
        for porta in dados.get("Portas") or set():
            if porta in PORTAS_OT:
                nos_ot.add(origem)
                nos_ot.add(destino)

    cores_no = {
        "Interno": {"background": "#22C55E", "border": "#86EFAC", "highlight": {"background": "#4ADE80", "border": "#BBF7D0"}},
        "Externo": {"background": "#F97316", "border": "#FDBA74", "highlight": {"background": "#FB923C", "border": "#FED7AA"}},
        "DNS": {"background": "#38BDF8", "border": "#7DD3FC", "highlight": {"background": "#7DD3FC", "border": "#BAE6FD"}},
        "OT": {"background": "#EF4444", "border": "#FECACA", "highlight": {"background": "#F87171", "border": "#FEE2E2"}},
        "Outro": {"background": "#A78BFA", "border": "#C4B5FD", "highlight": {"background": "#C4B5FD", "border": "#DDD6FE"}},
    }

    rede = Network(
        height="820px",
        width="100%",
        bgcolor="#070B14",
        font_color="#E2E8F0",
        directed=False,
        notebook=False,
        cdn_resources="in_line",
    )

    rede.set_options(
        """
        {
          "interaction": {
            "dragNodes": true,
            "dragView": true,
            "zoomView": true,
            "hover": true,
            "multiselect": true,
            "navigationButtons": true,
            "tooltipDelay": 60,
            "hideEdgesOnDrag": false,
            "keyboard": { "enabled": true }
          },
          "physics": {
            "enabled": true,
            "barnesHut": {
              "gravitationalConstant": -16000,
              "centralGravity": 0.12,
              "springLength": 220,
              "springConstant": 0.025,
              "damping": 0.25,
              "avoidOverlap": 0.9
            },
            "stabilization": {
              "enabled": true,
              "iterations": 400,
              "updateInterval": 15,
              "fit": true
            },
            "minVelocity": 0.4,
            "timestep": 0.45
          },
          "nodes": {
            "borderWidth": 3,
            "shadow": { "enabled": true, "color": "rgba(0,0,0,0.45)", "size": 8, "x": 0, "y": 3 },
            "font": {
              "color": "#F8FAFC",
              "size": 13,
              "face": "Inter, Segoe UI, Arial, sans-serif",
              "strokeWidth": 4,
              "strokeColor": "#070B14"
            }
          },
          "edges": {
            "smooth": { "type": "dynamic", "roundness": 0.4 },
            "shadow": false,
            "selectionWidth": 4,
            "hoverWidth": 3,
            "font": {
              "size": 10,
              "color": "#CBD5E1",
              "strokeWidth": 3,
              "strokeColor": "#070B14",
              "align": "middle"
            }
          },
          "layout": { "improvedLayout": true, "randomSeed": 42 }
        }
        """
    )

    for ip in grafo_visual.nodes:
        tipo_base = grafo_visual.nodes[ip]["Tipo"]
        volume = grafo_visual.nodes[ip]["Volume"]
        conexoes = grafo_visual.degree(ip)
        eh_ot = ip in nos_ot
        tipo = "OT" if eh_ot else tipo_base

        protocolos = ", ".join(sorted(protocolos_por_ip[ip])) or "—"
        portas = ", ".join(str(p) for p in sorted(portas_por_ip[ip])[:18]) or "—"
        top_apps = ", ".join(
            f"{a} ({bytes_legivel(v)})"
            for a, v in apps_por_ip[ip].most_common(5)
        ) or "—"

        tamanho = min(max(24 + (volume / 100000) ** 0.42 * 16, 26), 86)
        forma = "diamond" if eh_ot else ("triangle" if tipo_base == "Externo" else "dot")

        # Tooltip em texto puro (vis.js/pyvis costuma exibir HTML como texto literal)
        ot_tag = "Sim — comunicação OT detectada" if eh_ot else "Não"
        tooltip = (
            f"Endereço IP: {ip}\n"
            f"Tipo de host: {tipo}\n"
            f"Envolvido em OT?: {ot_tag}\n"
            f"Qtd. de conexões: {conexoes}\n"
            f"Volume de tráfego: {bytes_legivel(volume)}\n"
            f"Protocolos / aplicações: {top_apps}\n"
            f"Camada de transporte: {protocolos}\n"
            f"Portas observadas: {portas}"
        )

        rede.add_node(
            ip,
            label=ip,
            title=tooltip,
            size=tamanho,
            shape=forma,
            color=cores_no.get(tipo, cores_no["Outro"]),
            borderWidth=4 if eh_ot else 3,
        )

    apps_usadas = set()

    for origem, destino, dados in grafo_visual.edges(data=True):
        ip_a = dados["IP_A"]
        ip_b = dados["IP_B"]
        pacotes_a_para_b = dados["AparaB"]
        pacotes_b_para_a = dados["BparaA"]

        if pacotes_a_para_b > 0 and pacotes_b_para_a > 0:
            tipo_comunicacao = "Bidirecional"
            direcao_detalhada = (
                f"{ip_a} → {ip_b}: {pacotes_a_para_b} pct<br>"
                f"{ip_b} → {ip_a}: {pacotes_b_para_a} pct"
            )
        elif pacotes_a_para_b > 0:
            tipo_comunicacao = "Somente ida"
            direcao_detalhada = f"{ip_a} → {ip_b}: {pacotes_a_para_b} pct"
        else:
            tipo_comunicacao = "Somente vinda"
            direcao_detalhada = f"{ip_b} → {ip_a}: {pacotes_b_para_a} pct"

        apps = dados.get("Apps") or {}
        if apps:
            app_dom = max(apps, key=apps.get)
        else:
            app_dom = next(iter(dados["Protocolos"]), "Outro")

        apps_usadas.add(app_dom)
        cor_aresta = CORES_APP.get(app_dom, CORES_APP["Outro"])

        protocolos = ", ".join(sorted(dados["Protocolos"]))
        portas = ", ".join(str(p) for p in sorted(dados["Portas"]))
        apps_txt = ", ".join(
            f"{a}: {bytes_legivel(v)}" for a, v in sorted(apps.items(), key=lambda x: -x[1])
        ) or app_dom

        largura = min(max(1.4 + (dados["Bytes"] / 400000) ** 0.5 * 2.2, 1.4), 9)

        # Direção em texto puro (sem tags HTML)
        if pacotes_a_para_b > 0 and pacotes_b_para_a > 0:
            direcao_txt = (
                f"{ip_a} -> {ip_b}: {pacotes_a_para_b} pct; "
                f"{ip_b} -> {ip_a}: {pacotes_b_para_a} pct"
            )
        elif pacotes_a_para_b > 0:
            direcao_txt = f"{ip_a} -> {ip_b}: {pacotes_a_para_b} pct"
        else:
            direcao_txt = f"{ip_b} -> {ip_a}: {pacotes_b_para_a} pct"

        tooltip = (
            f"Ligação de rede\n"
            f"Protocolo principal: {app_dom}\n"
            f"Ponta A: {ip_a}\n"
            f"Ponta B: {ip_b}\n"
            f"Sentido: {tipo_comunicacao}\n"
            f"Direção: {direcao_txt}\n"
            f"Aplicações: {apps_txt}\n"
            f"Transporte: {protocolos}\n"
            f"Portas: {portas}\n"
            f"Fluxos: {dados['Fluxos']} | "
            f"Pacotes: {dados['Pacotes']:,} | "
            f"Volume: {bytes_legivel(dados['Bytes'])}"
        )

        rede.add_edge(
            origem,
            destino,
            title=tooltip,
            width=largura,
            color={"color": cor_aresta, "highlight": "#F8FAFC", "hover": "#E2E8F0"},
            label=app_dom if len(app_dom) <= 18 else app_dom[:16] + "…",
            font={"size": 9, "color": "#CBD5E1", "strokeWidth": 0, "align": "middle"},
        )

    html_rede = rede.generate_html(notebook=False)

    # Centraliza o mapa ao carregar (fit após estabilização da física)
    js_centralizar = """
    <script type="text/javascript">
    (function () {
      function centralizarMapa() {
        try {
          var net = null;
          if (typeof network !== "undefined" && network) { net = network; }
          else if (typeof nodes !== "undefined" && typeof edges !== "undefined" && typeof vis !== "undefined") {
            /* fallback: procura instância global criada pelo pyvis */
            if (window.network) net = window.network;
          }
          if (!net) {
            var canvases = document.getElementsByTagName("canvas");
            if (canvases.length && window.network) net = window.network;
          }
          if (net && typeof net.fit === "function") {
            net.fit({ animation: { duration: 400, easingFunction: "easeInOutQuad" } });
          }
        } catch (e) {}
      }
      function agendar() {
        try {
          if (typeof network !== "undefined" && network) {
            window.network = network;
            network.on("stabilizationIterationsDone", function () {
              network.setOptions({ physics: false });
              centralizarMapa();
            });
            network.once("stabilized", function () { centralizarMapa(); });
            setTimeout(centralizarMapa, 800);
            setTimeout(centralizarMapa, 1600);
          } else {
            setTimeout(agendar, 200);
          }
        } catch (e) {
          setTimeout(centralizarMapa, 1000);
        }
      }
      if (document.readyState === "complete") agendar();
      else window.addEventListener("load", agendar);
    })();
    </script>
    """

    # CSS do tooltip: fundo legível e texto claro (vis.js padrão fica ilegível no tema escuro)
    css_tooltip = """
    <style>
    div.vis-tooltip {
      position: absolute;
      visibility: hidden;
      padding: 10px 12px !important;
      white-space: pre-line !important;
      max-width: 380px !important;
      font-family: Inter, Segoe UI, Arial, sans-serif !important;
      font-size: 13px !important;
      line-height: 1.45 !important;
      color: #0F172A !important;
      background-color: #F8FAFC !important;
      border: 1px solid #94A3B8 !important;
      border-radius: 8px !important;
      box-shadow: 0 8px 24px rgba(0,0,0,0.35) !important;
      pointer-events: none;
      z-index: 9999 !important;
    }
    div.vis-tooltip b { color: #0F172A !important; }
    </style>
    """
    if "</head>" in html_rede:
        html_rede = html_rede.replace("</head>", css_tooltip + "</head>", 1)
    else:
        html_rede = css_tooltip + html_rede
    # script de centralização antes de </body>
    if "</body>" in html_rede:
        html_rede = html_rede.replace("</body>", js_centralizar + "</body>", 1)
    else:
        html_rede = html_rede + js_centralizar
    components.html(html_rede, height=820, scrolling=False)

    # Legenda compacta
    legenda_nos = (
        "🟢 Interno (círculo)  ·  🟠 Externo (triângulo)  ·  "
        "🔴 OT (losango)  ·  🔵 DNS  ·  🟣 Outro"
    )
    apps_legenda = sorted(apps_usadas)
    chips = "  ·  ".join(
        f'<span style="color:{CORES_APP.get(a, "#94A3B8")};">●</span> {html.escape(a)}'
        for a in apps_legenda[:14]
    )
    st.markdown(
        f"""
        <div style="background:#0F172A;border:1px solid #1E293B;border-radius:12px;padding:14px 16px;margin-top:10px;font-size:13px;color:#CBD5E1;">
          <b style="color:#F1F5F9;">Legenda — nós:</b> {legenda_nos}<br>
          <b style="color:#F1F5F9;">Legenda — arestas (protocolo dominante por volume):</b> {chips or "—"}
          <div style="margin-top:8px;color:#64748B;font-size:12px;">
            Arraste nós · zoom com o scroll · hover para detalhes · filtro de protocolo acima ·
            export HTML abaixo para uso offline.
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.download_button(
        "⬇️ Exportar mapa em HTML (offline)",
        data=html_rede.encode("utf-8"),
        file_name="mapa_comunicacao_pcap.html",
        mime="text/html",
        help="Abre em qualquer navegador sem Streamlit. Inclui nós arrastáveis e tooltips.",
    )
    return html_rede


def _tag_df(df, nome_arquivo):
    """
    Acrescenta coluna 'Captura' (nome do PCAP de origem).
    Não usa 'Arquivo': essa coluna já existe em eventos de exposição/OT
    para o nome mascarado de arquivo transferido (FTP/HTTP).
    """
    if df is None or not isinstance(df, pd.DataFrame):
        return pd.DataFrame()
    out = df.copy()
    if out.empty:
        if "Captura" not in out.columns:
            out["Captura"] = pd.Series(dtype=object)
        return out
    if "Captura" in out.columns:
        out["Captura"] = nome_arquivo
    else:
        out.insert(0, "Captura", nome_arquivo)
    return out


def mesclar_resultados(lista_resultados):
    """
    Combina N análises de PCAP em um único dicionário de resultado.
    lista_resultados: [(nome_arquivo, sha256, resultado), ...]
    """
    if not lista_resultados:
        raise ValueError("Nenhum resultado para mesclar.")

    if len(lista_resultados) == 1:
        nome, sha, res = lista_resultados[0]
        for chave in (
            "eventos", "eventos_ot", "alertas", "downloads_suspeitos",
            "fluxos", "externos", "dns", "amostra", "iocs", "iocs_candidatos",
            "ativos_ot", "transferencias_ot", "anomalias_ot", "protocolos",
            "origens", "portas", "detalhes_ot",
        ):
            if chave in res and isinstance(res[chave], pd.DataFrame) and not res[chave].empty:
                res[chave] = _tag_df(res[chave], nome)
        if isinstance(res.get("ativos_ot"), pd.DataFrame):
            res["ativos_ot"] = deduplicar_ativos_ot(res["ativos_ot"])
        if isinstance(res.get("iocs_candidatos"), pd.DataFrame):
            res["iocs_candidatos"] = deduplicar_iocs(res["iocs_candidatos"], col_ioc="IOC candidato")
        if isinstance(res.get("iocs"), pd.DataFrame):
            res["iocs"] = deduplicar_iocs(res["iocs"], col_ioc="IOC")
        res["arquivos"] = pd.DataFrame([{
            "Captura": nome,
            "SHA-256": sha,
            "Pacotes": res["total"],
            "Volume": bytes_legivel(res["bytes"]),
            "Início UTC": texto_data(res["inicio"]),
            "Fim UTC": texto_data(res["fim"]),
            "Erros": res["erros"],
            "Limite atingido": "Sim" if res["limite"] else "Não",
        }])
        res["sha256_lista"] = [sha]
        return res

    total = 0
    total_bytes = 0
    erros = 0
    limite = False
    inicio = None
    fim = None
    grafo = nx.Graph()
    servicos = Counter()
    arquivos_meta = []
    shas = []

    dfs = defaultdict(list)

    chaves_df = (
        "eventos", "eventos_ot", "alertas", "downloads_suspeitos",
        "fluxos", "externos", "dns", "amostra", "iocs", "iocs_candidatos",
        "ativos_ot", "transferencias_ot", "anomalias_ot", "protocolos",
        "origens", "portas", "detalhes_ot",
    )

    for nome, sha, res in lista_resultados:
        total += res["total"]
        total_bytes += res["bytes"]
        erros += res["erros"]
        limite = limite or res["limite"]
        shas.append(sha)

        if res["inicio"]:
            inicio = res["inicio"] if inicio is None else min(inicio, res["inicio"])
        if res["fim"]:
            fim = res["fim"] if fim is None else max(fim, res["fim"])

        arquivos_meta.append({
            "Captura": nome,
            "SHA-256": sha,
            "Pacotes": res["total"],
            "Volume": bytes_legivel(res["bytes"]),
            "Início UTC": texto_data(res["inicio"]),
            "Fim UTC": texto_data(res["fim"]),
            "Erros": res["erros"],
            "Limite atingido": "Sim" if res["limite"] else "Não",
        })

        for chave in chaves_df:
            tagged = _tag_df(res.get(chave), nome)
            if not tagged.empty:
                dfs[chave].append(tagged)

        for k, v in (res.get("servicos") or {}).items():
            servicos[k] += v

        # Une grafos (soma volumes em nós/arestas quando possível).
        g = res.get("grafo")
        if g is not None and g.nodes:
            for n, atr in g.nodes(data=True):
                if grafo.has_node(n):
                    grafo.nodes[n]["Volume"] = grafo.nodes[n].get("Volume", 0) + atr.get("Volume", 0)
                else:
                    grafo.add_node(n, **atr)
            for u, v, atr in g.edges(data=True):
                if grafo.has_edge(u, v):
                    e = grafo[u][v]
                    e["Bytes"] = e.get("Bytes", 0) + atr.get("Bytes", 0)
                    e["Pacotes"] = e.get("Pacotes", 0) + atr.get("Pacotes", 0)
                    e["Fluxos"] = e.get("Fluxos", 0) + atr.get("Fluxos", 0)
                    e["AparaB"] = e.get("AparaB", 0) + atr.get("AparaB", 0)
                    e["BparaA"] = e.get("BparaA", 0) + atr.get("BparaA", 0)
                    e.setdefault("Protocolos", set()).update(atr.get("Protocolos") or set())
                    e.setdefault("Portas", set()).update(atr.get("Portas") or set())
                    apps = e.setdefault("Apps", {})
                    for app, vol in (atr.get("Apps") or {}).items():
                        apps[app] = apps.get(app, 0) + vol
                    e.setdefault("IP_A", atr.get("IP_A", u))
                    e.setdefault("IP_B", atr.get("IP_B", v))
                else:
                    grafo.add_edge(u, v, **{**atr})

    def _concat(chave):
        partes = dfs.get(chave) or []
        if not partes:
            return pd.DataFrame()
        return pd.concat(partes, ignore_index=True)

    # Agrega contagens de protocolos / origens / portas / detalhes_ot.
    def _agregar_contagem(df, col_nome, col_valor="Pacotes"):
        if df.empty or col_nome not in df.columns:
            return df
        return (
            df.groupby(col_nome, as_index=False)[col_valor]
            .sum()
            .sort_values(col_valor, ascending=False)
        )

    protocolos = _agregar_contagem(_concat("protocolos"), "Protocolo")
    origens = _agregar_contagem(_concat("origens"), "IP de origem")
    portas = _agregar_contagem(_concat("portas"), "Serviço/porta destino")
    detalhes_ot = _agregar_contagem(_concat("detalhes_ot"), "Protocolo OT")

    return {
        "total": total,
        "bytes": total_bytes,
        "inicio": inicio,
        "fim": fim,
        "erros": erros,
        "limite": limite,
        "protocolos": protocolos,
        "origens": origens.head(100) if not origens.empty else origens,
        "portas": portas.head(100) if not portas.empty else portas,
        "fluxos": _concat("fluxos"),
        "externos": _concat("externos"),
        "dns": _concat("dns"),
        "eventos": _concat("eventos"),
        "eventos_ot": _concat("eventos_ot"),
        "iocs": deduplicar_iocs(_concat("iocs"), col_ioc="IOC"),
        "iocs_candidatos": deduplicar_iocs(_concat("iocs_candidatos"), col_ioc="IOC candidato"),
        "downloads_suspeitos": _concat("downloads_suspeitos"),
        "amostra": _concat("amostra"),
        "alertas": _concat("alertas"),
        "ativos_ot": deduplicar_ativos_ot(_concat("ativos_ot")),
        "transferencias_ot": _concat("transferencias_ot"),
        "anomalias_ot": _concat("anomalias_ot"),
        "detalhes_ot": detalhes_ot,
        "grafo": grafo,
        "servicos": servicos,
        "arquivos": pd.DataFrame(arquivos_meta),
        "sha256_lista": shas,
    }


def detectar_irregularidades_multi(resultado, lista_meta):
    """
    Heurísticas de irregularidade entre uma ou várias capturas.
    Não afirma comprometimento — apenas padrões que merecem revisão.
    """
    irregularidades = []
    n_arquivos = len(lista_meta)

    # 1) IP externo presente em múltiplas capturas
    if n_arquivos >= 2 and not resultado["externos"].empty and "Captura" in resultado["externos"].columns:
        por_ip = resultado["externos"].groupby("IP externo")["Captura"].nunique()
        for ip, qtd in por_ip.items():
            if qtd >= 2:
                irregularidades.append({
                    "Severidade": "Média",
                    "Tipo": "IP externo recorrente entre capturas",
                    "Alvo": ip,
                    "Arquivos envolvidos": qtd,
                    "Evidência": f"O IP {ip} aparece em {qtd} arquivos distintos.",
                    "Ordem sugerida": "Verificar timeline para sequência temporal desse IP.",
                })

    # 2) Mesmo hash de download em mais de um arquivo
    dl = resultado.get("downloads_suspeitos")
    if dl is not None and not dl.empty and "SHA-256" in dl.columns:
        col_arq = "Captura" if "Captura" in dl.columns else None
        if col_arq:
            por_hash = dl.groupby("SHA-256").agg(
                arquivos=(col_arq, "nunique"),
                ocorrencias=(col_arq, "count"),
            )
        else:
            por_hash = dl.groupby("SHA-256").size().to_frame("ocorrencias")
            por_hash["arquivos"] = 1
        for h, row in por_hash.iterrows():
            if row.get("arquivos", 1) >= 2 or row.get("ocorrencias", 0) >= 2:
                irregularidades.append({
                    "Severidade": "Alta",
                    "Tipo": "Mesmo payload/executável em capturas distintas",
                    "Alvo": h,
                    "Arquivos envolvidos": int(row.get("arquivos", 1)),
                    "Evidência": (
                        f"SHA-256 {h[:16]}… observado {int(row['ocorrencias'])} vez(es) "
                        f"em {int(row.get('arquivos', 1))} arquivo(s)."
                    ),
                    "Ordem sugerida": "Ordenar downloads por data/hora e correlacionar cliente/servidor.",
                })

    # 3) Comunicação OT a partir de IP público
    alertas = resultado.get("alertas")
    if alertas is not None and not alertas.empty:
        ot_ext = alertas[alertas["Tipo"].astype(str).str.contains("OT externa", case=False, na=False)]
        for _, a in ot_ext.head(50).iterrows():
            irregularidades.append({
                "Severidade": a.get("Severidade", "Alta"),
                "Tipo": "Comunicação OT com origem/destino público",
                "Alvo": f"{a.get('Origem', '-')} → {a.get('Destino', '-')}",
                "Arquivos envolvidos": 1,
                "Evidência": a.get("Detalhe", ""),
                "Ordem sugerida": "Priorizar na timeline eventos OT com IPs públicos.",
            })

    # 4) Varredura TCP
    if alertas is not None and not alertas.empty:
        scans = alertas[alertas["Tipo"].astype(str).str.contains("varredura", case=False, na=False)]
        for _, a in scans.head(30).iterrows():
            irregularidades.append({
                "Severidade": a.get("Severidade", "Média"),
                "Tipo": "Possível varredura TCP",
                "Alvo": a.get("Origem", "-"),
                "Arquivos envolvidos": 1,
                "Evidência": a.get("Detalhe", ""),
                "Ordem sugerida": "Colocar varredura antes de eventos OT/alteração na mesma origem.",
            })

    # 5) Sobreposição temporal estranha entre arquivos (mesmo host interno em janelas distantes com mesmo IOC)
    if n_arquivos >= 2 and lista_meta:
        # Ordena arquivos por início de captura
        ordenados = sorted(
            lista_meta,
            key=lambda x: x[2]["inicio"] or datetime.max.replace(tzinfo=timezone.utc),
        )
        for i in range(len(ordenados) - 1):
            n1, _, r1 = ordenados[i]
            n2, _, r2 = ordenados[i + 1]
            if r1["fim"] and r2["inicio"] and r2["inicio"] < r1["fim"]:
                irregularidades.append({
                    "Severidade": "Baixa",
                    "Tipo": "Sobreposição temporal entre capturas",
                    "Alvo": f"{n1} ∩ {n2}",
                    "Arquivos envolvidos": 2,
                    "Evidência": (
                        f"O período de '{n1}' e '{n2}' se sobrepõe. "
                        "Eventos podem parecer duplicados na timeline."
                    ),
                    "Ordem sugerida": "Usar Nº pacote + Captura para desambiguar.",
                })

    # 6) Sequência típica de irregularidade: varredura → OT escrita → download
    timeline = montar_timeline_eventos(resultado)
    if not timeline.empty:
        fontes_seq = timeline["Fonte"].tolist()
        cats = timeline["Categoria"].astype(str).str.lower().tolist()
        tem_scan = any("varredura" in c for c in cats)
        tem_ot_alt = any("alteração" in c or "escrita" in c or "transferência ot" in c for c in cats)
        tem_dl = any(f == "Download HTTP" for f in fontes_seq)
        if tem_scan and (tem_ot_alt or tem_dl):
            irregularidades.append({
                "Severidade": "Alta",
                "Tipo": "Sequência comportamental suspeita",
                "Alvo": "Timeline consolidada",
                "Arquivos envolvidos": n_arquivos,
                "Evidência": (
                    "Na ordem temporal aparecem varredura e, em seguida, "
                    "alteração/transferência OT e/ou download de executável."
                ),
                "Ordem sugerida": (
                    "1) Varredura → 2) Contato OT / escrita → 3) Transferência ou download. "
                    "Revise a timeline completa abaixo."
                ),
            })

    # Dedup por tipo+alvo
    vistos = set()
    limpos = []
    for item in irregularidades:
        chave = (item["Tipo"], item["Alvo"])
        if chave in vistos:
            continue
        vistos.add(chave)
        limpos.append(item)

    # Ordena por severidade
    ordem_sev = {"Alta": 0, "Média": 1, "Baixa": 2}
    limpos.sort(key=lambda x: ordem_sev.get(x["Severidade"], 9))
    return pd.DataFrame(limpos)


def classificar_acao_timeline(fonte, row, cat, det, proto):
    """
    Gera texto de ação legível para a timeline
    (upload/download, cópia SMB, escrita OT, Telnet, etc.).
    """
    if row.get("Ação") and str(row.get("Ação")).strip() not in {"", "-", "None"}:
        return str(row.get("Ação")).strip()

    cat_l = str(cat or "").lower()
    det_l = str(det or "").lower()
    proto_l = str(proto or "").lower()
    operacao = str(row.get("Operação") or "")
    classificacao = str(row.get("Classificação") or "")

    if fonte == "Download HTTP":
        tipo_arq = row.get("Tipo de arquivo") or cat
        return f"Download de {tipo_arq} via HTTP"

    if "transferência ot" in cat_l or "transferencia ot" in cat_l:
        return f"Transferência OT candidata ({proto or 'OT'})"
    if "alteração ot" in cat_l or "escrita" in cat_l:
        return f"Escrita/alteração OT — {operacao or proto or 'comando'}"

    if "credencial" in cat_l:
        if "ftp" in proto_l:
            return "Autenticação FTP (credencial exposta)"
        if "http" in proto_l:
            return "Autenticação HTTP (credencial exposta)"
        if "smtp" in proto_l:
            return "Autenticação SMTP (credencial exposta)"
        if "imap" in proto_l or "pop" in proto_l:
            return "Autenticação de e-mail (credencial exposta)"
        return f"Credencial exposta ({proto or 'protocolo'})"

    if "transferência de arquivo" in cat_l or "transferencia de arquivo" in cat_l:
        if "ftp" in proto_l:
            if "retr" in det_l:
                return "Download FTP (RETR)"
            if "stor" in det_l or "appe" in det_l:
                return "Upload FTP (STOR/APPE)"
            return "Transferência de arquivo via FTP"
        if "http" in proto_l:
            return "Upload/download de arquivo via HTTP"
        return "Transferência de arquivo"

    if "smb" in cat_l or "smb" in proto_l:
        if "write" in det_l or "escrita" in det_l or "cópia" in det_l or "copia" in det_l:
            return "Cópia/escrita SMB"
        if "read" in det_l or "leitura" in det_l:
            return "Leitura SMB"
        if "create" in det_l or "criação" in det_l or "criacao" in det_l:
            return "Criação/abertura de arquivo SMB"
        if "delete" in det_l or "exclusão" in det_l or "exclusao" in det_l:
            return "Exclusão SMB"
        if "tree connect" in det_l or "compartilhamento" in det_l:
            return "Acesso a compartilhamento SMB"
        if "session" in det_l or "autenticação" in det_l or "autenticacao" in det_l:
            return "Autenticação SMB"
        return "Atividade SMB"

    if "telnet" in proto_l or "telnet" in cat_l:
        return "Sessão Telnet (texto claro)"

    if "varredura" in cat_l:
        return "Possível varredura TCP"
    if "ot externa" in cat_l:
        return "Comunicação OT com IP público"
    if "download de executável" in cat_l or "download de executavel" in cat_l:
        return "Download de executável/payload via HTTP"

    if fonte == "OT":
        if operacao and operacao not in {"Não determinada", "-", "None"}:
            return f"Operação OT: {operacao}"
        if classificacao and classificacao not in {"-", "Indicador comportamental", "None"}:
            return classificacao
        return f"Comunicação OT ({proto or 'protocolo OT'})"

    if fonte == "Alerta":
        return str(cat or "Alerta de rede")

    return str(cat or fonte or "Evento")


def montar_timeline_eventos(resultado):
    """
    Consolida exposição, OT, alertas e downloads em uma timeline única
    com data/hora, nº do pacote, ação detectada e arquivo de origem.
    """
    linhas = []

    def _add(df, fonte, col_cat="Categoria", col_det="Detalhe"):
        if df is None or df.empty:
            return
        for _, row in df.iterrows():
            cat = row.get(col_cat) or row.get("Tipo") or row.get("Classificação") or fonte
            det = row.get(col_det) or row.get("Evidência") or row.get("Motivos") or ""
            proto = (
                row.get("Protocolo")
                or row.get("Protocolo OT")
                or row.get("Tipo de arquivo")
                or "-"
            )
            acao = classificar_acao_timeline(fonte, row, cat, det, proto)
            linhas.append({
                "Captura": row.get("Captura", "-"),
                "Nº pacote": row.get("Nº pacote", "-"),
                "Data/hora UTC": row.get("Data/hora UTC", "-"),
                "Fonte": fonte,
                "Ação": acao,
                "Categoria": cat,
                "Protocolo": proto,
                "Origem": row.get("Origem") or row.get("Cliente") or row.get("Servidor") or "-",
                "Destino": row.get("Destino") or row.get("Servidor") or row.get("Cliente") or "-",
                "Detalhe": str(det)[:300],
            })

    _add(resultado.get("eventos"), "Exposição")
    _add(resultado.get("eventos_ot"), "OT")
    _add(resultado.get("alertas"), "Alerta", col_cat="Tipo", col_det="Detalhe")
    _add(
        resultado.get("downloads_suspeitos"),
        "Download HTTP",
        col_cat="Tipo de arquivo",
        col_det="Motivos",
    )

    if not linhas:
        return pd.DataFrame()

    df = pd.DataFrame(linhas)
    df["_ord"] = df["Data/hora UTC"].apply(
        lambda v: "9999-99-99" if (not v or v == "-") else str(v)
    )
    df = df.sort_values(by=["_ord", "Captura", "Nº pacote"], ascending=True).drop(
        columns=["_ord"]
    ).reset_index(drop=True)
    df.insert(0, "Ordem", range(1, len(df) + 1))
    return df



def desenhar_timeline_eventos(df_timeline, chart_key="plotly_timeline_eventos"):
    """Gráfico de dispersão temporal + tabela cronológica."""
    if df_timeline is None or df_timeline.empty:
        st.info("Nenhum evento com data/hora para montar a timeline.")
        return

    st.subheader("Timeline de eventos")
    st.caption(
        "Linha do tempo consolidada (exposição, OT, alertas e downloads HTTP). "
        "Cada ponto é um evento com ação detectada (FTP/SMB/Telnet/upload/download/OT), nº de pacote e horário UTC."
    )

    # Prepara eixo temporal para Plotly (ignora linhas sem data parseável).
    plot_rows = []
    for _, row in df_timeline.iterrows():
        raw = row.get("Data/hora UTC")
        if not raw or raw == "-":
            continue
        try:
            # formato texto_data: YYYY-MM-DD HH:MM:SS
            ts = datetime.strptime(str(raw)[:19], "%Y-%m-%d %H:%M:%S")
        except Exception:
            continue
        plot_rows.append({
            "ts": ts,
            "Fonte": row["Fonte"],
            "Ação": row.get("Ação", row.get("Categoria", "")),
            "Categoria": row["Categoria"],
            "Protocolo": row["Protocolo"],
            "Origem": row["Origem"],
            "Destino": row["Destino"],
            "Nº pacote": row["Nº pacote"],
            "Detalhe": row["Detalhe"],
            "rótulo": f"{row['Fonte']}: {row.get('Ação', row.get('Categoria', ''))}",
        })

    if plot_rows:
        df_plot = pd.DataFrame(plot_rows)
        # Posição Y por fonte para legibilidade
        ordem_fontes = {"Exposição": 3, "OT": 2, "Alerta": 1, "Download HTTP": 0}
        df_plot["eixo_y"] = df_plot["Fonte"].map(lambda f: ordem_fontes.get(f, -1))

        fig = px.scatter(
            df_plot,
            x="ts",
            y="eixo_y",
            color="Fonte",
            hover_data={
                "ts": True,
                "Nº pacote": True,
                "Ação": True,
                "Categoria": True,
                "Protocolo": True,
                "Origem": True,
                "Destino": True,
                "Detalhe": True,
                "eixo_y": False,
            },
            color_discrete_map={
                "Exposição": "#F43F5E",
                "OT": "#F97316",
                "Alerta": "#EAB308",
                "Download HTTP": "#A78BFA",
            },
            labels={"ts": "Data/hora UTC", "eixo_y": ""},
        )
        fig.update_yaxes(
            tickvals=list(ordem_fontes.values()),
            ticktext=list(ordem_fontes.keys()),
            range=[-0.6, 3.6],
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.6)",
            font_color="#E2E8F0",
            height=320,
            margin=dict(t=20, b=40, l=10, r=10),
            legend=dict(orientation="h", y=1.12),
            xaxis=dict(gridcolor="#1E293B", showgrid=True),
            yaxis=dict(gridcolor="#1E293B", showgrid=True),
        )
        fig.update_traces(marker=dict(size=11, opacity=0.85, line=dict(width=0)))
        st.plotly_chart(fig, use_container_width=True, key=chart_key)
    else:
        st.caption("Datas não parseáveis para o gráfico; a tabela abaixo permanece completa.")

    st.dataframe(df_timeline, use_container_width=True, hide_index=True)
    st.download_button(
        "Baixar timeline em CSV",
        df_timeline.to_csv(index=False).encode("utf-8"),
        "timeline_eventos_pcap.csv",
        "text/csv",
        key=f"dl_timeline_{chart_key}",
    )



def _pdf_texto(val, limite=120):
    if val is None:
        return "-"
    s = str(val).replace("\n", " ").strip()
    return s if len(s) <= limite else s[: limite - 1] + "…"



def _pdf_escape(texto):
    """Escapa texto para stream PDF Type1 (latin-1 seguro)."""
    s = str(texto) if texto is not None else ""
    # normaliza acentos para evitar caracteres inválidos no fallback
    try:
        s = s.encode("latin-1", errors="replace").decode("latin-1")
    except Exception:
        s = s.encode("ascii", errors="replace").decode("ascii")
    return (
        s.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("\r", " ")
        .replace("\n", " ")
    )



def _gerar_pdf_simples(linhas_texto):
    """
    Gera um PDF mínimo sem dependências externas (fallback).
    linhas_texto: lista de strings (uma por linha visual).
    """
    from io import BytesIO

    # Quebra páginas a cada ~55 linhas
    max_linhas = 52
    paginas = []
    pagina = []
    for linha in linhas_texto:
        # quebra linhas longas
        s = str(linha) if linha is not None else ""
        while len(s) > 95:
            pagina.append(s[:95])
            s = s[95:]
            if len(pagina) >= max_linhas:
                paginas.append(pagina)
                pagina = []
        pagina.append(s)
        if len(pagina) >= max_linhas:
            paginas.append(pagina)
            pagina = []
    if pagina:
        paginas.append(pagina)
    if not paginas:
        paginas = [["(sem conteúdo)"]]

    objects = []
    # 1: Catalog, 2: Pages, then per page: page, content
    # We'll build content streams first
    content_ids = []
    page_ids = []
    obj_num = 3

    content_objs = []
    for pag in paginas:
        y = 800
        cmds = ["BT", "/F1 9 Tf", "14 TL", "50 800 Td"]
        first = True
        for linha in pag:
            esc = _pdf_escape(linha)
            if first:
                cmds.append(f"({esc}) Tj")
                first = False
            else:
                cmds.append(f"T* ({esc}) Tj")
        cmds.append("ET")
        stream = "\n".join(cmds).encode("latin-1", errors="replace")
        content_objs.append(stream)
        content_ids.append(obj_num)
        obj_num += 1
        page_ids.append(obj_num)
        obj_num += 1

    # Font object
    font_id = obj_num
    obj_num += 1

    # Build PDF body
    parts = []
    offsets = [0]

    def add_obj(num, body_bytes):
        offsets.append(None)  # placeholder
        while len(offsets) <= num:
            offsets.append(None)
        offsets[num] = sum(len(p) for p in parts)
        parts.append(f"{num} 0 obj\n".encode("latin-1"))
        parts.append(body_bytes)
        parts.append(b"\nendobj\n")

    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    add_obj(1, f"<< /Type /Catalog /Pages 2 0 R >>".encode("latin-1"))
    add_obj(
        2,
        f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("latin-1"),
    )

    for i, stream in enumerate(content_objs):
        cid = content_ids[i]
        pid = page_ids[i]
        add_obj(
            cid,
            f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1")
            + stream
            + b"\nendstream",
        )
        add_obj(
            pid,
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                f"/Contents {cid} 0 R /Resources << /Font << /F1 {font_id} 0 R >> >> >>"
            ).encode("latin-1"),
        )

    add_obj(
        font_id,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    )

    body = b"".join(parts)
    xref_pos = len(body) + len(b"%PDF-1.4\n")
    # recount offsets with header
    header = b"%PDF-1.4\n"
    # recompute offsets properly
    parts2 = []
    offsets = [0] * (font_id + 1)

    def add_obj2(num, body_bytes):
        offsets[num] = len(header) + sum(len(p) for p in parts2)
        parts2.append(f"{num} 0 obj\n".encode("latin-1"))
        parts2.append(body_bytes)
        parts2.append(b"\nendobj\n")

    add_obj2(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    add_obj2(2, f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("latin-1"))
    for i, stream in enumerate(content_objs):
        cid = content_ids[i]
        pid = page_ids[i]
        add_obj2(
            cid,
            f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream",
        )
        add_obj2(
            pid,
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                f"/Contents {cid} 0 R /Resources << /Font << /F1 {font_id} 0 R >> >> >>"
            ).encode("latin-1"),
        )
    add_obj2(font_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    body = b"".join(parts2)
    xref_pos = len(header) + len(body)
    max_obj = font_id
    xref = [f"xref\n0 {max_obj + 1}\n", "0000000000 65535 f \n"]
    for i in range(1, max_obj + 1):
        xref.append(f"{offsets[i]:010d} 00000 n \n")
    trailer = (
        f"trailer\n<< /Size {max_obj + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    )
    return header + body + "".join(xref).encode("latin-1") + trailer.encode("latin-1")



def _fig_para_bytes(fig, dpi=130):
    """Converte figura matplotlib em PNG bytes."""
    from io import BytesIO
    buf = BytesIO()
    fig.savefig(buf, format="png", dpi=dpi, bbox_inches="tight", facecolor=fig.get_facecolor())
    try:
        import matplotlib.pyplot as plt
        plt.close(fig)
    except Exception:
        pass
    buf.seek(0)
    return buf


def _graficos_relatorio(resultado):
    """
    Gera figuras alinhadas à visão web: pizza de protocolos, barras OT/origens,
    e mapa de topologia SEM detalhamento por IP.
    Todos os gráficos exibem os valores numéricos (contagens) nas fatias/barras.
    Retorna dict nome -> BytesIO PNG.
    """
    imgs = {}
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return imgs

    def _rotulos_barra_h(ax, bars, valores):
        """Escreve o número no final de cada barra horizontal."""
        xmax = max(valores) if len(valores) else 1
        for bar, val in zip(bars, valores):
            try:
                v = int(val)
            except Exception:
                v = val
            w = bar.get_width()
            y = bar.get_y() + bar.get_height() / 2
            ax.text(
                w + xmax * 0.01,
                y,
                f"{v:,}".replace(",", "."),
                va="center",
                ha="left",
                fontsize=8,
                color="#0F172A",
                fontweight="bold",
            )
        ax.set_xlim(0, xmax * 1.18 if xmax else 1)

    def _autopct_pizza(valores, min_pct=6.0):
        """Mostra quantidade+% só em fatias grandes o bastante (evita sobreposição)."""
        total = float(sum(valores)) or 1.0

        def _fmt(pct):
            if pct < min_pct:
                return ""
            qtd = int(round(pct * total / 100.0))
            return f"{qtd}\n({pct:.0f}%)"

        return _fmt

    # --- Pizza protocolos (quantidade + percentual, sem sobreposição) ---
    try:
        dfp = resultado.get("protocolos")
        if dfp is not None and not dfp.empty and "Protocolo" in dfp.columns:
            top = dfp.head(8).copy()  # limita fatias para legibilidade
            nomes = top["Protocolo"].astype(str).tolist()
            vals = [int(x) for x in top["Pacotes"].tolist()]
            total = sum(vals) or 1

            fig, ax = plt.subplots(figsize=(7.2, 4.6), facecolor="white")
            # donut: centro livre reduz sobreposição visual
            wedges, texts, autotexts = ax.pie(
                vals,
                labels=None,
                autopct=_autopct_pizza(vals, min_pct=7.0),
                startangle=90,
                pctdistance=0.72,
                explode=[0.02] * len(vals),
                wedgeprops={
                    "linewidth": 1.0,
                    "edgecolor": "white",
                    "width": 0.55,
                },
            )
            for t in autotexts:
                t.set_fontsize(8)
                t.set_fontweight("bold")
                t.set_color("#0F172A")

            # Legenda com TODOS os números (fonte confiável quando a fatia é pequena)
            legenda = []
            for p, v in zip(nomes, vals):
                pct = 100.0 * v / total
                legenda.append(f"{p}: {v:,} ({pct:.1f}%)".replace(",", "."))
            ax.legend(
                wedges,
                legenda,
                title="Protocolo — pacotes (%)",
                loc="center left",
                bbox_to_anchor=(1.02, 0.5),
                fontsize=8,
                frameon=True,
                fancybox=True,
                framealpha=0.95,
                edgecolor="#E2E8F0",
            )
            ax.set_title("Distribuição de protocolos (quantidade e %)", fontsize=11)
            # espaço à direita para a legenda
            fig.subplots_adjust(left=0.05, right=0.62, top=0.90, bottom=0.05)
            imgs["protocolos"] = _fig_para_bytes(fig)
    except Exception:
        pass

    # --- Barras OT com números ---
    try:
        dfo = resultado.get("detalhes_ot")
        if dfo is not None and not dfo.empty and "Protocolo OT" in dfo.columns:
            top = dfo.head(12).sort_values("Pacotes")
            vals = [int(x) for x in top["Pacotes"].tolist()]
            fig, ax = plt.subplots(
                figsize=(6.0, max(2.4, 0.38 * len(top) + 1.2)),
                facecolor="white",
            )
            bars = ax.barh(
                top["Protocolo OT"].astype(str),
                vals,
                color="#EF4444",
            )
            _rotulos_barra_h(ax, bars, vals)
            ax.set_xlabel("Pacotes")
            ax.set_title("Protocolos OT observados (quantidade)", fontsize=11)
            ax.tick_params(axis="y", labelsize=8)
            fig.tight_layout()
            imgs["ot"] = _fig_para_bytes(fig)
    except Exception:
        pass

    # --- Barras origens com números ---
    try:
        dfo = resultado.get("origens")
        if dfo is not None and not dfo.empty and "IP de origem" in dfo.columns:
            top = dfo.head(12).sort_values("Pacotes")
            vals = [int(x) for x in top["Pacotes"].tolist()]
            fig, ax = plt.subplots(
                figsize=(6.0, max(2.4, 0.36 * len(top) + 1.2)),
                facecolor="white",
            )
            bars = ax.barh(
                top["IP de origem"].astype(str),
                vals,
                color="#38BDF8",
            )
            _rotulos_barra_h(ax, bars, vals)
            ax.set_xlabel("Pacotes")
            ax.set_title("Principais IPs de origem (quantidade)", fontsize=11)
            ax.tick_params(axis="y", labelsize=7)
            fig.tight_layout()
            imgs["origens"] = _fig_para_bytes(fig)
    except Exception:
        pass

    # --- Barras portas de destino (se houver) ---
    try:
        dfp = resultado.get("portas")
        if dfp is not None and not dfp.empty:
            col_nome = "Serviço/porta destino" if "Serviço/porta destino" in dfp.columns else dfp.columns[0]
            col_val = "Pacotes" if "Pacotes" in dfp.columns else dfp.columns[1]
            top = dfp.head(12).sort_values(col_val)
            vals = [int(x) for x in top[col_val].tolist()]
            fig, ax = plt.subplots(
                figsize=(6.0, max(2.4, 0.36 * len(top) + 1.2)),
                facecolor="white",
            )
            bars = ax.barh(
                top[col_nome].astype(str),
                vals,
                color="#A78BFA",
            )
            _rotulos_barra_h(ax, bars, vals)
            ax.set_xlabel("Pacotes")
            ax.set_title("Portas / serviços de destino (quantidade)", fontsize=11)
            ax.tick_params(axis="y", labelsize=7)
            fig.tight_layout()
            imgs["portas"] = _fig_para_bytes(fig)
    except Exception:
        pass

    # --- Mapa de topologia simplificado (sem detalhe por IP) ---
    try:
        grafo = resultado.get("grafo")
        if grafo is not None and getattr(grafo, "number_of_nodes", lambda: 0)() > 0:
            import networkx as nx
            edges = sorted(
                grafo.edges(data=True),
                key=lambda e: e[2].get("Bytes", 0),
                reverse=True,
            )[:120]
            g = nx.Graph()
            for a, b, d in edges:
                g.add_edge(a, b, **d)
            for n in list(g.nodes()):
                if n in grafo.nodes:
                    g.nodes[n]["Tipo"] = grafo.nodes[n].get("Tipo", "Outro")
                    g.nodes[n]["Volume"] = grafo.nodes[n].get("Volume", 1)

            pos = nx.spring_layout(g, seed=42, k=1.2 / max(len(g.nodes()) ** 0.5, 1))
            fig, ax = plt.subplots(figsize=(7.2, 5.2), facecolor="#0B1220")
            ax.set_facecolor("#0B1220")
            ax.set_title(
                "Mapa de topologia (visão geral — sem detalhe por IP)",
                color="#E2E8F0",
                fontsize=11,
            )

            cores_tipo = {
                "Interno": "#22C55E",
                "Externo": "#F97316",
                "DNS": "#38BDF8",
                "Outro": "#A78BFA",
            }
            for a, b, d in g.edges(data=True):
                apps = d.get("Apps") or {}
                if apps:
                    app = max(apps, key=apps.get)
                else:
                    protos = d.get("Protocolos") or set()
                    app = next(iter(protos), "Outro") if protos else "Outro"
                cor = CORES_APP.get(app, "#64748B")
                vol = max(d.get("Bytes", 1), 1)
                w = min(0.6 + (vol / 500000) ** 0.5, 3.5)
                x = [pos[a][0], pos[b][0]]
                y = [pos[a][1], pos[b][1]]
                ax.plot(x, y, color=cor, linewidth=w, alpha=0.75, zorder=1)

            for n, data in g.nodes(data=True):
                tipo = data.get("Tipo", "Outro")
                cor = cores_tipo.get(tipo, cores_tipo["Outro"])
                vol = max(data.get("Volume", 1), 1)
                size = min(max(40 + (vol / 80000) ** 0.4 * 80, 40), 280)
                ax.scatter(
                    pos[n][0], pos[n][1],
                    s=size, c=cor, edgecolors="white", linewidths=0.6,
                    zorder=2, alpha=0.95,
                )

            from matplotlib.lines import Line2D
            handles = [
                Line2D([0], [0], marker="o", color="w", label=t,
                       markerfacecolor=c, markersize=8)
                for t, c in cores_tipo.items()
            ]
            ax.legend(
                handles=handles, loc="lower right", fontsize=7,
                framealpha=0.85, facecolor="#1E293B", labelcolor="#E2E8F0",
            )
            ax.set_xticks([])
            ax.set_yticks([])
            for spine in ax.spines.values():
                spine.set_visible(False)
            fig.tight_layout()
            imgs["mapa"] = _fig_para_bytes(fig, dpi=140)
    except Exception:
        pass

    return imgs





def _n_df(df):
    if df is None:
        return 0
    if hasattr(df, "empty"):
        return 0 if df.empty else int(len(df))
    try:
        return int(len(df))
    except Exception:
        return 0


def classificar_criticidade_ot(protocolos_str, portas_str=""):
    """Heurística local de criticidade do ativo OT (sem internet)."""
    p = (str(protocolos_str) + " " + str(portas_str)).lower()
    alta = ("s7", "modbus", "iec", "dnp3", "cip", "enip", "opc")
    if any(x in p for x in alta):
        return "Alta"
    if "ot" in p or "plc" in p:
        return "Média"
    return "Baixa"


def calcular_severidade_consolidada(resultado):
    """
    Score único local: Crítico / Alto / Médio / Baixo / Informativo.
    Baseado apenas em heurísticas da captura.
    """
    n_dl = _n_df(resultado.get("downloads_suspeitos"))
    n_exp = _n_df(resultado.get("eventos"))
    n_alertas = _n_df(resultado.get("alertas"))
    n_transf = _n_df(resultado.get("transferencias_ot"))
    n_ativos = contar_ativos_ot_unicos(resultado.get("ativos_ot"))
    n_ext = _n_df(resultado.get("externos"))
    n_irr = _n_df(resultado.get("irregularidades"))
    n_iocs = contar_iocs_unicos(resultado.get("iocs_candidatos"))

    pontos = 0
    justificativas = []

    if n_dl:
        pontos += 40 + min(n_dl * 5, 20)
        justificativas.append(f"Download de executável/payload ({n_dl})")
    if n_transf:
        pontos += 25 + min(n_transf * 3, 15)
        justificativas.append(f"Transferência OT candidata ({n_transf})")
    if n_exp:
        pontos += 15 + min(n_exp, 15)
        justificativas.append(f"Exposição de dados em claro ({n_exp})")
    if n_ativos and n_ext:
        pontos += 20
        justificativas.append("Ativos OT e IPs públicos na mesma captura")
    if n_irr:
        pontos += 10 + min(n_irr * 2, 10)
        justificativas.append(f"Irregularidades multi-captura ({n_irr})")
    if n_alertas:
        pontos += min(n_alertas * 2, 15)
        justificativas.append(f"Alertas heurísticos ({n_alertas})")
    if n_iocs:
        pontos += min(n_iocs, 10)
        justificativas.append(f"IOCs candidatos derivados ({n_iocs})")

    if pontos >= 70:
        nivel = "Crítico"
    elif pontos >= 45:
        nivel = "Alto"
    elif pontos >= 25:
        nivel = "Médio"
    elif pontos >= 10:
        nivel = "Baixo"
    else:
        nivel = "Informativo"

    if not justificativas:
        justificativas.append("Nenhum indicador de alta severidade pelas heurísticas atuais")

    return {
        "nivel": nivel,
        "pontos": min(pontos, 100),
        "justificativas": justificativas,
    }


def montar_cadeia_ataque(resultado):
    """Ordena evidências em fases estilo kill-chain simplificada (local)."""
    fases = {
        "Reconhecimento": [],
        "Acesso inicial / entrega": [],
        "Movimentação / contato OT": [],
        "Ação em objetivo": [],
        "Exfiltração / exposição": [],
    }
    try:
        tl = montar_timeline_eventos(resultado)
    except Exception:
        tl = None

    if tl is not None and not tl.empty:
        for _, row in tl.head(60).iterrows():
            acao = str(row.get("Ação") or row.get("Categoria") or "").lower()
            fonte = str(row.get("Fonte") or "").lower()
            texto = (
                f"{row.get('Data/hora UTC', '-')} | {row.get('Ação') or row.get('Categoria')} | "
                f"{row.get('Origem')} → {row.get('Destino')} | {row.get('Captura')}"
            )
            if any(x in acao or x in fonte for x in ("dns", "scan", "varredura", "arp")):
                fases["Reconhecimento"].append(texto)
            elif any(x in acao or x in fonte for x in ("download", "http", "payload", "execut")):
                fases["Acesso inicial / entrega"].append(texto)
            elif any(x in acao or x in fonte for x in ("modbus", "s7", "iec", "cip", "opc", "dnp", "ot")):
                if any(x in acao for x in ("write", "upload", "start", "stop", "program")):
                    fases["Ação em objetivo"].append(texto)
                else:
                    fases["Movimentação / contato OT"].append(texto)
            elif any(x in acao or x in fonte for x in ("ftp", "telnet", "smb", "credencial", "exposição", "cleartext")):
                fases["Exfiltração / exposição"].append(texto)
            else:
                fases["Acesso inicial / entrega"].append(texto)

    dl = resultado.get("downloads_suspeitos")
    if dl is not None and not dl.empty:
        for _, row in dl.head(8).iterrows():
            fases["Acesso inicial / entrega"].append(
                f"Download {row.get('Tipo de arquivo', 'binário')} SHA-256={str(row.get('SHA-256', '-'))[:16]}… "
                f"| {row.get('Cliente')} → {row.get('Servidor')}"
            )

    exp = resultado.get("eventos")
    if exp is not None and not exp.empty:
        for _, row in exp.head(8).iterrows():
            fases["Exfiltração / exposição"].append(
                f"{row.get('Categoria')} / {row.get('Protocolo')} | {row.get('Origem')} → {row.get('Destino')}"
            )

    transf = resultado.get("transferencias_ot")
    if transf is not None and not transf.empty:
        for _, row in transf.head(8).iterrows():
            fases["Ação em objetivo"].append(
                f"Transferência OT {row.get('Protocolo')} | {row.get('Origem')} → {row.get('Destino')} | {row.get('Volume')}"
            )

    return fases


def comparar_multi_pcap(resultado):
    """Comparativo entre capturas: o que aparece só em uma, em várias, etc."""
    arq = resultado.get("arquivos")
    if arq is None or arq.empty or "Captura" not in arq.columns:
        return []
    nomes = [str(x) for x in arq["Captura"].tolist()]
    if len(nomes) <= 1:
        return [f"Análise de captura única: `{nomes[0] if nomes else '-'}`."]

    linhas = [f"**{len(nomes)} capturas** correlacionadas: " + ", ".join(f"`{n}`" for n in nomes)]

    # Alert types per capture
    alertas = resultado.get("alertas")
    if alertas is not None and not alertas.empty and "Captura" in alertas.columns:
        for nome in nomes:
            sub = alertas[alertas["Captura"].astype(str) == nome]
            linhas.append(f"- `{nome}`: {len(sub)} alerta(s)")
    irr = resultado.get("irregularidades")
    if irr is not None and not irr.empty:
        linhas.append(f"- Irregularidades de correlação multi-captura: **{len(irr)}**")
        for _, row in irr.head(12).iterrows():
            linhas.append(
                f"  - [{row.get('Severidade', '-')}] {row.get('Tipo', '-')} — {row.get('Evidência', '-')}"
            )
    return linhas


def checklist_resposta(resultado, severidade):
    """Checklist acionável SOC / engenharia OT."""
    items = []
    n_dl = _n_df(resultado.get("downloads_suspeitos"))
    n_exp = _n_df(resultado.get("eventos"))
    n_transf = _n_df(resultado.get("transferencias_ot"))
    n_ativos = contar_ativos_ot_unicos(resultado.get("ativos_ot"))
    n_ext = _n_df(resultado.get("externos"))

    items.append(
        {
            "item": "Preservar PCAPs originais, hashes SHA-256 e este relatório (cadeia de custódia)",
            "dono": "SOC / Forense",
            "prioridade": "Imediata",
        }
    )
    if n_dl:
        items.append(
            {
                "item": "Submeter hashes de payload a sandbox/threat intel; isolar hosts clientes do download",
                "dono": "SOC",
                "prioridade": "Imediata",
            }
        )
        items.append(
            {
                "item": "Bloquear temporariamente URL/IP de download no perímetro até validação",
                "dono": "Rede / SOC",
                "prioridade": "Alta",
            }
        )
    if n_exp:
        items.append(
            {
                "item": "Rotacionar credenciais potencialmente expostas e desabilitar Telnet/FTP em claro",
                "dono": "IAM / Infra",
                "prioridade": "Alta",
            }
        )
    if n_transf or n_ativos:
        items.append(
            {
                "item": "Validar com engenharia se writes/uploads OT ocorreram em janela de manutenção autorizada",
                "dono": "Engenharia OT",
                "prioridade": "Alta",
            }
        )
        items.append(
            {
                "item": "Revisar segmentação (Purdue / zonas e condutos) entre OT e IT/internet",
                "dono": "Arquitetura / OT",
                "prioridade": "Média",
            }
        )
    if n_ext and n_ativos:
        items.append(
            {
                "item": "Investigar rotas e firewall entre ativos OT e IPs públicos observados",
                "dono": "Rede",
                "prioridade": "Alta",
            }
        )
    items.append(
        {
            "item": "Correlacionar timeline com logs de firewall, EDR e historiador de processo",
            "dono": "SOC + OT",
            "prioridade": "Média",
        }
    )
    if severidade.get("nivel") in ("Crítico", "Alto"):
        items.insert(
            1,
            {
                "item": f"Acionar plantão — severidade consolidada **{severidade.get('nivel')}** ({severidade.get('pontos')} pts)",
                "dono": "SOC Manager",
                "prioridade": "Imediata",
            },
        )
    return items


def enriquecer_externos_internet(resultado, permitir=False, max_ips=8, timeout=3.0):
    """
    Consultas OPCIONAIS à internet (ip-api.com, sem chave).
    Só roda se o usuário autorizar explicitamente.
    Não envia PCAPs — apenas IPs públicos já observados na captura.
    """
    if not permitir:
        return []
    import json
    import urllib.request
    import urllib.error

    ext = resultado.get("externos")
    if ext is None or ext.empty:
        return []
    col = "IP externo" if "IP externo" in ext.columns else ext.columns[0]
    ips = [str(x) for x in ext[col].head(max_ips).tolist()]
    out = []
    for ip in ips:
        if not ip or ip.startswith(("10.", "192.168.", "127.", "169.254.")):
            continue
        # IPv6 / CGNAT rough skip for 172.16-31 handled partially
        if ip.startswith("172."):
            try:
                segundo = int(ip.split(".")[1])
                if 16 <= segundo <= 31:
                    continue
            except Exception:
                pass
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AnalisadorOT-PCAP/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            if data.get("status") != "success":
                out.append({"IP": ip, "Erro": data.get("message", "falha")})
                continue
            out.append(
                {
                    "IP": ip,
                    "País": data.get("country", "-"),
                    "Região": data.get("regionName", "-"),
                    "Cidade": data.get("city", "-"),
                    "ISP": data.get("isp", "-"),
                    "Org": data.get("org", "-"),
                    "ASN": data.get("as", "-"),
                }
            )
        except Exception as erro:
            out.append({"IP": ip, "Erro": str(erro)[:80]})
    return out


def fatos_e_hipoteses(resultado):
    """Separa evidências objetivas da captura de interpretações."""
    fatos = []
    hipoteses = []

    n_dl = _n_df(resultado.get("downloads_suspeitos"))
    n_exp = _n_df(resultado.get("eventos"))
    n_ot = _n_df(resultado.get("eventos_ot"))
    n_ativos = contar_ativos_ot_unicos(resultado.get("ativos_ot"))
    n_ext = _n_df(resultado.get("externos"))
    n_transf = _n_df(resultado.get("transferencias_ot"))

    if n_dl:
        fatos.append(f"Há **{n_dl}** sessão(ões) HTTP com conteúdo classificado como executável/payload.")
        hipoteses.append(
            "O download pode ser malware, atualização legítima ou ferramenta de engenharia — "
            "exige validação de hash e reputação."
        )
    if n_exp:
        fatos.append(f"Há **{n_exp}** evento(s) de possível dado/credencial em protocolo sem TLS.")
        hipoteses.append("Credenciais podem estar comprometidas se o tráfego foi interceptável.")
    if n_ativos:
        fatos.append(f"**{n_ativos}** IP(s) distintos comunicaram com assinatura de protocolo OT.")
    if n_ot:
        fatos.append(f"**{n_ot}** evento(s) OT foram extraídos das capturas.")
    if n_transf:
        fatos.append(f"**{n_transf}** fluxo(s) compatível(is) com transferência OT de maior volume.")
        hipoteses.append(
            "Pode tratar-se de upload de lógica de CLP ou coleta de dados de processo "
            "(autorizado ou não)."
        )
    if n_ativos and n_ext:
        fatos.append("Na mesma análise coexistem ativos OT e comunicação com IPs públicos.")
        hipoteses.append(
            "Pode existir ponte indevida entre zona de processo e IT/internet "
            "(ou captura mista de várias VLANs)."
        )
    if not fatos:
        fatos.append("Nenhum indicador forte foi materializado pelas heurísticas atuais.")
        hipoteses.append("Ausência de alerta não prova ausência de ameaça.")
    return fatos, hipoteses



def gerar_relatorio_analista(resultado, enriquecimento_externo=None):
    """
    Relatório narrativo detalhado — rede, automação e segurança IT/OT.
    Inclui severidade consolidada, cadeia de ataque, fatos vs hipóteses,
    comparativo multi-PCAP, criticidade OT, checklist e enriquecimento opcional.
    """
    def _linhas_df(df, cols, max_linhas=25):
        out = []
        if df is None or (hasattr(df, "empty") and df.empty):
            out.append("- *(sem registros)*")
            return out
        cols_ok = [c for c in cols if c in df.columns]
        if not cols_ok:
            cols_ok = list(df.columns)[:6]
        for _, row in df.head(max_linhas).iterrows():
            partes = []
            for c in cols_ok:
                v = row.get(c, "-")
                if v is None or (isinstance(v, float) and str(v) == "nan"):
                    v = "-"
                partes.append(f"**{c}:** `{v}`")
            out.append("- " + " | ".join(partes))
        if len(df) > max_linhas:
            out.append(f"- *… +{len(df) - max_linhas} registro(s) omitido(s)*")
        return out

    linhas = []
    n_arq = _n_df(resultado.get("arquivos"))
    n_pct = int(resultado.get("total") or 0)
    vol = bytes_legivel(resultado.get("bytes") or 0)
    inicio = texto_data(resultado.get("inicio"))
    fim = texto_data(resultado.get("fim"))
    n_ativos = contar_ativos_ot_unicos(resultado.get("ativos_ot"))
    n_ot = _n_df(resultado.get("eventos_ot"))
    n_transf = _n_df(resultado.get("transferencias_ot"))
    n_exp = _n_df(resultado.get("eventos"))
    n_alertas = _n_df(resultado.get("alertas"))
    n_dl = _n_df(resultado.get("downloads_suspeitos"))
    n_iocs = contar_iocs_unicos(resultado.get("iocs_candidatos"))
    n_irr = _n_df(resultado.get("irregularidades"))
    n_ext = _n_df(resultado.get("externos"))
    n_dns = _n_df(resultado.get("dns"))
    n_fluxos = _n_df(resultado.get("fluxos"))
    n_iocs_conhecidos = _n_df(resultado.get("iocs"))

    sev = calcular_severidade_consolidada(resultado)
    fatos, hipoteses = fatos_e_hipoteses(resultado)
    cadeia = montar_cadeia_ataque(resultado)
    checklist = checklist_resposta(resultado, sev)
    multi = comparar_multi_pcap(resultado)
    if enriquecimento_externo is None:
        enriquecimento_externo = []

    linhas.append("# Relatório analítico — Rede, Segurança IT e OT")
    linhas.append("")
    linhas.append(
        "*Documento gerado localmente a partir das heurísticas da captura. "
        "Não substitui investigação forense completa. "
        "Consultas externas, se houver, foram autorizadas explicitamente e não enviam o PCAP.*"
    )
    linhas.append("")
    linhas.append("## 0. Severidade consolidada")
    linhas.append(
        f"- **Nível:** **{sev['nivel']}**  \n"
        f"- **Pontuação orientativa:** {sev['pontos']}/100  \n"
        f"- **Principais fatores:**"
    )
    for j in sev["justificativas"]:
        linhas.append(f"  - {j}")

    linhas.append("")
    linhas.append("## 1. Escopo e inventário")
    linhas.append(
        f"- **Arquivos:** {n_arq}\n"
        f"- **Pacotes:** {n_pct:,}\n".replace(",", ".")
        + f"- **Volume:** {vol}\n"
        f"- **Período UTC:** {inicio} → {fim}\n"
        f"- **Fluxos (tabela):** {n_fluxos} | **Externos:** {n_ext} | **DNS (amostra):** {n_dns}"
    )
    arq_df = resultado.get("arquivos")
    if arq_df is not None and not arq_df.empty:
        linhas.append("")
        linhas.append("### 1.1 Capturas")
        for _, row in arq_df.iterrows():
            linhas.append(
                f"- **`{row.get('Captura', '-')}`**  \n"
                f"  - SHA-256: `{row.get('SHA-256', '-')}`  \n"
                f"  - Pacotes: {row.get('Pacotes', '-')} | Volume: {row.get('Volume', '-')}  \n"
                f"  - Janela: {row.get('Início UTC', '-')} → {row.get('Fim UTC', '-')}"
            )

    linhas.append("")
    linhas.append("## 2. Fatos observados vs hipóteses")
    linhas.append("### 2.1 Fatos (evidência na captura)")
    for f in fatos:
        linhas.append(f"- {f}")
    linhas.append("### 2.2 Hipóteses (interpretação — validar)")
    for h in hipoteses:
        linhas.append(f"- {h}")

    linhas.append("")
    linhas.append("## 3. Cadeia de ataque sugerida (ordenação heurística)")
    for fase, itens in cadeia.items():
        linhas.append(f"### {fase}")
        if not itens:
            linhas.append("- *(sem evidências classificadas nesta fase)*")
        else:
            for it in itens[:12]:
                linhas.append(f"- {it}")
            if len(itens) > 12:
                linhas.append(f"- *… +{len(itens) - 12} item(ns)*")

    linhas.append("")
    linhas.append("## 4. Comparativo multi-PCAP")
    for m in multi:
        linhas.append(f"- {m}" if not m.startswith("-") and not m.startswith("**") else m)
    # fix: multi items already have - prefix sometimes
    if not multi:
        linhas.append("- *(captura única ou sem dados)*")

    linhas.append("")
    linhas.append("## 5. Painel de indicadores")
    linhas.append(
        f"| Indicador | Qtd |\n|---|---:|\n"
        f"| Ativos OT (IPs únicos) | {n_ativos} |\n"
        f"| Eventos OT | {n_ot} |\n"
        f"| Transferências OT | {n_transf} |\n"
        f"| Exposições | {n_exp} |\n"
        f"| Alertas | {n_alertas} |\n"
        f"| Downloads executável | {n_dl} |\n"
        f"| IOCs candidatos | {n_iocs} |\n"
        f"| IOCs lista local | {n_iocs_conhecidos} |\n"
        f"| Irregularidades | {n_irr} |"
    )

    linhas.append("")
    linhas.append("## 6. Protocolos, origens e portas")
    linhas.extend(_linhas_df(resultado.get("protocolos"), ["Protocolo", "Pacotes"], 20))
    linhas.append("### Origens")
    linhas.extend(_linhas_df(resultado.get("origens"), ["IP de origem", "Pacotes"], 15))
    linhas.append("### Portas / serviços")
    linhas.extend(_linhas_df(resultado.get("portas"), ["Serviço/porta destino", "Pacotes"], 15))

    linhas.append("")
    linhas.append("## 7. Timeline unificada (detalhada)")
    try:
        tl = montar_timeline_eventos(resultado)
        if tl is not None and not tl.empty:
            for _, row in tl.head(40).iterrows():
                linhas.append(
                    f"- **#{row.get('Ordem', '-')}** | **{row.get('Data/hora UTC', '-')}** | "
                    f"pacote `{row.get('Nº pacote', '-')}` | *{row.get('Captura', '-')}*\n"
                    f"  - **{row.get('Ação') or row.get('Categoria') or '-'}** "
                    f"({row.get('Fonte', '-')}) | `{row.get('Origem')}` → `{row.get('Destino')}`"
                )
            if len(tl) > 40:
                linhas.append(f"- *… +{len(tl) - 40} eventos na interface*")
        else:
            linhas.append("- *(vazia)*")
    except Exception as err_tl:
        linhas.append(f"- *(erro timeline: `{err_tl}`)*")

    linhas.append("")
    linhas.append("## 8. Alertas e downloads")
    linhas.extend(
        _linhas_df(
            resultado.get("alertas"),
            ["Severidade", "Tipo", "Origem", "Destino", "Detalhe", "Captura"],
            30,
        )
    )
    linhas.append("### Downloads")
    linhas.extend(
        _linhas_df(
            resultado.get("downloads_suspeitos"),
            ["Captura", "Tipo de arquivo", "SHA-256", "Severidade", "Cliente", "Servidor"],
            20,
        )
    )

    linhas.append("")
    linhas.append("## 9. Ambiente OT (com criticidade heurística)")
    ativos = resultado.get("ativos_ot")
    if ativos is not None and not ativos.empty:
        for _, row in ativos.head(30).iterrows():
            crit = classificar_criticidade_ot(
                row.get("Protocolos OT", ""),
                row.get("Portas OT", ""),
            )
            linhas.append(
                f"- **Ativo:** `{row.get('Ativo', '-')}` | **Criticidade:** **{crit}** | "
                f"Protocolos: {row.get('Protocolos OT', '-')} | Portas: {row.get('Portas OT', '-')} | "
                f"Peers: {row.get('Peers', '-')} | Fluxos: {row.get('Fluxos', '-')}"
            )
    else:
        linhas.append("- *(nenhum ativo OT)*")
    linhas.append("### Protocolos OT / transferências / eventos")
    linhas.extend(_linhas_df(resultado.get("detalhes_ot"), ["Protocolo OT", "Pacotes"], 15))
    linhas.extend(
        _linhas_df(
            resultado.get("transferencias_ot"),
            ["Origem", "Destino", "Protocolo", "Volume", "Pacotes", "Captura"],
            15,
        )
    )
    linhas.extend(
        _linhas_df(
            resultado.get("eventos_ot"),
            ["Captura", "Nº pacote", "Data/hora UTC", "Protocolo", "Origem", "Destino", "Detalhe"],
            20,
        )
    )

    linhas.append("")
    linhas.append("## 10. Exposição, externos e DNS")
    linhas.extend(
        _linhas_df(
            resultado.get("eventos"),
            ["Captura", "Categoria", "Protocolo", "Origem", "Destino", "Detalhe"],
            20,
        )
    )
    linhas.append("### IPs externos")
    linhas.extend(
        _linhas_df(
            resultado.get("externos"),
            ["IP externo", "Fluxos", "Pacotes", "Volume", "Serviços observados"],
            20,
        )
    )
    linhas.append("### DNS")
    linhas.extend(
        _linhas_df(
            resultado.get("dns"),
            ["Consulta", "Tipo", "Resposta", "Cliente", "Servidor"],
            15,
        )
    )

    linhas.append("")
    linhas.append("## 11. Enriquecimento externo (GeoIP / ASN) — opcional")
    if enriquecimento_externo:
        for item in enriquecimento_externo:
            if "Erro" in item:
                linhas.append(f"- `{item.get('IP')}`: erro — {item.get('Erro')}")
            else:
                linhas.append(
                    f"- **`{item.get('IP')}`** — {item.get('País')}/{item.get('Região')}/{item.get('Cidade')} | "
                    f"ISP: {item.get('ISP')} | Org: {item.get('Org')} | {item.get('ASN')}"
                )
        linhas.append("")
        linhas.append("*Fonte: ip-api.com (consulta autorizada pelo usuário). PCAP não foi enviado.*")
    else:
        linhas.append(
            "- Nenhuma consulta externa executada. "
            "Ative em **Configurações → Permitir consultas externas** para GeoIP/ASN de IPs públicos."
        )

    linhas.append("")
    linhas.append("## 12. IOCs")
    linhas.append("### Candidatos derivados")
    linhas.extend(
        _linhas_df(
            resultado.get("iocs_candidatos"),
            ["Tipo", "IOC candidato", "Motivo", "Evidência"],
            30,
        )
    )
    linhas.append("### Lista local")
    linhas.extend(
        _linhas_df(resultado.get("iocs"), ["Tipo", "IOC", "Ocorrências", "Fonte"], 20)
    )

    linhas.append("")
    linhas.append("## 13. Irregularidades")
    linhas.extend(
        _linhas_df(
            resultado.get("irregularidades"),
            ["Severidade", "Tipo", "Alvo", "Evidência", "Ordem sugerida"],
            25,
        )
    )

    linhas.append("")
    linhas.append("## 14. Pontos de atenção IT")
    if n_dl:
        linhas.append("- **Alta:** Validar hashes; isolar clientes do download; revisar egress HTTP.")
    if n_exp:
        linhas.append("- **Alta/Média:** Rotacionar segredos; eliminar serviços em claro.")
    if n_ext and n_dl:
        linhas.append("- **Média:** Cruzar IPs externos com servidores de payload.")
    if n_alertas and not (n_dl or n_exp):
        linhas.append(f"- Revisar {n_alertas} alerta(s) na interface.")
    if not (n_dl or n_exp or n_alertas):
        linhas.append("- Sem alertas IT críticos pelas heurísticas atuais.")

    linhas.append("")
    linhas.append("## 15. Pontos de atenção OT")
    if n_ativos and n_ext:
        linhas.append("- **Alta:** Possível ponte OT↔pública — validar segmentação.")
    if n_transf:
        linhas.append("- **Alta:** Transferência OT — confrontar com change management.")
    if n_ot:
        linhas.append("- **Média:** Inventariar funções (write/start/upload) vs baseline.")
    if not (n_ativos or n_transf or n_ot):
        linhas.append("- Sem indícios OT relevantes nas heurísticas atuais.")

    linhas.append("")
    linhas.append("## 16. Checklist de resposta")
    linhas.append("| Prioridade | Responsável | Ação |")
    linhas.append("|---|---|---|")
    for c in checklist:
        linhas.append(f"| {c['prioridade']} | {c['dono']} | {c['item']} |")

    linhas.append("")
    linhas.append("## 17. Recomendações finais")
    linhas.append(
        f"- Tratar como severidade **{sev['nivel']}** até prova em contrário.\n"
        "- Preservar evidências e correlacionar com firewall, EDR e historiador.\n"
        "- Threat intel de hash/IP é **opcional** e deve ser feita sob política da organização."
    )
    linhas.append("")
    linhas.append("---")
    linhas.append(
        f"*Analisador OT de PCAP · local · severidade={sev['nivel']} ({sev['pontos']}/100) · "
        f"pacotes={n_pct} · OT ativos={n_ativos} · downloads={n_dl}*"
    )
    return "\n".join(linhas)



def gerar_relatorio_analista_html(resultado, enriquecimento_externo=None):
    """
    HTML do relatório analítico (offline) com severidade, mapa estático e detalhamento.
    """
    import html as html_mod
    import re
    import base64

    md = gerar_relatorio_analista(resultado, enriquecimento_externo=enriquecimento_externo)
    sev = calcular_severidade_consolidada(resultado)
    cores_sev = {
        "Crítico": "#DC2626",
        "Alto": "#EA580C",
        "Médio": "#CA8A04",
        "Baixo": "#2563EB",
        "Informativo": "#64748B",
    }
    cor_s = cores_sev.get(sev["nivel"], "#64748B")

    # Mapa estático (mesma lógica do PDF) embutido em base64 se possível
    mapa_html = ""
    try:
        imgs = _graficos_relatorio(resultado)
        if imgs.get("mapa"):
            b64 = base64.b64encode(imgs["mapa"].getvalue()).decode("ascii")
            mapa_html = (
                "<h2>Mapa de topologia (visão geral)</h2>"
                "<p style='color:#94A3B8;font-size:0.9rem;'>Sem detalhamento por IP — apenas estrutura e protocolos.</p>"
                f"<img src='data:image/png;base64,{b64}' "
                "style='max-width:100%;border-radius:12px;border:1px solid #1E293B;'/>"
            )
        # pizza/protocolos
        extras = []
        for key, titulo in (
            ("protocolos", "Distribuição de protocolos"),
            ("ot", "Protocolos OT"),
            ("origens", "Principais origens"),
        ):
            if imgs.get(key):
                b64 = base64.b64encode(imgs[key].getvalue()).decode("ascii")
                extras.append(
                    f"<h3>{titulo}</h3>"
                    f"<img src='data:image/png;base64,{b64}' "
                    "style='max-width:100%;border-radius:10px;border:1px solid #1E293B;margin-bottom:12px;'/>"
                )
        if extras:
            mapa_html = "<h2>Gráficos da análise</h2>" + "".join(extras) + mapa_html
    except Exception:
        mapa_html = ""

    def md_para_html(src):
        linhas_out = []
        em_lista = False
        em_tabela = False
        for bruta in src.splitlines():
            linha = bruta.rstrip()
            if not linha.strip():
                if em_lista:
                    linhas_out.append("</ul>")
                    em_lista = False
                if em_tabela:
                    linhas_out.append("</tbody></table>")
                    em_tabela = False
                linhas_out.append("")
                continue
            if linha.startswith("### "):
                if em_lista:
                    linhas_out.append("</ul>")
                    em_lista = False
                t = html_mod.escape(linha[4:])
                linhas_out.append(f"<h3>{t}</h3>")
            elif linha.startswith("## "):
                if em_lista:
                    linhas_out.append("</ul>")
                    em_lista = False
                t = html_mod.escape(linha[3:])
                linhas_out.append(f"<h2>{t}</h2>")
            elif linha.startswith("# "):
                if em_lista:
                    linhas_out.append("</ul>")
                    em_lista = False
                t = html_mod.escape(linha[2:])
                linhas_out.append(f"<h1>{t}</h1>")
            elif linha.startswith("---"):
                if em_lista:
                    linhas_out.append("</ul>")
                    em_lista = False
                if em_tabela:
                    linhas_out.append("</tbody></table>")
                    em_tabela = False
                linhas_out.append("<hr/>")
            elif "|" in linha and linha.strip().startswith("|"):
                if em_lista:
                    linhas_out.append("</ul>")
                    em_lista = False
                cells = [c.strip() for c in linha.strip().strip("|").split("|")]
                if cells and all(set(c) <= set("-: ") and c for c in cells):
                    continue
                if not em_tabela:
                    em_tabela = True
                    linhas_out.append(
                        "<table><thead><tr>"
                        + "".join(f"<th>{html_mod.escape(c)}</th>" for c in cells)
                        + "</tr></thead><tbody>"
                    )
                else:
                    linhas_out.append(
                        "<tr>"
                        + "".join(f"<td>{html_mod.escape(c)}</td>" for c in cells)
                        + "</tr>"
                    )
            elif linha.lstrip().startswith("- "):
                if em_tabela:
                    linhas_out.append("</tbody></table>")
                    em_tabela = False
                if not em_lista:
                    linhas_out.append("<ul>")
                    em_lista = True
                item = linha.lstrip()[2:]
                # negrito **x** e codigo `x`
                item = html_mod.escape(item)
                item = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", item)
                item = re.sub(r"`(.+?)`", r"<code>\1</code>", item)
                linhas_out.append(f"<li>{item}</li>")
            else:
                if em_lista:
                    linhas_out.append("</ul>")
                    em_lista = False
                item = html_mod.escape(linha)
                item = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", item)
                item = re.sub(r"`(.+?)`", r"<code>\1</code>", item)
                item = re.sub(r"\*(.+?)\*", r"<em>\1</em>", item)
                linhas_out.append(f"<p>{item}</p>")
        if em_lista:
            linhas_out.append("</ul>")
        if em_tabela:
            linhas_out.append("</tbody></table>")
        return "\n".join(linhas_out)

    corpo = md_para_html(md)
    sev_nivel = sev["nivel"]
    sev_pontos = sev["pontos"]
    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Relatório analítico — Rede · Segurança IT · OT</title>
  <style>
    /* fontes do sistema — offline */
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Ubuntu, sans-serif;
      background: linear-gradient(180deg, #0B1220 0%, #0F172A 40%, #111827 100%);
      color: #E2E8F0;
      min-height: 100vh;
      line-height: 1.55;
    }}
    .wrap {{
      max-width: 920px;
      margin: 0 auto;
      padding: 28px 20px 48px;
    }}
    .hero {{
      background: linear-gradient(135deg, #0F172A 0%, #1E3A5F 50%, #0F172A 100%);
      border: 1px solid #1E293B;
      border-radius: 16px;
      padding: 20px 22px;
      margin-bottom: 22px;
    }}
    .hero h1 {{
      margin: 0 0 6px 0;
      font-size: 1.35rem;
      color: #F8FAFC;
      font-weight: 600;
    }}
    .hero p {{
      margin: 0;
      color: #94A3B8;
      font-size: 0.92rem;
    }}
    h1 {{ color: #F8FAFC; font-size: 1.4rem; }}
    h2 {{
      color: #F1F5F9;
      font-size: 1.1rem;
      margin-top: 1.6rem;
      border-bottom: 1px solid #1E293B;
      padding-bottom: 6px;
    }}
    h3 {{ color: #CBD5E1; font-size: 1rem; margin-top: 1.1rem; }}
    p {{ color: #CBD5E1; }}
    ul {{ padding-left: 1.2rem; }}
    li {{ margin: 0.35rem 0; color: #CBD5E1; }}
    strong {{ color: #F8FAFC; }}
    code {{
      background: #1E293B;
      color: #7DD3FC;
      padding: 1px 6px;
      border-radius: 4px;
      font-size: 0.88em;
    }}
    hr {{ border: 0; border-top: 1px solid #1E293B; margin: 1.5rem 0; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 0.8rem 0 1.2rem;
      font-size: 0.9rem;
    }}
    th, td {{
      border: 1px solid #1E293B;
      padding: 8px 10px;
      text-align: left;
    }}
    th {{ background: #1E293B; color: #F8FAFC; }}
    td {{ color: #CBD5E1; }}
    .footer {{
      margin-top: 2rem;
      color: #64748B;
      font-size: 0.82rem;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <h1>Relatório analítico — Rede · Segurança IT · OT</h1>
      <p>Síntese detalhada · fatos vs hipóteses · cadeia de ataque · checklist. Processamento local.</p>
      <div style="margin-top:12px;display:inline-block;padding:6px 12px;border-radius:999px;
                  background:{cor_s};color:#fff;font-weight:600;font-size:0.9rem;">
        Severidade: {sev_nivel} ({sev_pontos}/100)
      </div>
    </div>
    <article>
      {mapa_html}
      {corpo}
    </article>
    <div class="footer">Analisador OT de PCAP · relatório gerado localmente</div>
  </div>
</body>
</html>
"""


def abrir_relatorio_nova_aba(html_doc, open_id=0):
    """Abre SEMPRE uma nova aba do navegador com o HTML do relatório.

    open_id deve mudar a cada clique para o Streamlit reexecutar o JS
    (components.html não dispara de novo se o conteúdo/chave forem iguais).
    """
    import json
    import time as _time
    payload = json.dumps(html_doc)
    ts = int(_time.time() * 1000)
    nome_aba = f"relatorio_ot_{ts}_{open_id}"
    # key única força novo iframe/script a cada geração
    components.html(
        f"""
        <script>
        (function() {{
          var html = {payload};
          var blob = new Blob([html], {{ type: "text/html;charset=utf-8" }});
          var url = URL.createObjectURL(blob);
          var nome = "{nome_aba}";
          var w = null;
          try {{ w = window.open(url, "_blank"); }} catch (e1) {{}}
          if (!w) {{
            try {{ w = window.top.open(url, "_blank"); }} catch (e2) {{}}
          }}
          if (!w) {{
            try {{ w = window.open(url, nome); }} catch (e3) {{}}
          }}
          var msg = document.getElementById("msg_{open_id}");
          if (!w) {{
            if (msg) msg.innerText =
              "O navegador bloqueou a nova aba. Permita pop-ups para este site e clique novamente em Relatório.";
          }} else {{
            if (msg) msg.innerText = "Relatório detalhado aberto em nova aba (" + nome + ").";
          }}
        }})();
        </script>
        <p id="msg_{open_id}" style="font-family:system-ui,sans-serif;color:#94A3B8;font-size:13px;margin:4px 0;">
          Abrindo relatório detalhado… (#{open_id})
        </p>
        """,
        height=52,
    )



def gerar_relatorio_pdf(resultado, lista_meta=None, progresso=None):
    """
    Gera PDF estruturado com os mesmos eixos da análise web
    (tabelas, gráficos e mapa de topologia sem detalhe por IP).

    progresso: callable opcional (fracao 0-1, texto) para atualizar barra na UI.
    Preferência: reportlab (completo). Fallback textual só se reportlab não existir.
    """
    def _p(frac, msg=""):
        if callable(progresso):
            try:
                progresso(min(max(frac, 0.0), 1.0), msg)
            except Exception:
                pass

    _p(0.05, "Verificando motor de PDF…")
    try:
        import reportlab  # noqa: F401
        tem_reportlab = True
    except ImportError:
        tem_reportlab = False

    if tem_reportlab:
        _p(0.15, "Montando relatório completo…")
        pdf = _gerar_pdf_reportlab(resultado, lista_meta, progresso=_p)
        _p(1.0, "Concluído")
        try:
            import streamlit as _st
            _st.session_state["pdf_modo"] = "completo"
        except Exception:
            pass
        return pdf

    _p(0.3, "reportlab ausente — usando PDF textual…")
    pdf = _gerar_pdf_fallback(resultado, lista_meta)
    _p(1.0, "Concluído (modo textual)")
    try:
        import streamlit as _st
        _st.session_state["pdf_modo"] = "textual"
    except Exception:
        pass
    return pdf


def _gerar_pdf_fallback(resultado, lista_meta=None):
    """PDF textual simples quando reportlab não está instalado."""
    linhas = []
    linhas.append("RELATORIO — Analisador OT de PCAP")
    linhas.append("=" * 60)
    linhas.append("Processamento local · heuristicas OT · timeline unificada")
    linhas.append("")

    def _len_df(df):
        if df is None:
            return 0
        if hasattr(df, "empty"):
            return 0 if df.empty else len(df)
        try:
            return len(df)
        except Exception:
            return 0

    n_ativos = contar_ativos_ot_unicos(resultado.get("ativos_ot"))
    n_iocs = contar_iocs_unicos(resultado.get("iocs_candidatos"))
    n_irr = _len_df(resultado.get("irregularidades"))
    n_arq = _len_df(resultado.get("arquivos"))
    inicio = texto_data(resultado.get("inicio"))
    fim = texto_data(resultado.get("fim"))

    linhas.append("1. RESUMO EXECUTIVO")
    linhas.append(f"  Arquivos analisados: {n_arq}")
    linhas.append(f"  Pacotes: {resultado.get('total', 0)}")
    linhas.append(f"  Volume: {bytes_legivel(resultado.get('bytes', 0))}")
    linhas.append(f"  Periodo UTC: {inicio} -> {fim}")
    linhas.append(f"  Ativos OT (IPs unicos): {n_ativos}")
    linhas.append(f"  Eventos OT: {_len_df(resultado.get('eventos_ot'))}")
    linhas.append(f"  IOCs candidatos (unicos): {n_iocs}")
    linhas.append(f"  Irregularidades: {n_irr}")
    linhas.append(f"  Downloads HTTP: {_len_df(resultado.get('downloads_suspeitos'))}")
    linhas.append(f"  Alertas: {_len_df(resultado.get('alertas'))}")
    linhas.append("")

    def _dump(titulo, df, cols, max_n=30):
        linhas.append(titulo)
        if df is None or (hasattr(df, "empty") and df.empty):
            linhas.append("  (nenhum registro)")
            linhas.append("")
            return
        use = [c for c in cols if c in df.columns] or list(df.columns)[:5]
        for _, row in df.head(max_n).iterrows():
            partes = [f"{c}={str(row.get(c, ''))[:60]}" for c in use]
            linhas.append("  - " + " | ".join(partes))
        if len(df) > max_n:
            linhas.append(f"  ... ({len(df) - max_n} registros omitidos)")
        linhas.append("")

    _dump("2. ARQUIVOS", resultado.get("arquivos"), ["Captura", "SHA-256", "Pacotes", "Volume"])
    _dump("3. IRREGULARIDADES", resultado.get("irregularidades"), ["Severidade", "Tipo", "Alvo", "Evidência"])
    timeline = montar_timeline_eventos(resultado)
    _dump("4. TIMELINE (amostra)", timeline, ["Ordem", "Captura", "Data/hora UTC", "Ação", "Origem", "Destino"], 40)
    _dump("5. ATIVOS OT", resultado.get("ativos_ot"), ["Ativo", "Protocolos OT", "Portas OT", "Fluxos"])
    _dump("6. ALERTAS", resultado.get("alertas"), ["Severidade", "Tipo", "Origem", "Destino", "Detalhe"])
    _dump("7. DOWNLOADS", resultado.get("downloads_suspeitos"), ["Captura", "Tipo de arquivo", "SHA-256", "Severidade"])
    _dump("8. IOCs CANDIDATOS", resultado.get("iocs_candidatos"), ["Tipo", "IOC candidato", "Motivo"])
    _dump("9. PROTOCOLOS", resultado.get("protocolos"), ["Protocolo", "Pacotes"])
    linhas.append("Fim do relatorio.")
    return _gerar_pdf_simples(linhas)


def _gerar_pdf_reportlab(resultado, lista_meta=None, progresso=None):
    """Implementação completa com reportlab (tabelas + gráficos + mapa)."""
    def _p(frac, msg=""):
        if callable(progresso):
            try:
                progresso(frac, msg)
            except Exception:
                pass
    from io import BytesIO
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
        Image,
        KeepTogether,
    )

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=1.6 * cm,
        rightMargin=1.6 * cm,
        topMargin=1.6 * cm,
        bottomMargin=1.6 * cm,
        title="Relatório Analisador OT de PCAP",
        author="Analisador OT de PCAP",
    )

    styles = getSampleStyleSheet()
    titulo = ParagraphStyle(
        "TituloOT",
        parent=styles["Heading1"],
        fontSize=16,
        spaceAfter=8,
        textColor=colors.HexColor("#0F172A"),
        alignment=TA_CENTER,
    )
    h2 = ParagraphStyle(
        "H2OT",
        parent=styles["Heading2"],
        fontSize=12,
        spaceBefore=12,
        spaceAfter=6,
        textColor=colors.HexColor("#1E293B"),
    )
    corpo = ParagraphStyle(
        "CorpoOT",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )
    pequeno = ParagraphStyle(
        "PeqOT",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#64748B"),
    )
    celula = ParagraphStyle(
        "CelOT",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=9,
        textColor=colors.HexColor("#1E293B"),
    )

    story = []
    story.append(Paragraph("Relatório — Analisador OT de PCAP", titulo))
    story.append(Paragraph(
        "Mesmos dados da análise web: resumo, protocolos, OT, timeline, irregularidades, "
        "alertas, IOCs e mapa de topologia (visão geral, sem detalhe por IP).",
        pequeno,
    ))
    story.append(Spacer(1, 6))

    _p(0.25, "Gerando gráficos e mapa de topologia…")
    imgs = _graficos_relatorio(resultado)
    _p(0.55, "Montando tabelas do relatório…")

    def _add_img(chave, largura_cm=16.0):
        bio = imgs.get(chave)
        if not bio:
            return
        try:
            from reportlab.lib.utils import ImageReader
            bio.seek(0)
            ir = ImageReader(bio)
            iw, ih = ir.getSize()
            aspect = (ih / float(iw)) if iw else 0.62
            w = largura_cm * cm
            h = w * aspect
            # limita altura de página
            max_h = 18 * cm
            if h > max_h:
                h = max_h
                w = h / aspect if aspect else w
            bio.seek(0)
            img = Image(bio, width=w, height=h)
            img.hAlign = "CENTER"
            story.append(Spacer(1, 6))
            story.append(img)
            story.append(Spacer(1, 6))
        except Exception:
            pass

    def _len_df(df):
        if df is None:
            return 0
        if hasattr(df, "empty"):
            return 0 if df.empty else int(len(df))
        try:
            return int(len(df))
        except Exception:
            return 0

    n_ativos = contar_ativos_ot_unicos(resultado.get("ativos_ot"))
    n_iocs = contar_iocs_unicos(resultado.get("iocs_candidatos"))
    n_irr = _len_df(resultado.get("irregularidades"))
    n_arq = _len_df(resultado.get("arquivos"))
    inicio = texto_data(resultado.get("inicio"))
    fim = texto_data(resultado.get("fim"))
    resumo_linhas = [
        ["Arquivos analisados", str(n_arq)],
        ["Pacotes", f"{resultado.get('total', 0):,}".replace(",", ".")],
        ["Volume", bytes_legivel(resultado.get("bytes", 0))],
        ["Período UTC", f"{inicio} → {fim}"],
        ["Ativos OT (IPs únicos)", str(n_ativos)],
        ["Eventos OT", str(_len_df(resultado.get("eventos_ot")))],
        ["IOCs candidatos (únicos)", str(n_iocs)],
        ["Irregularidades", str(n_irr)],
        ["Downloads executáveis/HTTP", str(_len_df(resultado.get("downloads_suspeitos")))],
        ["Alertas", str(_len_df(resultado.get("alertas")))],
    ]
    t = Table(resumo_linhas, colWidths=[7 * cm, 10 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(Paragraph("1. Resumo executivo", h2))
    story.append(t)

    story.append(Paragraph("Mapa de topologia (visão geral)", h2))
    story.append(Paragraph(
        "Nós coloridos por tipo de host (interno/externo/DNS). "
        "Arestas coloridas pelo protocolo dominante. "
        "Sem rótulos de IP — apenas a estrutura da comunicação.",
        pequeno,
    ))
    _add_img("mapa", largura_cm=16.5)

    def _tabela_df(df, colunas, max_linhas=40, titulo_sec=None):
        if titulo_sec:
            story.append(Paragraph(titulo_sec, h2))
        if df is None or df.empty:
            story.append(Paragraph("Nenhum registro.", corpo))
            return
        cols = [c for c in colunas if c in df.columns]
        if not cols:
            cols = list(df.columns)[:6]
        dados = [[Paragraph(f"<b>{c}</b>", celula) for c in cols]]
        for _, row in df.head(max_linhas).iterrows():
            dados.append([
                Paragraph(_pdf_texto(row.get(c), 80), celula) for c in cols
            ])
        largura = 17.5 * cm / max(len(cols), 1)
        tab = Table(dados, colWidths=[largura] * len(cols), repeatRows=1)
        tab.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#94A3B8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(tab)
        if len(df) > max_linhas:
            story.append(Paragraph(
                f"Exibindo {max_linhas} de {len(df)} registros.",
                pequeno,
            ))

    _tabela_df(
        resultado.get("arquivos"),
        ["Captura", "SHA-256", "Pacotes", "Volume", "Início UTC", "Fim UTC"],
        max_linhas=30,
        titulo_sec="2. Arquivos analisados",
    )
    _tabela_df(
        resultado.get("irregularidades"),
        ["Severidade", "Tipo", "Alvo", "Evidência", "Ordem sugerida"],
        max_linhas=40,
        titulo_sec="3. Irregularidades",
    )
    timeline = montar_timeline_eventos(resultado)
    _tabela_df(
        timeline,
        ["Ordem", "Captura", "Nº pacote", "Data/hora UTC", "Fonte", "Ação", "Origem", "Destino"],
        max_linhas=50,
        titulo_sec="4. Timeline unificada (amostra)",
    )
    _tabela_df(
        resultado.get("ativos_ot"),
        ["Ativo", "Protocolos OT", "Portas OT", "Peers", "Fluxos", "Capturas"],
        max_linhas=40,
        titulo_sec="5. Ativos OT (IPs únicos)",
    )
    _tabela_df(
        resultado.get("detalhes_ot"),
        ["Protocolo OT", "Pacotes"],
        max_linhas=20,
        titulo_sec="6. Protocolos OT observados",
    )
    _add_img("ot", largura_cm=12.0)
    _tabela_df(
        resultado.get("alertas"),
        ["Severidade", "Tipo", "Origem", "Destino", "Detalhe", "Captura"],
        max_linhas=40,
        titulo_sec="7. Alertas",
    )
    _tabela_df(
        resultado.get("eventos"),
        ["Captura", "Nº pacote", "Data/hora UTC", "Categoria", "Protocolo", "Origem", "Destino", "Detalhe"],
        max_linhas=30,
        titulo_sec="8. Exposição de dados",
    )
    _tabela_df(
        resultado.get("downloads_suspeitos"),
        ["Captura", "Data/hora UTC", "Cliente", "Servidor", "Tipo de arquivo", "SHA-256", "Severidade"],
        max_linhas=30,
        titulo_sec="9. Downloads de executáveis / payloads",
    )
    _tabela_df(
        resultado.get("iocs_candidatos"),
        ["Tipo", "IOC candidato", "Motivo", "Evidência", "Fonte"],
        max_linhas=40,
        titulo_sec="10. IOCs candidatos (únicos)",
    )
    _tabela_df(
        resultado.get("iocs"),
        ["Tipo", "IOC", "Ocorrências", "Fonte"],
        max_linhas=30,
        titulo_sec="11. IOCs da lista local",
    )
    _tabela_df(
        resultado.get("protocolos"),
        ["Protocolo", "Pacotes"],
        max_linhas=20,
        titulo_sec="12. Distribuição de protocolos",
    )
    _add_img("protocolos", largura_cm=12.0)
    _add_img("origens", largura_cm=12.0)
    _add_img("portas", largura_cm=12.0)
    _tabela_df(
        resultado.get("externos"),
        ["IP externo", "Fluxos", "Pacotes", "Volume", "Captura"],
        max_linhas=30,
        titulo_sec="13. IPs externos",
    )

    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "Fim do relatório. Valide os indicadores no contexto operacional.",
        pequeno,
    ))

    _p(0.9, "Renderizando PDF…")
    doc.build(story)
    _p(1.0, "PDF pronto")
    return buffer.getvalue()



def resumo_servicos(fluxos):
    portas_tls = {443, 465, 636, 993, 995, 8443}
    portas_http = {80, 8000, 8080, 3128}

    portas = set()
    valores = Counter()

    for chave in fluxos:
        _, _, porta_a, _, porta_b = chave
        conjunto = {porta_a, porta_b}

        portas.update(
            porta
            for porta in conjunto
            if porta
        )

        if conjunto & portas_http:
            valores["HTTP"] += 1

        if 445 in conjunto:
            valores["SMB"] += 1

        if {20, 21} & conjunto:
            valores["FTP"] += 1

        if 23 in conjunto:
            valores["Telnet"] += 1

        if 1900 in conjunto:
            valores["SSDP"] += 1

        if conjunto & portas_tls:
            valores["SSL/TLS provável"] += 1

    valores["Conexões"] = len(fluxos)
    valores["Portas observadas"] = len(portas)

    return valores


# ------------------------------------------------------------
# DETECÇÃO DE DOWNLOAD DE EXECUTÁVEIS / PAYLOADS VIA HTTP
# Funciona em QUALQUER porta TCP: a identificação é feita pelo conteúdo
# (linha de requisição/resposta HTTP e assinatura do arquivo), não pela porta.
# ------------------------------------------------------------

PORTAS_HTTP_PADRAO = {80, 8000, 8008, 8080, 8888, 3128}
LIMITE_STREAM_HTTP = 32 * 1024 * 1024
LIMITE_STREAMS_HTTP = 200

REGEX_REQUISICAO_HTTP = re.compile(
    rb"^(GET|POST|HEAD|PUT)\s+(\S+)\s+HTTP/1\.[01]\r\n"
)

REGEX_UA_FERRAMENTA = re.compile(
    r"(?i)\b(curl|wget|python-requests|python-urllib|powershell|certutil|"
    r"bitsadmin|go-http-client|libwww-perl|winhttp)\b"
)

REGEX_SERVIDOR_IMPROVISADO = re.compile(
    r"(?i)(simplehttp|python|werkzeug|http\.server|node|express)"
)

REGEX_CONTENT_TYPE_EXECUTAVEL = re.compile(
    r"(?i)(x-msdownload|x-dosexec|x-executable|x-msdos-program|x-elf|"
    r"x-sh|x-powershell|vnd\.microsoft\.portable-executable)"
)

SECOES_PE_PADRAO = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata",
    ".pdata", ".bss", ".tls", ".crt", ".didat", ".gfids", ".xdata",
}

ASSINATURAS_ARQUIVO = [
    (b"\x7fELF", "ELF (executável Linux)", "Alta"),
    (b"\xcf\xfa\xed\xfe", "Mach-O (executável macOS)", "Alta"),
    (b"\xfe\xed\xfa\xcf", "Mach-O (executável macOS)", "Alta"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal / classe Java", "Média"),
    (b"#!", "Script com shebang", "Média"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE (Office legado / MSI)", "Média"),
    (b"MSCF", "Arquivo CAB", "Média"),
    (b"PK\x03\x04", "ZIP / JAR / OOXML", "Baixa"),
    (b"Rar!", "Arquivo RAR", "Baixa"),
    (b"7z\xbc\xaf\x27\x1c", "Arquivo 7-Zip", "Baixa"),
]


def entropia_shannon(dados):
    if not dados:
        return 0.0
    contagem = Counter(dados)
    total = len(dados)
    return -sum(
        (n / total) * math.log2(n / total) for n in contagem.values()
    )


def analisar_pe_bytes(dados, fim_captura=None):
    """
    Análise estática leve de cabeçalho PE, sem executar o arquivo.
    Retorna None se não houver 'MZ'. Usa pefile apenas se estiver instalado
    (para imports/imphash); o restante usa somente a biblioteca padrão.
    """
    if len(dados) < 0x40 or dados[:2] != b"MZ":
        return None

    try:
        e_lfanew = struct.unpack_from("<I", dados, 0x3C)[0]

        if e_lfanew + 24 > len(dados) or dados[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return {"valido": False, "indicadores": ["Prefixo MZ sem assinatura PE válida."]}

        maquina, n_secoes, timestamp, _, _, tam_opt, _ = struct.unpack_from(
            "<HHIIIHH", dados, e_lfanew + 4
        )
        opt = e_lfanew + 24
        magic = struct.unpack_from("<H", dados, opt)[0]
        entry_point = struct.unpack_from("<I", dados, opt + 16)[0]
        subsistema = struct.unpack_from("<H", dados, opt + 68)[0]
        secoes_off = opt + tam_opt

        secoes = []
        for i in range(min(n_secoes, 96)):
            o = secoes_off + 40 * i
            if o + 40 > len(dados):
                break
            nome, vsize, va, rsize, rptr = struct.unpack_from("<8sIIII", dados, o)
            carac = struct.unpack_from("<I", dados, o + 36)[0]
            bruto = dados[rptr:rptr + rsize] if rptr and rsize else b""
            secoes.append({
                "nome": nome.rstrip(b"\x00").decode("latin-1", errors="replace"),
                "va": va,
                "vsize": vsize,
                "rsize": rsize,
                "entropia": entropia_shannon(bruto),
                "executavel": bool(carac & 0x20000000),
                "gravavel": bool(carac & 0x80000000),
            })
    except Exception:
        return {"valido": False, "indicadores": ["Cabeçalho PE malformado."]}

    arquitetura = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"}.get(
        maquina, f"0x{maquina:04X}"
    )

    data_compilacao = None
    try:
        if timestamp:
            data_compilacao = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except Exception:
        data_compilacao = None

    # Imports (opcional, via pefile)
    total_imports = None
    dlls = []
    imphash = None
    funcoes_importadas = []
    try:
        import pefile  # noqa: WPS433

        pe = pefile.PE(data=dados, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        imphash = pe.get_imphash() or None
        total_imports = 0
        for entrada in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dlls.append(entrada.dll.decode("latin-1", errors="replace"))
            for imp in entrada.imports:
                total_imports += 1
                if imp.name:
                    funcoes_importadas.append(imp.name.decode("latin-1", errors="replace"))
        pe.close()
    except Exception:
        pass

    indicadores = []

    for s in secoes:
        if s["entropia"] >= 7.0 and s["rsize"] >= 1024:
            indicadores.append(
                f"Seção {s['nome']} com entropia {s['entropia']:.2f} "
                f"(compatível com conteúdo cifrado/comprimido)."
            )
        if s["vsize"] >= 16384 and s["vsize"] >= 4 * max(s["rsize"], 1):
            indicadores.append(
                f"Seção {s['nome']} ocupa {s['vsize']} B em memória e só "
                f"{s['rsize']} B em disco (expansão em tempo de execução)."
            )

    incomuns = [s["nome"] for s in secoes if s["nome"].lower() not in SECOES_PE_PADRAO]
    if incomuns:
        indicadores.append("Seções com nomes incomuns: " + ", ".join(incomuns) + ".")

    for s in secoes:
        if s["va"] <= entry_point < s["va"] + max(s["vsize"], s["rsize"]):
            primeira_exec = next((x for x in secoes if x["executavel"]), None)
            if s["gravavel"]:
                indicadores.append(f"Entry point em seção gravável ({s['nome']}).")
            elif primeira_exec and s is not primeira_exec:
                indicadores.append(
                    f"Entry point em {s['nome']}, e não na primeira seção executável."
                )
            break

    if total_imports is not None and total_imports <= 5:
        indicadores.append(
            f"Apenas {total_imports} função(ões) importada(s): resolução "
            f"dinâmica de APIs provável."
        )

    if {"NtWriteVirtualMemory", "NtReadVirtualMemory"} & set(funcoes_importadas):
        indicadores.append(
            "Importa Nt*VirtualMemory (compatível com unpacking/injeção em memória; "
            "hipótese de análise estática)."
        )

    if timestamp == 0:
        indicadores.append("Timestamp de compilação zerado.")
    elif data_compilacao and fim_captura and data_compilacao > fim_captura:
        indicadores.append("Timestamp de compilação posterior à captura (possivelmente forjado).")

    return {
        "valido": True,
        "arquitetura": arquitetura,
        "formato": "PE32+" if magic == 0x20B else "PE32",
        "subsistema": subsistema,
        "compilacao": data_compilacao,
        "entry_point": entry_point,
        "secoes": secoes,
        "dlls": dlls,
        "total_imports": total_imports,
        "imphash": imphash,
        "indicadores": indicadores,
    }


def resumo_pe(pe):
    if not pe or not pe.get("valido"):
        return "-"
    partes = [
        f"{pe['formato']} {pe['arquitetura']}",
        "compilado em "
        + (pe["compilacao"].strftime("%Y-%m-%d %H:%M UTC") if pe["compilacao"] else "data indisponível"),
        f"{len(pe['secoes'])} seções (" + ", ".join(s["nome"] for s in pe["secoes"]) + ")",
        f"EP=0x{pe['entry_point']:X}",
    ]
    if pe.get("total_imports") is not None:
        partes.append(f"{pe['total_imports']} imports")
    if pe.get("imphash"):
        partes.append(f"imphash={pe['imphash']}")
    return " | ".join(partes)


def decodificar_chunked(corpo):
    saida = bytearray()
    pos = 0
    while True:
        fim = corpo.find(b"\r\n", pos)
        if fim < 0:
            break
        try:
            tamanho = int(corpo[pos:fim].split(b";")[0].strip(), 16)
        except ValueError:
            return bytes(corpo)
        if tamanho == 0:
            break
        pos = fim + 2
        saida += corpo[pos:pos + tamanho]
        pos += tamanho + 2
    return bytes(saida)


def parsear_cabecalhos_http(bloco):
    linhas = bloco.split(b"\r\n")
    primeira = linhas[0].decode("latin-1", errors="replace")
    cabecalhos = {}
    for linha in linhas[1:]:
        if b":" in linha:
            nome, valor = linha.split(b":", 1)
            cabecalhos[nome.strip().lower().decode("latin-1", errors="replace")] = (
                valor.strip().decode("latin-1", errors="replace")
            )
    return primeira, cabecalhos


def identificar_arquivo(corpo, fim_captura=None):
    """Retorna (tipo, severidade, análise_pe) com base na assinatura do conteúdo."""
    if corpo[:2] == b"MZ":
        pe = analisar_pe_bytes(corpo, fim_captura)
        if pe and pe.get("valido"):
            return "PE (executável/DLL Windows)", "Alta", pe
        return "MZ sem cabeçalho PE válido", "Média", pe

    for assinatura, nome, severidade in ASSINATURAS_ARQUIVO:
        if corpo.startswith(assinatura):
            return nome, severidade, None

    return None, None, None


class RastreadorDownloadsHTTP:
    """
    Remonta respostas HTTP por fluxo TCP (independente da porta), extrai o corpo,
    calcula hashes e identifica o tipo real do arquivo pela assinatura.

    Limitações: considera a primeira resposta de cada conexão (não separa
    várias respostas em keep-alive) e não decifra HTTPS.
    """

    def __init__(self):
        self.requisicoes = {}
        self.respostas = {}

    def processar(self, pacote, instante, origem, destino, porta_origem, porta_destino):
        if TCP not in pacote or Raw not in pacote or not origem or not destino:
            return

        try:
            payload = bytes(pacote[Raw].load)
        except Exception:
            return

        if not payload:
            return

        chave = (origem, porta_origem, destino, porta_destino)
        seq = int(pacote[TCP].seq)
        resposta = self.respostas.get(chave)

        if resposta is not None:
            if resposta["bytes"] >= LIMITE_STREAM_HTTP:
                resposta["truncado"] = True
            elif seq not in resposta["segmentos"]:
                resposta["segmentos"][seq] = payload
                resposta["bytes"] += len(payload)
            return

        if payload.startswith(b"HTTP/1."):
            if len(self.respostas) < LIMITE_STREAMS_HTTP:
                self.respostas[chave] = {
                    "primeiro_seq": seq,
                    "segmentos": {seq: payload},
                    "bytes": len(payload),
                    "instante": instante,
                    "truncado": False,
                }
            return

        casamento = REGEX_REQUISICAO_HTTP.match(payload)

        if casamento and chave not in self.requisicoes:
            fim_cab = payload.find(b"\r\n\r\n")
            bloco = payload[: fim_cab if fim_cab > 0 else len(payload)]
            _, cabecalhos = parsear_cabecalhos_http(bloco)
            self.requisicoes[chave] = {
                "metodo": casamento.group(1).decode("ascii"),
                "uri": casamento.group(2).decode("latin-1", errors="replace"),
                "host": cabecalhos.get("host", ""),
                "user_agent": cabecalhos.get("user-agent", ""),
                "instante": instante,
            }

    def finalizar(self, fim_captura=None):
        resultados = []

        for chave, resposta in self.respostas.items():
            try:
                registro = self._avaliar(chave, resposta, fim_captura)
            except Exception:
                registro = None
            if registro:
                resultados.append(registro)

        return resultados

    def _avaliar(self, chave, resposta, fim_captura):
        servidor, porta_servidor, cliente, porta_cliente = chave

        # Montagem contígua por número de sequência (tolera reordenação,
        # retransmissão e sobreposição; para na primeira lacuna).
        base = resposta["primeiro_seq"]
        pedacos = sorted(
            ((seq - base) & 0xFFFFFFFF, dados)
            for seq, dados in resposta["segmentos"].items()
        )
        buffer = bytearray()
        esperado = 0
        lacuna = False
        for deslocamento, dados in pedacos:
            if deslocamento > esperado:
                lacuna = True
                break
            if deslocamento + len(dados) <= esperado:
                continue
            buffer += dados[esperado - deslocamento:]
            esperado = deslocamento + len(dados)

        separador = buffer.find(b"\r\n\r\n")
        if separador < 0:
            return None

        linha_status, cab = parsear_cabecalhos_http(bytes(buffer[:separador]))
        partes = linha_status.split()
        codigo = int(partes[1]) if len(partes) > 1 and partes[1].isdigit() else 0

        if not 200 <= codigo < 300:
            return None

        corpo = bytes(buffer[separador + 4:])

        if "chunked" in cab.get("transfer-encoding", "").lower():
            corpo = decodificar_chunked(corpo)

        tamanho_declarado = (
            int(cab["content-length"]) if cab.get("content-length", "").isdigit() else None
        )
        if tamanho_declarado is not None:
            corpo = corpo[:tamanho_declarado]

        completo = (
            not lacuna
            and not resposta["truncado"]
            and (tamanho_declarado is None or len(corpo) >= tamanho_declarado)
        )

        tipo, severidade, pe = identificar_arquivo(corpo, fim_captura)
        content_type = cab.get("content-type", "")
        tipo_executavel_declarado = bool(REGEX_CONTENT_TYPE_EXECUTAVEL.search(content_type))
        octet_stream = "octet-stream" in content_type.lower()

        if not tipo:
            if tipo_executavel_declarado:
                tipo, severidade = "Executável declarado pelo Content-Type", "Média"
            elif octet_stream and len(corpo) >= 4096 and entropia_shannon(corpo[:1_000_000]) >= 7.5:
                tipo, severidade = "Binário opaco de alta entropia (possível payload cifrado)", "Média"
            else:
                return None

        requisicao = self.requisicoes.get((cliente, porta_cliente, servidor, porta_servidor), {})
        uri = requisicao.get("uri", "-")
        host = requisicao.get("host") or f"{servidor}:{porta_servidor}"
        user_agent = requisicao.get("user_agent", "")
        servidor_http = cab.get("server", "")

        sha256 = hashlib.sha256(corpo).hexdigest()
        md5 = hashlib.md5(corpo).hexdigest()
        sha1 = hashlib.sha1(corpo).hexdigest()

        nome_arquivo = uri.split("?")[0].rstrip("/").split("/")[-1].lower()
        nome_e_hash = bool(re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", nome_arquivo))
        hash_confere = nome_e_hash and nome_arquivo in {sha256, sha1, md5}

        motivos = [f"Conteúdo identificado como {tipo}."]

        if porta_servidor not in PORTAS_HTTP_PADRAO:
            motivos.append(f"HTTP em porta não padrão ({porta_servidor}).")
        if REGEX_UA_FERRAMENTA.search(user_agent):
            motivos.append(f"Cliente de linha de comando/script ({user_agent}).")
        if servidor_http and REGEX_SERVIDOR_IMPROVISADO.search(servidor_http):
            motivos.append(f"Servidor HTTP improvisado/de desenvolvimento ({servidor_http}).")
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d+)?", host):
            motivos.append("Host acessado por IP literal, sem nome DNS.")
        if hash_confere:
            motivos.append("Nome do arquivo na URL é o hash do próprio conteúdo (distribuição por hash).")
        if tipo.startswith("PE") and (octet_stream or "text" in content_type.lower()):
            motivos.append(f"Executável PE servido com Content-Type genérico ({content_type}).")
        if pe and pe.get("indicadores"):
            motivos.extend(pe["indicadores"])
        if not completo:
            motivos.append("Captura incompleta do arquivo (hash parcial).")

        # Severidade: assinatura executável + contexto adicional sobe o nível.
        contexto = len(motivos) - 1
        if severidade == "Alta" and contexto < 2:
            severidade = "Média"
        elif severidade == "Média" and contexto >= 3:
            severidade = "Alta"

        return {
            "Data/hora UTC": texto_data(resposta["instante"]),
            "Cliente": cliente,
            "Servidor": servidor,
            "Porta servidor": porta_servidor,
            "Método": requisicao.get("metodo", "-"),
            "URL": f"http://{host}{uri}" if uri != "-" else "-",
            "User-Agent": user_agent or "-",
            "Server HTTP": servidor_http or "-",
            "Content-Type": content_type or "-",
            "Tipo de arquivo": tipo,
            "Bytes do arquivo": len(corpo),
            "Tamanho": bytes_legivel(len(corpo)),
            "Completo": "Sim" if completo else "Não",
            "Entropia": round(entropia_shannon(corpo[:8_000_000]), 3),
            "SHA-256": sha256,
            "SHA-1": sha1,
            "MD5": md5,
            "Hash confere com a URL": "Sim" if hash_confere else "Não",
            "Severidade": severidade,
            "Motivos": " ".join(motivos),
            "Análise PE": resumo_pe(pe),
            "Imphash": (pe or {}).get("imphash") or "-",
        }


def analisar_pcap(caminho, limite, iocs_ips, iocs_dominios):
    protocolos = Counter()
    origens = Counter()
    destinos = Counter()
    portas = Counter()
    dominios = Counter()

    fluxos = defaultdict(
        lambda: {
            "Pacotes": 0,
            "Bytes": 0,
            "Primeiro": None,
            "Último": None,
            "A→B": 0,
            "B→A": 0,
            "Bytes A→B": 0,
            "Bytes B→A": 0,
        }
    )

    syn_destinos = defaultdict(set)

    amostra = []
    dns_lista = []
    eventos = []

    eventos_chaves = set()
    usuarios_fluxo = {}

    eventos_ot = []
    eventos_ot_chaves = set()
    detalhes_ot = Counter()

    total = 0
    total_bytes = 0
    erros = 0

    inicio = None
    fim = None
    limite_atingido = False

    rastreador_http = RastreadorDownloadsHTTP()

    leitor = abrir_pcap(caminho)

    try:
        for pacote in leitor:
            if total >= limite:
                limite_atingido = True
                break

            total += 1

            try:
                tamanho = len(pacote)
                instante = data_utc(pacote.time)

                origem, destino, versao = ips_pacote(pacote)

                transporte, porta_origem, porta_destino, flags = transporte_pacote(
                    pacote
                )

                protocolo = protocolo_pacote(pacote)

                fluxo = chave_fluxo(
                    origem,
                    destino,
                    transporte,
                    porta_origem,
                    porta_destino,
                )

                total_bytes += tamanho
                protocolos[protocolo] += 1

                if instante:
                    if inicio is None or instante < inicio:
                        inicio = instante

                    if fim is None or instante > fim:
                        fim = instante

                if origem:
                    origens[origem] += 1

                if destino:
                    destinos[destino] += 1

                if porta_destino is not None:
                    portas[f"{transporte}/{porta_destino}"] += 1

                if fluxo:
                    dados = fluxos[fluxo]

                    dados["Pacotes"] += 1
                    dados["Bytes"] += tamanho

                    if instante:
                        if (
                            dados["Primeiro"] is None
                            or instante < dados["Primeiro"]
                        ):
                            dados["Primeiro"] = instante

                        if (
                            dados["Último"] is None
                            or instante > dados["Último"]
                        ):
                            dados["Último"] = instante

                    if (origem, porta_origem or 0) == (fluxo[1], fluxo[2]):
                        dados["A→B"] += 1
                        dados["Bytes A→B"] += tamanho
                    else:
                        dados["B→A"] += 1
                        dados["Bytes B→A"] += tamanho

                if (
                    TCP in pacote
                    and origem
                    and destino
                    and "S" in flags
                    and "A" not in flags
                ):
                    syn_destinos[origem].add(
                        f"{destino}:{porta_destino}"
                    )

                consulta = extrair_consulta_dns(
                    pacote,
                    instante,
                )

                if consulta:
                    dns_lista.append(consulta)
                    dominios[consulta["Domínio"].lower()] += 1

                rastreador_http.processar(
                    pacote,
                    instante,
                    origem,
                    destino,
                    porta_origem,
                    porta_destino,
                )

                detectar_exposicao(
                    pacote,
                    instante,
                    origem,
                    destino,
                    porta_origem,
                    porta_destino,
                    fluxo,
                    usuarios_fluxo,
                    eventos,
                    eventos_chaves,
                    num_pacote=total,
                )

                detectar_ot_pacote(
                    pacote,
                    instante,
                    origem,
                    destino,
                    porta_origem,
                    porta_destino,
                    fluxo,
                    eventos_ot,
                    eventos_ot_chaves,
                    detalhes_ot,
                    num_pacote=total,
                )

                if len(amostra) < LIMITE_PACOTES_AMOSTRA:
                    amostra.append(
                        {
                            "Nº": total,
                            "Data/hora UTC": (
                                instante.strftime(
                                    "%Y-%m-%d %H:%M:%S.%f"
                                )[:-3]
                                if instante
                                else "-"
                            ),
                            "Origem": origem or "-",
                            "Destino": destino or "-",
                            "IP": versao or "-",
                            "Protocolo": protocolo,
                            "Serviço destino": (
                                nome_servico(porta_destino)
                                if porta_destino
                                else "-"
                            ),
                            "Porta origem": porta_origem or "-",
                            "Porta destino": porta_destino or "-",
                            "Flags TCP": flags or "-",
                            "Bytes": tamanho,
                        }
                    )

            except Exception:
                erros += 1

    finally:
        leitor.close()

    tabela_fluxos = []

    externos = defaultdict(
        lambda: {
            "Fluxos": 0,
            "Bidirecionais": 0,
            "Pacotes": 0,
            "Bytes": 0,
            "Serviços": set(),
        }
    )

    for chave, dados in fluxos.items():
        transporte, ip_a, porta_a, ip_b, porta_b = chave

        duracao = (
            (dados["Último"] - dados["Primeiro"]).total_seconds()
            if dados["Primeiro"] and dados["Último"]
            else 0
        )

        bidirecional = dados["A→B"] > 0 and dados["B→A"] > 0

        tabela_fluxos.append(
            {
                "Fluxo": texto_fluxo(chave),
                "Pacotes": dados["Pacotes"],
                "Bytes": dados["Bytes"],
                "Volume": bytes_legivel(dados["Bytes"]),
                "Duração (s)": round(duracao, 3),
                "Pacotes A→B": dados["A→B"],
                "Pacotes B→A": dados["B→A"],
                "Bytes A→B": dados["Bytes A→B"],
                "Bytes B→A": dados["Bytes B→A"],
                "Bidirecional": "Sim" if bidirecional else "Não",
            }
        )

        for ip, porta in [(ip_a, porta_a), (ip_b, porta_b)]:
            if ip_publico(ip):
                externos[ip]["Fluxos"] += 1
                externos[ip]["Pacotes"] += dados["Pacotes"]
                externos[ip]["Bytes"] += dados["Bytes"]
                externos[ip]["Serviços"].add(
                    f"{transporte}/{porta}"
                )

                if bidirecional:
                    externos[ip]["Bidirecionais"] += 1

    alertas = []

    for origem, destinos_unicos in syn_destinos.items():
        if len(destinos_unicos) >= 20:
            alertas.append(
                {
                    "Severidade": (
                        "Alta"
                        if len(destinos_unicos) >= 100
                        else "Média"
                    ),
                    "Tipo": "Possível varredura TCP",
                    "Origem": origem,
                    "Detalhe": (
                        f"SYN sem ACK para "
                        f"{len(destinos_unicos)} destinos únicos."
                    ),
                }
            )

    for dominio, quantidade in dominios.items():
        if len(dominio) >= 100:
            alertas.append(
                {
                    "Severidade": "Baixa",
                    "Tipo": "Consulta DNS longa",
                    "Origem": "-",
                    "Detalhe": (
                        f"Domínio com {len(dominio)} caracteres; "
                        f"{quantidade} ocorrência(s)."
                    ),
                }
            )

    # Alertas OT derivados do comportamento observado.
    alertas_chaves = set()

    for chave, dados in fluxos.items():
        transporte, ip_a, porta_a, ip_b, porta_b = chave
        porta_ot = None
        origem_ot = None
        destino_ot = None

        if porta_b in PORTAS_OT:
            porta_ot = porta_b
            origem_ot = ip_a
            destino_ot = ip_b
        elif porta_a in PORTAS_OT:
            porta_ot = porta_a
            origem_ot = ip_b
            destino_ot = ip_a

        if porta_ot and ip_publico(origem_ot):
            adicionar_alerta(
                alertas,
                alertas_chaves,
                {
                    "Severidade": "Alta",
                    "Tipo": "Possível comunicação OT externa",
                    "Origem": origem_ot,
                    "Destino": destino_ot,
                    "Porta destino": porta_ot,
                    "Detalhe": (
                        f"IP público observado em comunicação com "
                        f"{PORTAS_OT[porta_ot]} (porta {porta_ot})."
                    ),
                },
            )

    downloads_suspeitos = rastreador_http.finalizar(fim)

    for item in downloads_suspeitos:
        adicionar_alerta(
            alertas,
            alertas_chaves,
            {
                "Severidade": item["Severidade"],
                "Tipo": "Download de executável/payload via HTTP",
                "Origem": item["Servidor"],
                "Destino": item["Cliente"],
                "Porta destino": item["Porta servidor"],
                "Detalhe": (
                    f"{item['Tipo de arquivo']}; SHA-256 {item['SHA-256']}; "
                    f"{item['Motivos']}"
                ),
            },
        )

    transferencias_ot = gerar_transferencias_ot(fluxos)
    ativos_ot = gerar_ativos_ot(fluxos)
    anomalias_ot = gerar_anomalias_ot(fluxos, transferencias_ot)

    for _, linha in anomalias_ot.iterrows():
        adicionar_alerta(
            alertas,
            alertas_chaves,
            {
                "Severidade": linha["Severidade"],
                "Tipo": linha["Tipo"],
                "Origem": linha["Origem"],
                "Destino": linha["Destino"],
                "Porta destino": "-",
                "Detalhe": linha["Evidência"],
            },
        )

    iocs_candidatos = gerar_iocs_candidatos(
        alertas,
        transferencias_ot,
        externos,
        eventos_ot,
        downloads_suspeitos,
    )

    iocs = []

    for ip in sorted(iocs_ips):
        ocorrencias = origens[ip] + destinos[ip]

        if ocorrencias:
            iocs.append(
                {
                    "Tipo": "IP",
                    "IOC": ip,
                    "Ocorrências": ocorrencias,
                    "Fonte": "Lista local",
                }
            )

    for dominio in sorted(iocs_dominios):
        if dominios[dominio]:
            iocs.append(
                {
                    "Tipo": "Domínio",
                    "IOC": dominio,
                    "Ocorrências": dominios[dominio],
                    "Fonte": "Lista local",
                }
            )

    tabela_externos = []

    for ip, dados in externos.items():
        tabela_externos.append(
            {
                "IP externo": ip,
                "Fluxos": dados["Fluxos"],
                "Fluxos bidirecionais": dados["Bidirecionais"],
                "Comunicação bidirecional": (
                    "Sim"
                    if dados["Bidirecionais"]
                    else "Não"
                ),
                "Pacotes": dados["Pacotes"],
                "Volume": bytes_legivel(dados["Bytes"]),
                "Serviços observados": ", ".join(
                    sorted(dados["Serviços"])[:10]
                ),
            }
        )

    dataframe_fluxos = pd.DataFrame(tabela_fluxos)

    if not dataframe_fluxos.empty:
        dataframe_fluxos = dataframe_fluxos.sort_values(
            by=["Bytes", "Pacotes"],
            ascending=False,
        ).head(1000)

    dataframe_externos = pd.DataFrame(tabela_externos)

    if not dataframe_externos.empty:
        dataframe_externos = dataframe_externos.sort_values(
            by=["Fluxos bidirecionais", "Fluxos"],
            ascending=False,
        )

    return {
        "total": total,
        "bytes": total_bytes,
        "inicio": inicio,
        "fim": fim,
        "erros": erros,
        "limite": limite_atingido,
        "protocolos": pd.DataFrame(
            [
                {
                    "Protocolo": chave,
                    "Pacotes": valor,
                }
                for chave, valor in protocolos.most_common()
            ]
        ),
        "origens": pd.DataFrame(
            [
                {
                    "IP de origem": chave,
                    "Pacotes": valor,
                }
                for chave, valor in origens.most_common(100)
            ]
        ),
        "portas": pd.DataFrame(
            [
                {
                    "Serviço/porta destino": chave,
                    "Pacotes": valor,
                }
                for chave, valor in portas.most_common(100)
            ]
        ),
        "fluxos": dataframe_fluxos,
        "externos": dataframe_externos,
        "dns": pd.DataFrame(dns_lista[:2000]),
        "eventos": pd.DataFrame(eventos),
        "eventos_ot": pd.DataFrame(eventos_ot),
        "iocs": pd.DataFrame(iocs),
        "iocs_candidatos": iocs_candidatos,
        "downloads_suspeitos": pd.DataFrame(downloads_suspeitos),
        "amostra": pd.DataFrame(amostra),
        "alertas": pd.DataFrame(alertas),
        "ativos_ot": ativos_ot,
        "transferencias_ot": transferencias_ot,
        "anomalias_ot": anomalias_ot,
        "detalhes_ot": pd.DataFrame(
            [
                {"Protocolo OT": chave, "Pacotes": valor}
                for chave, valor in detalhes_ot.most_common()
            ]
        ),
        "grafo": criar_grafo(fluxos),
        "servicos": resumo_servicos(fluxos),
    }



def render_rodape():
    """Rodapé no estilo informativo (inspirado em apackets.com)."""
    st.markdown(
        """
        <div class="footer-apackets">
          <h4>Sobre esta análise</h4>
          <p>
            Esta ferramenta analisa arquivos <b>PCAP / PCAPNG</b> de forma <b>local</b>:
            as capturas e listas de IOC <b>não são enviadas para a internet</b>.
            O motor reconstrói visão de hosts, protocolos, eventos OT, exposição em canais sem TLS,
            timeline unificada e irregularidades entre múltiplas capturas.
          </p>
          <div class="cols">
            <div>
              <h4>Privacidade</h4>
              <p>Processamento na sua máquina. Senhas nunca são exibidas nem armazenadas.
              Use apenas capturas que você tem autorização para inspecionar.</p>
            </div>
            <div>
              <h4>O que a análise entrega</h4>
              <p>Topologia com protocolos nas arestas, ativos OT distintos, transferências candidatas,
              downloads HTTP de executáveis, IOCs candidatos e relatório PDF sob demanda.</p>
            </div>
          </div>
          <p style="margin-top:18px;color:#64748B;font-size:0.8rem;">
            Analisador OT de PCAP · processamento local · heurísticas de protocolo e comportamento
          </p>
        </div>
        """,
        unsafe_allow_html=True,
    )



# Estado da barra lateral
if "mostrar_config" not in st.session_state:
    st.session_state["mostrar_config"] = False

with st.sidebar:
    st.markdown("### Menu")

    # 1) Botão de configurações
    if st.button("⚙️  Configurações", use_container_width=True, key="btn_abrir_config"):
        st.session_state["mostrar_config"] = not st.session_state["mostrar_config"]

    # 2) Conteúdo de configuração aparece logo ABAIXO do botão (empurra o restante para baixo)
    if st.session_state["mostrar_config"]:
        st.markdown("---")
        st.markdown("**Ajustes da análise**")
        limite_pacotes = st.number_input(
            "Máximo de pacotes",
            min_value=1000,
            max_value=5_000_000,
            value=int(st.session_state.get("limite_pacotes", 200_000)),
            step=10_000,
            key="cfg_limite_pacotes",
        )
        st.session_state["limite_pacotes"] = limite_pacotes
        arquivo_ioc = st.file_uploader(
            "Lista local de IOCs (opcional)",
            type=["txt", "csv"],
            help="Um IP ou domínio por linha.",
            key="cfg_arquivo_ioc",
        )
        st.session_state["permitir_internet"] = st.checkbox(
            "Permitir consultas externas (GeoIP/ASN de IPs públicos)",
            value=st.session_state.get("permitir_internet", False),
            help="Opcional. Consulta ip-api.com apenas com IPs já vistos na captura. "
            "PCAPs e hashes NÃO são enviados. Desligado = 100% offline.",
            key="cfg_permitir_internet",
        )
        st.caption(
            "Senhas nunca são exibidas. A ferramenta só indica possível exposição "
            "em protocolos sem criptografia. Análise de PCAP é sempre local."
        )
        st.markdown("---")
    else:
        limite_pacotes = st.session_state.get("limite_pacotes", 200_000)
        arquivo_ioc = st.session_state.get("cfg_arquivo_ioc")

    # 3) Gerar PDF — uma geração por vez (evita sobrecarga)
    if "pdf_gerando" not in st.session_state:
        st.session_state["pdf_gerando"] = False
    if "relatorio_gerando" not in st.session_state:
        st.session_state["relatorio_gerando"] = False

    if st.session_state["pdf_gerando"]:
        st.button(
            "⏳ Gerando PDF… aguarde",
            use_container_width=True,
            disabled=True,
            key="btn_gerar_pdf_busy",
        )
        st.caption("Uma geração por vez. Aguarde concluir antes de solicitar outro PDF.")
        barra_pdf = st.progress(0, text="Iniciando geração do PDF…")

        def _atualizar_progresso(frac, msg=""):
            try:
                barra_pdf.progress(
                    min(max(float(frac), 0.0), 1.0),
                    text=msg or "Gerando PDF…",
                )
            except Exception:
                pass

        try:
            if st.session_state.get("resultado_analise") is not None:
                try:
                    pdf_bytes = gerar_relatorio_pdf(
                        st.session_state["resultado_analise"],
                        st.session_state.get("lista_resultados_meta"),
                        progresso=_atualizar_progresso,
                    )
                    st.session_state["pdf_relatorio_bytes"] = pdf_bytes
                    st.session_state["pdf_relatorio_ok"] = True
                    st.session_state.pop("pdf_relatorio_erro", None)
                except Exception as erro_pdf:
                    st.session_state["pdf_relatorio_ok"] = False
                    st.session_state["pdf_relatorio_erro"] = str(erro_pdf)
                    st.session_state["pdf_relatorio_bytes"] = None
            else:
                st.session_state["pdf_relatorio_ok"] = False
                st.session_state["pdf_relatorio_erro"] = "Nenhuma análise disponível."
                st.session_state["pdf_relatorio_bytes"] = None
        finally:
            # Sempre libera o cadeado para permitir nova geração
            st.session_state["pdf_gerando"] = False
        st.rerun()

    else:
        # Se relatório textual estiver gerando, também bloqueia PDF
        bloquear_pdf = bool(st.session_state.get("relatorio_gerando"))
        if st.button(
            "📄  Gerar PDF",
            use_container_width=True,
            key="btn_gerar_pdf_sidebar",
            disabled=bloquear_pdf,
            help="Gera o PDF completo. Só uma geração por vez para não sobrecarregar o equipamento.",
        ):
            if st.session_state.get("pdf_gerando") or st.session_state.get("relatorio_gerando"):
                st.warning("Já existe uma geração em andamento. Aguarde concluir.")
            elif st.session_state.get("resultado_analise") is not None:
                st.session_state["pdf_gerando"] = True
                st.session_state["pdf_relatorio_ok"] = None
                st.session_state["pdf_relatorio_bytes"] = None
                st.session_state.pop("pdf_relatorio_erro", None)
                st.rerun()
            else:
                st.warning("Analise ao menos um PCAP antes de gerar o PDF.")
        if bloquear_pdf:
            st.caption("Aguarde o relatório textual terminar para gerar o PDF.")

    # Download somente quando o PDF estiver pronto (abaixo do botão de gerar).
    # A página permanece navegável: o download ocorre no navegador, sem bloquear o Streamlit.
    if st.session_state.get("pdf_relatorio_ok") and st.session_state.get("pdf_relatorio_bytes"):
        st.markdown(
            """
            <style>
            /* Botão de download: opaco ao clicar até o navegador concluir o save */
            div[data-testid="stSidebar"] div[data-testid="stDownloadButton"] button {
              transition: opacity 0.2s ease;
            }
            div[data-testid="stSidebar"] div[data-testid="stDownloadButton"] button:active,
            div[data-testid="stSidebar"] div[data-testid="stDownloadButton"] button.dl-busy {
              opacity: 0.45 !important;
              pointer-events: none;
            }
            </style>
            <script>
            (function () {
              function bindDownloadOpacity() {
                var buttons = window.parent.document.querySelectorAll(
                  'div[data-testid="stSidebar"] div[data-testid="stDownloadButton"] button'
                );
                buttons.forEach(function (btn) {
                  if (btn.dataset.dlBound) return;
                  btn.dataset.dlBound = "1";
                  btn.addEventListener("click", function () {
                    btn.classList.add("dl-busy");
                    btn.style.opacity = "0.45";
                    /* reabilita após o navegador iniciar o download (não trava a página) */
                    setTimeout(function () {
                      btn.classList.remove("dl-busy");
                      btn.style.opacity = "1";
                    }, 2500);
                  });
                });
              }
              setTimeout(bindDownloadOpacity, 400);
              setTimeout(bindDownloadOpacity, 1200);
            })();
            </script>
            """,
            unsafe_allow_html=True,
        )
        st.download_button(
            "⬇️ Baixar relatório PDF",
            data=st.session_state["pdf_relatorio_bytes"],
            file_name="relatorio_analise_ot_pcap.pdf",
            mime="application/pdf",
            use_container_width=True,
            key="download_relatorio_pdf_sidebar",
            help="O download não bloqueia a página — você pode continuar navegando nas abas.",
        )
        if st.session_state.get("pdf_modo") == "textual":
            st.caption(
                "PDF textual (reportlab não instalado). "
                "Para relatório completo: pip install reportlab matplotlib"
            )
        else:
            st.caption(
                "Relatório pronto. O download não trava a página — "
                "continue navegando enquanto o arquivo é salvo."
            )
    elif st.session_state.get("pdf_relatorio_ok") is False:
        st.error(
            f"Falha ao gerar PDF: {st.session_state.get('pdf_relatorio_erro', 'erro desconhecido')}"
        )

    # Botão Relatório — sempre liberado após gerar; cada clique abre nova aba
    st.markdown("")
    if "relatorio_open_id" not in st.session_state:
        st.session_state["relatorio_open_id"] = 0
    # Garante que o cadeado nunca fique preso entre cliques
    st.session_state["relatorio_gerando"] = False

    bloquear_rel = bool(st.session_state.get("pdf_gerando"))

    # Abre a aba se houver HTML pendente (do clique anterior)
    if st.session_state.get("abrir_relatorio_browser") and st.session_state.get("relatorio_analista_html"):
        oid = int(st.session_state.get("relatorio_open_id") or 1)
        abrir_relatorio_nova_aba(st.session_state["relatorio_analista_html"], open_id=oid)
        st.session_state["abrir_relatorio_browser"] = False
        st.caption(f"Relatório aberto em nova aba (#{oid}). O botão já está liberado para gerar outro.")

    if st.button(
        "📋  Relatório",
        use_container_width=True,
        key="btn_relatorio_analista",
        disabled=bloquear_rel,
        help="Abre o relatório em nova aba. Pode clicar de novo a qualquer momento.",
    ):
        if st.session_state.get("pdf_gerando"):
            st.warning("Aguarde o PDF terminar antes de gerar o relatório.")
        elif st.session_state.get("resultado_analise") is None:
            st.warning("Analise ao menos um PCAP antes de abrir o relatório.")
        else:
            try:
                res = st.session_state["resultado_analise"]
                enriq = []
                if st.session_state.get("permitir_internet") or st.session_state.get("cfg_permitir_internet"):
                    enriq = enriquecer_externos_internet(res, permitir=True)
                st.session_state["enriquecimento_externo"] = enriq
                st.session_state["relatorio_analista_md"] = gerar_relatorio_analista(
                    res, enriquecimento_externo=enriq
                )
                st.session_state["relatorio_analista_html"] = gerar_relatorio_analista_html(
                    res, enriquecimento_externo=enriq
                )
                st.session_state["relatorio_open_id"] = int(st.session_state.get("relatorio_open_id") or 0) + 1
                st.session_state["abrir_relatorio_browser"] = True
                st.session_state["relatorio_gerando"] = False
                st.rerun()
            except Exception as erro_rel:
                st.session_state["relatorio_gerando"] = False
                st.session_state["abrir_relatorio_browser"] = False
                st.error(f"Falha ao montar o relatório: {erro_rel}")

    if bloquear_rel:
        st.caption("Aguarde o PDF terminar para gerar o relatório textual.")

iocs_ips, iocs_dominios = carregar_iocs(arquivo_ioc)

st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
arquivos = st.file_uploader(
    "Selecione um ou mais arquivos PCAP, PCAPNG ou CAP",
    type=["pcap", "pcapng", "cap"],
    accept_multiple_files=True,
    help="Analisa todos os arquivos, une a timeline e destaca irregularidades entre capturas.",
)

# Invalida PDF guardado se a seleção de arquivos mudar
_nomes_arq = tuple(sorted(a.name for a in arquivos)) if arquivos else tuple()
if st.session_state.get("_pdf_arquivos_chave") != _nomes_arq:
    st.session_state["_pdf_arquivos_chave"] = _nomes_arq
    st.session_state["pdf_relatorio_bytes"] = None
    st.session_state["pdf_relatorio_ok"] = None
    st.session_state["pdf_gerando"] = False
    st.session_state["relatorio_gerando"] = False
    st.session_state.pop("pdf_relatorio_erro", None)
    st.session_state["relatorio_analista_md"] = None
    st.session_state["relatorio_analista_html"] = None
    st.session_state["abrir_aba_relatorio"] = False
    st.session_state["abrir_relatorio_browser"] = False

if not arquivos:
    st.info(
        "Selecione um ou mais arquivos PCAP/PCAPNG para iniciar a análise."
    )
    render_rodape()
    st.stop()

for arq in arquivos:
    if arq.size / 1024 / 1024 > TAMANHO_MAXIMO_ARQUIVO_MB:
        st.error(
            f"'{arq.name}' excede o limite de {TAMANHO_MAXIMO_ARQUIVO_MB} MB."
        )
        st.stop()

caminhos_temporarios = []

try:
    lista_resultados = []  # (nome, sha256, resultado)

    barra = st.progress(0.0, text="Preparando análise multi-arquivo…")
    for idx, arq in enumerate(arquivos):
        barra.progress(
            idx / max(len(arquivos), 1),
            text=f"Analisando {arq.name} ({idx + 1}/{len(arquivos)})…",
        )
        caminho, sha256 = salvar_upload(arq)
        caminhos_temporarios.append(caminho)
        res = analisar_pcap(
            caminho,
            int(limite_pacotes),
            iocs_ips,
            iocs_dominios,
        )
        lista_resultados.append((arq.name, sha256, res))

    barra.progress(1.0, text="Mesclando resultados e montando timeline…")
    resultado = mesclar_resultados(lista_resultados)
    irregularidades = detectar_irregularidades_multi(resultado, lista_resultados)
    resultado["irregularidades"] = irregularidades
    barra.empty()

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Arquivos", len(lista_resultados))
    col2.metric(
        "Pacotes analisados",
        f"{resultado['total']:,}".replace(",", "."),
    )
    col3.metric("Volume analisado", bytes_legivel(resultado["bytes"]))
    col4.metric("Pacotes com erro", resultado["erros"])
    col5.metric(
        "Duração (união)",
        (
            str(resultado["fim"] - resultado["inicio"]).split(".")[0]
            if resultado["inicio"] and resultado["fim"]
            else "Indisponível"
        ),
    )

    st.subheader("Arquivos analisados")
    st.dataframe(
        resultado["arquivos"],
        use_container_width=True,
        hide_index=True,
    )

    # Guarda resultado para Gerar PDF / Relatório da barra lateral
    st.session_state["resultado_analise"] = resultado
    st.session_state["lista_resultados_meta"] = lista_resultados

    if resultado["inicio"] and resultado["fim"]:
        st.subheader("Período coberto (todas as capturas)")
        coluna_inicio, coluna_fim = st.columns(2)
        coluna_inicio.metric(
            "Início UTC",
            resultado["inicio"].strftime("%d/%m/%Y %H:%M:%S"),
        )
        coluna_fim.metric(
            "Fim UTC",
            resultado["fim"].strftime("%d/%m/%Y %H:%M:%S"),
        )
        st.date_input(
            "Calendário do período unificado",
            value=(
                resultado["inicio"].date(),
                resultado["fim"].date(),
            ),
            disabled=True,
            help="Extremos de data/hora entre todos os PCAPs analisados.",
        )

    if resultado["limite"]:
        st.warning(
            "O limite de pacotes foi atingido em pelo menos um arquivo. "
            "A análise pode estar parcial."
        )

    if not irregularidades.empty:
        altas = (irregularidades["Severidade"] == "Alta").sum()
        st.error(
            f"⚠️ {len(irregularidades)} irregularidade(s) detectada(s) "
            f"({int(altas)} de severidade alta). "
            "Veja a aba 'Irregularidades / Timeline'."
        )
    elif len(lista_resultados) > 1:
        st.success(
            "Nenhuma irregularidade multi-captura foi apontada pelas regras atuais. "
            "Revise mesmo assim a timeline unificada."
        )

    if not resultado["downloads_suspeitos"].empty:
        st.error(
            f"⚠️ {len(resultado['downloads_suspeitos'])} download(s) de executável/payload "
            "via HTTP identificado(s). Veja a aba 'Downloads de executáveis'."
        )

    abas = st.tabs(
        [
            "Resumo",
            "Mapa de comunicação",
            "Fluxos",
            "IPs externos",
            "DNS",
            "Exposição de dados",
            "OT / Ativos",
            "Upload / Download OT",
            "IOCs conhecidos",
            "IOCs candidatos",
            "Irregularidades / Timeline",
            "Pacotes",
            "Indicadores",
            "Downloads de executáveis",
        ]
    )

    with abas[0]:
        esquerda, direita = st.columns(2)

        with esquerda:
            st.subheader("Distribuição de protocolos")

            if not resultado["protocolos"].empty:
                df_proto = resultado["protocolos"].copy()
                fig_pie = px.pie(
                    df_proto,
                    names="Protocolo",
                    values="Pacotes",
                    hole=0.48,
                    color_discrete_sequence=px.colors.qualitative.Set2,
                )
                fig_pie.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#E2E8F0",
                    legend=dict(orientation="h", y=-0.12),
                    margin=dict(t=20, b=20, l=10, r=10),
                    height=340,
                )
                fig_pie.update_traces(textposition="inside", textinfo="percent+label")
                st.plotly_chart(fig_pie, use_container_width=True, key="plotly_proto_pie")

                fig_bar = px.bar(
                    df_proto.sort_values("Pacotes"),
                    x="Pacotes",
                    y="Protocolo",
                    orientation="h",
                    color="Pacotes",
                    color_continuous_scale="Teal",
                    text="Pacotes",
                )
                fig_bar.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#E2E8F0",
                    coloraxis_showscale=False,
                    margin=dict(t=10, b=10, l=10, r=10),
                    height=280,
                    xaxis_title=None,
                    yaxis_title=None,
                )
                fig_bar.update_traces(textposition="outside")
                st.plotly_chart(fig_bar, use_container_width=True, key="plotly_proto_bar")

            st.caption("Tabela de protocolos (mantida para exportação e filtro)")
            st.dataframe(
                resultado["protocolos"],
                use_container_width=True,
                hide_index=True,
            )

        with direita:
            st.subheader("Principais IPs de origem")
            if not resultado["origens"].empty:
                top_orig = resultado["origens"].head(15)
                fig_orig = px.bar(
                    top_orig.sort_values("Pacotes"),
                    x="Pacotes",
                    y="IP de origem",
                    orientation="h",
                    color="Pacotes",
                    color_continuous_scale="Oranges",
                    text="Pacotes",
                )
                fig_orig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#E2E8F0",
                    coloraxis_showscale=False,
                    margin=dict(t=10, b=10, l=10, r=10),
                    height=360,
                    xaxis_title=None,
                    yaxis_title=None,
                )
                fig_orig.update_traces(textposition="outside")
                st.plotly_chart(fig_orig, use_container_width=True, key="plotly_origens_bar")

            st.dataframe(
                resultado["origens"],
                use_container_width=True,
                hide_index=True,
            )

            st.subheader("Portas de destino observadas")
            if not resultado["portas"].empty:
                top_portas = resultado["portas"].head(15)
                fig_port = px.bar(
                    top_portas.sort_values("Pacotes"),
                    x="Pacotes",
                    y="Serviço/porta destino",
                    orientation="h",
                    color="Pacotes",
                    color_continuous_scale="Blues",
                    text="Pacotes",
                )
                fig_port.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#E2E8F0",
                    coloraxis_showscale=False,
                    margin=dict(t=10, b=10, l=10, r=10),
                    height=360,
                    xaxis_title=None,
                    yaxis_title=None,
                )
                fig_port.update_traces(textposition="outside")
                st.plotly_chart(fig_port, use_container_width=True, key="plotly_portas_bar")

            st.dataframe(
                resultado["portas"],
                use_container_width=True,
                hide_index=True,
            )

    with abas[1]:
        servicos = resultado["servicos"]

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Conexões", servicos["Conexões"])
        col2.metric("Portas observadas", servicos["Portas observadas"])
        col3.metric("SSL/TLS provável", servicos["SSL/TLS provável"])
        col4.metric("HTTP", servicos["HTTP"])

        col5, col6, col7, col8 = st.columns(4)

        col5.metric("SMB", servicos["SMB"])
        col6.metric("FTP", servicos["FTP"])
        col7.metric("Telnet", servicos["Telnet"])
        col8.metric("SSDP", servicos["SSDP"])

        st.subheader("Visão OT")
        ot1, ot2, ot3, ot4 = st.columns(4)
        n_ativos_ot = contar_ativos_ot_unicos(resultado["ativos_ot"])
        n_iocs_cand = contar_iocs_unicos(resultado["iocs_candidatos"])
        ot1.metric("Ativos OT (únicos)", n_ativos_ot)
        ot2.metric("Eventos OT", len(resultado["eventos_ot"]))
        ot3.metric("Transferências candidatas", len(resultado["transferencias_ot"]))
        ot4.metric("IOCs candidatos (únicos)", n_iocs_cand)

        st.subheader("Mapa de topologia")
        apps_disponiveis = listar_apps_grafo(resultado["grafo"])
        filtros_selecionados = st.multiselect(
            "Filtrar arestas por protocolo / aplicação",
            options=apps_disponiveis,
            default=[],
            help=(
                "Vazio = todos os protocolos. Selecione um ou mais para isolar "
                "tráfego OT, DNS, HTTP, etc. (pivô estilo A-Packets). "
                "Use o botão de download abaixo do mapa para exportar HTML offline."
            ),
            key="filtro_protocolo_mapa",
        )

        desenhar_mapa_comunicacao(
            resultado["grafo"],
            filtros_app=filtros_selecionados or None,
        )

    with abas[2]:
        st.subheader("Fluxos de comunicação")

        st.dataframe(
            resultado["fluxos"],
            use_container_width=True,
            hide_index=True,
        )

        if not resultado["fluxos"].empty:
            st.download_button(
                "Baixar fluxos em CSV",
                resultado["fluxos"].to_csv(index=False).encode("utf-8"),
                "fluxos_pcap.csv",
                "text/csv",
            )

    with abas[3]:
        st.subheader("IPs externos acessados")

        st.caption(
            "Comunicação bidirecional indica pacotes observados nos dois sentidos."
        )

        if resultado["externos"].empty:
            st.info("Nenhum IP público foi identificado.")
        else:
            st.dataframe(
                resultado["externos"],
                use_container_width=True,
                hide_index=True,
            )

            st.download_button(
                "Baixar IPs externos em CSV",
                resultado["externos"].to_csv(index=False).encode("utf-8"),
                "ips_externos_pcap.csv",
                "text/csv",
            )

    with abas[4]:
        st.subheader("Consultas DNS")

        if resultado["dns"].empty:
            st.info("Nenhuma consulta DNS foi identificada.")
        else:
            st.dataframe(
                resultado["dns"],
                use_container_width=True,
                hide_index=True,
            )

            ranking = (
                resultado["dns"]["Domínio"]
                .value_counts()
                .head(30)
                .rename_axis("Domínio")
                .reset_index(name="Consultas")
            )

            grafico_dns = px.bar(
                ranking.sort_values("Consultas"),
                x="Consultas",
                y="Domínio",
                orientation="h",
                title="Domínios mais consultados",
            )

            st.plotly_chart(
                grafico_dns,
                use_container_width=True,
                key="plotly_dns_bar",
            )

    with abas[5]:
        st.subheader("Possível exposição de dados")

        st.caption(
            "Cada linha indica o nº do pacote e a data/hora UTC em que o evento foi observado. "
            "Senhas não são exibidas, salvas ou exportadas."
        )

        if resultado["eventos"].empty:
            st.success(
                "Nenhum indicador de exposição foi identificado."
            )
        else:
            df_ev = resultado["eventos"].copy()
            if "Data/hora UTC" in df_ev.columns:
                df_ev = df_ev.sort_values("Data/hora UTC", ascending=True)
            cols_pref = [c for c in ["Nº pacote", "Data/hora UTC", "Categoria", "Protocolo", "Origem", "Destino", "Porta destino", "Detalhe", "Usuário identificado", "Arquivo"] if c in df_ev.columns]
            demais = [c for c in df_ev.columns if c not in cols_pref]
            df_ev = df_ev[cols_pref + demais]
            st.dataframe(
                df_ev,
                use_container_width=True,
                hide_index=True,
            )

            st.download_button(
                "Baixar indicadores em CSV",
                df_ev.to_csv(index=False).encode("utf-8"),
                "exposicao_dados_pcap.csv",
                "text/csv",
            )

    with abas[6]:
        st.subheader("Ativos e protocolos OT")
        st.caption(
            "A identificação é baseada na porta/protocolo observado na captura; "
            "ela não confirma a função operacional do equipamento."
        )

        col1, col2, col3 = st.columns(3)
        col1.metric(
            "Ativos OT (IPs únicos)",
            contar_ativos_ot_unicos(resultado["ativos_ot"]),
            help="Apenas IPs que comunicaram em portas/protocolos OT, sem repetir o mesmo IP.",
        )
        col2.metric(
            "Transferências OT candidatas",
            len(resultado["transferencias_ot"]),
        )
        col3.metric(
            "Eventos OT",
            len(resultado["eventos_ot"]),
        )

        if resultado["detalhes_ot"].empty:
            st.info("Nenhum protocolo OT conhecido pelas heurísticas atuais foi identificado.")
        else:
            fig_ot = px.bar(
                resultado["detalhes_ot"].sort_values("Pacotes"),
                x="Pacotes",
                y="Protocolo OT",
                orientation="h",
                color="Pacotes",
                color_continuous_scale="Reds",
                text="Pacotes",
                title="Pacotes por protocolo OT",
            )
            fig_ot.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#E2E8F0",
                coloraxis_showscale=False,
                margin=dict(t=40, b=10, l=10, r=10),
                height=max(220, 40 * len(resultado["detalhes_ot"]) + 80),
                xaxis_title=None,
                yaxis_title=None,
            )
            fig_ot.update_traces(textposition="outside")
            st.plotly_chart(fig_ot, use_container_width=True, key="plotly_ot_bar")
            st.dataframe(
                resultado["detalhes_ot"],
                use_container_width=True,
                hide_index=True,
            )

        st.subheader("Ativos OT observados")
        st.caption(
            "Cada linha é um IP distinto que participou de comunicação em porta/protocolo OT. "
            "IPs repetidos entre capturas foram unificados."
        )
        if resultado["ativos_ot"].empty:
            st.info("Nenhum ativo participou de fluxo nas portas OT monitoradas.")
        else:
            st.dataframe(
                resultado["ativos_ot"],
                use_container_width=True,
                hide_index=True,
            )

        st.subheader("Eventos/protocolos OT")
        st.caption(
            "Lista cronológica com nº do pacote e data/hora UTC de cada ocorrência OT."
        )
        if resultado["eventos_ot"].empty:
            st.info("Nenhum evento OT específico foi identificado.")
        else:
            df_ot = resultado["eventos_ot"].copy()
            if "Data/hora UTC" in df_ot.columns:
                df_ot = df_ot.sort_values("Data/hora UTC", ascending=True)
            cols_pref = [
                c for c in [
                    "Nº pacote", "Data/hora UTC", "Categoria", "Protocolo OT",
                    "Fabricante", "Família PLC/OT", "Operação", "Classificação",
                    "Origem", "Destino", "Porta destino", "Transporte", "Detalhe",
                ] if c in df_ot.columns
            ]
            demais = [c for c in df_ot.columns if c not in cols_pref]
            df_ot = df_ot[cols_pref + demais]
            st.dataframe(
                df_ot,
                use_container_width=True,
                hide_index=True,
            )
            st.download_button(
                "Baixar eventos OT em CSV",
                df_ot.to_csv(index=False).encode("utf-8"),
                "eventos_ot_pcap.csv",
                "text/csv",
            )

    with abas[7]:
        st.subheader("Upload / Download em ambiente OT")
        st.caption(
            "A classificação abaixo é heurística: usa direção cliente/servidor e "
            "assimetria de bytes. Ela não substitui a validação do projeto, PLC "
            "ou ferramenta do fabricante."
        )

        if resultado["transferencias_ot"].empty:
            st.info(
                "Nenhum fluxo OT apresentou volume e assimetria suficientes "
                "para ser classificado como transferência candidata."
            )
        else:
            st.dataframe(
                resultado["transferencias_ot"],
                use_container_width=True,
                hide_index=True,
            )
            st.download_button(
                "Baixar transferências OT em CSV",
                resultado["transferencias_ot"].to_csv(index=False).encode("utf-8"),
                "transferencias_ot_pcap.csv",
                "text/csv",
            )

    with abas[8]:
        st.subheader("IOCs encontrados na lista local")
        st.caption(
            "São IOCs conhecidos somente porque foram fornecidos na lista local."
        )

        if arquivo_ioc is None:
            st.info(
                "Envie uma lista TXT/CSV com IPs e domínios na barra lateral."
            )
        elif resultado["iocs"].empty:
            st.success("Nenhum IOC da lista local foi encontrado.")
        else:
            st.dataframe(
                resultado["iocs"],
                use_container_width=True,
                hide_index=True,
            )

    with abas[9]:
        st.subheader("IOCs candidatos derivados da captura")
        st.caption(
            "Sem uma base externa, estes indicadores não são IOCs confirmados. "
            "Valores duplicados (mesmo Tipo + IOC) foram removidos — contagem distinta."
        )
        st.metric("IOCs candidatos únicos", contar_iocs_unicos(resultado["iocs_candidatos"]))

        if resultado["iocs_candidatos"].empty:
            st.success("Nenhum IOC candidato foi derivado pelas regras atuais.")
        else:
            st.dataframe(
                resultado["iocs_candidatos"],
                use_container_width=True,
                hide_index=True,
            )
            st.download_button(
                "Baixar IOCs candidatos em CSV",
                resultado["iocs_candidatos"].to_csv(index=False).encode("utf-8"),
                "iocs_candidatos_pcap.csv",
                "text/csv",
            )

    with abas[10]:
        st.subheader("Irregularidades entre capturas")
        st.caption(
            "Padrões heurísticos que cruzam um ou vários PCAPs. "
            "Não substituem análise forense; servem para priorizar a ordem dos eventos."
        )
        irreg = resultado.get("irregularidades", pd.DataFrame())
        if irreg is None or irreg.empty:
            st.success("Nenhuma irregularidade multi-captura foi apontada pelas regras atuais.")
        else:
            st.dataframe(irreg, use_container_width=True, hide_index=True)
            st.download_button(
                "Baixar irregularidades em CSV",
                irreg.to_csv(index=False).encode("utf-8"),
                "irregularidades_pcap.csv",
                "text/csv",
            )
            # Ordem sugerida consolidada
            if "Ordem sugerida" in irreg.columns:
                st.subheader("Ordem de investigação sugerida")
                for i, row in irreg.iterrows():
                    st.markdown(
                        f"**{row.get('Severidade', '')} · {row.get('Tipo', '')}**  \n"
                        f"Alvo: `{row.get('Alvo', '-')}`  \n"
                        f"{row.get('Ordem sugerida', '')}"
                    )

        timeline = montar_timeline_eventos(resultado)
        desenhar_timeline_eventos(timeline, chart_key="plotly_tl_irreg")

        if not timeline.empty:
            st.subheader("Ordem global dos eventos (cronológica)")
            st.caption(
                "Coluna **Ordem** = sequência unificada por data/hora UTC entre todos os arquivos. "
                "Use Captura + Nº pacote para localizar o frame no PCAP original."
            )
            st.dataframe(timeline, use_container_width=True, hide_index=True)

    with abas[11]:
        st.subheader("Amostra de pacotes")
        st.caption(
            "Cada linha traz o arquivo de origem, o nº sequencial do pacote na análise "
            "e a data/hora UTC com milissegundos."
        )

        st.dataframe(
            resultado["amostra"],
            use_container_width=True,
            hide_index=True,
        )

        if not resultado["amostra"].empty:
            st.download_button(
                "Baixar amostra em CSV",
                resultado["amostra"].to_csv(index=False).encode("utf-8"),
                "amostra_pacotes.csv",
                "text/csv",
            )

    with abas[12]:
        st.subheader("Indicadores para investigação")
        st.caption(
            "Indicadores devem ser validados conforme o contexto do ambiente. "
            "Uma anomalia de rede não é, sozinha, evidência de comprometimento."
        )

        timeline = montar_timeline_eventos(resultado)
        desenhar_timeline_eventos(timeline, chart_key="plotly_tl_indicadores")

        st.subheader("Alertas detectados")
        if resultado["alertas"].empty:
            st.success(
                "Nenhum indicador foi encontrado pelas regras atuais."
            )
        else:
            st.dataframe(
                resultado["alertas"],
                use_container_width=True,
                hide_index=True,
            )

        st.subheader("Anomalias comportamentais OT")
        if resultado["anomalias_ot"].empty:
            st.info("Nenhuma anomalia comportamental OT foi identificada pelas regras atuais.")
        else:
            st.dataframe(
                resultado["anomalias_ot"],
                use_container_width=True,
                hide_index=True,
            )

    with abas[13]:
        st.subheader("Downloads de executáveis / payloads via HTTP")
        st.caption(
            "Identificação pelo conteúdo (requisição/resposta HTTP e assinatura do arquivo), "
            "em qualquer porta TCP. HTTPS não é decifrado. A análise do binário é estática e "
            "não confirma a família de malware; valide o hash em fontes de inteligência."
        )

        if resultado["downloads_suspeitos"].empty:
            st.success("Nenhum download de executável/payload foi identificado em HTTP.")
        else:
            st.dataframe(
                resultado["downloads_suspeitos"],
                use_container_width=True,
                hide_index=True,
            )
            st.download_button(
                "Baixar downloads em CSV",
                resultado["downloads_suspeitos"].to_csv(index=False).encode("utf-8"),
                "downloads_executaveis_pcap.csv",
                "text/csv",
            )

    render_rodape()

except Exception as erro:
    st.error(f"Não foi possível analisar o arquivo: {erro}")
    render_rodape()

finally:
    for caminho_temporario in caminhos_temporarios:
        if caminho_temporario and os.path.exists(caminho_temporario):
            try:
                os.remove(caminho_temporario)
            except OSError:
                pass
