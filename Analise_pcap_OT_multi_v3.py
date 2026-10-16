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
from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, IPv6, Raw, TCP, UDP
from scapy.utils import PcapNgReader, PcapReader
try:
    from scapy.config import conf as _scapy_conf
    _scapy_conf.verb = 0  # silencia logs do Scapy (performance + console limpo)
except Exception:
    pass

try:
    from protocolos_ot import (
        CONFIANCA_ALTA,
        CONFIANCA_BAIXA,
        CONFIANCA_MEDIA,
        ORDEM_CONFIANCA,
        melhor_confianca,
        analisar_mms_payload as _mms_mod,
        analisar_s7_payload as _s7_mod,
        analisar_modbus_payload as _mb_mod,
    )
except ImportError:
    CONFIANCA_ALTA, CONFIANCA_MEDIA, CONFIANCA_BAIXA = "alta", "media", "baixa"
    ORDEM_CONFIANCA = {CONFIANCA_ALTA: 3, CONFIANCA_MEDIA: 2, CONFIANCA_BAIXA: 1}
    def melhor_confianca(a, b):
        if not a: return b or CONFIANCA_BAIXA
        if not b: return a
        return a if ORDEM_CONFIANCA.get(a, 0) >= ORDEM_CONFIANCA.get(b, 0) else b
    _mms_mod = _s7_mod = _mb_mod = None


TAMANHO_MAXIMO_ARQUIVO_MB = 300  # Scapy é pesado; use editcap/tshark para pré-filtro em capturas maiores
LIMITE_PACOTES_AMOSTRA = 5000
LIMITE_EVENTOS = 1000
LIMITE_NOS_MAPA = 60
LIMITE_ARESTAS_MAPA = 180
LIMITE_PAYLOAD = 8192
LIMITE_TRANSFERENCIA_OT = 1024

try:
    from base_plcs_offline import (
        BASE_PLCS_VERSAO,
        info_funcao_s7,
        info_funcao_modbus,
        info_umas,
        fabricante_por_protocolo,
        protocolo_na_base,
        porta_permitida_para_protocolo,
        mensagem_protocolo_fora_da_base,
        resumo_base,
        PORTAS_PERMITIDAS_POR_PROTOCOLO,
        FUNCOES_UMAS as BASE_FUNCOES_UMAS,
    )
    _BASE_PLC_OK = True
except ImportError:
    BASE_PLCS_VERSAO = "indisponivel"
    _BASE_PLC_OK = False
    BASE_FUNCOES_UMAS = {}
    def info_funcao_s7(c):
        return {"nome": f"Função S7 0x{c:02X}" if c is not None else "S7", "critico": False, "categoria": "?"}
    def info_funcao_modbus(c):
        return {"nome": f"FC {c}", "critico": False, "categoria": "?"}
    def info_umas(c):
        return f"UMAS 0x{c:02X}" if c is not None else "UMAS"
    def fabricante_por_protocolo(n):
        return None
    def protocolo_na_base(n):
        return True
    def porta_permitida_para_protocolo(n, p):
        return True
    def mensagem_protocolo_fora_da_base(n, p=None):
        return f"Protocolo «{n}» fora da base offline — estenda base_plcs_offline.py."
    def resumo_base():
        return {"versao": "indisponivel", "offline": True}
    PORTAS_PERMITIDAS_POR_PROTOCOLO = {}

LIMITE_EVENTOS_OT = 1000

# ---------------------------------------------------------------------------
# Aviso oficial — análise preliminar (UI, PDF, HTML e markdown)
# ---------------------------------------------------------------------------
AVISO_ANALISE_PRELIMINAR = (
    "Análise preliminar — validação obrigatória no PCAP"
)
AVISO_ANALISE_PRELIMINAR_TEXTO = (
    "Este relatório é gerado automaticamente por heurísticas offline aplicadas ao(s) "
    "arquivo(s) PCAP. Indicadores, classificações de protocolo (OT ou IT), alertas, "
    "IOCs candidatos e hipóteses de comportamento são evidências técnicas derivadas "
    "da captura e não constituem prova conclusiva de incidente ou de comprometimento. "
    "Todo achado deve ser validado manualmente no PCAP original (Wireshark, tshark ou "
    "ferramenta equivalente), no contexto operacional da rede e, quando aplicável, "
    "com inteligência de ameaças e engenharia de processo. Falsos positivos podem "
    "ocorrer — em especial quando tráfego IT genérico é interpretado como protocolo "
    "industrial. Preserve o PCAP original e o hash SHA-256 para cadeia de custódia."
)
AVISO_ANALISE_PRELIMINAR_CURTO = (
    "Análise preliminar baseada em heurísticas. Valide todos os indicadores "
    "diretamente no PCAP original antes de qualquer ação operacional ou forense."
)

# Portas/protocolos OT reconhecidos por heurísticas de captura.
# A identificação não significa, por si só, que o tráfego seja malicioso.
PORTAS_OT = {
    102: "Siemens S7comm / ISO-TSAP",
    502: "Modbus TCP",
    2404: "IEC 60870-5-104",
    44818: "EtherNet/IP / CIP",
    2222: "EtherNet/IP I/O (UDP)",
    4840: "OPC UA",
    4843: "OPC UA (TLS)",
    20000: "DNP3",
    47808: "BACnet/IP",
    5000: "Mitsubishi MC / SLMP",
    5001: "Mitsubishi MC / SLMP",
    9600: "Omron FINS",
    48898: "Beckhoff ADS",
    34962: "PROFINET (UDP RT)",
    34963: "PROFINET (UDP)",
    34964: "PROFINET (UDP RPC)",
    34980: "EtherCAT (UDP)",
    5094: "HART-IP",
    1883: "MQTT",
    8883: "MQTT (TLS)",
    2455: "CODESYS",
    11740: "CODESYS Gateway",
    4712: "IEEE C37.118",
    4713: "IEEE C37.118",
    3671: "KNXnet/IP",
    61450: "CC-Link IE Field Basic",
    61451: "CC-Link IE Field Basic",
    45237: "CC-Link / SLMP search",
}

# EtherTypes L2 (identificação offline sem IP)
ETHERTYPES_OT = {
    0x8892: "PROFINET",
    0x88A4: "EtherCAT",
    0x88B8: "IEC 61850 GOOSE",
    0x88BA: "IEC 61850 SV",
    0x88CC: "LLDP (topologia)",
    0x88E3: "PROFINET MRP",
}

META_PROTOCOLOS_OT = {
    "Siemens S7comm / ISO-TSAP": ("Siemens", "S7 / S7comm"),
    "Siemens S7comm-plus": ("Siemens", "S7comm-plus"),
    "Modbus TCP": ("Schneider / múltiplos fabricantes", "Modbus TCP"),
    "Schneider UMAS / Unity Pro": ("Schneider Electric", "UMAS / Unity Pro / Control Expert"),
    "Modbus RTU over TCP": ("Schneider / múltiplos fabricantes", "Modbus RTU encapsulado"),
    "IEC 60870-5-104": ("IEC / múltiplos fabricantes", "IEC-104"),
    "EtherNet/IP / CIP": ("Rockwell / múltiplos fabricantes", "EtherNet/IP / CIP"),
    "EtherNet/IP I/O (UDP)": ("Rockwell / ODVA", "EtherNet/IP implicit I/O"),
    "OPC UA": ("OPC Foundation / múltiplos fabricantes", "OPC UA"),
    "OPC UA (TLS)": ("OPC Foundation", "OPC UA cifrado"),
    "DNP3": ("DNP3 / múltiplos fabricantes", "DNP3"),
    "BACnet/IP": ("BACnet / múltiplos fabricantes", "BACnet/IP"),
    "Mitsubishi MC / SLMP": ("Mitsubishi Electric", "MC / SLMP"),
    "Omron FINS": ("Omron", "FINS"),
    "Beckhoff ADS": ("Beckhoff", "ADS"),
    "PROFINET": ("PROFIBUS & PROFINET International", "PROFINET L2"),
    "PROFINET (UDP RT)": ("PI", "PROFINET"),
    "PROFINET (UDP)": ("PI", "PROFINET"),
    "PROFINET (UDP RPC)": ("PI", "PROFINET RPC"),
    "PROFINET MRP": ("PI", "Media Redundancy"),
    "EtherCAT": ("EtherCAT Technology Group", "EtherCAT L2"),
    "EtherCAT (UDP)": ("ETG", "EtherCAT over UDP"),
    "IEC 61850 GOOSE": ("IEC", "GOOSE"),
    "IEC 61850 SV": ("IEC", "Sampled Values"),
    "HART-IP": ("FieldComm Group", "HART-IP"),
    "MQTT": ("OASIS / Eclipse Sparkplug", "MQTT"),
    "MQTT (TLS)": ("OASIS", "MQTT cifrado"),
    "CODESYS": ("CODESYS GmbH", "CODESYS"),
    "CODESYS Gateway": ("CODESYS GmbH", "CODESYS"),
    "IEEE C37.118": ("IEEE", "Synchrophasor"),
    "KNXnet/IP": ("KNX Association", "KNXnet/IP"),
    "CC-Link IE Field Basic": ("CLPA / Mitsubishi", "CC-Link IE"),
    "CC-Link / SLMP search": ("CLPA / Mitsubishi", "SLMP"),
    "LLDP (topologia)": ("IEEE 802.1AB", "LLDP"),
}

PORTAS_TRANSFERENCIA_OT = {102, 502, 2404, 44818, 2222, 4840, 4843, 20000, 47808, 5000, 5001, 9600, 48898, 34962, 34963, 34964, 34980, 5094, 1883, 2455, 11740, 4712, 4713, 3671, 61450, 61451}

FUNCOES_MODBUS_ESCRITA = {5, 6, 15, 16, 22, 23}
FUNCOES_S7_TRANSFERENCIA_CANDIDATA = {0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}
FUNCOES_S7_CONTROLE_PLC = {0x28, 0x29}  # PI-Service (start), PLC Stop
FUNCOES_S7_ESCRITA = {0x05}  # Write Var

# Nomes oficiais / usuais S7comm (Job function codes)
NOMES_FUNCAO_S7 = {
    0x00: "CPU services",
    0x04: "Read Var",
    0x05: "Write Var",
    0x1A: "Request download",
    0x1B: "Download block",
    0x1C: "Download ended",
    0x1D: "Start upload",
    0x1E: "Upload",
    0x1F: "End upload",
    0x28: "PI-Service (PLC Start)",
    0x29: "PLC Stop",
    0xF0: "Setup communication",
}

NOMES_ROSCTR_S7 = {
    0x01: "Job",
    0x02: "Ack",
    0x03: "Ack-Data",
    0x07: "Userdata",
}

NOMES_FUNCAO_MODBUS = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    43: "Read Device Identification",
}

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
    et = ethertype_pacote(pacote)
    if et in ETHERTYPES_OT:
        return ETHERTYPES_OT[et]
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
    """Mostra o nome de usuário na análise; nunca a senha."""
    if not usuario:
        return "Não identificado"
    u = str(usuario).strip()
    u = "".join(ch for ch in u if ch.isprintable() and ch not in "\r\n\t")
    if not u:
        return "Não identificado"
    if len(u) > 64:
        u = u[:61] + "..."
    return u


def redigir_senha_em_texto(texto):
    """Remove valores de senha de qualquer texto antes de gravar em alerta/relatório."""
    if not texto:
        return texto
    t = str(texto)
    t = re.sub(
        r"(?i)\b(password|passwd|pwd|senha|pass)\s*[=:]\s*[^&\s\r\n\"']+",
        r"\1=[REDACTED]",
        t,
    )
    t = re.sub(r"(?im)\bPASS\s+\S+", "PASS [REDACTED]", t)
    t = re.sub(
        r"(?i)(authorization\s*:\s*basic\s+)[A-Za-z0-9+/=]+",
        r"\1[REDACTED]",
        t,
    )
    return t


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
                    "Detalhe": redigir_senha_em_texto(
                        "Comando FTP PASS identificado. Usuário observado: "
                        + str(usuarios_fluxo.get(fluxo, "Não identificado"))
                        + ". A senha não foi exibida nem armazenada."
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
                    "Detalhe": redigir_senha_em_texto(
                        "Comando POP3 PASS identificado. Usuário observado: "
                        + str(usuarios_fluxo.get(fluxo, "Não identificado"))
                        + ". A senha não foi exibida nem armazenada."
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
            user_visivel = usuario_hash if usuario_hash and usuario_hash != "Não identificado" else "Não identificado"
            if basic:
                detalhe = (
                    f"Cabeçalho HTTP Basic Authorization identificado. "
                    f"Usuário observado: {user_visivel}. A senha não foi exibida nem armazenada."
                )
            else:
                detalhe = (
                    f"Campo de senha em possível formulário HTTP identificado. "
                    f"Usuário observado: {user_visivel}. A senha não foi exibida nem armazenada."
                )
            detalhe = redigir_senha_em_texto(detalhe)

            adicionar_evento(
                eventos,
                chaves_eventos,
                {
                    **base,
                    "Categoria": "Possível credencial exposta",
                    "Protocolo": "HTTP sem TLS",
                    "Usuário identificado": user_visivel,
                    "Ação": "Credencial em claro (HTTP)",
                    "Detalhe": detalhe,
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


def analisar_profinet_payload(payload, ethertype=None):
    """PROFINET L2 (EtherType 0x8892) — FrameID DCP/RT offline."""
    if ethertype is not None and ethertype != 0x8892:
        # UDP RPC não usa este path
        pass
    if not payload or len(payload) < 2:
        return None
    frame_id = int.from_bytes(payload[0:2], "big")
    DCP_IDS = {
        0xFEFC: "DCP Hello",
        0xFEFD: "DCP Get/Set",
        0xFEFE: "DCP Identify Req",
        0xFEFF: "DCP Identify Res",
    }
    if frame_id in DCP_IDS:
        svc = None
        if len(payload) >= 4:
            svc = payload[2]
        return {
            "PROFINET": True,
            "FrameID": frame_id,
            "Tipo": DCP_IDS[frame_id],
            "ServiceID": svc,
            "Cyclic": False,
        }
    # Cyclic RT ranges (simplificado)
    if 0x8000 <= frame_id <= 0xBBFF or 0xBC00 <= frame_id <= 0xBFFF:
        return {
            "PROFINET": True,
            "FrameID": frame_id,
            "Tipo": "RT cyclic I/O",
            "ServiceID": None,
            "Cyclic": True,
        }
    if ethertype == 0x8892:
        return {
            "PROFINET": True,
            "FrameID": frame_id,
            "Tipo": f"FrameID 0x{frame_id:04X}",
            "ServiceID": None,
            "Cyclic": False,
        }
    return None


def analisar_ethercat_payload(payload, ethertype=None):
    """EtherCAT L2 (0x88A4) ou UDP 34980 — header length+type offline."""
    if not payload or len(payload) < 2:
        return None
    if ethertype is not None and ethertype not in (None, 0x88A4):
        return None
    hdr = int.from_bytes(payload[0:2], "little")
    length = hdr & 0x07FF
    typ = (hdr >> 12) & 0x0F
    # Type 1 = EtherCAT command
    if typ not in (1, 2, 3, 4, 5) and ethertype != 0x88A4:
        return None
    cmd = payload[2] if len(payload) > 2 else None
    CMDS = {
        1: "APRD", 2: "APWR", 3: "APRW", 4: "FPRD", 5: "FPWR", 6: "FPRW",
        7: "BRD", 8: "BWR", 9: "BRW", 10: "LRD", 11: "LWR", 12: "LRW", 13: "ARMW",
    }
    return {
        "EtherCAT": True,
        "Length": length,
        "Type": typ,
        "Cmd": cmd,
        "Cmd nome": CMDS.get(cmd, f"0x{cmd:02X}" if cmd is not None else None),
    }


def _ber_buscar_strings(data, limite=8):
    """Extrai strings printable curtas de APDU BER (heurística offline)."""
    out = []
    n = len(data)
    i = 0
    while i < n - 2 and len(out) < limite:
        # tag + length + content (length curto 1 byte)
        tag = data[i]
        ln = data[i + 1]
        if ln > 0 and ln < 80 and i + 2 + ln <= n:
            chunk = data[i + 2 : i + 2 + ln]
            if tag in (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x91):
                try:
                    s = chunk.decode("utf-8", errors="ignore").strip("\x00")
                    if s and all(32 <= ord(c) < 127 for c in s[:40]) and len(s) >= 2:
                        out.append(s[:60])
                except Exception:
                    pass
            i += 2 + ln
        else:
            i += 1
    return out


def analisar_goose_payload(payload, ethertype=None):
    """
    IEC 61850 GOOSE (EtherType 0x88B8).
    APPID | Length | Reserved1 | Reserved2 | APDU (BER).
    Extrai stNum/sqNum quando possíveis e strings (goID/datSet).
    """
    if ethertype is not None and ethertype != 0x88B8:
        return None
    if not payload or len(payload) < 8:
        return None
    appid = int.from_bytes(payload[0:2], "big")
    length = int.from_bytes(payload[2:4], "big")
    reserved1 = int.from_bytes(payload[4:6], "big") if len(payload) >= 6 else 0
    reserved2 = int.from_bytes(payload[6:8], "big") if len(payload) >= 8 else 0
    apdu = payload[8:] if len(payload) > 8 else b""

    st_num = sq_num = None
    simulation = None
    # Heurística: inteiros BER 0x85 (stNum), 0x86 (sqNum) em muitos GOOSE
    k = 0
    while k < len(apdu) - 2:
        tag = apdu[k]
        ln = apdu[k + 1]
        if ln > 0 and ln <= 4 and k + 2 + ln <= len(apdu):
            val = int.from_bytes(apdu[k + 2 : k + 2 + ln], "big")
            if tag == 0x85 and st_num is None:
                st_num = val
            elif tag == 0x86 and sq_num is None:
                sq_num = val
            elif tag == 0x87 and simulation is None:
                simulation = bool(val)
            k += 2 + ln
        else:
            k += 1

    strings = _ber_buscar_strings(apdu)
    go_id = strings[0] if strings else None
    dat_set = strings[1] if len(strings) > 1 else None

    return {
        "GOOSE": True,
        "APPID": appid,
        "Length": length,
        "Reserved1": reserved1,
        "Reserved2": reserved2,
        "stNum": st_num,
        "sqNum": sq_num,
        "Simulation": simulation,
        "goID": go_id,
        "datSet": dat_set,
        "Strings": strings[:5],
    }


def analisar_sv_payload(payload, ethertype=None):
    """
    IEC 61850 Sampled Values (EtherType 0x88BA).
    APPID | Length | Reserved1 | Reserved2 | ASDU(s).
    """
    if ethertype is not None and ethertype != 0x88BA:
        return None
    if not payload or len(payload) < 8:
        return None
    appid = int.from_bytes(payload[0:2], "big")
    length = int.from_bytes(payload[2:4], "big")
    reserved1 = int.from_bytes(payload[4:6], "big") if len(payload) >= 6 else 0
    reserved2 = int.from_bytes(payload[6:8], "big") if len(payload) >= 8 else 0
    apdu = payload[8:] if len(payload) > 8 else b""
    strings = _ber_buscar_strings(apdu, limite=4)
    smp_cnt = None
    # smpCnt frequentemente tag 0x85
    k = 0
    while k < len(apdu) - 2:
        tag = apdu[k]
        ln = apdu[k + 1]
        if ln > 0 and ln <= 4 and k + 2 + ln <= len(apdu):
            if tag == 0x85 and smp_cnt is None:
                smp_cnt = int.from_bytes(apdu[k + 2 : k + 2 + ln], "big")
                break
            k += 2 + ln
        else:
            k += 1
    return {
        "SV": True,
        "APPID": appid,
        "Length": length,
        "Reserved1": reserved1,
        "Reserved2": reserved2,
        "smpCnt": smp_cnt,
        "svID": strings[0] if strings else None,
        "Strings": strings[:4],
    }



def analisar_mqtt_payload(payload):
    """MQTT CONNECT/PUBLISH (não decifra TLS)."""
    if not payload or len(payload) < 2:
        return None
    # Fixed header: byte0 = type<<4 | flags
    tipo = (payload[0] >> 4) & 0x0F
    TIPOS = {
        1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
        8: "SUBSCRIBE", 9: "SUBACK", 12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT",
    }
    if tipo not in TIPOS:
        return None
    sparkplug = False
    if b"spBv1.0" in payload[:200] or b"spAv1.0" in payload[:200]:
        sparkplug = True
    return {
        "MQTT": True,
        "Tipo": TIPOS[tipo],
        "Sparkplug": sparkplug,
    }


def analisar_hartip_payload(payload):
    """HART-IP: versão + tipo de mensagem (heurística)."""
    if not payload or len(payload) < 8:
        return None
    # Common: version byte, message type
    ver = payload[0]
    if ver not in (1, 2):
        return None
    msg_type = payload[1]
    return {"HART-IP": True, "Versão": ver, "MessageType": msg_type}


def analisar_modbus_rtu_tcp(payload):
    """
    Modbus RTU encapsulado em TCP (sem MBAP).
    Muito conservador: rejeita qualquer coisa que pareça MBAP, HTTP, TLS, PE,
    e só aceita FC padrão (não 0x5A UMAS). Reduz FP em tráfego Unity/UMAS.
    """
    if not payload or len(payload) < 4:
        return None
    # MBAP clássico → não é RTU
    if len(payload) >= 7 and payload[2:4] == b"\x00\x00":
        length = int.from_bytes(payload[4:6], "big")
        if 2 <= length <= len(payload) - 6:
            return None
    if (
        payload[:2] == b"MZ"
        or payload[:5] == b"HTTP/"
        or payload[:3] in (b"\x16\x03\x01", b"\x16\x03\x03")
        or payload[:4] in (b"GET ", b"POST")
        or payload[0] == 0x03  # TPKT/S7
    ):
        return None
    addr, fc = payload[0], payload[1]
    if addr == 0 or addr > 247:
        return None
    fc_n = fc & 0x7F
    # Não interpretar 0x5A como RTU (é UMAS em MBAP)
    if fc_n not in {1, 2, 3, 4, 5, 6, 15, 16, 22, 23, 43}:
        return None
    min_len = {
        1: 6, 2: 6, 3: 6, 4: 6,
        5: 6, 6: 6,
        15: 9, 16: 9,
        22: 8, 23: 11, 43: 5,
    }.get(fc_n, 8)
    if len(payload) < min_len:
        return None
    # Exige tamanho "parecido" com trama RTU curta (evita binários longos de engenharia)
    if len(payload) > 260:
        return None
    info = info_funcao_modbus(fc_n)
    return {
        "Modbus RTU TCP": True,
        "Slave": addr,
        "Função": fc_n,
        "Nome função": info.get("nome", f"FC {fc_n}"),
        "Exceção": bool(fc & 0x80),
        "Escrita": fc_n in FUNCOES_MODBUS_ESCRITA,
        "Identificação dispositivo": fc_n == 43,
    }



def analisar_codesys_payload(payload):
    """Heurística CODESYS: magic 'c' 's' 's' ou blk."""
    if not payload or len(payload) < 4:
        return None
    if payload[0:4] in (b"css\x00", b"\x00css", b"BlkS", b"blk\x00"):
        return {"CODESYS": True, "Magic": payload[0:4].hex()}
    # Alguns usam little-endian size + tag
    return None


def analisar_knx_payload(payload):
    """KNXnet/IP header: header length 0x06, version 0x10."""
    if not payload or len(payload) < 6:
        return None
    if payload[0] == 0x06 and payload[1] == 0x10:
        svc = int.from_bytes(payload[2:4], "big")
        return {"KNXnet/IP": True, "Service": svc}
    return None


def analisar_c37118_payload(payload):
    """IEEE C37.118 synchrophasor — sync byte 0xAA."""
    if not payload or len(payload) < 4:
        return None
    if payload[0] != 0xAA:
        return None
    frame_type = (payload[1] >> 4) & 0x07
    return {"C37.118": True, "FrameType": frame_type}


def ethertype_pacote(pacote):
    """Obtém EtherType (considera VLAN 0x8100)."""
    if Ether not in pacote:
        return None
    try:
        et = int(pacote[Ether].type)
        if et == 0x8100 and len(pacote[Ether].payload) >= 4:
            # VLAN tagged: real type after 4 bytes
            raw = bytes(pacote[Ether].payload)[:4]
            if len(raw) >= 4:
                et = int.from_bytes(raw[2:4], "big")
        return et
    except Exception:
        return None


def macs_pacote(pacote):
    if Ether not in pacote:
        return None, None
    try:
        return str(pacote[Ether].src), str(pacote[Ether].dst)
    except Exception:
        return None, None



def classificar_protocolo_ot(
    porta_origem,
    porta_destino,
    payload=b"",
    transporte=None,
    ethertype=None,
    retornar_confianca=False,
):
    """
    Identifica protocolo OT por assinatura / EtherType primeiro.
    Se retornar_confianca=True → (nome, confiança: alta|media|baixa).
    100% offline.
    """
    portas = (porta_destino, porta_origem)

    if payload and (
        payload[:2] == b"MZ"
        or payload[:4] == b"\x7fELF"
        or payload[:5] == b"HTTP/"
        or REGEX_REQUISICAO_HTTP.match(payload)
    ):
        payload = b""

    # --- Camada 2 (EtherType) ---
    if ethertype in ETHERTYPES_OT:
        if ethertype == 0x8892:
            pn = analisar_profinet_payload(payload or b"\x00\x00", ethertype)
            if pn:
                return "PROFINET"
        if ethertype == 0x88A4:
            if analisar_ethercat_payload(payload or b"\x00\x00", ethertype):
                return "EtherCAT"
        if ethertype == 0x88B8:
            if analisar_goose_payload(payload or b"\x00" * 8, ethertype):
                return "IEC 61850 GOOSE"
        if ethertype == 0x88BA:
            return "IEC 61850 SV"
        if ethertype == 0x88E3:
            return "PROFINET MRP"
        if ethertype == 0x88CC:
            return "LLDP (topologia)"
        # EtherType conhecido mesmo sem parse profundo
        return ETHERTYPES_OT.get(ethertype)

    # --- TCP com assinatura (restrita por porta para evitar FP em payloads binários) ---
    if transporte == "TCP" and payload:
        portas_fluxo = {p for p in (porta_origem, porta_destino) if p is not None}

        # S7 / MMS: só em 102 (ou se payload TPKT 0x03 e porta desconhecida, ainda exige TPKT)
        if 102 in portas_fluxo or (payload and payload[0:1] == b"\x03"):
            s7 = analisar_s7_payload(payload)
            if s7 and s7.get("S7"):
                if s7.get("Variante") == "S7comm-plus":
                    return "Siemens S7comm-plus"
                return "Siemens S7comm / ISO-TSAP"
            if 102 in portas_fluxo:
                try:
                    if _mms_mod and _mms_mod(payload):
                        return "IEC 61850 MMS"
                except Exception:
                    pass

        # Modbus / UMAS: prioriza porta 502; MBAP válido também aceito
        mb = analisar_modbus_payload(payload)
        if mb:
            if mb.get("UMAS"):
                return "Schneider UMAS / Unity Pro"
            if 502 in portas_fluxo:
                return "Modbus TCP"
        # RTU over TCP: nunca quando já há MBAP/UMAS; evita FP em Unity
        if not mb and 502 not in portas_fluxo:
            rtu = analisar_modbus_rtu_tcp(payload)
            if rtu:
                return "Modbus RTU over TCP"

        def _porta_ok(nome):
            return any(porta_permitida_para_protocolo(nome, p) for p in portas_fluxo) if portas_fluxo else False

        if _porta_ok("EtherNet/IP / CIP") and analisar_enip_payload(payload):
            return "EtherNet/IP / CIP"
        if _porta_ok("OPC UA") and analisar_opcua_payload(payload):
            return "OPC UA"
        if _porta_ok("IEC 60870-5-104") and analisar_iec104_payload(payload):
            return "IEC 60870-5-104"
        if _porta_ok("DNP3") and analisar_dnp3_payload(payload):
            return "DNP3"
        if _porta_ok("Mitsubishi MC / SLMP") and analisar_mitsubishi_payload(payload):
            return "Mitsubishi MC / SLMP"
        if _porta_ok("Beckhoff ADS") and analisar_ads_payload(payload):
            return "Beckhoff ADS"
        if _porta_ok("MQTT") and analisar_mqtt_payload(payload):
            return "MQTT"
        if _porta_ok("HART-IP") and analisar_hartip_payload(payload):
            return "HART-IP"
        if _porta_ok("CODESYS") and analisar_codesys_payload(payload):
            return "CODESYS"
        if _porta_ok("IEEE C37.118") and analisar_c37118_payload(payload):
            return "IEEE C37.118"

    # --- UDP com assinatura (também restrita por porta) ---
    if transporte == "UDP" and payload:
        portas_fluxo = {p for p in (porta_origem, porta_destino) if p is not None}

        def _porta_ok_u(nome):
            return any(porta_permitida_para_protocolo(nome, p) for p in portas_fluxo) if portas_fluxo else False

        if _porta_ok_u("Omron FINS") and analisar_fins_payload(payload):
            return "Omron FINS"
        if _porta_ok_u("DNP3") and analisar_dnp3_payload(payload):
            return "DNP3"
        if _porta_ok_u("BACnet/IP") and analisar_bacnet_payload(payload):
            return "BACnet/IP"
        if _porta_ok_u("EtherNet/IP / CIP") and analisar_enip_payload(payload):
            return "EtherNet/IP / CIP"
        if analisar_ethercat_payload(payload):
            return "EtherCAT (UDP)"
        if analisar_profinet_payload(payload):
            return "PROFINET (UDP RPC)"
        if _porta_ok_u("KNXnet/IP") and analisar_knx_payload(payload):
            return "KNXnet/IP"
        if _porta_ok_u("HART-IP") and analisar_hartip_payload(payload):
            return "HART-IP"
        if _porta_ok_u("IEEE C37.118") and analisar_c37118_payload(payload):
            return "IEEE C37.118"
        if _porta_ok_u("MQTT") and analisar_mqtt_payload(payload):
            return "MQTT"

    # --- Porta + evidência mínima (não rotular só por porta) ---
    for porta in portas:
        if porta is None:
            continue
        if porta in PORTAS_OT:
            nome = PORTAS_OT[porta]
            # Criptografados: identificar apenas canal
            if porta in (4843, 8883):
                return nome
            # Portas OT clássicas com tráfego na porta ainda contam (com menor confiança)
            if porta in (502, 102, 2404, 44818, 4840, 20000, 47808, 2222):
                return nome
            # PROFINET / EtherCAT / CC-Link / HART / C37 / KNX / CODESYS por porta
            if porta in (
                34962, 34963, 34964, 34980, 5094, 4712, 4713, 3671,
                2455, 11740, 61450, 61451, 45237, 1883, 5000, 5001, 9600, 48898,
            ):
                return nome

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
    """
    TPKT/COTP + S7comm (0x32) ou S7comm-plus (0x72).
    Extrai ROSCTR, comprimentos e código de função Job (quando presente).
    Pacotes só COTP (sem PDU S7) retornam COTP=True sem função.
    """
    if not payload or len(payload) < 7 or payload[0] != 0x03:
        return None

    # TPKT length (bytes 2-3)
    tpkt_len = int.from_bytes(payload[2:4], "big") if len(payload) >= 4 else 0

    # COTP: byte 4 = length of COTP header following this byte
    indice = 4
    cotp_len = payload[4] if len(payload) > 4 else 0
    if cotp_len and 4 + 1 + cotp_len <= len(payload):
        indice = 5 + cotp_len
    else:
        # fallback comum: DT COTP 02 F0 80 → índice 7
        if len(payload) > 6 and payload[4] == 0x02:
            indice = 7

    if indice >= len(payload):
        return {
            "S7": False,
            "COTP": True,
            "Variante": "COTP",
            "ROSCTR": None,
            "Função": None,
            "Nome função": "COTP (sem PDU S7)",
            "Tamanho parâmetro": 0,
            "Tamanho dados": 0,
            "Critico": False,
            "Controle PLC": False,
            "Transferência": False,
            "Escrita": False,
        }

    # S7comm classic
    if payload[indice] == 0x32:
        rosctr = payload[indice + 1] if len(payload) > indice + 1 else None
        param_len = 0
        data_len = 0
        if len(payload) >= indice + 10:
            param_len = int.from_bytes(payload[indice + 6:indice + 8], "big")
            data_len = int.from_bytes(payload[indice + 8:indice + 10], "big")
        funcao = payload[indice + 10] if len(payload) > indice + 10 else None
        # Em Ack-Data (0x03) o layout pode diferir; função só é confiável em Job (0x01)
        nome = None
        if funcao is not None:
            nome = NOMES_FUNCAO_S7.get(funcao, f"Função 0x{funcao:02X}")
        ros_nome = NOMES_ROSCTR_S7.get(rosctr, f"0x{rosctr:02X}") if isinstance(rosctr, int) else None
        transferencia = funcao in FUNCOES_S7_TRANSFERENCIA_CANDIDATA if funcao is not None else False
        controle = funcao in FUNCOES_S7_CONTROLE_PLC if funcao is not None else False
        escrita = funcao in FUNCOES_S7_ESCRITA if funcao is not None else False
        return {
            "S7": True,
            "COTP": True,
            "Variante": "S7comm",
            "ROSCTR": rosctr,
            "ROSCTR nome": ros_nome,
            "Função": funcao,
            "Nome função": nome or "Mensagem S7comm",
            "Tamanho parâmetro": param_len,
            "Tamanho dados": data_len,
            "TPKT length": tpkt_len,
            "Critico": bool(controle or transferencia or escrita),
            "Controle PLC": controle,
            "Transferência": transferencia,
            "Escrita": escrita,
        }

    # S7comm-plus
    if payload[indice] == 0x72:
        opcode = payload[indice + 1] if len(payload) > indice + 1 else None
        return {
            "S7": True,
            "COTP": True,
            "Variante": "S7comm-plus",
            "ROSCTR": None,
            "ROSCTR nome": None,
            "Função": opcode,
            "Nome função": f"S7comm-plus opcode 0x{opcode:02X}" if opcode is not None else "S7comm-plus",
            "Tamanho parâmetro": 0,
            "Tamanho dados": 0,
            "TPKT length": tpkt_len,
            "Critico": False,
            "Controle PLC": False,
            "Transferência": False,
            "Escrita": False,
        }

    # ISO-TSAP / COTP sem S7 reconhecido (possível MMS ou COTP puro)
    return {
        "S7": False,
        "COTP": True,
        "Variante": "COTP",
        "ROSCTR": None,
        "Função": None,
        "Nome função": "COTP/ISO-TSAP (sem S7comm)",
        "Tamanho parâmetro": 0,
        "Tamanho dados": 0,
        "Critico": False,
        "Controle PLC": False,
        "Transferência": False,
        "Escrita": False,
    }



def analisar_modbus_payload(payload):
    """Modbus TCP (MBAP) + detecção Schneider UMAS (FC 0x5A)."""
    if not payload or len(payload) < 8:
        return None
    if payload[2:4] != b"\x00\x00":
        return None
    length = int.from_bytes(payload[4:6], "big")
    if length < 2 or length > len(payload) - 6:
        return None
    unit = payload[6]
    fc = payload[7]
    fc_n = fc & 0x7F
    excecao = bool(fc & 0x80)

    # Schneider UMAS: FC 90 (0x5A) sobre Modbus TCP
    if fc_n == 0x5A and not excecao:
        session = payload[8] if len(payload) > 8 else None
        umas_fn = payload[9] if len(payload) > 9 else None
        umas_nome = info_umas(umas_fn) if umas_fn is not None else "UMAS"
        return {
            "Modbus": True,
            "UMAS": True,
            "Função": 0x5A,
            "Nome função": f"UMAS / {umas_nome}",
            "UMAS função": umas_fn,
            "UMAS session": session,
            "Exceção": False,
            "Código exceção": None,
            "Escrita": True,  # programação/upload — tratar como alteração candidata
            "Identificação dispositivo": False,
            "Unit": unit,
            "Tamanho": length,
            "Protocolo": "Schneider UMAS / Unity Pro",
            "Fabricante": "Schneider Electric",
            "Critico": True,
        }

    info = info_funcao_modbus(fc_n)
    escrita = fc_n in FUNCOES_MODBUS_ESCRITA
    return {
        "Modbus": True,
        "UMAS": False,
        "Função": fc_n,
        "Nome função": info.get("nome", f"FC {fc_n}"),
        "Exceção": excecao,
        "Código exceção": payload[8] if excecao and len(payload) > 8 else None,
        "Escrita": escrita and not excecao,
        "Identificação dispositivo": fc_n == 43,
        "Unit": unit,
        "Tamanho": length,
        "Protocolo": "Modbus TCP",
        "Critico": bool(info.get("critico")) and not excecao,
    }


def analisar_enip_payload(payload):
    """
    EtherNet/IP encapsulation (ODVA) + CIP quando presente — detalhado offline.
    Cabeçalho: Command(2) Length(2) Session(4) Status(4) SenderContext(8) Options(4) [CPF...]
    """
    if not payload or len(payload) < 24:
        return None
    comando = int.from_bytes(payload[0:2], "little")
    COMANDOS = {
        0x0000: "NOP",
        0x0001: "ListServices",
        0x0004: "ListIdentity",
        0x0063: "ListInterfaces",
        0x0065: "RegisterSession",
        0x0066: "UnRegisterSession",
        0x006F: "SendRRData",
        0x0070: "SendUnitData",
        0x0072: "IndicateStatus",
        0x0073: "Cancel",
    }
    if comando not in COMANDOS and comando not in {0x0001, 0x0004, 0x0065, 0x0066, 0x006F, 0x0070}:
        return None
    length = int.from_bytes(payload[2:4], "little")
    session = int.from_bytes(payload[4:8], "little")
    status = int.from_bytes(payload[8:12], "little")
    STATUS = {
        0: "Success",
        1: "Invalid/unsupported command",
        2: "Insufficient memory",
        3: "Incorrect data",
        100: "Invalid session handle",
        101: "Invalid length",
        105: "Unsupported protocol",
    }
    # CIP service dentro do CPF (após encaps 24 bytes)
    SERVICOS_CIP = {
        0x01: "Get_Attributes_All",
        0x02: "Set_Attributes_All",
        0x03: "Get_Attribute_List",
        0x04: "Set_Attribute_List",
        0x05: "Reset",
        0x06: "Start",
        0x07: "Stop",
        0x08: "Create",
        0x09: "Delete",
        0x0A: "Multiple_Service_Packet",
        0x0D: "Apply_Attributes",
        0x0E: "Get_Attribute_Single",
        0x10: "Set_Attribute_Single",
        0x11: "Find_Next_Object_Instance",
        0x15: "Restore",
        0x16: "Save",
        0x17: "No_Operation",
        0x18: "Get_Member",
        0x19: "Set_Member",
        0x1A: "Insert_Member",
        0x1B: "Remove_Member",
        0x1D: "Get_Attribute_All_Reply",
        0x4B: "Forward_Close",
        0x4C: "Unconnected_Send",
        0x4D: "Forward_Open",
        0x4E: "Large_Forward_Open",
        0x52: "Execute_PCCC",
        0x54: "Read_Tag",
        0x4F: "Get_Connection_Owner",
        0x55: "Write_Tag",
        0x56: "Read_Tag_Fragmented",
        0x57: "Write_Tag_Fragmented",
        0x58: "Get_Instance_Attribute_List",
    }
    servico = None
    servico_nome = None
    # Varre região típica do CPF em busca de service code CIP
    for off in range(24, min(len(payload), 120)):
        b = payload[off]
        if b in SERVICOS_CIP or (b & 0x7F) in SERVICOS_CIP:
            code = b & 0x7F
            if code in SERVICOS_CIP:
                servico = code
                servico_nome = SERVICOS_CIP[code]
                if b & 0x80:
                    servico_nome = servico_nome + " (reply)"
                break
    escrita = servico in {0x02, 0x04, 0x10, 0x19, 0x1A, 0x4D, 0x4E, 0x55, 0x57}
    conexao = servico in {0x4B, 0x4D, 0x4E}
    return {
        "EtherNet/IP": True,
        "Comando": comando,
        "Comando nome": COMANDOS.get(comando, f"0x{comando:04X}"),
        "Length": length,
        "Session": session,
        "Status": status,
        "Status nome": STATUS.get(status, f"0x{status:08X}"),
        "Serviço CIP": servico,
        "Serviço CIP nome": servico_nome,
        "Escrita": escrita,
        "Conexão CIP": conexao,
        "ListIdentity": comando == 0x0004,
        "RegisterSession": comando == 0x0065,
    }



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
    """
    Dissecação DNP3 offline (link + transporte + aplicação quando possível).
    Identifica função de aplicação (READ/SELECT/OPERATE/…), objeto CROB 12/1,
    inconsistência de comprimento e padrões de format-string/fuzzing.
    """
    if not payload or len(payload) < 10 or payload[0:2] != b"\x05\x64":
        return None

    length_field = payload[2]
    controle = payload[3]
    # Função de link nos 4 bits inferiores do controle (DIR/PRM/FCB/FCV + FUNC)
    func_link = controle & 0x0F
    dir_bit = bool(controle & 0x80)
    prm_bit = bool(controle & 0x40)

    dest = int.from_bytes(payload[4:6], "little") if len(payload) >= 8 else None
    src = int.from_bytes(payload[6:8], "little") if len(payload) >= 8 else None

    # Dados de usuário após cabeçalho de link (10 bytes: start..src + CRC 2)
    # Estrutura: 0-1 start, 2 len, 3 ctrl, 4-5 dest, 6-7 src, 8-9 HDR CRC
    user = payload[10:] if len(payload) > 10 else b""

    # Inconsistência: length do link diz quantos bytes após o campo length
    # (ctrl+dest+src+user+CRCs de dados). Heurística: se length=2 mas há muito payload.
    malformado = False
    motivo_malform = None
    expected_min = 5  # ctrl+dest+src no mínimo após length
    if length_field <= 2 and len(payload) > 20:
        malformado = True
        motivo_malform = (
            f"Campo length do link={length_field} incompatível com "
            f"payload TCP de {len(payload)} bytes"
        )

    # Format-string / fuzzing em ASCII
    format_string = False
    try:
        ascii_zone = bytes(b if 32 <= b < 127 else 32 for b in payload)
        if b"%25" in payload or b"%254x" in payload or payload.count(b"%") >= 4:
            format_string = True
        if b"%x%x" in payload or b"%n" in payload or b"%s%s" in payload:
            format_string = True
        if ascii_zone.count(b"%") >= 6:
            format_string = True
    except Exception:
        pass

    if format_string:
        malformado = True
        motivo_malform = (motivo_malform or "") + (
            "; padrão ASCII tipo format-string/fuzzing no payload"
            if motivo_malform
            else "Padrão ASCII tipo format-string/fuzzing no payload"
        )

    # Transporte (1 byte) + aplicação
    transport = user[0] if len(user) >= 1 else None
    app_ctrl = user[1] if len(user) >= 2 else None
    app_func = user[2] if len(user) >= 3 else None

    FUNCOES_APP = {
        0x00: "CONFIRM",
        0x01: "READ",
        0x02: "WRITE",
        0x03: "SELECT",
        0x04: "OPERATE",
        0x05: "DIRECT_OPERATE",
        0x06: "DIRECT_OPERATE_NR",
        0x07: "IMMED_FREEZE",
        0x08: "IMMED_FREEZE_NR",
        0x09: "FREEZE_CLEAR",
        0x0A: "FREEZE_CLEAR_NR",
        0x0B: "FREEZE_AT_TIME",
        0x0C: "FREEZE_AT_TIME_NR",
        0x0D: "COLD_RESTART",
        0x0E: "WARM_RESTART",
        0x0F: "INITIALIZE_DATA",
        0x10: "INITIALIZE_APPL",
        0x11: "START_APPL",
        0x12: "STOP_APPL",
        0x13: "SAVE_CONFIG",
        0x14: "ENABLE_UNSOLICITED",
        0x15: "DISABLE_UNSOLICITED",
        0x16: "ASSIGN_CLASS",
        0x17: "DELAY_MEASURE",
        0x18: "RECORD_CURRENT_TIME",
        0x19: "OPEN_FILE",
        0x1A: "CLOSE_FILE",
        0x1B: "DELETE_FILE",
        0x1D: "GET_FILE_INFO",
        0x1E: "AUTHENTICATE_FILE",
        0x1F: "ABORT_FILE",
        0x20: "ACTIVATE_CONFIG",
        0x21: "AUTHENTICATE_REQ",
        0x22: "AUTHENTICATE_RESP",
        0x81: "RESPONSE",
        0x82: "UNSOLICITED_RESPONSE",
    }
    nome_func = FUNCOES_APP.get(app_func, f"0x{app_func:02X}" if app_func is not None else None)

    # Object header (após app function): group, variation, qualifier
    group = user[3] if len(user) >= 4 else None
    variation = user[4] if len(user) >= 5 else None
    qualifier = user[5] if len(user) >= 6 else None
    crob = bool(group == 12 and variation == 1)

    controle_direto = nome_func in {
        "OPERATE",
        "DIRECT_OPERATE",
        "DIRECT_OPERATE_NR",
    }
    escrita = controle_direto or nome_func in {"WRITE", "SELECT"}

    FUNCOES_LINK = {
        0: "RESET_LINK",
        1: "RESET_USER",
        2: "TEST_LINK",
        3: "USER_DATA_CONFIRM",
        4: "USER_DATA_NO_CONFIRM",
        9: "REQUEST_STATUS",
        11: "LINK_STATUS",
    }

    return {
        "DNP3": True,
        "Controle": controle,
        "Função link": func_link,
        "Função link nome": FUNCOES_LINK.get(func_link, f"0x{func_link:02X}"),
        "DIR": dir_bit,
        "PRM": prm_bit,
        "Destino DNP3": dest,
        "Origem DNP3": src,
        "Length link": length_field,
        "Função app": app_func,
        "Função app nome": nome_func,
        "Grupo": group,
        "Variação": variation,
        "Qualificador": qualifier,
        "CROB": crob,
        "Controle direto": controle_direto,
        "Escrita": escrita,
        "Malformado": malformado,
        "Motivo malformado": motivo_malform,
        "Format string": format_string,
        "Tamanho payload": len(payload),
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


# ---------------------------------------------------------------------------
# Catálogo de alertas alinhado a plataformas OT de mercado
# (detectáveis offline a partir de PCAP)
# ---------------------------------------------------------------------------
CATALOGO_ALERTAS_OT = {
    "Host Scan": {
        "severidade": "Média",
        "familia": "reconhecimento",
        "descricao": "Varredura de muitos hosts (poucas portas por destino).",
    },
    "Port Scan": {
        "severidade": "Média",
        "familia": "reconhecimento",
        "descricao": "Varredura de muitas portas em poucos hosts.",
    },
    "Network Scanners Alert": {
        "severidade": "Média",
        "familia": "reconhecimento",
        "descricao": "Comportamento compatível com scanner de rede.",
    },
    "Network Scanners Communicating with Control and Process Devices": {
        "severidade": "Alta",
        "familia": "reconhecimento",
        "descricao": "Origem com perfil de scan atingindo portas OT/ICS.",
    },
    "Failed Login": {
        "severidade": "Baixa",
        "familia": "autenticacao",
        "descricao": "Falha de autenticação em protocolo legível.",
    },
    "Multiple Failed Login Attempts": {
        "severidade": "Alta",
        "familia": "autenticacao",
        "descricao": "Múltiplas falhas de login em janela curta.",
    },
    "Weak/Default Password": {
        "severidade": "Alta",
        "familia": "autenticacao",
        "descricao": "Uso de credencial padrão ou fraca observada.",
    },
    "External Plaintext Credentials Transmission": {
        "severidade": "Alta",
        "familia": "autenticacao",
        "descricao": "Credencial em claro na rede.",
    },
    "Executable File Transfer": {
        "severidade": "Alta",
        "familia": "arquivo",
        "descricao": "Transferência de executável/payload via HTTP.",
    },
    "Suspicious File Transfer": {
        "severidade": "Média",
        "familia": "arquivo",
        "descricao": "Transferência de arquivo suspeita (FTP/SMB/HTTP).",
    },
    "Configuration Download": {
        "severidade": "Alta",
        "familia": "programacao_ot",
        "descricao": "Download de configuração/lógica do controlador.",
    },
    "Configuration Upload": {
        "severidade": "Alta",
        "familia": "programacao_ot",
        "descricao": "Upload de configuração/lógica para o controlador.",
    },
    "Firmware Download": {
        "severidade": "Alta",
        "familia": "programacao_ot",
        "descricao": "Transferência candidata de firmware.",
    },
    "Mode Change": {
        "severidade": "Alta",
        "familia": "controle_ot",
        "descricao": "Mudança de modo do controlador (start/stop/control).",
    },
    "Controller Not in Run Mode": {
        "severidade": "Alta",
        "familia": "controle_ot",
        "descricao": "Comando de parada de CPU/PLC observado.",
    },
    "Memory Reset": {
        "severidade": "Alta",
        "familia": "controle_ot",
        "descricao": "Indício de reset de memória/controle agressivo.",
    },
    "Online Edit": {
        "severidade": "Alta",
        "familia": "programacao_ot",
        "descricao": "Edição/programação online (UMAS/engenharia).",
    },
    "OT Activity with External Entities": {
        "severidade": "Alta",
        "familia": "segmentacao",
        "descricao": "Comunicação OT com entidade externa/pública.",
    },
    "Internet Communication": {
        "severidade": "Média",
        "familia": "segmentacao",
        "descricao": "Comunicação com Internet a partir da captura.",
    },
    "Unsecured Protocols": {
        "severidade": "Média",
        "familia": "higiene",
        "descricao": "Protocolo inseguro (Telnet, FTP claro, HTTP clear em contexto sensível).",
    },
    "SMB Communication": {
        "severidade": "Baixa",
        "familia": "lateral",
        "descricao": "Tráfego SMB/CIFS observado.",
    },
    "Denial of Service": {
        "severidade": "Alta",
        "familia": "disponibilidade",
        "descricao": "Padrão compatível com saturamento/flood SYN.",
    },
    "New Asset": {
        "severidade": "Baixa",
        "familia": "inventario",
        "descricao": "Endpoint OT observado na captura (inventário da janela).",
    },
    "Suspicious Activity": {
        "severidade": "Média",
        "familia": "generico",
        "descricao": "Atividade anômala agregada.",
    },
    "Policy Violation": {
        "severidade": "Média",
        "familia": "politica",
        "descricao": "Violação de política derivada de heurística offline.",
    },

    # --- Nomes alinhados a Nozomi Guardian (SIGN:* / VI:*) ---
    "Bad ip reputation": {
        "severidade": "Alta",
        "familia": "intel",
        "descricao": "Nozomi SIGN:MALICIOUS-IP — IP com má reputação observado na captura (heurística offline limitada).",
        "nozomi_id": "SIGN:MALICIOUS-IP",
    },
    "Bad IP reputation (new node)": {
        "severidade": "Alta",
        "familia": "intel",
        "descricao": "Nozomi VI:NEW-NODE:MALICIOUS-IP — novo nó associado a IP de má reputação.",
        "nozomi_id": "VI:NEW-NODE:MALICIOUS-IP",
    },
    "Cleartext password": {
        "severidade": "Alta",
        "familia": "autenticacao",
        "descricao": "Nozomi SIGN:CLEARTEXT-PASSWORD — senha em claro na rede.",
        "nozomi_id": "SIGN:CLEARTEXT-PASSWORD",
    },
    "Illegal parameters request": {
        "severidade": "Média",
        "familia": "protocolo_ot",
        "descricao": "Nozomi SIGN:ILLEGAL-PARAMETERS — parâmetros ilegais em pedido OT.",
        "nozomi_id": "SIGN:ILLEGAL-PARAMETERS",
    },
    "Link RST request by Producer": {
        "severidade": "Média",
        "familia": "transporte",
        "descricao": "RST TCP observado de forma anómala (produtor encerra sessão).",
        "nozomi_id": None,
    },
    "Malformed Network/Transport layer": {
        "severidade": "Média",
        "familia": "protocolo",
        "descricao": "Nozomi SIGN:NETWORK-MALFORMED — pacote malformado em L3/L4.",
        "nozomi_id": "SIGN:NETWORK-MALFORMED",
    },
    "Malformed traffic": {
        "severidade": "Média",
        "familia": "protocolo",
        "descricao": "Nozomi SIGN:MALFORMED-TRAFFIC — tráfego L7 malformado (DPI).",
        "nozomi_id": "SIGN:MALFORMED-TRAFFIC",
    },
    "Missing or unknown device": {
        "severidade": "Baixa",
        "familia": "inventario",
        "descricao": "Dispositivo/endpoint não catalogado na base offline ou só visto nesta captura.",
        "nozomi_id": None,
    },
    "MITM attack": {
        "severidade": "Alta",
        "familia": "ameaca",
        "descricao": "Nozomi SIGN:MITM — possível ARP poisoning / MitM.",
        "nozomi_id": "SIGN:MITM",
    },
    "Multiple Access Denied events": {
        "severidade": "Média",
        "familia": "autenticacao",
        "descricao": "Nozomi SIGN:MULTIPLE-ACCESS-DENIED — múltiplos acessos negados.",
        "nozomi_id": "SIGN:MULTIPLE-ACCESS-DENIED",
    },
    "Multiple unsuccessful logins": {
        "severidade": "Alta",
        "familia": "autenticacao",
        "descricao": "Nozomi SIGN:MULTIPLE-UNSUCCESSFUL-LOGINS — várias falhas de login.",
        "nozomi_id": "SIGN:MULTIPLE-UNSUCCESSFUL-LOGINS",
    },
    "Network Scan": {
        "severidade": "Média",
        "familia": "reconhecimento",
        "descricao": "Nozomi SIGN:NETWORK-SCAN / INCIDENT:PORT-SCAN — varredura de rede.",
        "nozomi_id": "SIGN:NETWORK-SCAN",
    },
    "Packet rule match": {
        "severidade": "Média",
        "familia": "assinatura",
        "descricao": "Match de regra/heurística offline de pacote (equivalente a packet rule).",
        "nozomi_id": None,
    },
    "Process time issue": {
        "severidade": "Baixa",
        "familia": "processo",
        "descricao": "Inconsistência temporal suspeita nos timestamps da captura.",
        "nozomi_id": None,
    },
    "Protocol-based flood": {
        "severidade": "Alta",
        "familia": "disponibilidade",
        "descricao": "Flood baseado em protocolo (muitos pedidos OT/ICS).",
        "nozomi_id": None,
    },
    "Suspicious time value": {
        "severidade": "Baixa",
        "familia": "protocolo",
        "descricao": "Valor de tempo suspeito em protocolo industrial.",
        "nozomi_id": None,
    },
    "TCP flood": {
        "severidade": "Alta",
        "familia": "disponibilidade",
        "descricao": "Nozomi SIGN:TCP-FLOOD / SIGN:TCP-SYN-FLOOD — flood TCP/SYN.",
        "nozomi_id": "SIGN:TCP-SYN-FLOOD",
    },
    "Unsupported function request": {
        "severidade": "Média",
        "familia": "protocolo_ot",
        "descricao": "Nozomi SIGN:UNSUPPORTED-FUNC — função não suportada/desconhecida no protocolo OT.",
        "nozomi_id": "SIGN:UNSUPPORTED-FUNC",
    },
    "Weak password": {
        "severidade": "Alta",
        "familia": "autenticacao",
        "descricao": "Nozomi SIGN:PASSWORD:WEAK — senha fraca observada.",
        "nozomi_id": "SIGN:PASSWORD:WEAK",
    },

}



def gerar_alertas_catalogo_mercado(
    alertas,
    alertas_chaves,
    *,
    syn_destinos,
    syn_portas_por_origem,
    syn_hosts_por_origem,
    syn_para_ot,
    fluxos,
    eventos_ot,
    downloads_suspeitos,
    externos,
    eventos=None,
):
    """
    Gera alertas com nomes alinhados a plataformas OT de mercado,
    somente quando houver evidência derivável do PCAP (offline).
    """
    eventos = eventos or []

    def _emit(tipo, origem="-", destino="-", porta="-", detalhe="", sev=None, usuario=None):
        meta = CATALOGO_ALERTAS_OT.get(tipo, {})
        det = redigir_senha_em_texto(detalhe or meta.get("descricao", ""))
        if usuario and str(usuario) not in ("", "-", "Não identificado") and "Usuário:" not in det:
            det = redigir_senha_em_texto(f"{det} Usuário: {usuario}.")
        row = {
            "Severidade": sev or meta.get("severidade", "Média"),
            "Tipo": tipo,
            "Origem": origem or "-",
            "Destino": destino or "-",
            "Porta destino": porta if porta not in (None, "") else "-",
            "Detalhe": det,
            "Família": meta.get("familia", "catalogo"),
        }
        if usuario and str(usuario) not in ("", "-"):
            row["Usuário identificado"] = str(usuario)
        adicionar_alerta(alertas, alertas_chaves, row)

    # --- Host Scan / Port Scan / Network Scanners ---
    for origem, destinos_unicos in syn_destinos.items():
        n_pairs = len(destinos_unicos)
        n_hosts = len(syn_hosts_por_origem.get(origem, set()))
        n_portas = len(syn_portas_por_origem.get(origem, set()))
        n_ot = len(syn_para_ot.get(origem, set()))

        if n_hosts >= 20 and n_portas <= 15:
            _emit(
                "Host Scan",
                origem=origem,
                detalhe=f"SYN sem ACK para {n_hosts} hosts únicos ({n_pairs} pares host:porta).",
                sev="Alta" if n_hosts >= 100 else "Média",
            )
            _emit(
                "Network Scanners Alert",
                origem=origem,
                detalhe=f"Perfil de scanner: {n_hosts} hosts, {n_portas} portas distintas.",
            )
        if n_portas >= 20 and n_hosts <= 15:
            _emit(
                "Port Scan",
                origem=origem,
                detalhe=f"SYN sem ACK para {n_portas} portas distintas em {n_hosts} host(s).",
                sev="Alta" if n_portas >= 100 else "Média",
            )
            _emit(
                "Network Scanners Alert",
                origem=origem,
                detalhe=f"Perfil de port scan: {n_portas} portas, {n_hosts} hosts.",
            )
        if n_ot >= 3 or (n_ot >= 1 and (n_hosts >= 10 or n_portas >= 10)):
            _emit(
                "Network Scanners Communicating with Control and Process Devices",
                origem=origem,
                detalhe=(
                    f"Origem com varredura atingiu {n_ot} alvo(s) em porta(s) OT/ICS "
                    f"(ex.: {', '.join(list(syn_para_ot.get(origem, set()))[:5])})."
                ),
                sev="Alta",
            )
        # SYN flood / DoS heurística
        if n_pairs >= 500:
            _emit(
                "Denial of Service",
                origem=origem,
                detalhe=f"Volume muito alto de SYN sem ACK ({n_pairs} alvos host:porta) — possível flood.",
                sev="Alta",
            )

    # --- OT external / Internet ---
    for ip, dados in (externos or {}).items():
        servicos = dados.get("Serviços") or set()
        serv_txt = ", ".join(sorted(list(servicos))[:8]) if servicos else "-"
        _emit(
            "Internet Communication",
            origem=ip,
            detalhe=f"IP público observado; fluxos={dados.get('Fluxos', 0)}; serviços={serv_txt}.",
            sev="Média",
        )

    # --- Unsecured protocols + SMB from flows ---
    portas_inseguras = {21: "FTP", 23: "Telnet", 69: "TFTP", 161: "SNMP", 512: "rexec", 513: "rlogin", 514: "rsh"}
    for chave, dados in fluxos.items():
        transporte, ip_a, porta_a, ip_b, porta_b = chave
        for ip_local, ip_rem, porta in (
            (ip_a, ip_b, porta_b),
            (ip_b, ip_a, porta_a),
        ):
            if porta is None:
                continue
            p = int(porta)
            if p in portas_inseguras:
                _emit(
                    "Unsecured Protocols",
                    origem=ip_local,
                    destino=ip_rem,
                    porta=p,
                    detalhe=f"Protocolo inseguro {portas_inseguras[p]} (porta {p}) entre {ip_local} e {ip_rem}.",
                )
            if p in (445, 139):
                _emit(
                    "SMB Communication",
                    origem=ip_local,
                    destino=ip_rem,
                    porta=p,
                    detalhe=f"Tráfego SMB/CIFS (porta {p}); pacotes={dados.get('Pacotes', 0)}.",
                )

    # --- Downloads / executable transfer ---
    for item in downloads_suspeitos or []:
        _emit(
            "Executable File Transfer",
            origem=item.get("Servidor", "-"),
            destino=item.get("Cliente", "-"),
            porta=item.get("Porta servidor", "-"),
            detalhe=(
                f"{item.get('Tipo de arquivo', 'arquivo')}; SHA-256 {item.get('SHA-256', '-')}; "
                f"{item.get('Motivos', '')}"
            ),
            sev=item.get("Severidade") or "Alta",
        )
        _emit(
            "Suspicious File Transfer",
            origem=item.get("Servidor", "-"),
            destino=item.get("Cliente", "-"),
            detalhe=f"Transferência HTTP de payload/executável observada.",
        )

    # --- Eventos OT → alertas de mercado ---
    for ev in eventos_ot or []:
        cat = str(ev.get("Categoria") or "").lower()
        clas = str(ev.get("Classificação") or "").lower()
        op = str(ev.get("Operação") or "").lower()
        det = str(ev.get("Detalhe") or "")
        blob = f"{cat} {clas} {op} {det}".lower()
        o = ev.get("Origem", "-")
        d = ev.get("Destino", "-")
        porta = ev.get("Porta destino", "-")

        if "plc stop" in blob or "0x29" in blob or "controller not" in blob:
            _emit("Controller Not in Run Mode", origem=o, destino=d, porta=porta, detalhe=det or op)
            _emit("Mode Change", origem=o, destino=d, porta=porta, detalhe=det or op)
        if "pi-service" in blob or "0x28" in blob or "plc start" in blob:
            _emit("Mode Change", origem=o, destino=d, porta=porta, detalhe=det or op)
        if "upload" in blob and ("s7" in blob or "bloco" in blob or "umas" in blob):
            _emit("Configuration Upload", origem=o, destino=d, porta=porta, detalhe=det or op)
            if "umas" in blob or "unity" in blob:
                _emit("Online Edit", origem=o, destino=d, porta=porta, detalhe=det or op)
        if "download" in blob and ("s7" in blob or "bloco" in blob or "umas" in blob):
            _emit("Configuration Download", origem=o, destino=d, porta=porta, detalhe=det or op)
        if "firmware" in blob:
            _emit("Firmware Download", origem=o, destino=d, porta=porta, detalhe=det or op)
        if "memory reset" in blob or "reset" in clas and "cip" in blob:
            _emit("Memory Reset", origem=o, destino=d, porta=porta, detalhe=det or op)
        if "umas" in blob or "unity pro" in blob:
            _emit("Online Edit", origem=o, destino=d, porta=porta, detalhe=det or "Schneider UMAS / engenharia")
            _emit("Configuration Upload", origem=o, destino=d, porta=porta, detalhe=det or op)

    # --- Credenciais / login: usuário visível; senha NUNCA ---
    falhas_login = Counter()
    for ev in eventos or []:
        cat = str(ev.get("Categoria") or "").lower()
        det_raw = str(ev.get("Detalhe") or "")
        det = det_raw.lower()
        acao = str(ev.get("Ação") or "").lower()
        blob = f"{cat} {det} {acao}"
        o = ev.get("Origem", "-")
        d = ev.get("Destino", "-")
        user = str(ev.get("Usuário identificado") or "Não identificado")
        det_safe = redigir_senha_em_texto(det_raw)
        if "credencial" in blob or "password" in blob or "senha" in blob or "pass " in blob:
            user_l = user.lower()
            if user_l in {
                "admin", "root", "administrator", "guest", "user", "default", "test", "operator"
            } or any(x in user_l for x in ("admin", "default")):
                _emit(
                    "Weak/Default Password",
                    origem=o,
                    destino=d,
                    usuario=user,
                    detalhe=(det_safe or "Credencial em claro com usuário de risco/padrão.")
                    + " A senha não é exibida.",
                )
                _emit(
                    "Weak password",
                    origem=o,
                    destino=d,
                    usuario=user,
                    detalhe=f"Usuário de risco/padrão: {user}. Senha não exibida.",
                )
            _emit(
                "External Plaintext Credentials Transmission",
                origem=o,
                destino=d,
                usuario=user,
                detalhe=(det_safe or "Credencial em protocolo legível.") + " A senha não é exibida.",
            )
            _emit(
                "Cleartext password",
                origem=o,
                destino=d,
                usuario=user,
                detalhe=f"Senha em claro detectada (valor omitido).",
            )
        if "login" in blob and any(x in blob for x in ("fail", "falha", "invalid", "denied", "incorrect")):
            falhas_login[o] += 1
            _emit(
                "Failed Login",
                origem=o,
                destino=d,
                usuario=user,
                detalhe=det_safe or "Falha de login.",
            )
        if "telnet" in blob or ("ftp" in blob and "pass" in blob):
            _emit(
                "Unsecured Protocols",
                origem=o,
                destino=d,
                usuario=user,
                detalhe=det_safe or "Protocolo com autenticação em claro.",
            )

    for origem, n in falhas_login.items():
        if n >= 3:
            _emit(
                "Multiple Failed Login Attempts",
                origem=origem,
                detalhe=f"{n} falhas de login observadas para a origem na captura.",
                sev="Alta",
            )

    # --- New Asset: endpoints OT únicos ---
    ips_ot = set()
    for ev in eventos_ot or []:
        for k in ("Origem", "Destino"):
            ip = ev.get(k)
            if ip and ip != "-":
                ips_ot.add(ip)
    for ip in sorted(ips_ot)[:50]:
        _emit(
            "New Asset",
            origem=ip,
            detalhe=f"Endpoint OT observado nesta captura (inventário offline da janela): {ip}.",
            sev="Baixa",
        )
        _emit(
            "Missing or unknown device",
            origem=ip,
            detalhe=f"Dispositivo OT visto só nesta captura (sem inventário histórico offline): {ip}.",
            sev="Baixa",
        )

    # --- Aliases Nozomi para as mesmas evidências ---
    # Network Scan (nome Nozomi)
    for origem, destinos_unicos in syn_destinos.items():
        n_hosts = len(syn_hosts_por_origem.get(origem, set()))
        n_portas = len(syn_portas_por_origem.get(origem, set()))
        n_pairs = len(destinos_unicos)
        if n_hosts >= 20 or n_portas >= 20:
            _emit(
                "Network Scan",
                origem=origem,
                detalhe=f"Nozomi-equivalent SIGN:NETWORK-SCAN: {n_hosts} hosts, {n_portas} portas, {n_pairs} pares SYN.",
                sev="Alta" if max(n_hosts, n_portas) >= 100 else "Média",
            )
        if n_pairs >= 200:
            _emit(
                "TCP flood",
                origem=origem,
                detalhe=f"Nozomi-equivalent SIGN:TCP-SYN-FLOOD: {n_pairs} SYN sem ACK.",
                sev="Alta",
            )
            _emit(
                "Protocol-based flood",
                origem=origem,
                detalhe=f"Volume elevado de tentativas de conexão ({n_pairs}).",
                sev="Alta",
            )

    # Cleartext / weak password (aliases Nozomi)
    for ev in eventos or []:
        cat = str(ev.get("Categoria") or "").lower()
        det = str(ev.get("Detalhe") or "").lower()
        blob = f"{cat} {det}"
        o = ev.get("Origem", "-")
        d = ev.get("Destino", "-")
        # Cleartext/Weak já tratados no bloco de credenciais (usuário visível, senha omitida).

    for origem, n in falhas_login.items():
        if n >= 3:
            _emit(
                "Multiple unsuccessful logins",
                origem=origem,
                detalhe=f"Nozomi SIGN:MULTIPLE-UNSUCCESSFUL-LOGINS equivalent: {n} falhas.",
                sev="Alta",
            )
            _emit(
                "Multiple Access Denied events",
                origem=origem,
                detalhe=f"{n} eventos de acesso negado/falha de login.",
            )

    # Unsupported function / illegal parameters from OT events
    for ev in eventos_ot or []:
        op = str(ev.get("Operação") or "")
        det = str(ev.get("Detalhe") or "")
        clas = str(ev.get("Classificação") or "")
        blob = f"{op} {det} {clas}".lower()
        o = ev.get("Origem", "-")
        d = ev.get("Destino", "-")
        porta = ev.get("Porta destino", "-")
        # Função S7/Modbus desconhecida
        if "função 0x" in blob or "fc " in blob or "desconhecido" in blob or "unknown" in blob:
            _emit(
                "Unsupported function request",
                origem=o,
                destino=d,
                porta=porta,
                detalhe=det or op or "Função OT não mapeada na base offline.",
            )
        # Modbus exception / illegal
        if "exceção" in blob or "exception" in blob or "illegal" in blob:
            _emit(
                "Illegal parameters request",
                origem=o,
                destino=d,
                porta=porta,
                detalhe=det or op,
            )
        # Malformed markers from existing parsers
        if "malformado" in blob or "malformed" in blob:
            _emit(
                "Malformed traffic",
                origem=o,
                destino=d,
                porta=porta,
                detalhe=det or op,
            )
            _emit(
                "Malformed Network/Transport layer",
                origem=o,
                destino=d,
                detalhe=det or op,
            )

    # Packet rule match: qualquer alerta OT crítico já é um "match" heurístico
    if any(
        str(ev.get("Categoria") or "").lower() in (
            "alteração ot candidata",
            "transferência ot candidata",
            "anomalia ot",
        )
        for ev in (eventos_ot or [])
    ):
        _emit(
            "Packet rule match",
            detalhe="Heurística offline de protocolo OT correspondente a operação sensível (write/stop/upload).",
            sev="Média",
        )

    return alertas



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



def classificar_protocolo_ot_info(porta_origem, porta_destino, payload=b"", transporte=None, ethertype=None):
    """Sempre retorna (nome|None, confiança|None)."""
    nome = classificar_protocolo_ot(
        porta_origem, porta_destino, payload, transporte, ethertype, retornar_confianca=False
    )
    if not nome:
        return None, None
    # Confiança por origem da decisão
    if ethertype is not None and ethertype in ETHERTYPES_OT:
        return nome, CONFIANCA_ALTA
    if payload:
        # Se assinatura específica bateu, alta
        if any([
            analisar_s7_payload(payload),
            analisar_modbus_payload(payload),
            analisar_modbus_rtu_tcp(payload) if "analisar_modbus_rtu_tcp" in globals() else None,
            analisar_dnp3_payload(payload),
            analisar_enip_payload(payload),
            analisar_opcua_payload(payload),
            analisar_iec104_payload(payload),
            analisar_profinet_payload(payload, ethertype),
            analisar_ethercat_payload(payload, ethertype),
            analisar_goose_payload(payload, ethertype),
            analisar_sv_payload(payload, ethertype),
            analisar_mqtt_payload(payload),
        ]):
            return nome, CONFIANCA_ALTA
        if _mms_mod and _mms_mod(payload):
            return nome, CONFIANCA_ALTA
    portas = (porta_destino, porta_origem)
    for p in portas:
        if p in (502, 102, 2404, 44818, 4840, 20000, 47808, 2222):
            return nome, CONFIANCA_MEDIA
        if p in PORTAS_OT:
            return nome, CONFIANCA_BAIXA
    return nome, CONFIANCA_MEDIA


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
    fluxos_ot_meta=None,
    tcp_buffers=None,
):
    """Detecta protocolo/família OT e operações relevantes com evidência do payload (offline)."""
    transporte, _, _, _ = transporte_pacote(pacote)
    payload = payload_limitado(pacote)
    et = ethertype_pacote(pacote)
    # L2 sem IP: usa MACs para não perder PROFINET/EtherCAT/GOOSE
    if not origem or not destino:
        mac_o, mac_d = macs_pacote(pacote)
        origem = origem or (f"mac:{mac_o}" if mac_o else "-")
        destino = destino or (f"mac:{mac_d}" if mac_d else "-")

    # Reassemblagem TCP simples (últimos bytes do fluxo) para S7/OPC UA/ADS/MMS
    payload_analise = payload
    if transporte == "TCP" and payload and tcp_buffers is not None and fluxo:
        buf = tcp_buffers.get(fluxo, b"")
        buf = (buf + payload)[-65536:]  # mantém até 64 KiB
        tcp_buffers[fluxo] = buf
        payload_analise = buf[-max(LIMITE_PAYLOAD, 4096):]

    protocolo_ot, conf = classificar_protocolo_ot_info(
        porta_origem,
        porta_destino,
        payload_analise,
        transporte,
        ethertype=et,
    )
    if protocolo_ot and fluxos_ot_meta is not None and fluxo:
        prev = fluxos_ot_meta.get(fluxo) or {}
        fluxos_ot_meta[fluxo] = {
            "Protocolo": protocolo_ot,
            "Confiança": melhor_confianca(prev.get("Confiança"), conf),
            "Assinatura": prev.get("Assinatura") or (conf == CONFIANCA_ALTA),
            "Portas": list({p for p in (porta_origem, porta_destino) if p is not None}),
        }

    if not protocolo_ot:
        return

    payload = payload_analise
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
            funcao = s7.get("Função")
            nome_f = s7.get("Nome função") or (
                f"Função S7 0x{funcao:02X}" if funcao is not None else "Mensagem S7comm"
            )
            operacao = nome_f
            ros = s7.get("ROSCTR")
            ros_nome = s7.get("ROSCTR nome")
            ros_txt = ros_nome or (f"0x{ros:02X}" if isinstance(ros, int) else "-")
            detalhe = (
                f"TPKT/COTP/{s7.get('Variante', 'S7')}; ROSCTR={ros_txt}; "
                f"função={nome_f}"
                + (f" (0x{funcao:02X})" if funcao is not None else "")
                + f"; parâmetro={s7.get('Tamanho parâmetro', 0)} B; "
                f"dados={s7.get('Tamanho dados', 0)} B."
            )
            if s7.get("Controle PLC"):
                if funcao == 0x29:
                    categoria = "Alteração OT candidata"
                    classificacao = "PLC Stop (S7 0x29) — parada de CPU"
                else:
                    categoria = "Alteração OT candidata"
                    classificacao = "PI-Service / PLC Start (S7 0x28)"
            elif s7.get("Transferência"):
                categoria = "Transferência OT candidata"
                if funcao in (0x1D, 0x1E, 0x1F):
                    classificacao = f"Upload de bloco S7 ({nome_f})"
                else:
                    classificacao = f"Download de bloco S7 ({nome_f})"
            elif s7.get("Escrita"):
                categoria = "Alteração OT candidata"
                classificacao = "Write Var S7 (escrita de variável)"
            elif funcao == 0x04:
                categoria = "Leitura OT"
                classificacao = "Read Var S7"
            elif funcao == 0xF0:
                categoria = "Sessão OT"
                classificacao = "Setup communication S7"
            elif not s7.get("S7"):
                operacao = s7.get("Nome função") or "COTP"
                detalhe = "Frame ISO-TSAP/COTP sem PDU S7comm."
                categoria = "Sessão OT"
                classificacao = "COTP/ISO-TSAP"

    elif protocolo_ot == "Siemens S7comm-plus":
        s7 = analisar_s7_payload(payload)
        operacao = (s7 or {}).get("Nome função") or "S7comm-plus"
        detalhe = f"Variante S7comm-plus (0x72); {operacao}."
        categoria = "Comunicação OT"
        classificacao = "S7comm-plus"

    elif protocolo_ot == "IEC 61850 MMS":
        operacao = "MMS"
        detalhe = "IEC 61850 MMS sobre ISO-TSAP (heurística BER; não é S7)."
        categoria = "Comunicação OT"
        classificacao = "IEC 61850 MMS"

    elif protocolo_ot in ("Modbus TCP", "Schneider UMAS / Unity Pro"):
        mb = analisar_modbus_payload(payload)
        if mb and mb.get("UMAS"):
            umas_fn = mb.get("UMAS função")
            operacao = mb.get("Nome função") or "UMAS"
            detalhe = (
                f"Schneider UMAS (Modbus FC 0x5A) sobre TCP/502; "
                f"subfunção={info_umas(umas_fn)}; session={mb.get('UMAS session')}; "
                f"PDU={mb.get('Tamanho')} B. Programação/upload Unity Pro ou Control Expert."
            )
            categoria = "Transferência OT candidata"
            classificacao = "Schneider UMAS — programação/engenharia PLC"
            fabricante = "Schneider Electric"
            familia = "Modicon / Unity Pro"
        elif mb:
            if mb.get("Exceção"):
                operacao = f"Exceção Modbus FC {mb['Função']}"
                detalhe = f"MBAP; exceção FC={mb['Função']}; código={mb.get('Código exceção')}."
                categoria = "Anomalia OT"
                classificacao = "Modbus exception response"
            elif mb.get("Identificação dispositivo"):
                operacao = "Modbus FC 43 (identificação)"
                detalhe = "Leitura de identificação do dispositivo (FC 43)."
                classificacao = "Inventário Modbus"
            else:
                fc = mb["Função"]
                nome_mb = mb.get("Nome função") or NOMES_FUNCAO_MODBUS.get(fc, f"FC {fc}")
                operacao = f"Modbus {nome_mb}"
                detalhe = f"MBAP válido; {nome_mb} (FC {fc}); PDU={mb['Tamanho']} B."
                if mb["Escrita"]:
                    categoria = "Alteração OT candidata"
                    classificacao = f"Escrita Modbus ({nome_mb})"
                    detalhe += " A operação de escrita deve ser validada no contexto operacional."
                elif fc in (1, 2, 3, 4):
                    categoria = "Leitura OT"
                    classificacao = f"Leitura Modbus ({nome_mb})"

    elif protocolo_ot == "EtherNet/IP / CIP":
        enip = analisar_enip_payload(payload)
        if enip:
            cmd_n = enip.get("Comando nome") or f"0x{enip['Comando']:04X}"
            svc_n = enip.get("Serviço CIP nome")
            if svc_n:
                operacao = f"CIP {svc_n}"
            else:
                operacao = f"ENIP {cmd_n}"
            partes = [
                f"cmd={cmd_n}",
                f"status={enip.get('Status nome')}",
                f"session=0x{enip.get('Session', 0):08X}",
            ]
            if svc_n:
                partes.append(f"CIP={svc_n}")
            detalhe = "EtherNet/IP; " + "; ".join(partes) + "."
            if enip.get("ListIdentity"):
                categoria = "Descoberta OT"
                classificacao = "ListIdentity (inventário CIP)"
            elif enip.get("RegisterSession"):
                categoria = "Sessão OT"
                classificacao = "RegisterSession"
            elif enip.get("Conexão CIP"):
                categoria = "Conexão CIP"
                classificacao = svc_n or "Forward_Open/Close"
            elif enip.get("Escrita"):
                categoria = "Alteração OT candidata"
                classificacao = "Escrita CIP candidata"

    elif protocolo_ot == "IEC 60870-5-104":
        iec = analisar_iec104_payload(payload)
        if iec:
            operacao = "APCI/ASDU IEC-104"
            detalhe = f"IEC-104; tipo APCI={iec['Tipo APCI']}; ASDU={iec['ASDU']}."

    elif protocolo_ot == "DNP3":
        dnp = analisar_dnp3_payload(payload)
        if dnp:
            nome = dnp.get("Função app nome") or "link/application"
            operacao = f"DNP3 {nome}"
            partes = [
                f"link={dnp.get('Função link nome')}",
                f"controle=0x{dnp['Controle']:02X}",
            ]
            if dnp.get("Origem DNP3") is not None:
                partes.append(f"master/src={dnp['Origem DNP3']}")
            if dnp.get("Destino DNP3") is not None:
                partes.append(f"outstation/dst={dnp['Destino DNP3']}")
            if dnp.get("Função app nome"):
                partes.append(f"app={dnp['Função app nome']}")
            if dnp.get("Grupo") is not None:
                partes.append(f"obj={dnp['Grupo']}/{dnp.get('Variação')}")
            if dnp.get("CROB"):
                partes.append("CROB(12/1)")
            if dnp.get("Malformado"):
                partes.append(f"MALFORMADO: {dnp.get('Motivo malformado')}")
            detalhe = "DNP3; " + "; ".join(str(p) for p in partes) + "."
            if dnp.get("Controle direto") or dnp.get("CROB"):
                categoria = "Alteração OT candidata"
                classificacao = (
                    "OPERATE/CROB DNP3 sem validação de resposta na captura"
                    if dnp.get("Controle direto")
                    else "Objeto CROB DNP3"
                )
            elif dnp.get("Malformado") or dnp.get("Format string"):
                categoria = "Anomalia OT"
                classificacao = "Payload DNP3 malformado ou padrão de fuzzing"
            elif dnp.get("Função app nome") == "SELECT":
                categoria = "Preparação de controle OT"
                classificacao = "SELECT DNP3 observado"
            elif dnp.get("Função app nome") == "READ":
                categoria = "Leitura OT"
                classificacao = "READ DNP3"

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

    elif protocolo_ot in ("Beckhoff ADS", "Beckhoff ADS (candidato)"):
        ads = analisar_ads_payload(payload)
        if ads:
            operacao = "ADS/AMS"
            detalhe = ads["Evidência"] + "."

    elif protocolo_ot == "PROFINET" or (protocolo_ot or "").startswith("PROFINET"):
        pn = analisar_profinet_payload(payload, ethertype_pacote(pacote))
        if pn:
            operacao = f"PROFINET {pn.get('Tipo')}"
            detalhe = f"FrameID=0x{pn.get('FrameID', 0):04X}; tipo={pn.get('Tipo')}."
            if pn.get("Tipo", "").startswith("DCP"):
                categoria = "Descoberta / configuração OT"
                classificacao = "PROFINET DCP"
            elif pn.get("Cyclic"):
                categoria = "I/O cíclico OT"
                classificacao = "PROFINET RT"
        else:
            operacao = "PROFINET"
            detalhe = "Tráfego PROFINET identificado (EtherType/porta)."

    elif protocolo_ot in ("EtherCAT", "EtherCAT (UDP)"):
        ec = analisar_ethercat_payload(payload, ethertype_pacote(pacote))
        if ec:
            operacao = f"EtherCAT {ec.get('Cmd nome') or ''}".strip()
            detalhe = f"type={ec.get('Type')}; cmd={ec.get('Cmd nome')}; len={ec.get('Length')}."
            categoria = "I/O cíclico OT"
            classificacao = "EtherCAT"
        else:
            operacao = "EtherCAT"
            detalhe = "Tráfego EtherCAT identificado."

    elif protocolo_ot == "IEC 61850 GOOSE":
        g = analisar_goose_payload(payload, ethertype_pacote(pacote))
        if g:
            operacao = "GOOSE"
            partes = [f"APPID=0x{g.get('APPID', 0):04X}"]
            if g.get("stNum") is not None:
                partes.append(f"stNum={g['stNum']}")
            if g.get("sqNum") is not None:
                partes.append(f"sqNum={g['sqNum']}")
            if g.get("goID"):
                partes.append(f"goID={g['goID']}")
            if g.get("datSet"):
                partes.append(f"datSet={g['datSet']}")
            if g.get("Simulation"):
                partes.append("simulation=true")
            detalhe = "IEC 61850 GOOSE; " + "; ".join(partes) + "."
        else:
            operacao = "GOOSE"
            detalhe = "IEC 61850 GOOSE (EtherType 0x88B8)."
        categoria = "Evento IEC 61850"
        classificacao = "GOOSE"

    elif protocolo_ot == "IEC 61850 SV":
        sv = analisar_sv_payload(payload, ethertype_pacote(pacote))
        if sv:
            operacao = "Sampled Values"
            partes = [f"APPID=0x{sv.get('APPID', 0):04X}"]
            if sv.get("smpCnt") is not None:
                partes.append(f"smpCnt={sv['smpCnt']}")
            if sv.get("svID"):
                partes.append(f"svID={sv['svID']}")
            detalhe = "IEC 61850 SV; " + "; ".join(partes) + "."
        else:
            operacao = "Sampled Values"
            detalhe = "IEC 61850 SV (EtherType 0x88BA)."
        categoria = "Amostras IEC 61850"
        classificacao = "SV"

    elif protocolo_ot in ("MQTT", "MQTT (TLS)"):
        mq = analisar_mqtt_payload(payload) if payload else None
        if protocolo_ot == "MQTT (TLS)":
            operacao = "MQTT TLS"
            detalhe = "Canal MQTT cifrado (conteúdo não inspecionado)."
            classificacao = "Identificado sem dissecação (cifrado)"
        elif mq:
            operacao = f"MQTT {mq.get('Tipo')}"
            detalhe = f"tipo={mq.get('Tipo')}" + ("; Sparkplug B" if mq.get("Sparkplug") else "")
            if mq.get("Sparkplug"):
                classificacao = "MQTT Sparkplug"
        else:
            operacao = "MQTT"
            detalhe = "Tráfego MQTT por porta/assinatura."

    elif protocolo_ot == "HART-IP":
        h = analisar_hartip_payload(payload) if payload else None
        operacao = "HART-IP"
        detalhe = f"ver={h.get('Versão') if h else '-'}; msg={h.get('MessageType') if h else '-'}."

    elif protocolo_ot == "Modbus RTU over TCP":
        rtu = analisar_modbus_rtu_tcp(payload)
        if rtu:
            fc = rtu.get("Função")
            nome_mb = NOMES_FUNCAO_MODBUS.get(fc, f"FC {fc}")
            operacao = f"Modbus RTU {nome_mb}"
            detalhe = f"slave={rtu.get('Slave')}; {nome_mb} (FC {fc}, RTU encapsulado)."
            if rtu.get("Escrita"):
                categoria = "Alteração OT candidata"
                classificacao = f"Escrita Modbus RTU ({nome_mb})"
            elif fc in (1, 2, 3, 4):
                categoria = "Leitura OT"
                classificacao = f"Leitura Modbus RTU ({nome_mb})"

    elif protocolo_ot in ("CODESYS", "CODESYS Gateway"):
        operacao = "CODESYS"
        detalhe = "Tráfego CODESYS (heurística/porta)."

    elif protocolo_ot == "IEEE C37.118":
        c = analisar_c37118_payload(payload) if payload else None
        operacao = "C37.118"
        detalhe = f"frame_type={c.get('FrameType') if c else '-'}."

    elif protocolo_ot == "KNXnet/IP":
        k = analisar_knx_payload(payload) if payload else None
        operacao = "KNXnet/IP"
        detalhe = f"service=0x{k.get('Service'):04X}." if k else "KNXnet/IP."

    elif protocolo_ot in ("CC-Link IE Field Basic", "CC-Link / SLMP search"):
        operacao = protocolo_ot
        detalhe = "CC-Link IE / SLMP por porta conhecida (UDP)."

    elif protocolo_ot == "OPC UA (TLS)":
        operacao = "OPC UA TLS"
        detalhe = "OPC UA em canal TLS (4843) — conteúdo não inspecionado."
        classificacao = "Identificado sem dissecação (cifrado)"

    elif protocolo_ot == "OPC UA":
        opc = analisar_opcua_payload(payload)
        if opc:
            operacao = f"OPC UA {opc['Mensagem']}"
            detalhe = f"Mensagem OPC UA TCP {opc['Mensagem']} identificada (sem decifração de sessão segura)."
            classificacao = "Identificado (hello/msg); sessão segura não decifrada"
        else:
            operacao = "OPC UA"
            detalhe = "Tráfego porta 4840 sem cabeçalho HEL/MSG legível (possível sessão já cifrada)."
            classificacao = "Identificado sem dissecação de conteúdo"

    elif protocolo_ot in ("Mitsubishi MC / SLMP", "Mitsubishi MC / SLMP (candidato)"):
        mits = analisar_mitsubishi_payload(payload)
        if mits:
            operacao = "MC/SLMP"
            detalhe = f"Mitsubishi MC/SLMP; subheader=0x{mits['Subheader']:04X}."
        else:
            operacao = "MC/SLMP"
            detalhe = "Porta Mitsubishi/SLMP; payload sem assinatura 3E/4E completa."

    elif protocolo_ot in ("Omron FINS", "Omron FINS (candidato)"):
        fins = analisar_fins_payload(payload)
        if fins:
            operacao = "FINS"
            detalhe = f"Omron FINS; comando={fins['Comando']}."

    elif protocolo_ot == "EtherNet/IP I/O (UDP)":
        operacao = "EtherNet/IP I/O"
        detalhe = "UDP 2222 — mensagens implícitas CIP (I/O)."
        categoria = "I/O cíclico OT"
        classificacao = "EtherNet/IP implicit"

    elif protocolo_ot == "LLDP (topologia)":
        operacao = "LLDP"
        detalhe = "LLDP (descoberta de topologia L2)."
        categoria = "Descoberta de rede"
        classificacao = "LLDP"

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


def gerar_ativos_ot(fluxos, fluxos_ot_meta=None):
    """
    Resume ativos OT com a melhor confiança por fluxo.
    Porta ambígua sem assinatura não cria ativo OT (reduz falso positivo).
    """
    fluxos_ot_meta = fluxos_ot_meta or {}
    ativos = defaultdict(lambda: {
        "Protocolos": set(),
        "Portas": set(),
        "Peers": set(),
        "Bytes": 0,
        "Fluxos": 0,
        "Confiança": CONFIANCA_BAIXA,
    })

    for chave, dados in fluxos.items():
        try:
            transporte, ip_a, porta_a, ip_b, porta_b = chave
        except Exception:
            continue
        meta = fluxos_ot_meta.get(chave) or {}
        conf = meta.get("Confiança")
        proto_meta = meta.get("Protocolo")
        assinatura = bool(meta.get("Assinatura"))
        portas_ot = [p for p in (porta_a, porta_b) if p in PORTAS_OT]

        if not portas_ot and not proto_meta:
            continue

        # Só porta ambígua, sem assinatura → ignora
        if conf == CONFIANCA_BAIXA and not assinatura and not proto_meta:
            continue
        if conf == CONFIANCA_BAIXA and not assinatura:
            # portas clássicas ainda podem entrar como media implícita
            if not any(p in (502, 102, 2404, 44818, 4840, 20000, 47808, 2222) for p in portas_ot):
                continue

        protocolo = proto_meta or ", ".join(sorted({PORTAS_OT[p] for p in portas_ot}))
        conf_final = conf or (CONFIANCA_MEDIA if any(
            p in (502, 102, 2404, 44818, 4840, 20000, 47808, 2222) for p in portas_ot
        ) else CONFIANCA_BAIXA)

        for ip, peer in ((ip_a, ip_b), (ip_b, ip_a)):
            if not ip or ip == "-":
                continue
            ativos[ip]["Protocolos"].add(protocolo)
            ativos[ip]["Portas"].update(portas_ot)
            ativos[ip]["Peers"].add(peer)
            ativos[ip]["Bytes"] += dados.get("Bytes", 0)
            ativos[ip]["Fluxos"] += 1
            ativos[ip]["Confiança"] = melhor_confianca(ativos[ip]["Confiança"], conf_final)

    linhas = []
    for ip, dados in ativos.items():
        linhas.append({
            "Ativo": ip,
            "Protocolos OT": ", ".join(sorted(dados["Protocolos"])),
            "Portas OT": ", ".join(str(x) for x in sorted(dados["Portas"])) if dados["Portas"] else "-",
            "Confiança": dados["Confiança"],
            "Peers": len(dados["Peers"]),
            "Fluxos": dados["Fluxos"],
            "Volume": bytes_legivel(dados["Bytes"]),
        })

    if not linhas:
        return pd.DataFrame()
    df = pd.DataFrame(linhas)
    df["_c"] = df["Confiança"].map(lambda x: -ORDEM_CONFIANCA.get(x, 0))
    return df.sort_values(by=["_c", "Fluxos", "Peers"], ascending=[True, False, False]).drop(columns=["_c"])


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
    "Mitsubishi MC / SLMP": "#B45309",
    "Omron FINS": "#92400E",
    "Beckhoff ADS": "#78350F",
    "PROFINET": "#7C3AED",
    "PROFINET (UDP RT)": "#7C3AED",
    "PROFINET (UDP RPC)": "#6D28D9",
    "EtherCAT": "#DB2777",
    "EtherCAT (UDP)": "#DB2777",
    "IEC 61850 GOOSE": "#059669",
    "IEC 61850 SV": "#10B981",
    "HART-IP": "#0D9488",
    "MQTT": "#0284C7",
    "MQTT (TLS)": "#0369A1",
    "CODESYS": "#4F46E5",
    "IEEE C37.118": "#CA8A04",
    "KNXnet/IP": "#65A30D",
    "CC-Link IE Field Basic": "#EA580C",
    "Modbus RTU over TCP": "#F43F5E",
    "EtherNet/IP I/O (UDP)": "#F97316",
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
            if app in PORTAS_OT.values() or any(
                x in str(app)
                for x in (
                    "Modbus", "S7", "IEC", "CIP", "OPC", "DNP", "PROFINET",
                    "EtherCAT", "MQTT", "HART", "CODESYS", "GOOSE", "MMS", "CC-Link", "FINS", "ADS",
                )
            ):
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
                "Ordem sugerida": (
                    "Revisar na timeline a origem do SYN scan e correlacionar com "
                    "downloads, C2 ou atividade OT (se houver) da mesma origem."
                ),
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

    # 6) Sequências comportamentais (só menciona OT se houver evidência OT real)
    timeline = montar_timeline_eventos(resultado)
    if not timeline.empty:
        fontes_seq = timeline["Fonte"].tolist()
        cats = timeline["Categoria"].astype(str).str.lower().tolist()
        tem_scan = any("varredura" in c for c in cats)
        tem_ot_alt = any(
            ("alteração" in c or "escrita" in c or "transferência ot" in c)
            and "ot" in c
            for c in cats
        )
        # Fallback: categorias explícitas de alteração OT
        if not tem_ot_alt:
            tem_ot_alt = any(
                c in ("alteração ot candidata", "transferência ot candidata", "anomalia ot")
                or c.startswith("alteração ot")
                for c in cats
            )
        # Confirma com eventos_ot (fonte de verdade)
        eot_df = resultado.get("eventos_ot")
        tem_eventos_ot = (
            eot_df is not None
            and hasattr(eot_df, "empty")
            and (not eot_df.empty)
        )
        if not tem_eventos_ot:
            tem_ot_alt = False

        tem_dl = any(f == "Download HTTP" for f in fontes_seq)

        if tem_scan and tem_ot_alt:
            irregularidades.append({
                "Severidade": "Alta",
                "Tipo": "Sequência comportamental suspeita (IT→OT)",
                "Alvo": "Timeline consolidada",
                "Arquivos envolvidos": n_arquivos,
                "Evidência": (
                    "Na ordem temporal aparecem varredura e, em seguida, "
                    "eventos de alteração/transferência OT na captura."
                ),
                "Ordem sugerida": (
                    "1) Varredura → 2) Contato OT / escrita → 3) Transferência ou download. "
                    "Revise a timeline e valide no PCAP."
                ),
            })
        elif tem_scan and tem_dl and not tem_ot_alt:
            # Cenário IT puro (ex.: malware desktop) — não citar OT
            irregularidades.append({
                "Severidade": "Média",
                "Tipo": "Sequência comportamental suspeita (scan + download)",
                "Alvo": "Timeline consolidada",
                "Arquivos envolvidos": n_arquivos,
                "Evidência": (
                    "Na ordem temporal aparecem possível varredura TCP e download "
                    "de executável/payload via HTTP. Não há eventos OT confirmados."
                ),
                "Ordem sugerida": (
                    "1) Varredura → 2) Downloads HTTP. "
                    "Correlacionar origem do scan com clientes dos downloads; "
                    "validar hashes e URLs no PCAP (podem ser legítimos ou maliciosos)."
                ),
            })

    # 7) Controle OT (DNP3 OPERATE/CROB, Modbus write, etc.) e anomalias de payload
    eot = resultado.get("eventos_ot")
    if eot is not None and not eot.empty:
        n_operate = 0
        n_select = 0
        n_crob = 0
        n_malform = 0
        exemplos_mal = []
        pares = set()
        for _, row in eot.iterrows():
            blob = " ".join(
                str(row.get(c, ""))
                for c in ("Operação", "Classificação", "Detalhe", "Categoria")
            )
            bl = blob.lower()
            if "operate" in bl:
                n_operate += 1
            if "select" in bl:
                n_select += 1
            if "crob" in bl:
                n_crob += 1
            if "malform" in bl or "format-string" in bl or "fuzzing" in bl:
                n_malform += 1
                if len(exemplos_mal) < 3:
                    exemplos_mal.append(
                        f"pacote {row.get('Nº pacote', '?')}: {str(row.get('Detalhe', ''))[:160]}"
                    )
            o = str(row.get("Origem", ""))
            d = str(row.get("Destino", ""))
            if o and d and o != "-":
                pares.add((o, d))

        if n_operate and n_select == 0:
            irregularidades.append({
                "Severidade": "Alta",
                "Tipo": "OPERATE OT sem SELECT prévio",
                "Alvo": f"{n_operate} comando(s)",
                "Arquivos envolvidos": n_arquivos,
                "Evidência": (
                    f"{n_operate} OPERATE/DIRECT_OPERATE DNP3 (ou equivalente) "
                    "sem SELECT correspondente na captura."
                ),
                "Ordem sugerida": (
                    "1) Confirmar se o master é autorizado → 2) Verificar outstation "
                    "na janela temporal → 3) Restringir OPERATE sem SELECT no perímetro OT."
                ),
            })
        if n_crob:
            irregularidades.append({
                "Severidade": "Alta",
                "Tipo": "Comandos CROB (controle de saída/relé)",
                "Alvo": f"CROB ×{n_crob}",
                "Arquivos envolvidos": n_arquivos,
                "Evidência": (
                    f"{n_crob} evento(s) com objeto DNP3 grupo 12 variação 1 (CROB)."
                ),
                "Ordem sugerida": "Validar com engenharia se houve atuação física em relés/saídas.",
            })
        if n_malform:
            irregularidades.append({
                "Severidade": "Alta",
                "Tipo": "Payload OT malformado ou padrão de fuzzing",
                "Alvo": f"{n_malform} pacote(s)",
                "Arquivos envolvidos": n_arquivos,
                "Evidência": (
                    f"{n_malform} pacote(s) com length inconsistente e/ou ASCII tipo "
                    f"format-string. Exemplos: {' | '.join(exemplos_mal)}"
                ),
                "Ordem sugerida": (
                    "Tratar como teste de robustez ou tentativa de exploração do parser; "
                    "aplicar patch e filtrar payloads anômalos."
                ),
            })
        # Fluxo unidirecional dominante OT (sem respostas na tabela de eventos)
        if n_operate >= 10 and len(pares) == 1:
            irregularidades.append({
                "Severidade": "Média",
                "Tipo": "Rajada OT unidirecional (possível lab/replay/forjado)",
                "Alvo": next(iter(pares))[0] + " → " + next(iter(pares))[1],
                "Arquivos envolvidos": n_arquivos,
                "Evidência": (
                    f"Muitos comandos de controle ({n_operate}) em um único par IP, "
                    "padrão compatível com captura sintética, replay ou fuzzing."
                ),
                "Ordem sugerida": "Checar handshake TCP, respostas e legitimidade do master.",
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



def _extrair_numeros_pacote(valor):
    """Extrai inteiros de '12', '1…50 (50x)', '1-10', etc."""
    import re
    if valor is None or valor == "-" or (isinstance(valor, float) and str(valor) == "nan"):
        return []
    if isinstance(valor, (int, float)) and not isinstance(valor, bool):
        try:
            return [int(valor)]
        except Exception:
            return []
    s = str(valor)
    nums = [int(x) for x in re.findall(r"\d+", s)]
    return nums


def filtro_wireshark_frames(valor_pacote, captura=None):
    """
    Gera filtro de exibição Wireshark para ir ao(s) frame(s).
    Nº pacote do analisador = frame.number no mesmo PCAP (1-based).
    """
    nums = _extrair_numeros_pacote(valor_pacote)
    if not nums:
        return "-"
    lo, hi = min(nums), max(nums)
    if lo == hi:
        filt = f"frame.number == {lo}"
    else:
        filt = f"frame.number >= {lo} && frame.number <= {hi}"
    return filt


def dica_wireshark(valor_pacote, captura=None):
    """Texto curto: como abrir no Wireshark."""
    nums = _extrair_numeros_pacote(valor_pacote)
    if not nums:
        return "Abra o PCAP no Wireshark; frame não identificado neste evento."
    lo, hi = min(nums), max(nums)
    arq = f" `{captura}`" if captura and captura not in ("-", "", None) else ""
    if lo == hi:
        return (
            f"Wireshark{arq}: Ctrl+G → {lo}  |  filtro: frame.number == {lo}"
        )
    return (
        f"Wireshark{arq}: Ctrl+G → {lo} (até {hi})  |  "
        f"filtro: frame.number >= {lo} && frame.number <= {hi}"
    )



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
            n_pkt = row.get("Nº pacote", "-")
            cap = row.get("Captura", "-")
            linhas.append({
                "Captura": cap,
                "Nº pacote": n_pkt,
                "Frame Wireshark": n_pkt,
                "Filtro Wireshark": filtro_wireshark_frames(n_pkt, cap),
                "Como abrir no Wireshark": dica_wireshark(n_pkt, cap),
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
    # Agrega eventos OT repetitivos (ex.: 197× OPERATE idênticos) para não poluir o relatório
    if not df.empty:
        agregados = []
        grupo_cols = ["Captura", "Fonte", "Ação", "Categoria", "Protocolo", "Origem", "Destino"]
        for key, g in df.groupby(grupo_cols, dropna=False, sort=False):
            if len(g) == 1:
                agregados.append(g.iloc[0].to_dict())
                continue
            first = g.iloc[0].to_dict()
            n = len(g)
            nums = []
            for v in g["Nº pacote"].tolist():
                nums.extend(_extrair_numeros_pacote(v))
            if nums:
                lo, hi = min(nums), max(nums)
                first["Nº pacote"] = f"{lo}…{hi} ({n}x)" if lo != hi else f"{lo} ({n}x)"
                first["Frame Wireshark"] = f"{lo}–{hi}" if lo != hi else str(lo)
                first["Filtro Wireshark"] = filtro_wireshark_frames(f"{lo} {hi}")
                first["Como abrir no Wireshark"] = dica_wireshark(f"{lo} {hi}", first.get("Captura"))
            else:
                first["Nº pacote"] = f"{g['Nº pacote'].iloc[0]}…{g['Nº pacote'].iloc[-1]} ({n}x)"
                first["Filtro Wireshark"] = "-"
                first["Como abrir no Wireshark"] = dica_wireshark(None)
            first["Data/hora UTC"] = f"{g['Data/hora UTC'].iloc[0]} → {g['Data/hora UTC'].iloc[-1]}"
            det0 = str(first.get("Detalhe") or "")
            if n > 1:
                first["Detalhe"] = (det0 + f" | Agregado: {n} eventos equivalentes").strip(" |")
                first["Ação"] = f"{first.get('Ação', '-')} (×{n})"
            agregados.append(first)
        df = pd.DataFrame(agregados)

    df["_ord"] = df["Data/hora UTC"].apply(
        lambda v: "9999-99-99" if (not v or v == "-") else str(v)[:19]
    )
    df = df.sort_values(by=["_ord", "Captura"], ascending=True).drop(
        columns=["_ord"]
    ).reset_index(drop=True)
    df.insert(0, "Ordem", range(1, len(df) + 1))
    return df




def montar_marcos_incidente(resultado):
    """
    Linha do tempo resumida do incidente: poucos marcos narrativos
    (não cada pacote). 100% offline.
    Retorna lista de dicts: ordem, quando, titulo, detalhe, severidade, fase.
    """
    marcos = []
    tl = None
    try:
        tl = montar_timeline_eventos(resultado)
    except Exception:
        tl = None

    def _primeiro_quando(df, pred):
        if df is None or getattr(df, "empty", True):
            return None, None
        for _, row in df.iterrows():
            blob = " ".join(
                str(row.get(c, ""))
                for c in ("Ação", "Categoria", "Detalhe", "Protocolo", "Fonte", "Classificação", "Operação")
            ).lower()
            if pred(blob, row):
                return row.get("Data/hora UTC") or row.get("Data/hora UTC"), row
        return None, None

    # 1) Anomalia / fuzzing / malformado
    quando, row = (None, None)
    if tl is not None and not tl.empty:
        quando, row = _primeiro_quando(
            tl,
            lambda b, r: any(x in b for x in ("malform", "fuzzing", "format-string", "format string", "%25")),
        )
    if row is not None:
        npk = row.get("Nº pacote", "-")
        cap = row.get("Captura", "-")
        marcos.append({
            "Ordem": len(marcos) + 1,
            "Quando UTC": quando or "-",
            "Título": "Payload anômalo / possível fuzzing",
            "Detalhe": str(row.get("Detalhe") or row.get("Ação") or "")[:220],
            "Fase": "Acesso inicial",
            "Severidade": "Alta",
            "Origem": row.get("Origem", "-"),
            "Destino": row.get("Destino", "-"),
            "Nº pacote": npk,
            "Filtro Wireshark": filtro_wireshark_frames(npk, cap),
            "Captura": cap,
        })

    # 2) Primeiro contato OT genérico
    quando_ot, row_ot = (None, None)
    if tl is not None and not tl.empty:
        quando_ot, row_ot = _primeiro_quando(
            tl,
            lambda b, r: (
                str(r.get("Fonte", "")).lower() == "ot"
                or "dnp" in b
                or "modbus" in b
                or "s7" in b
                or "ot" in b
            )
            and not any(x in b for x in ("malform", "fuzzing", "format-string")),
        )
    if row_ot is not None:
        npk = row_ot.get("Nº pacote", "-")
        cap = row_ot.get("Captura", "-")
        marcos.append({
            "Ordem": len(marcos) + 1,
            "Quando UTC": quando_ot or "-",
            "Título": "Início do contato OT",
            "Detalhe": str(row_ot.get("Ação") or row_ot.get("Categoria") or "Comunicação OT")[:220],
            "Fase": "Movimentação OT",
            "Severidade": "Média",
            "Origem": row_ot.get("Origem", "-"),
            "Destino": row_ot.get("Destino", "-"),
            "Nº pacote": npk,
            "Filtro Wireshark": filtro_wireshark_frames(npk, cap),
            "Captura": cap,
        })

    # 3) Controle OT (OPERATE/CROB/escrita) — agregado
    ops = _contar_ops_ot_controle(resultado) if "_contar_ops_ot_controle" in globals() or True else {}
    try:
        ops = _contar_ops_ot_controle(resultado)
    except Exception:
        ops = {"operate": 0, "crob": 0, "select": 0, "malform": 0, "controle": 0}

    n_ctrl = max(ops.get("operate", 0), ops.get("crob", 0), ops.get("controle", 0))
    if n_ctrl or ops.get("operate") or ops.get("crob"):
        # janela temporal dos operates
        inicio_c, fim_c = "-", "-"
        if tl is not None and not tl.empty:
            filtrados = []
            for _, r in tl.iterrows():
                b = str(r.get("Ação", "") + r.get("Detalhe", "")).lower()
                if any(x in b for x in ("operate", "crob", "escrita", "alteração", "alteracao")):
                    filtrados.append(r)
            pkt_nums = []
            cap_c = "-"
            if filtrados:
                inicio_c = filtrados[0].get("Data/hora UTC", "-")
                fim_c = filtrados[-1].get("Data/hora UTC", "-")
                orig = filtrados[0].get("Origem", "-")
                dest = filtrados[0].get("Destino", "-")
                cap_c = filtrados[0].get("Captura", "-")
                for fr in filtrados:
                    pkt_nums.extend(_extrair_numeros_pacote(fr.get("Nº pacote")))
            else:
                orig, dest = "-", "-"
        else:
            orig, dest = "-", "-"
            pkt_nums = []
            cap_c = "-"
        sev_c = "Alta" if (ops.get("operate") and ops.get("select", 0) == 0) else "Média"
        titulo = "Comandos de controle OT"
        if ops.get("operate"):
            titulo = f"OPERATE/CROB (×{max(ops.get('operate', 0), ops.get('crob', 0))})"
        det = []
        if ops.get("operate"):
            det.append(f"{ops['operate']} OPERATE")
        if ops.get("crob"):
            det.append(f"{ops['crob']} CROB")
        if ops.get("select", 0) == 0 and ops.get("operate"):
            det.append("sem SELECT prévio na captura")
        if pkt_nums:
            lo, hi = min(pkt_nums), max(pkt_nums)
            det.append(f"frames Wireshark {lo}–{hi}")
        npk = f"{min(pkt_nums)}…{max(pkt_nums)}" if pkt_nums else "-"
        marcos.append({
            "Ordem": len(marcos) + 1,
            "Quando UTC": f"{inicio_c} → {fim_c}" if inicio_c != fim_c else str(inicio_c),
            "Título": titulo,
            "Detalhe": "; ".join(det) if det else "Alteração OT candidata",
            "Fase": "Ação em objetivo",
            "Severidade": sev_c,
            "Origem": orig,
            "Destino": dest,
            "Nº pacote": npk,
            "Filtro Wireshark": filtro_wireshark_frames(npk, cap_c),
            "Captura": cap_c,
        })

    # 4) Download de executável
    dl = resultado.get("downloads_suspeitos")
    if dl is not None and not getattr(dl, "empty", True):
        row = dl.iloc[0]
        npk = row.get("Nº pacote", "-")
        cap = row.get("Captura", "-")
        marcos.append({
            "Ordem": len(marcos) + 1,
            "Quando UTC": row.get("Data/hora UTC", "-"),
            "Título": f"Download de {row.get('Tipo de arquivo', 'executável/payload')}",
            "Detalhe": f"SHA-256 {str(row.get('SHA-256', '-'))[:20]}… | {row.get('Cliente', '-')} → {row.get('Servidor', '-')}",
            "Fase": "Entrega",
            "Severidade": str(row.get("Severidade") or "Alta"),
            "Origem": row.get("Cliente", "-"),
            "Destino": row.get("Servidor", "-"),
            "Nº pacote": npk,
            "Filtro Wireshark": filtro_wireshark_frames(npk, cap),
            "Captura": cap,
        })

    # 5) Exposição de dados
    exp = resultado.get("eventos")
    if exp is not None and not getattr(exp, "empty", True):
        row = exp.iloc[0]
        npk = row.get("Nº pacote", "-")
        cap = row.get("Captura", "-")
        marcos.append({
            "Ordem": len(marcos) + 1,
            "Quando UTC": row.get("Data/hora UTC", "-"),
            "Título": "Possível exposição de dados/credenciais",
            "Detalhe": str(row.get("Detalhe") or row.get("Categoria") or "")[:220],
            "Fase": "Exposição",
            "Severidade": "Alta",
            "Origem": row.get("Origem", "-"),
            "Destino": row.get("Destino", "-"),
            "Nº pacote": npk,
            "Filtro Wireshark": filtro_wireshark_frames(npk, cap),
            "Captura": cap,
        })

    # 6) Irregularidade multi-captura de destaque
    irr = resultado.get("irregularidades")
    if irr is not None and not getattr(irr, "empty", True):
        # pega a de maior severidade que ainda não esteja coberta pelo título
        ordem_s = {"Alta": 0, "Média": 1, "Baixa": 2}
        try:
            irr2 = irr.copy()
            irr2["_s"] = irr2["Severidade"].map(lambda x: ordem_s.get(str(x), 9))
            irr2 = irr2.sort_values("_s")
            for _, row in irr2.head(2).iterrows():
                tipo = str(row.get("Tipo", "Irregularidade"))
                if any(tipo.lower() in str(m.get("Título", "")).lower() for m in marcos):
                    continue
                marcos.append({
                    "Ordem": len(marcos) + 1,
                    "Quando UTC": "-",
                    "Título": tipo,
                    "Detalhe": str(row.get("Evidência", ""))[:220],
                    "Fase": "Correlação",
                    "Severidade": str(row.get("Severidade") or "Média"),
                    "Origem": "-",
                    "Destino": str(row.get("Alvo", "-"))[:40],
                })
        except Exception:
            pass

    # Renumerar
    for i, m in enumerate(marcos, 1):
        m["Ordem"] = i
    return marcos


def desenhar_marcos_incidente(marcos, chart_key="plotly_marcos_incidente"):
    """UI Streamlit: história do incidente em marcos + gráfico linear."""
    if not marcos:
        st.info("Sem marcos suficientes para montar a história do incidente.")
        return

    st.subheader("História do incidente (marcos)")
    st.caption(
        "Linha do tempo resumida: só os pontos decisivos, não cada pacote. "
        "Análise 100% local."
    )

    cores = {"Alta": "#EF4444", "Média": "#F59E0B", "Baixa": "#38BDF8", "Crítico": "#DC2626"}
    # Cartões
    for m in marcos:
        cor = cores.get(str(m.get("Severidade")), "#94A3B8")
        filt = m.get("Filtro Wireshark") or "-"
        npk = m.get("Nº pacote") or "-"
        cap = m.get("Captura") or "-"
        st.markdown(
            f"""
            <div style="border-left:4px solid {cor};background:#0F172A;border:1px solid #1E293B;
                        border-radius:10px;padding:12px 14px;margin:8px 0;">
              <div style="color:#94A3B8;font-size:0.8rem;">
                #{m.get('Ordem')} · {m.get('Fase')} · {m.get('Quando UTC')} ·
                <span style="color:{cor};font-weight:600;">{m.get('Severidade')}</span>
              </div>
              <div style="color:#F8FAFC;font-weight:600;margin-top:4px;">{m.get('Título')}</div>
              <div style="color:#CBD5E1;font-size:0.9rem;margin-top:4px;">{m.get('Detalhe')}</div>
              <div style="color:#64748B;font-size:0.8rem;margin-top:4px;">
                {m.get('Origem')} → {m.get('Destino')}
                &nbsp;|&nbsp; Captura: <code style="color:#7DD3FC;">{cap}</code>
              </div>
              <div style="margin-top:8px;padding:8px 10px;background:#1E293B;border-radius:8px;font-size:0.82rem;">
                <span style="color:#94A3B8;">Frame no Wireshark:</span>
                <code style="color:#F8FAFC;">{npk}</code>
                &nbsp;·&nbsp;
                <span style="color:#94A3B8;">Filtro:</span>
                <code style="color:#4ADE80;">{filt}</code>
                <div style="color:#64748B;margin-top:4px;">Abra o PCAP → Ctrl+G (ir ao pacote) ou cole o filtro na barra Display Filter</div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Gráfico de marcos no tempo (quando parseável)
    plot_rows = []
    for m in marcos:
        raw = str(m.get("Quando UTC") or "")
        ts = None
        for part in raw.replace("→", " ").split():
            try:
                ts = datetime.strptime(part[:19], "%Y-%m-%d %H:%M:%S")
                break
            except Exception:
                continue
        if ts is None:
            continue
        plot_rows.append({
            "ts": ts,
            "Título": m.get("Título"),
            "Fase": m.get("Fase"),
            "Severidade": m.get("Severidade"),
            "Ordem": m.get("Ordem"),
        })
    if plot_rows:
        dfp = pd.DataFrame(plot_rows)
        fig = px.scatter(
            dfp,
            x="ts",
            y="Ordem",
            color="Severidade",
            text="Título",
            color_discrete_map={
                "Alta": "#EF4444",
                "Média": "#F59E0B",
                "Baixa": "#38BDF8",
                "Crítico": "#DC2626",
            },
            hover_data=["Fase", "Severidade"],
        )
        fig.update_traces(textposition="top center", marker=dict(size=14))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#E2E8F0",
            height=280,
            margin=dict(t=30, b=20, l=10, r=10),
            yaxis_title="Marco",
            xaxis_title="UTC",
            showlegend=True,
        )
        # linha conectando marcos
        if len(dfp) >= 2:
            dfp2 = dfp.sort_values("ts")
            fig.add_scatter(
                x=dfp2["ts"],
                y=dfp2["Ordem"],
                mode="lines",
                line=dict(color="#475569", width=2, dash="dot"),
                showlegend=False,
                hoverinfo="skip",
            )
        st.plotly_chart(fig, use_container_width=True, key=chart_key)

    st.dataframe(pd.DataFrame(marcos), use_container_width=True, hide_index=True)


def marcos_para_markdown(marcos):
    """Texto markdown da história do incidente para o relatório."""
    if not marcos:
        return ["- *(sem marcos suficientes)*"]
    linhas = [
        "*No Wireshark, **Nº pacote = frame.number** no mesmo PCAP. "
        "Atalho: **Ctrl+G** (ir ao frame) ou cole o **Filtro Wireshark** na barra de filtro.*"
    ]
    for m in marcos:
        filt = m.get("Filtro Wireshark") or filtro_wireshark_frames(
            m.get("Nº pacote"), m.get("Captura")
        )
        bloco = [
            f"- **#{m.get('Ordem')} · {m.get('Quando UTC')} · [{m.get('Severidade')}] {m.get('Fase')}**",
            f"  **{m.get('Título')}** — {m.get('Detalhe')}",
            f"  `{m.get('Origem')}` → `{m.get('Destino')}`",
            f"  **Captura:** `{m.get('Captura', '-')}` · **Frame:** `{m.get('Nº pacote', '-')}`",
            f"  **Filtro Wireshark:** `{filt}`",
        ]
        linhas.append("\n".join(bloco))
    return linhas



def desenhar_timeline_eventos(df_timeline, chart_key="plotly_timeline_eventos"):
    """Gráfico de dispersão temporal + tabela cronológica."""
    if df_timeline is None or df_timeline.empty:
        st.info("Nenhum evento com data/hora para montar a timeline.")
        return

    st.subheader("Timeline de eventos")
    st.caption(
        "Linha do tempo consolidada (exposição, OT, alertas e downloads HTTP). "
        "**Nº pacote = frame.number no Wireshark** no mesmo arquivo PCAP. "
        "Use a coluna **Filtro Wireshark** (colar em Display Filter) ou **Ctrl+G** e digite o número do frame."
    )
    with st.expander("Como localizar no Wireshark", expanded=False):
        st.markdown(
            """
1. Abra no Wireshark o **mesmo arquivo** da coluna *Captura*.
2. **Ir para o pacote:** `Ctrl+G` (Linux/Windows) ou `Cmd+G` (macOS) → digite o **Nº pacote / Frame**.
3. **Filtro de exibição:** cole o valor de **Filtro Wireshark**, por exemplo:
   - um pacote: `frame.number == 12`
   - intervalo: `frame.number >= 2 && frame.number <= 198`
4. Opcional: marque o pacote e use *File → Export Specified Packets* para isolar o trecho.
            """
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

    cols_ordem = [
        c for c in [
            "Ordem",
            "Captura",
            "Nº pacote",
            "Frame Wireshark",
            "Filtro Wireshark",
            "Como abrir no Wireshark",
            "Data/hora UTC",
            "Fonte",
            "Ação",
            "Categoria",
            "Protocolo",
            "Origem",
            "Destino",
            "Detalhe",
        ]
        if c in df_timeline.columns
    ]
    outras = [c for c in df_timeline.columns if c not in cols_ordem]
    df_show = df_timeline[cols_ordem + outras]
    st.dataframe(df_show, use_container_width=True, hide_index=True)
    st.download_button(
        "Baixar timeline + filtros Wireshark (CSV)",
        df_show.to_csv(index=False).encode("utf-8"),
        "timeline_eventos_wireshark.csv",
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


def _contar_ops_ot_controle(resultado):
    """Conta OPERATE/CROB/escritas e anomalias DNP3/Modbus/S7 nas tabelas OT."""
    n_ctrl = 0
    n_malform = 0
    n_select = 0
    n_operate = 0
    n_crob = 0
    df = resultado.get("eventos_ot")
    if df is None or getattr(df, "empty", True):
        return {
            "controle": 0,
            "malform": 0,
            "select": 0,
            "operate": 0,
            "crob": 0,
        }
    for _, row in df.iterrows():
        blob = " ".join(
            str(row.get(c, ""))
            for c in ("Operação", "Classificação", "Detalhe", "Categoria", "Protocolo OT")
        ).lower()
        if "operate" in blob or "direct_operate" in blob:
            n_operate += 1
            n_ctrl += 1
        if "crob" in blob:
            n_crob += 1
            n_ctrl += 1
        if "select" in blob:
            n_select += 1
        if "malform" in blob or "format-string" in blob or "fuzzing" in blob:
            n_malform += 1
        if "alteração ot" in blob or "alteracao ot" in blob or "escrita" in blob:
            n_ctrl += 1
    return {
        "controle": n_ctrl,
        "malform": n_malform,
        "select": n_select,
        "operate": n_operate,
        "crob": n_crob,
    }


def calcular_severidade_consolidada(resultado):
    """
    Score único local: Crítico / Alto / Médio / Baixo / Informativo.
    Prioriza controle OT (OPERATE/CROB), anomalias de payload e malware HTTP.
    100% offline.
    """
    n_dl = _n_df(resultado.get("downloads_suspeitos"))
    n_exp = _n_df(resultado.get("eventos"))
    n_alertas = _n_df(resultado.get("alertas"))
    n_transf = _n_df(resultado.get("transferencias_ot"))
    n_ativos = contar_ativos_ot_unicos(resultado.get("ativos_ot"))
    n_ext = _n_df(resultado.get("externos"))
    n_irr = _n_df(resultado.get("irregularidades"))
    n_iocs = contar_iocs_unicos(resultado.get("iocs_candidatos"))
    ops = _contar_ops_ot_controle(resultado)

    pontos = 0
    justificativas = []

    if n_dl:
        pontos += 40 + min(n_dl * 5, 20)
        justificativas.append(f"Download de executável/payload ({n_dl})")

    # Controle OT (OPERATE/CROB) pesa mais que mera presença de protocolo
    if ops["operate"] or ops["crob"]:
        n_op = max(ops["operate"], ops["crob"])
        pontos += 35 + min(n_op // 5, 25)
        justificativas.append(
            f"Comandos de controle OT (OPERATE/CROB) observados (~{n_op})"
        )
        if ops["select"] == 0 and ops["operate"]:
            pontos += 15
            justificativas.append("OPERATE sem SELECT prévio na captura")
    elif ops["controle"]:
        pontos += 20 + min(ops["controle"] // 10, 15)
        justificativas.append(f"Alterações OT candidatas ({ops['controle']})")

    if ops["malform"]:
        pontos += 20 + min(ops["malform"] * 5, 15)
        justificativas.append(
            f"Payload OT malformado / padrão de fuzzing ({ops['malform']})"
        )

    if n_transf:
        pontos += 15 + min(n_transf * 3, 15)
        justificativas.append(f"Transferência OT candidata ({n_transf})")
    if n_exp:
        pontos += 15 + min(n_exp, 15)
        justificativas.append(f"Exposição de dados em claro ({n_exp})")
    if n_ativos and n_ext:
        pontos += 20
        justificativas.append("Ativos OT e IPs públicos na mesma captura")
    if n_irr:
        pontos += 10 + min(n_irr * 2, 10)
        justificativas.append(f"Irregularidades ({n_irr})")
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
        "ops_ot": ops,
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
                if any(
                    x in acao
                    for x in (
                        "write", "upload", "start", "stop", "program",
                        "operate", "crob", "select", "direct_operate",
                        "alteração", "alteracao", "escrita",
                    )
                ):
                    fases["Ação em objetivo"].append(texto)
                elif any(x in acao for x in ("malform", "fuzzing", "format-string", "format string")):
                    fases["Acesso inicial / entrega"].append(texto)
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



def exportar_iocs_json(resultado):
    """IOCs candidatos + conhecidos em JSON simples (offline)."""
    import json
    from datetime import datetime, timezone
    itens = []
    for key, col in (("iocs_candidatos", "IOC candidato"), ("iocs", "IOC")):
        df = resultado.get(key)
        if df is None or getattr(df, "empty", True):
            continue
        for _, row in df.iterrows():
            itens.append({
                "tipo": str(row.get("Tipo", "")),
                "valor": str(row.get(col, row.get("IOC", ""))),
                "motivo": str(row.get("Motivo", row.get("Fonte", ""))),
                "evidencia": str(row.get("Evidência", row.get("Ocorrências", ""))),
                "origem": "candidato" if key == "iocs_candidatos" else "lista_local",
            })
    return json.dumps({
        "gerado_em": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ferramenta": "Analisador OT de PCAP",
        "iocs": itens,
    }, ensure_ascii=False, indent=2)


def exportar_iocs_stix(resultado):
    """
    Bundle STIX 2.1 mínimo com indicadores (IPv4, domain-name, file hashes).
    100% offline — sem envio a serviços externos.
    """
    import json
    import uuid
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects = []
    identity_id = f"identity--{uuid.uuid4()}"
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "Analisador OT de PCAP",
        "identity_class": "tool",
    })

    def _add_indicator(pattern, name, description=""):
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": name[:120],
            "description": (description or "")[:500],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": ["anomalous-activity"],
        })

    for key, col in (("iocs_candidatos", "IOC candidato"), ("iocs", "IOC")):
        df = resultado.get(key)
        if df is None or getattr(df, "empty", True):
            continue
        for _, row in df.iterrows():
            tipo = str(row.get("Tipo", "")).lower()
            valor = str(row.get(col, row.get("IOC", ""))).strip()
            if not valor or valor == "-":
                continue
            desc = str(row.get("Motivo", row.get("Evidência", "")))
            if "ip" in tipo:
                _add_indicator(f"[ipv4-addr:value = '{valor}']", f"IP {valor}", desc)
            elif "dom" in tipo or "host" in tipo:
                _add_indicator(f"[domain-name:value = '{valor}']", f"Domain {valor}", desc)
            elif "hash" in tipo or "sha" in tipo or len(valor) in (32, 40, 64):
                if len(valor) == 64:
                    _add_indicator(f"[file:hashes.'SHA-256' = '{valor}']", f"SHA-256 {valor[:16]}…", desc)
                elif len(valor) == 40:
                    _add_indicator(f"[file:hashes.'SHA-1' = '{valor}']", f"SHA-1 {valor[:16]}…", desc)
                elif len(valor) == 32:
                    _add_indicator(f"[file:hashes.MD5 = '{valor}']", f"MD5 {valor[:16]}…", desc)
            else:
                _add_indicator(f"[x-ot-ioc:value = '{valor}']", valor[:80], desc)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    return json.dumps(bundle, ensure_ascii=False, indent=2)



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
    linhas.append(f"> **{AVISO_ANALISE_PRELIMINAR}**  ")
    linhas.append(f"> {AVISO_ANALISE_PRELIMINAR_TEXTO}")
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
    linhas.append("## 3.1 História do incidente (marcos)")
    try:
        marcos = montar_marcos_incidente(resultado)
        linhas.extend(marcos_para_markdown(marcos))
    except Exception as err_m:
        linhas.append(f"- *(falha ao montar marcos: `{err_m}`)*")

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
            for _, row in tl.head(15).iterrows():
                linhas.append(
                    "\n".join([
                        f"- **#{row.get('Ordem', '-')}** | **{row.get('Data/hora UTC', '-')}** | "
                        f"frame `{row.get('Nº pacote', '-')}` | *{row.get('Captura', '-')}*",
                        f"  - **{row.get('Ação') or row.get('Categoria') or '-'}** "
                        f"({row.get('Fonte', '-')}) | `{row.get('Origem')}` → `{row.get('Destino')}`",
                        f"  - **Wireshark:** `{row.get('Filtro Wireshark') or filtro_wireshark_frames(row.get('Nº pacote'), row.get('Captura'))}` "
                        f"(Ctrl+G ou Display Filter)",
                    ])
                )
            if len(tl) > 15:
                linhas.append(f"- *… +{len(tl) - 15} grupo(s) na timeline agregada da interface*")
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
        f"- Tratar como severidade **{sev['nivel']}** até prova em contrário."
    )
    linhas.append(
        "- Preservar evidências e correlacionar com firewall, EDR e historiador."
    )
    linhas.append(
        "- Análise automática é **100% local** (sem consultas à internet)."
    )

    linhas.append("")
    linhas.append("## 18. Resumo final — o que pode ter ocorrido")
    ops = sev.get("ops_ot") or _contar_ops_ot_controle(resultado)
    resumo = []
    if ops.get("operate") or ops.get("crob"):
        resumo.append(
            f"Foram observados **{ops.get('operate', 0)} OPERATE** e **{ops.get('crob', 0)} CROB** "
            "em tráfego OT — comandos de **controle de processo/saídas**, não mera telemetria."
        )
        if ops.get("select", 0) == 0 and ops.get("operate", 0):
            resumo.append(
                "Não há SELECT prévio na captura: controle **direto** "
                "(ou SELECT em outra janela não capturada)."
            )
    if ops.get("malform"):
        resumo.append(
            f"**{ops.get('malform')}** pacote(s) OT malformado(s) ou com padrão de "
            "**format-string/fuzzing** (teste de robustez ou exploração de parser)."
        )
    if n_dl:
        resumo.append(
            f"**{n_dl}** download(s) de executável/payload via HTTP — validar hash sob política local."
        )
    if n_exp:
        resumo.append(
            f"**{n_exp}** evento(s) de possível exposição de dados/credenciais em claro."
        )
    if n_ext and n_ativos:
        resumo.append(
            "Ativos OT e IPs públicos na mesma análise — revisar segmentação."
        )
    if not resumo:
        resumo.append(
            "Heurísticas sem indicadores fortes. Ausência de alerta não prova ausência de ameaça."
        )
    resumo.append(
        f"**Severidade consolidada: {sev['nivel']} ({sev['pontos']}/100).** "
        "Impacto em campo só se confirma com logs do dispositivo e da engenharia."
    )
    for r in resumo:
        linhas.append(f"- {r}")

    linhas.append("")
    linhas.append("---")
    linhas.append(
        f"*Analisador OT de PCAP · 100% local · severidade={sev['nivel']} ({sev['pontos']}/100) · "
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
    <div style="margin:16px 0;padding:14px 16px;border-radius:10px;border:1px solid #F59E0B;
                background:#FEF3C7;color:#78350F;font-size:0.9rem;line-height:1.5;">
      <strong>{AVISO_ANALISE_PRELIMINAR}</strong><br/>
      {AVISO_ANALISE_PRELIMINAR_TEXTO}
    </div>
    <article>
      {mapa_html}
      {corpo}
    </article>
    <div class="footer">
      Analisador OT de PCAP · relatório gerado localmente<br/>
      <span style="color:#92400E;">{AVISO_ANALISE_PRELIMINAR_CURTO}</span>
    </div>
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
    linhas.append("*** " + AVISO_ANALISE_PRELIMINAR + " ***")
    linhas.append(AVISO_ANALISE_PRELIMINAR_TEXTO)
    linhas.append("")
    linhas.append("-" * 60)
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
    linhas.append("")
    linhas.append("Fim do relatorio.")
    linhas.append(AVISO_ANALISE_PRELIMINAR_CURTO)
    linhas.append(AVISO_ANALISE_PRELIMINAR_TEXTO)
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
    story.append(Spacer(1, 4))
    aviso_estilo = ParagraphStyle(
        "AvisoPrelim",
        parent=pequeno,
        textColor=colors.HexColor("#92400E"),
        backColor=colors.HexColor("#FEF3C7"),
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=8,
        leading=12,
    )
    story.append(Paragraph(
        f"<b>{AVISO_ANALISE_PRELIMINAR}</b><br/>{AVISO_ANALISE_PRELIMINAR_TEXTO}",
        aviso_estilo,
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
        f"<b>Fim do relatório.</b> {AVISO_ANALISE_PRELIMINAR_CURTO}",
        pequeno,
    ))
    story.append(Paragraph(
        AVISO_ANALISE_PRELIMINAR_TEXTO,
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


# Hosts/CDN frequentemente legítimos (atualização de software, CDN de app).
# Não remove o download da lista — apenas reduz severidade automática.
_HOSTS_ATUALIZACAO_COMUM = (
    "windowsupdate.com",
    "microsoft.com",
    "update.microsoft.com",
    "download.windowsupdate.com",
    "gvt1.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "skype.com",
    "download.skype.com",
    "apple.com",
    "mzstatic.com",
    "adobe.com",
    "akamaihd.net",
    "akamaized.net",
    "cloudfront.net",
    "office.net",
    "office365.com",
    "live.com",
)


def host_parece_atualizacao_legitima(host: str) -> bool:
    if not host:
        return False
    h = host.lower().split(":")[0].strip(".")
    for suf in _HOSTS_ATUALIZACAO_COMUM:
        if h == suf or h.endswith("." + suf):
            return True
    return False


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

        # CDN/atualização conhecida: mantém o registro, mas não escala como "Alta"
        # (vale para qualquer PCAP — desktop IT, OT com jump host, etc.)
        if host_parece_atualizacao_legitima(host):
            motivos.append(
                "Host compatível com CDN/atualização de software comum "
                "(severidade reduzida; validar se o ambiente deveria baixar daqui)."
            )
            if severidade == "Alta":
                severidade = "Média"
            # Porta padrão + host conhecido → Informativa
            if porta_servidor in PORTAS_HTTP_PADRAO and contexto <= 2:
                severidade = "Baixa"

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


def analisar_pcap(caminho, limite, iocs_ips, iocs_dominios, progresso=None):
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

    syn_destinos = defaultdict(set)  # origem -> set("ip:porta")
    syn_portas_por_origem = defaultdict(set)  # origem -> set(portas)
    syn_hosts_por_origem = defaultdict(set)  # origem -> set(ips destino)
    syn_para_ot = defaultdict(set)  # origem -> set("ip:porta") onde porta é OT

    amostra = []
    dns_lista = []
    eventos = []

    eventos_chaves = set()
    usuarios_fluxo = {}

    eventos_ot = []
    eventos_ot_chaves = set()
    detalhes_ot = Counter()
    fluxos_ot_meta = {}
    tcp_buffers = {}

    total = 0
    total_bytes = 0
    erros = 0

    inicio = None
    fim = None
    limite_atingido = False

    rastreador_http = RastreadorDownloadsHTTP()

    leitor = abrir_pcap(caminho)
    # Portas que merecem inspeção OT/exposição (evita trabalho pesado em todo pacote)
    _PORTAS_INTERESSE_OT = set(PORTAS_OT.keys()) | set(PORTAS_TRANSFERENCIA_OT)
    _PORTAS_EXPOSICAO = {21, 22, 23, 25, 80, 110, 143, 445, 502, 102, 2404, 44818, 1883}
    _INTERVALO_PROGRESSO = 1000  # atualiza UI a cada N pacotes

    try:
        for pacote in leitor:
            # limite <= 0 significa processar TODOS os pacotes (sem corte)
            if limite and limite > 0 and total >= limite:
                limite_atingido = True
                break

            total += 1

            # Mantém a interface responsiva durante análises longas
            if progresso is not None and (total % _INTERVALO_PROGRESSO == 0 or total == 1):
                try:
                    progresso(total, limite if (limite and limite > 0) else 0)
                except Exception:
                    pass

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
                    syn_hosts_por_origem[origem].add(destino)
                    if porta_destino is not None:
                        syn_portas_por_origem[origem].add(int(porta_destino))
                        if int(porta_destino) in PORTAS_OT or int(porta_destino) in PORTAS_TRANSFERENCIA_OT:
                            syn_para_ot[origem].add(f"{destino}:{porta_destino}")

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

                # Exposição: só em portas típicas de credencial/arquivo (mais rápido)
                if (porta_destino in _PORTAS_EXPOSICAO) or (porta_origem in _PORTAS_EXPOSICAO):
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

                # OT: só quando porta/EtherType sugere protocolo industrial
                _et = None
                try:
                    _et = ethertype_pacote(pacote)
                except Exception:
                    _et = None
                _candidato_ot = (
                    (porta_destino in _PORTAS_INTERESSE_OT)
                    or (porta_origem in _PORTAS_INTERESSE_OT)
                    or (_et is not None and _et in ETHERTYPES_OT)
                )
                if _candidato_ot:
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
                        fluxos_ot_meta=fluxos_ot_meta,
                        tcp_buffers=tcp_buffers,
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
    ativos_ot = gerar_ativos_ot(fluxos, fluxos_ot_meta)
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

    # Alertas a partir de operações OT críticas observadas nos eventos
    # (S7 Stop/Start/Upload/Write, Modbus write, DNP3 OPERATE, etc.)
    for ev in eventos_ot:
        cat = str(ev.get("Categoria") or "")
        clas = str(ev.get("Classificação") or "")
        op = str(ev.get("Operação") or "")
        blob = f"{cat} {clas} {op}".lower()
        sev = None
        tipo = None
        if "plc stop" in blob or "0x29" in blob:
            sev, tipo = "Alta", "Comando PLC Stop (S7)"
        elif "plc start" in blob or "pi-service" in blob or "0x28" in blob:
            sev, tipo = "Alta", "Comando PLC Start / PI-Service (S7)"
        elif "upload de bloco" in blob or "start upload" in blob:
            sev, tipo = "Alta", "Upload de bloco S7"
        elif "download de bloco" in blob or "request download" in blob:
            sev, tipo = "Alta", "Download de bloco S7"
        elif "write var" in blob:
            sev, tipo = "Alta", "Escrita de variável S7"
        elif "umas" in blob or "unity pro" in blob:
            sev, tipo = "Alta", "Schneider UMAS — programação/upload PLC"
        elif "alteração ot candidata" in cat.lower() and "modbus" in blob and "umas" not in blob:
            sev, tipo = "Alta", "Escrita Modbus candidata"
        elif "operate" in blob or "crob" in blob:
            sev, tipo = "Alta", "Controle DNP3 (OPERATE/CROB)"
        elif "transferência ot candidata" in cat.lower():
            sev, tipo = "Média", "Transferência OT candidata"
        if sev and tipo:
            adicionar_alerta(
                alertas,
                alertas_chaves,
                {
                    "Severidade": sev,
                    "Tipo": tipo,
                    "Origem": ev.get("Origem", "-"),
                    "Destino": ev.get("Destino", "-"),
                    "Porta destino": ev.get("Porta destino", "-"),
                    "Detalhe": ev.get("Detalhe") or op or clas,
                },
            )


    # Catálogo de alertas estilo plataformas OT de mercado (somente evidência PCAP)
    gerar_alertas_catalogo_mercado(
        alertas,
        alertas_chaves,
        syn_destinos=syn_destinos,
        syn_portas_por_origem=syn_portas_por_origem,
        syn_hosts_por_origem=syn_hosts_por_origem,
        syn_para_ot=syn_para_ot,
        fluxos=fluxos,
        eventos_ot=eventos_ot,
        downloads_suspeitos=downloads_suspeitos,
        externos=externos,
        eventos=eventos,
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
        "fluxos_ot_meta": fluxos_ot_meta,
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
        f"""
        <div class="footer-apackets">
          <h4>Sobre esta análise</h4>
          <p>
            Esta ferramenta analisa arquivos <b>PCAP / PCAPNG</b> de forma <b>local</b>:
            as capturas e listas de IOC <b>não são enviadas para a internet</b>.
            O motor reconstrói visão de hosts, protocolos, eventos OT, exposição em canais sem TLS,
            timeline unificada e irregularidades entre múltiplas capturas.
          </p>
          <div style="margin:14px 0;padding:12px 14px;border-radius:8px;border:1px solid #F59E0B;
                      background:#FEF3C7;color:#78350F;font-size:0.88rem;line-height:1.45;">
            <strong>{AVISO_ANALISE_PRELIMINAR}</strong><br/>
            {AVISO_ANALISE_PRELIMINAR_CURTO}
          </div>
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
            "Máximo de pacotes (0 = todos)",
            min_value=0,
            max_value=50_000_000,
            value=int(st.session_state.get("limite_pacotes", 0)),
            step=10_000,
            key="cfg_limite_pacotes",
            help="0 = processar TODOS os pacotes, sem corte. "
                 "Qualquer valor > 0 limita a quantidade analisada. "
                 "Capturas grandes demoram mais; a barra de progresso mostra o avanço percentual.",
        )
        st.session_state["limite_pacotes"] = limite_pacotes
        if limite_pacotes == 0:
            st.caption("Sem limite: todos os pacotes serão processados. A barra indica o avanço.")
        else:
            st.caption(f"Limite ativo: {limite_pacotes:,} pacotes por arquivo.".replace(",", "."))
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
        limite_pacotes = st.session_state.get("limite_pacotes", 0)
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
        st.caption(f"⚠️ {AVISO_ANALISE_PRELIMINAR_CURTO}")
    elif st.session_state.get("pdf_relatorio_ok") is False:
        st.error(
            f"Falha ao gerar PDF: {st.session_state.get('pdf_relatorio_erro', 'erro desconhecido')}"
        )

    # Exportação IOC (JSON / STIX) — offline
    if st.session_state.get("resultado_analise") is not None:
        st.markdown("")
        st.caption("Exportar indicadores (offline)")
        try:
            js = exportar_iocs_json(st.session_state["resultado_analise"])
            st.download_button(
                "⬇️ IOCs JSON",
                data=js.encode("utf-8"),
                file_name="iocs_analise_ot.json",
                mime="application/json",
                use_container_width=True,
                key="dl_iocs_json",
            )
            stix = exportar_iocs_stix(st.session_state["resultado_analise"])
            st.download_button(
                "⬇️ IOCs STIX 2.1",
                data=stix.encode("utf-8"),
                file_name="iocs_analise_ot_stix.json",
                mime="application/json",
                use_container_width=True,
                key="dl_iocs_stix",
            )
        except Exception as err_exp:
            st.caption(f"Exportação IOC indisponível: {err_exp}")

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
    # Nova seleção de arquivos → força reanálise
    st.session_state.pop("_chave_analise", None)
    st.session_state["resultado_analise"] = None
    st.session_state["lista_resultados_meta"] = None

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

# Chave de cache: mesmos arquivos + limite + IOCs → não reanalisa a cada clique na UI
_ioc_nome = getattr(arquivo_ioc, "name", None) if arquivo_ioc is not None else None
_chave_analise = (
    tuple(sorted((a.name, int(getattr(a, "size", 0) or 0)) for a in arquivos)),
    int(limite_pacotes) if limite_pacotes is not None else 0,
    _ioc_nome,
)

_cache_ok = (
    st.session_state.get("_chave_analise") == _chave_analise
    and st.session_state.get("resultado_analise") is not None
    and st.session_state.get("lista_resultados_meta") is not None
)

try:
    if _cache_ok:
        resultado = st.session_state["resultado_analise"]
        lista_resultados = st.session_state["lista_resultados_meta"]
        st.caption("Resultado em cache — PCAP não foi reprocessado. Altere o arquivo ou o limite para nova análise.")
    else:
        lista_resultados = []  # (nome, sha256, resultado)

        barra = st.progress(0.0, text="Preparando análise multi-arquivo…")
        for idx, arq in enumerate(arquivos):
            base_frac = idx / max(len(arquivos), 1)
            span = 1.0 / max(len(arquivos), 1)

            try:
                _tam = int(getattr(arq, "size", 0) or 0)
                _estimativa = max(int(_tam / 600), 1) if _tam else 0
            except Exception:
                _estimativa = 0

            def _prog_fabrica(b=base_frac, s=span, nome=arq.name, i=idx, n=len(arquivos), est=_estimativa):
                def _prog(atual, lim):
                    if lim and lim > 0:
                        base_total = lim
                    elif est > 0:
                        base_total = est
                    else:
                        base_total = 0
                    if base_total > 0:
                        pct_arq = min(atual / base_total, 0.99)
                        pct_txt = f"{pct_arq * 100:.1f}%"
                        frac = b + s * pct_arq
                    else:
                        pct_arq = 1.0 - (1.0 / (1.0 + atual / 50000.0))
                        pct_txt = f"{atual:,} pcts".replace(",", ".")
                        frac = b + s * min(pct_arq, 0.95)
                    barra.progress(
                        min(max(frac, 0.01), 0.99),
                        text=(
                            f"Analisando {nome} ({i + 1}/{n}) — {pct_txt} "
                            f"· {atual:,} pacotes processados"
                        ).replace(",", "."),
                    )
                return _prog

            barra.progress(
                base_frac,
                text=f"Analisando {arq.name} ({idx + 1}/{len(arquivos)}) — iniciando…",
            )
            caminho, sha256 = salvar_upload(arq)
            caminhos_temporarios.append(caminho)
            res = analisar_pcap(
                caminho,
                int(limite_pacotes),
                iocs_ips,
                iocs_dominios,
                progresso=_prog_fabrica(),
            )
            lista_resultados.append((arq.name, sha256, res))

        barra.progress(1.0, text="Mesclando resultados e montando timeline…")
        resultado = mesclar_resultados(lista_resultados)
        irregularidades = detectar_irregularidades_multi(resultado, lista_resultados)
        resultado["irregularidades"] = irregularidades
        barra.progress(1.0, text="Análise concluída (100%).")
        barra.empty()

        st.session_state["resultado_analise"] = resultado
        st.session_state["lista_resultados_meta"] = lista_resultados
        st.session_state["_chave_analise"] = _chave_analise

    st.warning(
        f"**{AVISO_ANALISE_PRELIMINAR}**  \n"
        f"{AVISO_ANALISE_PRELIMINAR_TEXTO}"
    )
    try:
        _rb = resumo_base()
        st.caption(
            f"Base offline de PLCs v{_rb.get('versao', '?')} · "
            f"fabricantes: {', '.join(_rb.get('fabricantes', [])[:6])}… · "
            "protocolos fora da base serão sinalizados para extensão do código."
        )
    except Exception:
        pass

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
            "Limite de pacotes configurado pelo usuário foi atingido em pelo menos um arquivo. "
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
        try:
            marcos = montar_marcos_incidente(resultado)
            desenhar_marcos_incidente(marcos, chart_key="plotly_marcos_irreg")
        except Exception as err_marcos:
            st.caption(f"Marcos do incidente indisponíveis: {err_marcos}")
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
