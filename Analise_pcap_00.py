# ============================================================
# ARQUIVO: Analise_pcap_00.py
# ============================================================

import hashlib
import html
import ipaddress
import os
import re
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

st.set_page_config(
    page_title="Analisador Local de PCAP",
    page_icon="🔎",
    layout="wide",
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
    chave = (
        evento["Categoria"],
        evento["Protocolo"],
        evento["Origem"],
        evento["Destino"],
        evento["Porta destino"],
        evento["Detalhe"],
        evento["Usuário identificado"],
        evento["Arquivo"],
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

            adicionar_evento(
                eventos,
                chaves_eventos,
                {
                    **base,
                    "Categoria": "Possível transferência de arquivo",
                    "Protocolo": "FTP sem TLS",
                    "Arquivo": mascarar_arquivo(nome),
                    "Detalhe": f"Comando FTP {operacao} identificado.",
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
                "Detalhe": (
                    "Tráfego Telnet identificado. O protocolo normalmente "
                    "não utiliza criptografia."
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

    if porta_destino in portas_http or porta_origem in portas_http:
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
                        "Cabeçalho HTTP Content-Disposition identificado."
                    ),
                },
            )


def tipo_no(ip, ips_dns):
    if ip in ips_dns:
        return "DNS"

    if ip_interno(ip):
        return "Interno"

    if ip_publico(ip):
        return "Externo"

    return "Outro"


def criar_grafo(fluxos):
    """Cria grafo com portas, protocolos e direção de comunicação."""
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

        if grafo.has_edge(ip_a, ip_b):
            dados_aresta = grafo[ip_a][ip_b]

            dados_aresta["Bytes"] += dados["Bytes"]
            dados_aresta["Pacotes"] += dados["Pacotes"]
            dados_aresta["Fluxos"] += 1
            dados_aresta["AparaB"] += dados["A→B"]
            dados_aresta["BparaA"] += dados["B→A"]
            dados_aresta["Protocolos"].add(transporte)
            dados_aresta["Portas"].update(portas_fluxo)

        else:
            grafo.add_edge(
                ip_a,
                ip_b,
                IP_A=ip_a,
                IP_B=ip_b,
                Bytes=dados["Bytes"],
                Pacotes=dados["Pacotes"],
                Fluxos=1,
                AparaB=dados["A→B"],
                BparaA=dados["B→A"],
                Protocolos={transporte},
                Portas=portas_fluxo,
            )

    for ip in grafo.nodes:
        grafo.nodes[ip]["Volume"] = volume_ip[ip]
        grafo.nodes[ip]["Tipo"] = tipo_no(ip, ips_dns)

    return grafo


def desenhar_mapa_comunicacao(grafo):
    """Desenha mapa com nós arrastáveis e detalhes ao passar o mouse."""
    if not grafo.nodes:
        st.info("Não há dados suficientes para gerar o mapa.")
        return

    arestas = sorted(
        grafo.edges(data=True),
        key=lambda item: item[2]["Bytes"],
        reverse=True,
    )[:LIMITE_ARESTAS_MAPA]

    grafo_visual = nx.Graph()

    for origem, destino, dados in arestas:
        grafo_visual.add_edge(origem, destino, **dados)

    for ip in grafo_visual.nodes:
        grafo_visual.nodes[ip]["Volume"] = grafo.nodes[ip]["Volume"]
        grafo_visual.nodes[ip]["Tipo"] = grafo.nodes[ip]["Tipo"]

    protocolos_por_ip = defaultdict(set)
    portas_por_ip = defaultdict(set)

    for origem, destino, dados in grafo_visual.edges(data=True):
        protocolos_por_ip[origem].update(dados["Protocolos"])
        protocolos_por_ip[destino].update(dados["Protocolos"])
        portas_por_ip[origem].update(dados["Portas"])
        portas_por_ip[destino].update(dados["Portas"])

    cores = {
        "Interno": {
            "background": "#22C55E",
            "border": "#86EFAC",
        },
        "Externo": {
            "background": "#F97316",
            "border": "#FDBA74",
        },
        "DNS": {
            "background": "#38BDF8",
            "border": "#7DD3FC",
        },
        "Outro": {
            "background": "#A78BFA",
            "border": "#C4B5FD",
        },
    }

    rede = Network(
        height="720px",
        width="100%",
        bgcolor="#0F172A",
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
            "navigationButtons": true
          },
          "physics": {
            "enabled": true,
            "barnesHut": {
              "gravitationalConstant": -11000,
              "centralGravity": 0.25,
              "springLength": 180,
              "springConstant": 0.035,
              "damping": 0.20,
              "avoidOverlap": 1
            },
            "stabilization": {
              "enabled": true,
              "iterations": 250,
              "updateInterval": 25
            }
          },
          "nodes": {
            "shape": "dot",
            "borderWidth": 2,
            "font": {
              "color": "#E2E8F0",
              "size": 14,
              "face": "Arial"
            }
          },
          "edges": {
            "smooth": {
              "type": "continuous"
            },
            "color": {
              "color": "#64748B",
              "highlight": "#F8FAFC",
              "hover": "#38BDF8"
            }
          }
        }
        """
    )

    for ip in grafo_visual.nodes:
        tipo = grafo_visual.nodes[ip]["Tipo"]
        volume = grafo_visual.nodes[ip]["Volume"]
        conexoes = grafo_visual.degree(ip)

        protocolos = ", ".join(
            sorted(protocolos_por_ip[ip])
        ) or "Não identificado"

        portas = ", ".join(
            str(porta)
            for porta in sorted(portas_por_ip[ip])[:20]
        ) or "Não identificadas"

        tamanho = min(
            max(20 + (volume / 150000) ** 0.45 * 12, 22),
            70,
        )

        tooltip = f"""
        <div style="font-family: Arial; padding: 6px;">
            <b style="font-size: 15px;">{html.escape(ip)}</b><br>
            <hr style="border: 0; border-top: 1px solid #475569;">
            <b>Classificação:</b> {html.escape(tipo)}<br>
            <b>Conexões:</b> {conexoes}<br>
            <b>Volume:</b> {html.escape(bytes_legivel(volume))}<br>
            <b>Protocolos:</b> {html.escape(protocolos)}<br>
            <b>Portas observadas:</b> {html.escape(portas)}
        </div>
        """

        rede.add_node(
            ip,
            label=ip,
            title=tooltip,
            size=tamanho,
            color=cores.get(tipo, cores["Outro"]),
        )

    for origem, destino, dados in grafo_visual.edges(data=True):
        ip_a = dados["IP_A"]
        ip_b = dados["IP_B"]

        pacotes_a_para_b = dados["AparaB"]
        pacotes_b_para_a = dados["BparaA"]

        if pacotes_a_para_b > 0 and pacotes_b_para_a > 0:
            tipo_comunicacao = "Bidirecional"

            direcao_detalhada = (
                f"{ip_a} → {ip_b}: {pacotes_a_para_b} pacote(s)<br>"
                f"{ip_b} → {ip_a}: {pacotes_b_para_a} pacote(s)"
            )

            cor_aresta = "#22C55E"

        elif pacotes_a_para_b > 0:
            tipo_comunicacao = "Somente ida"

            direcao_detalhada = (
                f"{ip_a} → {ip_b}: {pacotes_a_para_b} pacote(s)"
            )

            cor_aresta = "#F97316"

        else:
            tipo_comunicacao = "Somente vinda"

            direcao_detalhada = (
                f"{ip_b} → {ip_a}: {pacotes_b_para_a} pacote(s)"
            )

            cor_aresta = "#38BDF8"

        protocolos = ", ".join(sorted(dados["Protocolos"]))

        portas = ", ".join(
            str(porta)
            for porta in sorted(dados["Portas"])
        )

        largura = min(
            max(1 + (dados["Bytes"] / 500000), 1),
            8,
        )

        tooltip = f"""
        <div style="font-family: Arial; padding: 6px;">
            <b style="font-size: 14px;">Comunicação</b><br>
            <hr style="border: 0; border-top: 1px solid #475569;">
            <b>Endpoint A:</b> {html.escape(ip_a)}<br>
            <b>Endpoint B:</b> {html.escape(ip_b)}<br>
            <b>Tipo:</b> {html.escape(tipo_comunicacao)}<br>
            <b>Direção:</b><br>
            {direcao_detalhada}<br>
            <b>Protocolos:</b> {html.escape(protocolos)}<br>
            <b>Portas:</b> {html.escape(portas)}<br>
            <b>Fluxos:</b> {dados["Fluxos"]}<br>
            <b>Pacotes totais:</b> {dados["Pacotes"]:,}<br>
            <b>Volume:</b> {html.escape(bytes_legivel(dados["Bytes"]))}
        </div>
        """

        rede.add_edge(
            origem,
            destino,
            title=tooltip,
            width=largura,
            color=cor_aresta,
        )

    html_rede = rede.generate_html(notebook=False)

    components.html(
        html_rede,
        height=750,
        scrolling=False,
    )

    st.caption(
        "Arraste um IP para reposicioná-lo. "
        "Verde = comunicação bidirecional. "
        "Laranja = somente ida. "
        "Azul = somente vinda. "
        "Passe o mouse sobre IPs e linhas para ver detalhes."
    )


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
        }
    )

    syn_destinos = defaultdict(set)

    amostra = []
    dns_lista = []
    eventos = []

    eventos_chaves = set()
    usuarios_fluxo = {}

    total = 0
    total_bytes = 0
    erros = 0

    inicio = None
    fim = None
    limite_atingido = False

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
                    else:
                        dados["B→A"] += 1

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
        "iocs": pd.DataFrame(iocs),
        "amostra": pd.DataFrame(amostra),
        "alertas": pd.DataFrame(alertas),
        "grafo": criar_grafo(fluxos),
        "servicos": resumo_servicos(fluxos),
    }


st.title("🔎 Analisador Local de PCAP")
st.caption(
    "Processamento local: PCAPs e listas de IOCs não são enviados para a internet."
)

with st.sidebar:
    st.header("Configuração")

    limite_pacotes = st.number_input(
        "Máximo de pacotes",
        min_value=1000,
        max_value=5_000_000,
        value=200_000,
        step=10_000,
    )

    arquivo_ioc = st.file_uploader(
        "Lista local de IOCs opcional",
        type=["txt", "csv"],
        help="Use um IP ou domínio por linha.",
    )

    st.warning(
        "Senhas não são exibidas. A ferramenta indica apenas possível "
        "exposição em protocolos sem criptografia."
    )

iocs_ips, iocs_dominios = carregar_iocs(arquivo_ioc)

arquivo = st.file_uploader(
    "Selecione um arquivo PCAP, PCAPNG ou CAP",
    type=["pcap", "pcapng", "cap"],
)

if not arquivo:
    st.info("Selecione um arquivo PCAP/PCAPNG para iniciar a análise.")
    st.stop()

if arquivo.size / 1024 / 1024 > TAMANHO_MAXIMO_ARQUIVO_MB:
    st.error(
        f"O limite é de {TAMANHO_MAXIMO_ARQUIVO_MB} MB."
    )
    st.stop()

caminho_temporario = None

try:
    with st.spinner("Salvando arquivo e calculando SHA-256..."):
        caminho_temporario, sha256 = salvar_upload(arquivo)

    with st.spinner("Analisando PCAP..."):
        resultado = analisar_pcap(
            caminho_temporario,
            int(limite_pacotes),
            iocs_ips,
            iocs_dominios,
        )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Pacotes analisados",
        f"{resultado['total']:,}".replace(",", "."),
    )

    col2.metric(
        "Volume analisado",
        bytes_legivel(resultado["bytes"]),
    )

    col3.metric(
        "Pacotes com erro",
        resultado["erros"],
    )

    col4.metric(
        "Duração",
        (
            str(resultado["fim"] - resultado["inicio"]).split(".")[0]
            if resultado["inicio"] and resultado["fim"]
            else "Indisponível"
        ),
    )

    st.caption("SHA-256 do arquivo analisado")
    st.code(sha256, language=None)

    if resultado["inicio"] and resultado["fim"]:
        st.subheader("Período identificado na captura")

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
            "Calendário do período da captura",
            value=(
                resultado["inicio"].date(),
                resultado["fim"].date(),
            ),
            disabled=True,
            help=(
                "Data inicial e final identificadas nos pacotes analisados."
            ),
        )

    if resultado["limite"]:
        st.warning(
            "O limite de pacotes foi atingido. A captura foi analisada parcialmente."
        )

    abas = st.tabs(
        [
            "Resumo",
            "Mapa de comunicação",
            "Fluxos",
            "IPs externos",
            "DNS",
            "Exposição de dados",
            "IOCs locais",
            "Pacotes",
            "Indicadores",
        ]
    )

    with abas[0]:
        esquerda, direita = st.columns(2)

        with esquerda:
            st.subheader("Protocolos")

            st.dataframe(
                resultado["protocolos"],
                use_container_width=True,
                hide_index=True,
            )

            if not resultado["protocolos"].empty:
                grafico = px.pie(
                    resultado["protocolos"],
                    names="Protocolo",
                    values="Pacotes",
                    hole=0.45,
                )

                st.plotly_chart(
                    grafico,
                    use_container_width=True,
                )

        with direita:
            st.subheader("Principais IPs de origem")

            st.dataframe(
                resultado["origens"],
                use_container_width=True,
                hide_index=True,
            )

            st.subheader("Portas de destino observadas")

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

        desenhar_mapa_comunicacao(resultado["grafo"])

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
            )

    with abas[5]:
        st.subheader("Possível exposição de dados")

        st.caption(
            "Senhas não são exibidas, salvas ou exportadas."
        )

        if resultado["eventos"].empty:
            st.success(
                "Nenhum indicador de exposição foi identificado."
            )
        else:
            st.dataframe(
                resultado["eventos"],
                use_container_width=True,
                hide_index=True,
            )

            st.download_button(
                "Baixar indicadores em CSV",
                resultado["eventos"].to_csv(index=False).encode("utf-8"),
                "exposicao_dados_pcap.csv",
                "text/csv",
            )

    with abas[6]:
        st.subheader("IOCs encontrados na lista local")

        if arquivo_ioc is None:
            st.info(
                "Envie uma lista TXT/CSV com IPs e domínios na barra lateral."
            )
        elif resultado["iocs"].empty:
            st.success(
                "Nenhum IOC da lista local foi encontrado."
            )
        else:
            st.dataframe(
                resultado["iocs"],
                use_container_width=True,
                hide_index=True,
            )

    with abas[7]:
        st.subheader("Amostra de pacotes")

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

    with abas[8]:
        st.subheader("Indicadores para investigação")

        st.caption(
            "Indicadores devem ser validados conforme o contexto do ambiente."
        )

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

except Exception as erro:
    st.error(f"Não foi possível analisar o arquivo: {erro}")

finally:
    if caminho_temporario and os.path.exists(caminho_temporario):
        os.remove(caminho_temporario)
