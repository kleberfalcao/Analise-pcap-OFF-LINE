# -*- coding: utf-8 -*-
"""
Base de conhecimento OFFLINE de PLCs, protocolos industriais e códigos de função.

Consulta apenas dados embutidos neste módulo — sem rede.
Quando o analisador identificar tráfego OT cuja família/protocolo NÃO estiver
nesta base, deve informar o usuário que é necessário estender o código.

Fontes de referência (consolidadas offline a partir de documentação pública):
  - Siemens S7comm / S7comm-plus (porta 102)
  - Schneider UMAS (Modbus FC 0x5A) / Modbus TCP
  - Rockwell / Allen-Bradley EtherNet/IP + CIP (44818 / 2222)
  - Omron FINS (9600)
  - Mitsubishi MELSEC / SLMP (5000–5001, 45237)
  - Beckhoff ADS (48898)
  - IEC 60870-5-104, DNP3, BACnet, PROFINET, EtherCAT, OPC UA, MQTT, HART-IP, etc.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Versão da base (incrementar ao adicionar fabricante/protocolo)
# ---------------------------------------------------------------------------
BASE_PLCS_VERSAO = "2026.10.1"

# ---------------------------------------------------------------------------
# Portas clássicas → protocolo (detecção primária por transporte)
# ---------------------------------------------------------------------------
PORTAS_PROTOCOLO: Dict[int, str] = {
    102: "Siemens S7comm / ISO-TSAP",
    502: "Modbus TCP",  # pode ser UMAS se FC=0x5A
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

# Portas onde assinaturas de payload de um protocolo SÓ podem ser aplicadas
PORTAS_PERMITIDAS_POR_PROTOCOLO: Dict[str, Set[int]] = {
    "MQTT": {1883, 8883},
    "MQTT (TLS)": {8883},
    "EtherNet/IP / CIP": {44818, 2222},
    "EtherNet/IP I/O (UDP)": {2222},
    "HART-IP": {5094},
    "DNP3": {20000},
    "IEC 60870-5-104": {2404},
    "BACnet/IP": {47808},
    "Omron FINS": {9600},
    "Beckhoff ADS": {48898},
    "OPC UA": {4840, 4843},
    "Siemens S7comm / ISO-TSAP": {102},
    "Siemens S7comm-plus": {102},
    "IEC 61850 MMS": {102},
    "Modbus TCP": {502},
    "Schneider UMAS / Unity Pro": {502},
    "Mitsubishi MC / SLMP": {5000, 5001, 45237},
    "CODESYS": {2455, 11740},
    "IEEE C37.118": {4712, 4713},
    "KNXnet/IP": {3671},
}

# ---------------------------------------------------------------------------
# Fabricantes / famílias PLC suportados (consulta offline)
# ---------------------------------------------------------------------------
FABRICANTES_PLC: Dict[str, Dict[str, Any]] = {
    "Siemens": {
        "familias": ["S7-300", "S7-400", "S7-1200", "S7-1500", "LOGO!", "ET 200"],
        "protocolos": ["Siemens S7comm / ISO-TSAP", "Siemens S7comm-plus", "PROFINET", "OPC UA"],
        "portas": [102, 34962, 34963, 34964, 4840],
        "software_engenharia": ["TIA Portal", "STEP 7"],
        "notas": "S7comm clássico (0x32) em S7-300/400; S7comm-plus (0x72) em S7-1200/1500.",
    },
    "Schneider Electric": {
        "familias": ["Modicon M340", "M580", "Quantum", "Premium", "M221", "M241", "M251"],
        "protocolos": ["Modbus TCP", "Schneider UMAS / Unity Pro", "OPC UA"],
        "portas": [502],
        "software_engenharia": ["Unity Pro", "EcoStruxure Control Expert", "Machine Expert"],
        "notas": "UMAS usa Modbus FC 0x5A (90) para programação/upload de lógica.",
    },
    "Rockwell / Allen-Bradley": {
        "familias": ["ControlLogix", "CompactLogix", "MicroLogix", "PLC-5"],
        "protocolos": ["EtherNet/IP / CIP", "EtherNet/IP I/O (UDP)"],
        "portas": [44818, 2222],
        "software_engenharia": ["Studio 5000", "RSLogix"],
        "notas": "CIP explícito TCP 44818; I/O implícito UDP 2222.",
    },
    "Omron": {
        "familias": ["CJ", "CS", "CP1", "NX", "NJ", "Sysmac"],
        "protocolos": ["Omron FINS", "EtherNet/IP / CIP", "EtherCAT"],
        "portas": [9600, 44818, 2222],
        "software_engenharia": ["CX-Programmer", "Sysmac Studio"],
        "notas": "FINS nativo TCP/UDP 9600 em muitas CPUs.",
    },
    "Mitsubishi": {
        "familias": ["MELSEC FX5", "iQ-R", "iQ-F", "Q-series"],
        "protocolos": ["Mitsubishi MC / SLMP", "CC-Link IE Field Basic", "Modbus TCP"],
        "portas": [5000, 5001, 45237, 61450, 61451, 502],
        "software_engenharia": ["GX Works2", "GX Works3"],
        "notas": "SLMP/MC protocol em portas 5000/5001; CC-Link IE Field Basic.",
    },
    "Beckhoff": {
        "familias": ["CX", "C60xx", "TwinCAT Runtime"],
        "protocolos": ["Beckhoff ADS", "EtherCAT"],
        "portas": [48898, 34980],
        "software_engenharia": ["TwinCAT"],
        "notas": "ADS/AMS TCP porta 48898.",
    },
    "CODESYS / multi-vendor": {
        "familias": ["WAGO", "Eaton", "Bosch Rexroth", "Turck", "Schneider M241/M251"],
        "protocolos": ["CODESYS", "Modbus TCP", "OPC UA"],
        "portas": [2455, 11740, 502, 4840],
        "software_engenharia": ["CODESYS IDE", "e!COCKPIT", "Machine Expert"],
        "notas": "Runtime CODESYS expõe porta 2455 / gateway 11740.",
    },
    "ABB": {
        "familias": ["AC500", "AC800M"],
        "protocolos": ["Modbus TCP", "OPC UA", "PROFINET", "EtherNet/IP / CIP"],
        "portas": [502, 4840, 44818],
        "software_engenharia": ["Automation Builder"],
        "notas": "Multi-protocolo via módulos de comunicação.",
    },
    "Genérico / multi-fabricante": {
        "familias": ["SCADA", "RTU", "medidores", "IHM"],
        "protocolos": [
            "Modbus TCP",
            "DNP3",
            "IEC 60870-5-104",
            "BACnet/IP",
            "OPC UA",
            "MQTT",
            "HART-IP",
            "IEEE C37.118",
            "KNXnet/IP",
        ],
        "portas": [502, 20000, 2404, 47808, 4840, 1883, 8883, 5094, 4712, 4713, 3671],
        "software_engenharia": [],
        "notas": "Protocolos abertos usados por vários fabricantes.",
    },
}

# ---------------------------------------------------------------------------
# Códigos de função S7comm (Siemens)
# ---------------------------------------------------------------------------
FUNCOES_S7: Dict[int, Dict[str, Any]] = {
    0x00: {"nome": "CPU services", "critico": False, "categoria": "servico"},
    0x04: {"nome": "Read Var", "critico": False, "categoria": "leitura"},
    0x05: {"nome": "Write Var", "critico": True, "categoria": "escrita"},
    0x1A: {"nome": "Request download", "critico": True, "categoria": "download"},
    0x1B: {"nome": "Download block", "critico": True, "categoria": "download"},
    0x1C: {"nome": "Download ended", "critico": True, "categoria": "download"},
    0x1D: {"nome": "Start upload", "critico": True, "categoria": "upload"},
    0x1E: {"nome": "Upload", "critico": True, "categoria": "upload"},
    0x1F: {"nome": "End upload", "critico": True, "categoria": "upload"},
    0x28: {"nome": "PI-Service (PLC Start/Control)", "critico": True, "categoria": "controle"},
    0x29: {"nome": "PLC Stop", "critico": True, "categoria": "controle"},
    0xF0: {"nome": "Setup communication", "critico": False, "categoria": "sessao"},
}

ROSCTR_S7: Dict[int, str] = {
    0x01: "Job",
    0x02: "Ack",
    0x03: "Ack-Data",
    0x07: "Userdata",
}

# ---------------------------------------------------------------------------
# Modbus function codes padrão
# ---------------------------------------------------------------------------
FUNCOES_MODBUS: Dict[int, Dict[str, Any]] = {
    1: {"nome": "Read Coils", "critico": False, "categoria": "leitura"},
    2: {"nome": "Read Discrete Inputs", "critico": False, "categoria": "leitura"},
    3: {"nome": "Read Holding Registers", "critico": False, "categoria": "leitura"},
    4: {"nome": "Read Input Registers", "critico": False, "categoria": "leitura"},
    5: {"nome": "Write Single Coil", "critico": True, "categoria": "escrita"},
    6: {"nome": "Write Single Register", "critico": True, "categoria": "escrita"},
    15: {"nome": "Write Multiple Coils", "critico": True, "categoria": "escrita"},
    16: {"nome": "Write Multiple Registers", "critico": True, "categoria": "escrita"},
    22: {"nome": "Mask Write Register", "critico": True, "categoria": "escrita"},
    23: {"nome": "Read/Write Multiple Registers", "critico": True, "categoria": "escrita"},
    43: {"nome": "Read Device Identification", "critico": False, "categoria": "inventario"},
    # Schneider UMAS
    0x5A: {
        "nome": "UMAS (Schneider Unity / Control Expert)",
        "critico": True,
        "categoria": "programacao",
        "protocolo": "Schneider UMAS / Unity Pro",
        "fabricante": "Schneider Electric",
    },
}

# Subcódigos UMAS mais comuns (após FC 0x5A + session key)
FUNCOES_UMAS: Dict[int, str] = {
    0x01: "INIT_COMM",
    0x02: "READ_ID",
    0x03: "READ_PROJECT_INFO",
    0x04: "READ_PLC_INFO",
    0x10: "READ_MEMORY_BLOCK",
    0x20: "READ_MEMORY_BLOCK",
    0x21: "WRITE_MEMORY_BLOCK",
    0x22: "READ_VARIABLES",
    0x23: "WRITE_VARIABLES",
    0x30: "TAKE_PLC_RESERVATION",
    0x31: "RELEASE_PLC_RESERVATION",
    0x40: "DOWNLOAD_START",
    0x41: "DOWNLOAD_DATA",
    0x42: "DOWNLOAD_END",
    0x50: "UPLOAD_START",
    0x51: "UPLOAD_DATA",
    0x52: "UPLOAD_END",
    0x58: "START_PLC",
    0x59: "STOP_PLC",
}

# ---------------------------------------------------------------------------
# CIP / EtherNet/IP (serviços comuns)
# ---------------------------------------------------------------------------
SERVICOS_CIP: Dict[int, str] = {
    0x01: "Get_Attributes_All",
    0x02: "Set_Attributes_All",
    0x03: "Get_Attribute_List",
    0x04: "Set_Attribute_List",
    0x05: "Reset",
    0x06: "Start",
    0x07: "Stop",
    0x0A: "Get_Attribute_Single",
    0x0E: "Get_Attribute_Single",
    0x10: "Set_Attribute_Single",
    0x4B: "Execute_PCCC",
    0x4C: "Read_Tag",
    0x4D: "Write_Tag",
    0x52: "Read_Tag_Fragmented",
    0x53: "Write_Tag_Fragmented",
    0x54: "Read_Modify_Write_Tag",
    0x55: "Multiple_Service_Packet",
}

# ---------------------------------------------------------------------------
# API de consulta offline
# ---------------------------------------------------------------------------

def protocolo_por_porta(porta: int) -> Optional[str]:
    return PORTAS_PROTOCOLO.get(int(porta)) if porta is not None else None


def porta_permitida_para_protocolo(nome_protocolo: str, porta: Optional[int]) -> bool:
    """
    Retorna True se o protocolo pode ser reivindicado nesta porta.
    Se o protocolo não estiver na lista de restrição, permite (EtherType etc.).
    """
    if porta is None:
        return True
    chave = nome_protocolo
    # normaliza aliases
    for k in PORTAS_PERMITIDAS_POR_PROTOCOLO:
        if k.lower() in (nome_protocolo or "").lower() or (nome_protocolo or "").lower() in k.lower():
            chave = k
            break
    permitidas = PORTAS_PERMITIDAS_POR_PROTOCOLO.get(chave)
    if permitidas is None:
        return True
    return int(porta) in permitidas


def info_funcao_s7(codigo: Optional[int]) -> Dict[str, Any]:
    if codigo is None:
        return {"nome": "Mensagem S7comm", "critico": False, "categoria": "desconhecido"}
    return FUNCOES_S7.get(
        int(codigo),
        {"nome": f"Função S7 0x{int(codigo):02X}", "critico": False, "categoria": "desconhecido"},
    )


def info_funcao_modbus(codigo: Optional[int]) -> Dict[str, Any]:
    if codigo is None:
        return {"nome": "Modbus", "critico": False, "categoria": "desconhecido"}
    c = int(codigo) & 0x7F
    return FUNCOES_MODBUS.get(
        c,
        {"nome": f"FC {c}", "critico": False, "categoria": "desconhecido"},
    )


def info_umas(subcodigo: Optional[int]) -> str:
    if subcodigo is None:
        return "UMAS"
    return FUNCOES_UMAS.get(int(subcodigo), f"UMAS 0x{int(subcodigo):02X}")


def fabricante_por_protocolo(nome_protocolo: str) -> Optional[str]:
    if not nome_protocolo:
        return None
    pl = nome_protocolo.lower()
    for fab, meta in FABRICANTES_PLC.items():
        for p in meta.get("protocolos", []):
            if p.lower() in pl or pl in p.lower():
                return fab
        if fab.lower() in pl:
            return fab
    if "s7" in pl or "siemens" in pl or "profinet" in pl:
        return "Siemens"
    if "umas" in pl or "schneider" in pl or "modbus" in pl:
        return "Schneider Electric" if "umas" in pl else "Genérico / multi-fabricante"
    if "cip" in pl or "ethernet/ip" in pl or "enip" in pl:
        return "Rockwell / Allen-Bradley"
    if "fins" in pl or "omron" in pl:
        return "Omron"
    if "melsec" in pl or "slmp" in pl or "mitsubishi" in pl or "cc-link" in pl:
        return "Mitsubishi"
    if "ads" in pl or "beckhoff" in pl or "ethercat" in pl:
        return "Beckhoff"
    return None


def protocolo_na_base(nome_protocolo: str) -> bool:
    if not nome_protocolo:
        return False
    conhecidos = set(PORTAS_PROTOCOLO.values())
    conhecidos.update(
        {
            "Siemens S7comm-plus",
            "IEC 61850 MMS",
            "Modbus RTU over TCP",
            "Schneider UMAS / Unity Pro",
            "PROFINET",
            "EtherCAT",
            "IEC 61850 GOOSE",
            "IEC 61850 SV",
        }
    )
    pl = nome_protocolo.lower()
    for c in conhecidos:
        if c.lower() in pl or pl in c.lower():
            return True
    for meta in FABRICANTES_PLC.values():
        for p in meta.get("protocolos", []):
            if p.lower() in pl or pl in p.lower():
                return True
    return False


def mensagem_protocolo_fora_da_base(nome_observado: str, porta: Optional[int] = None) -> str:
    """Texto padronizado para o relatório/UI quando algo não está na base offline."""
    porta_txt = f" (porta {porta})" if porta else ""
    return (
        f"Protocolo/família OT observada{porta_txt}: «{nome_observado}». "
        f"Não há entrada completa na base offline de PLCs (versão {BASE_PLCS_VERSAO}). "
        "Trate o achado como preliminar e considere estender "
        "`base_plcs_offline.py` / decodificadores no código para suporte formal a este fabricante ou variante."
    )


def resumo_base() -> Dict[str, Any]:
    return {
        "versao": BASE_PLCS_VERSAO,
        "fabricantes": list(FABRICANTES_PLC.keys()),
        "n_portas": len(PORTAS_PROTOCOLO),
        "n_funcoes_s7": len(FUNCOES_S7),
        "n_funcoes_modbus": len(FUNCOES_MODBUS),
        "n_funcoes_umas": len(FUNCOES_UMAS),
        "offline": True,
    }


def listar_fabricantes() -> List[str]:
    return list(FABRICANTES_PLC.keys())
