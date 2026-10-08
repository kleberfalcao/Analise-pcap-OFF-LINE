# -*- coding: utf-8 -*-
"""Detecção offline de protocolos OT/ICS (assinaturas, portas, EtherTypes)."""
from __future__ import annotations

import re
from typing import Optional, Tuple

REGEX_REQUISICAO_HTTP = re.compile(
    rb"^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH) ", re.I
)

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

ETHERTYPES_OT = {
    0x8892: "PROFINET",
    0x88A4: "EtherCAT",
    0x88B8: "IEC 61850 GOOSE",
    0x88BA: "IEC 61850 SV",
    0x88CC: "LLDP (topologia)",
    0x88E3: "PROFINET MRP",
}

# Níveis: alta = assinatura; media = porta clássica + tráfego; baixa = só porta ambígua
CONFIANCA_ALTA = "alta"
CONFIANCA_MEDIA = "media"
CONFIANCA_BAIXA = "baixa"
ORDEM_CONFIANCA = {CONFIANCA_ALTA: 3, CONFIANCA_MEDIA: 2, CONFIANCA_BAIXA: 1}

PORTAS_CLASSICAS = {502, 102, 2404, 44818, 4840, 20000, 47808, 2222}
PORTAS_AMBIGUAS = {
    5000, 5001, 9600, 48898, 1883, 2455, 11740, 5094, 4712, 4713, 3671,
    34962, 34963, 34964, 34980, 61450, 61451, 45237, 4843, 8883,
}


def melhor_confianca(a: Optional[str], b: Optional[str]) -> str:
    if not a:
        return b or CONFIANCA_BAIXA
    if not b:
        return a
    return a if ORDEM_CONFIANCA.get(a, 0) >= ORDEM_CONFIANCA.get(b, 0) else b


def analisar_modbus_payload(payload: bytes):
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
    escrita = fc_n in {5, 6, 15, 16, 22, 23}
    ident = fc_n == 43
    return {
        "Modbus": True,
        "Função": fc_n,
        "Exceção": excecao,
        "Código exceção": payload[8] if excecao and len(payload) > 8 else None,
        "Escrita": escrita and not excecao,
        "Identificação dispositivo": ident,
        "Unit": unit,
        "Tamanho": length,
    }


def analisar_modbus_rtu_tcp(payload: bytes):
    if not payload or len(payload) < 4:
        return None
    if len(payload) >= 7 and payload[2:4] == b"\x00\x00":
        length = int.from_bytes(payload[4:6], "big")
        if length == len(payload) - 6 and length >= 2:
            return None
    addr, fc = payload[0], payload[1]
    if addr == 0 or addr > 247:
        return None
    fc_n = fc & 0x7F
    if fc_n not in {1, 2, 3, 4, 5, 6, 15, 16, 22, 23, 43}:
        return None
    return {
        "Modbus RTU TCP": True,
        "Slave": addr,
        "Função": fc_n,
        "Exceção": bool(fc & 0x80),
        "Escrita": fc_n in {5, 6, 15, 16, 22, 23},
        "Identificação dispositivo": fc_n == 43,
    }


def analisar_s7_payload(payload: bytes):
    if not payload or len(payload) < 7 or payload[0] != 0x03:
        return None
    # TPKT + COTP
    if len(payload) < 4:
        return None
    indice = 4
    if len(payload) > 5 and payload[4] == 0x02:  # COTP length
        indice = 7
    # S7comm classic 0x32
    if indice < len(payload) and payload[indice] == 0x32:
        rosctr = payload[indice + 1] if len(payload) > indice + 1 else None
        funcao = None
        if len(payload) > indice + 10:
            funcao = payload[indice + 10]
        return {
            "S7": True,
            "Variante": "S7comm",
            "ROSCTR": rosctr,
            "Função": funcao,
            "Tamanho parâmetro": 0,
            "Tamanho dados": 0,
        }
    # S7comm-plus often 0x72 after COTP
    if indice < len(payload) and payload[indice] == 0x72:
        return {
            "S7": True,
            "Variante": "S7comm-plus",
            "ROSCTR": None,
            "Função": payload[indice + 1] if len(payload) > indice + 1 else None,
            "Tamanho parâmetro": 0,
            "Tamanho dados": 0,
        }
    return None


def analisar_mms_payload(payload: bytes):
    """IEC 61850 MMS sobre ISO-TSAP (porta 102) — heurística BER."""
    if not payload or len(payload) < 8:
        return None
    # TPKT
    if payload[0] != 0x03:
        return None
    # Se for S7, não marcar como MMS
    if analisar_s7_payload(payload):
        return None
    # COTP data + BER: tags comuns 0xA0 (confirmed-RequestPDU) etc.
    blob = payload[4:40]
    if any(b in blob for b in (0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0x61, 0x30)):
        # MMS string markers sometimes present
        if b"mms" in payload.lower() or b"\xa0" in payload[7:30]:
            return {"MMS": True, "Evidência": "BER/COTP compatível com MMS"}
        return {"MMS": True, "Evidência": "ISO-TSAP sem S7; possível MMS"}
    return None


def classificar_protocolo_ot_com_confianca(
    porta_origem,
    porta_destino,
    payload: bytes = b"",
    transporte=None,
    ethertype=None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Retorna (nome_protocolo, confiança).
    alta = assinatura/EtherType; media = porta clássica; baixa = porta ambígua só.
    """
    portas = (porta_destino, porta_origem)
    if payload and (
        payload[:2] == b"MZ"
        or payload[:4] == b"\x7fELF"
        or payload[:5] == b"HTTP/"
        or REGEX_REQUISICAO_HTTP.match(payload)
    ):
        payload = b""

    if ethertype in ETHERTYPES_OT:
        return ETHERTYPES_OT[ethertype], CONFIANCA_ALTA

    if transporte == "TCP" and payload:
        if analisar_s7_payload(payload):
            s7 = analisar_s7_payload(payload)
            if s7 and s7.get("Variante") == "S7comm-plus":
                return "Siemens S7comm-plus", CONFIANCA_ALTA
            return "Siemens S7comm / ISO-TSAP", CONFIANCA_ALTA
        if analisar_mms_payload(payload):
            return "IEC 61850 MMS", CONFIANCA_ALTA
        if analisar_modbus_payload(payload):
            return "Modbus TCP", CONFIANCA_ALTA
        if analisar_modbus_rtu_tcp(payload):
            return "Modbus RTU over TCP", CONFIANCA_ALTA
        # fallbacks handled in main module for enip/opc/dnp3 etc.

    for porta in portas:
        if porta is None:
            continue
        if porta in PORTAS_CLASSICAS:
            return PORTAS_OT.get(porta), CONFIANCA_MEDIA
        if porta in PORTAS_AMBIGUAS and porta in PORTAS_OT:
            return PORTAS_OT.get(porta), CONFIANCA_BAIXA
        if porta in PORTAS_OT:
            return PORTAS_OT[porta], CONFIANCA_MEDIA

    return None, None
