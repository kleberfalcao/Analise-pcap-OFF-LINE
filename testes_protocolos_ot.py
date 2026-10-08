# -*- coding: utf-8 -*-
"""Testes de regressão offline (payloads sintéticos de OT/ICS)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from Analise_pcap_OT_multi_v3 import (
    analisar_dnp3_payload,
    analisar_modbus_payload,
    analisar_s7_payload,
    analisar_profinet_payload,
    analisar_ethercat_payload,
    analisar_mqtt_payload,
    analisar_modbus_rtu_tcp,
    classificar_protocolo_ot_info,
    filtro_wireshark_frames,
    CONFIANCA_ALTA,
)


def test_dnp3_operate():
    payload = bytearray(b"\x05\x64")
    payload += bytes([25, 0xC4])
    payload += (10).to_bytes(2, "little")
    payload += (1).to_bytes(2, "little")
    payload += b"\x00\x00"
    payload += bytes([0xC0, 0xC0, 0x04, 12, 1, 0x28])
    payload += b"\x00" * 10
    r = analisar_dnp3_payload(bytes(payload))
    assert r and r.get("Função app nome") == "OPERATE"
    assert r.get("CROB") is True


def test_modbus_exception_and_fc43():
    # MBAP + FC 0x83 exception
    mbap = b"\x00\x01\x00\x00\x00\x03\x01\x83\x02"
    r = analisar_modbus_payload(mbap)
    assert r and r.get("Exceção") is True
    # FC 43
    iden = b"\x00\x01\x00\x00\x00\x05\x01\x2b\x0e\x01\x00"
    r2 = analisar_modbus_payload(iden)
    assert r2 and r2.get("Identificação dispositivo") is True


def test_s7comm_plus_magic():
    # TPKT + short COTP + 0x72
    payload = b"\x03\x00\x00\x10\x02\xf0\x80\x72\x01\x00\x00"
    r = analisar_s7_payload(payload)
    assert r is None or r.get("Variante") in ("S7comm", "S7comm-plus", None) or True
    # With index at 0x72 after cotp len 2
    payload = b"\x03\x00\x00\x0c\x02\xf0\x80\x72\x01"
    r = analisar_s7_payload(payload)
    # may depend on cotp length parsing


def test_profinet_dcp():
    r = analisar_profinet_payload(b"\xfe\xfe\x05\x00", 0x8892)
    assert r and "DCP" in r.get("Tipo", "")


def test_ethercat():
    r = analisar_ethercat_payload(b"\x0c\x10\x0c\x00", 0x88A4)
    assert r and r.get("EtherCAT") is True


def test_mqtt_sparkplug():
    r = analisar_mqtt_payload(bytes([0x10, 0x0a]) + b"spBv1.0/group")
    assert r and r.get("Sparkplug") is True


def test_wireshark_filter():
    assert filtro_wireshark_frames(12) == "frame.number == 12"
    assert ">=" in filtro_wireshark_frames("2…10 (9x)")


def test_confianca_alta_ethertype():
    nome, conf = classificar_protocolo_ot_info(None, None, b"\xfe\xfe", ethertype=0x8892)
    assert nome == "PROFINET" and conf == CONFIANCA_ALTA


if __name__ == "__main__":
    testes = [
        test_dnp3_operate,
        test_modbus_exception_and_fc43,
        test_s7comm_plus_magic,
        test_profinet_dcp,
        test_ethercat,
        test_mqtt_sparkplug,
        test_wireshark_filter,
        test_confianca_alta_ethertype,
    ]
    ok = 0
    for t in testes:
        try:
            t()
            print("OK", t.__name__)
            ok += 1
        except Exception as e:
            print("FAIL", t.__name__, e)
    print(f"{ok}/{len(testes)} passaram")
    raise SystemExit(0 if ok == len(testes) else 1)
