# -*- coding: utf-8 -*-
"""
iniciar.py — sobe o Analisador OT de PCAP em ambiente local (.venv).

- 100% offline na análise de PCAP (nenhum PCAP é enviado à internet).
- Valida Streamlit e demais bibliotecas; instala apenas o que faltar.
"""
import os
import socket
import subprocess
import sys
import time
import venv
import webbrowser
from pathlib import Path

# ---------------------------------------------------------------------------
# Caminhos
# ---------------------------------------------------------------------------
PASTA_PROJETO = Path(__file__).resolve().parent
ARQUIVO_APP = PASTA_PROJETO / "Analise_pcap_OT_multi_v3.py"
PASTA_VENV = PASTA_PROJETO / ".venv"

if os.name == "nt":
    PYTHON_VENV = PASTA_VENV / "Scripts" / "python.exe"
else:
    PYTHON_VENV = PASTA_VENV / "bin" / "python"

ENDERECO = "127.0.0.1"
PORTA = 8502
URL_APLICACAO = f"http://{ENDERECO}:{PORTA}"

# nome_pip -> módulo Python para import
# Streamlit é obrigatório e verificado primeiro.
PACOTES = {
    "streamlit": "streamlit",
    "scapy": "scapy",
    "pandas": "pandas",
    "plotly": "plotly",
    "networkx": "networkx",
    "pyvis": "pyvis",
    "reportlab": "reportlab",
    "matplotlib": "matplotlib",
}


def log(msg=""):
    print(msg, flush=True)


def executar(comando, check=True):
    log("")
    log("Executando:")
    log("  " + " ".join(str(x) for x in comando))
    resultado = subprocess.run(comando, check=False)
    if check and resultado.returncode != 0:
        raise subprocess.CalledProcessError(resultado.returncode, comando)
    return resultado.returncode


def porta_ativa():
    try:
        with socket.create_connection((ENDERECO, PORTA), timeout=1.5):
            return True
    except OSError:
        return False


def aguardar_inicio(tempo_maximo=45):
    inicio = time.time()
    while time.time() - inicio < tempo_maximo:
        if porta_ativa():
            return True
        time.sleep(1)
    return False


def garantir_venv():
    if PYTHON_VENV.exists():
        log(f"Ambiente .venv encontrado: {PYTHON_VENV}")
        return
    log("")
    log("Criando ambiente Python local (.venv)...")
    log(f"  Destino: {PASTA_VENV}")
    venv.create(str(PASTA_VENV), with_pip=True)
    if not PYTHON_VENV.exists():
        raise FileNotFoundError(
            f"Falha ao criar o venv. Python não encontrado em:\n  {PYTHON_VENV}"
        )
    log("Ambiente .venv criado com sucesso.")


def pacote_instalado(modulo):
    """Retorna True se o módulo importa no python do .venv."""
    r = subprocess.run(
        [str(PYTHON_VENV), "-c", f"import {modulo}"],
        capture_output=True,
        text=True,
    )
    return r.returncode == 0


def listar_pacotes_faltando():
    """Verifica biblioteca a biblioteca e devolve lista de nomes pip ausentes."""
    faltando = []
    log("")
    log("Validando bibliotecas instaladas...")
    for nome_pip, modulo in PACOTES.items():
        ok = pacote_instalado(modulo)
        status = "OK" if ok else "AUSENTE"
        log(f"  [{status}] {nome_pip} (import {modulo})")
        if not ok:
            faltando.append(nome_pip)
    return faltando


def instalar_pacotes(lista_pip):
    """Instala a lista de pacotes no .venv."""
    if not lista_pip:
        return
    log("")
    log("Instalando pacotes ausentes: " + ", ".join(lista_pip))
    log("(É necessária conexão com a internet apenas nesta etapa de instalação.)")

    executar(
        [
            str(PYTHON_VENV),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--upgrade",
            "pip",
            "setuptools",
            "wheel",
        ],
        check=False,
    )

    executar(
        [
            str(PYTHON_VENV),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--upgrade",
            *lista_pip,
        ],
        check=True,
    )
    log("Instalação concluída.")


def garantir_streamlit():
    """
    Verifica explicitamente se o Streamlit está instalado no .venv.
    Se não estiver, instala antes das demais bibliotecas.
    """
    log("")
    log("Verificando Streamlit (obrigatório para a interface web)...")
    if pacote_instalado("streamlit"):
        r = subprocess.run(
            [
                str(PYTHON_VENV),
                "-c",
                "import streamlit as st; print(getattr(st, '__version__', '?'))",
            ],
            capture_output=True,
            text=True,
        )
        versao = (r.stdout or "").strip() or "?"
        log(f"  [OK] Streamlit já instalado (versão {versao})")
        return

    log("  [AUSENTE] Streamlit não encontrado — instalando agora...")
    instalar_pacotes(["streamlit"])

    if not pacote_instalado("streamlit"):
        raise RuntimeError(
            "Falha ao instalar o Streamlit.\n"
            "Verifique a conexão com a internet e tente novamente:\n"
            f"  {PYTHON_VENV} -m pip install streamlit"
        )
    log("  [OK] Streamlit instalado com sucesso.")


def garantir_bibliotecas():
    """
    1) Garante Streamlit.
    2) Valida as demais bibliotecas e instala só as que faltam.
    """
    garantir_streamlit()

    faltando = listar_pacotes_faltando()
    faltando = [p for p in faltando if p != "streamlit"]
    if not faltando:
        log("")
        log("Todas as bibliotecas necessárias já estão instaladas.")
        return

    log("")
    log(f"{len(faltando)} biblioteca(s) ausente(s). Iniciando instalação...")
    instalar_pacotes(faltando)

    ainda = listar_pacotes_faltando()
    ainda = [p for p in ainda if p != "streamlit"]
    if ainda:
        log("")
        log("Ainda faltam pacotes — nova tentativa de instalação...")
        instalar_pacotes(ainda)
        ainda = [p for p in listar_pacotes_faltando() if p != "streamlit"]
        if ainda:
            raise RuntimeError(
                "Não foi possível instalar: " + ", ".join(ainda) + "\n"
                "Verifique a conexão com a internet e tente novamente."
            )

    log("")
    log("Todas as bibliotecas estão implantadas (incluindo reportlab e matplotlib).")


def main():
    log("=" * 60)
    log("ANALISADOR LOCAL DE PCAP (modo offline)")
    log("=" * 60)
    log(f"Pasta do projeto: {PASTA_PROJETO}")
    log(f"Aplicação:        {ARQUIVO_APP.name}")
    log(f"Python do venv:   {PYTHON_VENV}")
    log("")
    log("Modo de operação:")
    log("  • Análise de PCAP: 100% local (offline)")
    log("  • Nenhum arquivo PCAP é enviado à internet")
    log("  • Internet só é usada, se necessário, para instalar pacotes pip")
    log("  • Consultas externas (ip-api) só ocorrem se você ativar na interface")

    if not ARQUIVO_APP.exists():
        log("")
        log("ERRO: arquivo principal não encontrado:")
        log(f"  {ARQUIVO_APP}")
        log("")
        log("Coloque Analise_pcap_OT_multi_v3.py na mesma pasta que iniciar.py.")
        input("\nPressione Enter para sair...")
        return

    garantir_venv()
    garantir_bibliotecas()

    if porta_ativa():
        log("")
        log(f"A porta {PORTA} já está em uso.")
        log(f"Acesse: {URL_APLICACAO}")
        webbrowser.open(URL_APLICACAO)
        input("\nPressione Enter para sair...")
        return

    log("")
    log("Iniciando o analisador...")
    log(f"Endereço local: {URL_APLICACAO}")
    log("")
    log("Mantenha esta janela aberta enquanto utiliza a aplicação.")
    log("Para encerrar, pressione Ctrl+C neste terminal.")
    log("")

    processo = subprocess.Popen(
        [
            str(PYTHON_VENV),
            "-m",
            "streamlit",
            "run",
            str(ARQUIVO_APP),
            f"--server.address={ENDERECO}",
            f"--server.port={PORTA}",
            f"--browser.serverAddress={ENDERECO}",
            f"--browser.serverPort={PORTA}",
            "--server.headless=true",
            "--server.maxUploadSize=500",
            "--browser.gatherUsageStats=false",
        ]
    )

    if aguardar_inicio():
        log(f"Aplicação iniciada: {URL_APLICACAO}")
        webbrowser.open(URL_APLICACAO)
    else:
        log("O Streamlit não respondeu a tempo na porta configurada.")
        log(f"Tente abrir manualmente: {URL_APLICACAO}")

    try:
        processo.wait()
    except KeyboardInterrupt:
        log("")
        log("Encerrando aplicação...")
        processo.terminate()
        try:
            processo.wait(timeout=10)
        except Exception:
            processo.kill()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as erro:
        log("")
        log(f"ERRO ao instalar bibliotecas ou iniciar a aplicação: {erro}")
        log("Comando: " + " ".join(str(x) for x in (erro.cmd or [])))
        input("\nPressione Enter para sair...")
        sys.exit(1)
    except Exception as erro:
        log("")
        log(f"ERRO inesperado: {erro}")
        input("\nPressione Enter para sair...")
        sys.exit(1)
