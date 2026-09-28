import socket
import subprocess
import time
import venv
import webbrowser
from pathlib import Path


PASTA_PROJETO = Path(__file__).resolve().parent
ARQUIVO_APP = PASTA_PROJETO / "Analise_pcap_00.py"

PASTA_VENV = PASTA_PROJETO / ".venv"
PYTHON_VENV = PASTA_VENV / "Scripts" / "python.exe"

ENDERECO = "127.0.0.1"
PORTA = 8502
URL_APLICACAO = f"http://{ENDERECO}:{PORTA}"

PACOTES_NECESSARIOS = [
    "streamlit",
    "scapy",
    "pandas",
    "plotly",
    "networkx",
    "pyvis",
]

ARQUIVOS_VERIFICACAO = [
    PASTA_VENV / "Lib" / "site-packages" / "streamlit" / "proto" / "RootContainer_pb2.py",
    PASTA_VENV / "Lib" / "site-packages" / "scapy" / "__init__.py",
    PASTA_VENV / "Lib" / "site-packages" / "pandas" / "__init__.py",
    PASTA_VENV / "Lib" / "site-packages" / "plotly" / "__init__.py",
    PASTA_VENV / "Lib" / "site-packages" / "networkx" / "__init__.py",
    PASTA_VENV / "Lib" / "site-packages" / "pyvis" / "__init__.py",
]


def executar(comando):
    print("\nExecutando:")
    print(" ".join(str(item) for item in comando))
    subprocess.run(comando, check=True)


def bibliotecas_instaladas():
    return all(arquivo.exists() for arquivo in ARQUIVOS_VERIFICACAO)


def instalar_bibliotecas():
    print("\nInstalando bibliotecas no ambiente local .venv...")

    executar(
        [
            str(PYTHON_VENV),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--upgrade",
            "pip",
        ]
    )

    executar(
        [
            str(PYTHON_VENV),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--force-reinstall",
            *PACOTES_NECESSARIOS,
        ]
    )


def porta_ativa():
    try:
        with socket.create_connection((ENDERECO, PORTA), timeout=1):
            return True
    except OSError:
        return False


def aguardar_inicio(tempo_maximo=30):
    inicio = time.time()

    while time.time() - inicio < tempo_maximo:
        if porta_ativa():
            return True

        time.sleep(1)

    return False


def main():
    print("=" * 60)
    print("ANALISADOR LOCAL DE PCAP")
    print("=" * 60)
    print(f"Pasta do projeto: {PASTA_PROJETO}")

    if not ARQUIVO_APP.exists():
        print("\nErro: arquivo principal não encontrado:")
        print(ARQUIVO_APP)
        input("\nPressione Enter para sair...")
        return

    if not PYTHON_VENV.exists():
        print("\nCriando ambiente Python local .venv...")
        venv.create(PASTA_VENV, with_pip=True)

    if not bibliotecas_instaladas():
        instalar_bibliotecas()
    else:
        print("\nBibliotecas locais verificadas com sucesso.")

    if porta_ativa():
        print(f"\nA porta {PORTA} já está em uso.")
        print(f"Acesse: {URL_APLICACAO}")
        webbrowser.open(URL_APLICACAO)
        input("\nPressione Enter para sair...")
        return

    print("\nIniciando o analisador...")
    print(f"Endereço local: {URL_APLICACAO}")
    print("\nMantenha esta janela aberta enquanto utiliza a aplicação.")
    print("Para encerrar, pressione Ctrl + C neste terminal.\n")

    processo = subprocess.Popen(
        [
            str(PYTHON_VENV),
            "-m",
            "streamlit",
            "run",
            str(ARQUIVO_APP),
            "--server.address=127.0.0.1",
            "--server.port=8502",
            "--browser.serverAddress=127.0.0.1",
            "--browser.serverPort=8502",
            "--server.headless=true",
            "--server.maxUploadSize=500",
            "--browser.gatherUsageStats=false",
        ]
    )

    if aguardar_inicio():
        print(f"\nAplicação iniciada: {URL_APLICACAO}")
        webbrowser.open(URL_APLICACAO)
    else:
        print("\nO Streamlit não respondeu na porta configurada.")
        print(f"Tente abrir manualmente: {URL_APLICACAO}")

    try:
        processo.wait()
    except KeyboardInterrupt:
        print("\nEncerrando aplicação...")
        processo.terminate()
        processo.wait()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as erro:
        print(f"\nErro ao instalar bibliotecas ou iniciar a aplicação: {erro}")
        input("\nPressione Enter para sair...")
    except Exception as erro:
        print(f"\nErro inesperado: {erro}")
        input("\nPressione Enter para sair...")