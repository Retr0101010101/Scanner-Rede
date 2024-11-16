import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import os
import subprocess
from pathlib import Path

# Função para verificar se um IP está ativo (Ping)
def is_active(ip):
    try:
        command = ["ping", "-c", "1", str(ip)] if os.name != "nt" else ["ping", "-n", "1", str(ip)]
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception as e:
        print(f"[ERROR] Erro ao verificar atividade de {ip}: {e}")
        return False

# Função para escanear portas em um único IP
def scan_target(target, ports):
    if not is_active(target):  # Ignora IPs inativos
        print(f"[SKIPPED] {target} está inativo.")
        return
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((str(target), port))
                if result == 0:
                    log_result(target, port)
                    print(f"[OPEN] {target}:{port}")
        except Exception as e:
            print(f"[ERROR] {target}:{port} - {e}")

# Função para salvar resultados em um arquivo dentro de Documentos
def log_result(ip, port):
    documents_path = Path.home() / "Documents"  # Caminho para o diretório Documentos
    results_file = documents_path / "scan_results.txt"

    # Garante que o diretório existe
    documents_path.mkdir(parents=True, exist_ok=True)

    with open(results_file, "a") as file:
        file.write(f"[OPEN] {ip}:{port}\n")

# Função para escanear uma sub-rede
def scan_network(network, ports, max_threads=100):
    ip_range = ipaddress.ip_network(network, strict=False)
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for ip in ip_range:
            executor.submit(scan_target, ip, ports)

# Função para gerar IPs públicos automaticamente
def generate_global_ips(ports, max_threads=100, limit=None):
    count = 0
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for a in range(1, 256):
            for b in range(0, 256):
                for c in range(0, 256):
                    for d in range(1, 256):  # Evita IPs reservados
                        if limit and count >= limit:
                            return
                        target = f"{a}.{b}.{c}.{d}"
                        executor.submit(scan_target, target, ports)
                        count += 1

# Função para escanear uma lista de IPs específicos
def scan_specific_ips(ip_list, ports, max_threads=100):
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for ip in ip_list:
            executor.submit(scan_target, ip, ports)

# Função principal com menu para o usuário
if __name__ == "__main__":
    print("Escolha o tipo de varredura:")
    print("1 - Varredura de rede interna (sub-rede)")
    print("2 - Varredura global de IPs públicos")
    print("3 - Varredura em IPs específicos (informe uma lista)")
    choice = input("Digite sua escolha (1, 2 ou 3): ").strip()

    # Configuração de portas e threads
    ports_to_scan = [22, 80, 443]  # Adicione mais portas, se necessário
    max_threads = 100  # Número de threads simultâneas

    # Limpa o arquivo de resultados ao iniciar
    documents_path = Path.home() / "Documents"
    results_file = documents_path / "scan_results.txt"
    if results_file.exists():
        results_file.unlink()  # Remove o arquivo existente

    if choice == "1":
        network_range = input("Digite o range da rede interna (ex: 192.168.1.0/24): ").strip()
        print(f"Iniciando varredura na sub-rede {network_range} com {max_threads} threads...")
        scan_network(network_range, ports_to_scan, max_threads)

    elif choice == "2":
        limit = input("Quantos IPs você deseja escanear? (deixe vazio para todos): ").strip()
        limit = int(limit) if limit.isdigit() else None
        print(f"Iniciando varredura em IPs públicos com {max_threads} threads...")
        generate_global_ips(ports_to_scan, max_threads, limit)

    elif choice == "3":
        ips_input = input("Digite o(s) IP(s), separados por vírgula (ex: 192.168.1.1,192.168.1.2): ").strip()
        target_ips = [ip.strip() for ip in ips_input.split(",")]
        print(f"Iniciando varredura nos IPs especificados: {', '.join(target_ips)}...")
        scan_specific_ips(target_ips, ports_to_scan, max_threads)

    else:
        print("Opção inválida. Saindo do programa.")
