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
def scan_target(target, ports, save_results, results_list):
    if not is_active(target):  # Ignora IPs inativos
        print(f"[SKIPPED] {target} está inativo.")
        return
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((str(target), port))
                if result == 0:
                    result_text = f"[OPEN] {target}:{port}"
                    if save_results:
                        log_result(result_text)
                    else:
                        results_list.append(result_text)
                        print(result_text)
        except Exception as e:
            print(f"[ERROR] {target}:{port} - {e}")

# Função para salvar resultados em um arquivo dentro de Documentos
def log_result(text):
    documents_path = Path.home() / "Documents"  # Caminho para o diretório Documentos
    results_file = documents_path / "scan_results.txt"

    # Garante que o diretório existe
    documents_path.mkdir(parents=True, exist_ok=True)

    with open(results_file, "a") as file:
        file.write(text + "\n")

# Função para escanear uma sub-rede
def scan_network(network, ports, save_results, max_threads=100):
    ip_range = ipaddress.ip_network(network, strict=False)
    results_list = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for ip in ip_range:
            executor.submit(scan_target, ip, ports, save_results, results_list)
    return results_list

# Função para gerar IPs públicos automaticamente
def generate_global_ips(ports, save_results, max_threads=100, limit=None):
    results_list = []
    count = 0
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for a in range(1, 256):
            for b in range(0, 256):
                for c in range(0, 256):
                    for d in range(1, 256):  # Evita IPs reservados
                        if limit and count >= limit:
                            return results_list
                        target = f"{a}.{b}.{c}.{d}"
                        executor.submit(scan_target, target, ports, save_results, results_list)
                        count += 1
    return results_list

# Função para escanear uma lista de IPs específicos
def scan_specific_ips(ip_list, ports, save_results, max_threads=100):
    results_list = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for ip in ip_list:
            executor.submit(scan_target, ip, ports, save_results, results_list)
    return results_list

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

    if choice in ["1", "2", "3"]:
        save_choice = input("Deseja salvar os resultados em arquivo? (s/n): ").strip().lower()
        save_results = save_choice == "s"

        if choice == "1":
            network_range = input("Digite o range da rede interna (ex: 192.168.1.0/24): ").strip()
            print(f"Iniciando varredura na sub-rede {network_range} com {max_threads} threads...")
            results = scan_network(network_range, ports_to_scan, save_results, max_threads)

        elif choice == "2":
            limit = input("Quantos IPs você deseja escanear? (deixe vazio para todos): ").strip()
            limit = int(limit) if limit.isdigit() else None
            print(f"Iniciando varredura em IPs públicos com {max_threads} threads...")
            results = generate_global_ips(ports_to_scan, save_results, max_threads, limit)

        elif choice == "3":
            ips_input = input("Digite o(s) IP(s), separados por vírgula (ex: 192.168.1.1,192.168.1.2): ").strip()
            target_ips = [ip.strip() for ip in ips_input.split(",")]
            print(f"Iniciando varredura nos IPs especificados: {', '.join(target_ips)}...")
            results = scan_specific_ips(target_ips, ports_to_scan, save_results, max_threads)

        if not save_results:
            print("\n--- Resultados da Varredura ---")
            for result in results:
                print(result)

    else:
        print("Opção inválida. Saindo do programa.")
