import requests
import json

# Endereço do nosso servidor de análise local
SCAN_API_URL = "http://127.0.0.1:5000/scan"

def test_scan_file(file_path):
    """
    Função cliente em Python para se comunicar com o serviço de análise.
    O serviço em Rust fará uma requisição HTTP similar a esta.
    """
    headers = {"Content-Type": "application/json"}
    payload = {"file_path": file_path}

    try:
        response = requests.post(SCAN_API_URL, headers=headers, data=json.dumps(payload))
        response.raise_for_status() # Lança um erro para status
        
        print("--- Resposta da API ---")
        print(json.dumps(response.json(), indent=2))
        print("-----------------------")
        
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"Erro ao se comunicar com a API de análise: {e}")
        return None

if __name__ == '__main__':
    # Antes de executar, certifique-se que o servidor está rodando:
    # python -m cloud_services.api
    #
    # Exemplo de teste:
    # python -m real_time_monitor.ffi_bridge
    test_scan_file(r"C:\Windows\System32\notepad.exe") # Use 'r' para strings de caminho no Windows