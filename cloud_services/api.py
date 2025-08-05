from flask import Flask, request, jsonify
from av_core.analysis_engine.static_analyzer import StaticAnalyzer
import os

# Inicializa o servidor Flask e o motor de análise
app = Flask(__name__)
print("Iniciando motor de análise para o servidor local...")
MODEL_PATH = "av_core/models/static_classifier.joblib"
COLUMNS_PATH = "av_core/models/model_columns.csv"
analyzer = StaticAnalyzer(model_path=MODEL_PATH, columns_path=COLUMNS_PATH)
print("Motor carregado. Servidor pronto.")


@app.route('/scan', methods=['POST'])
def scan_endpoint():
    """Endpoint que recebe um caminho de arquivo e retorna a análise."""
    data = request.get_json()
    if not data or 'file_path' not in data:
        return jsonify({"error": "O caminho do arquivo ('file_path') é obrigatório."}), 400
    
    file_path = data['file_path']
    if not os.path.exists(file_path):
        return jsonify({"error": "Arquivo não encontrado."}), 404

    # Usa o motor de análise para escanear o arquivo
    result = analyzer.scan(file_path)
    
    return jsonify(result)

def run_scanner_service():
    # 'host="127.0.0.1"' garante que o servidor só seja acessível localmente.
    app.run(host="127.0.0.1", port=5000, debug=False)

if __name__ == '__main__':
    # Para iniciar o servidor, execute: python -m cloud_services.api
    run_scanner_service()