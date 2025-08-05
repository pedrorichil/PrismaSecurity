import argparse
from av_core.analysis_engine.static_analyzer import StaticAnalyzer

def main():
    """Ponto de entrada para escanear arquivos via linha de comando."""
    parser = argparse.ArgumentParser(description="PrismaSecurity - Motor de Análise Estática.")
    parser.add_argument("--file", required=True, help="Caminho do arquivo a ser analisado.")
    args = parser.parse_args()

    MODEL_PATH = "av_core/models/static_classifier.joblib"
    COLUMNS_PATH = "av_core/models/model_columns.csv"

    analyzer = StaticAnalyzer(model_path=MODEL_PATH, columns_path=COLUMNS_PATH)
    result = analyzer.scan(args.file)

    print("--- Resultado da Análise ---")
    for key, value in result.items():
        print(f"{key.capitalize()}: {value}")
    print("--------------------------")

if __name__ == "__main__":
    # Exemplo de uso: python -m av_core.scan --file C:\Windows\explorer.exe
    main()