import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.preprocessing import StandardScaler
import joblib
import json
import hashlib
from av_core.feature_extractors.static_features import StaticFeatureExtractor

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
MALWARE_DIR = os.path.join(SCRIPT_DIR, "data", "malware")
GOODWARE_DIR = os.path.join(SCRIPT_DIR, "data", "goodware")
VT_REPORTS_DIR = os.path.join(SCRIPT_DIR, "data", "vt_reports")
MODEL_DIR = os.path.join(SCRIPT_DIR, "models")
MODEL_OUTPUT_PATH = os.path.join(MODEL_DIR, "prisma_classifier.joblib")
COLUMNS_OUTPUT_PATH = os.path.join(MODEL_DIR, "model_columns.csv")
SCALER_OUTPUT_PATH = os.path.join(MODEL_DIR, "prisma_scaler.joblib")
DATASET_OUTPUT_PATH = os.path.join(PROJECT_ROOT, "enriched_dataset.csv")

def get_sha256_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except IOError:
        return None

def get_vt_features(file_hash):
    report_path = os.path.join(VT_REPORTS_DIR, f"{file_hash}.json")
    vt_features = {'vt_malicious': 0, 'vt_suspicious': 0, 'vt_undetected': 0}
    if os.path.exists(report_path):
        try:
            with open(report_path, 'r') as f:
                report = json.load(f)
            stats = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            vt_features['vt_malicious'] = stats.get('malicious', 0)
            vt_features['vt_suspicious'] = stats.get('suspicious', 0)
            vt_features['vt_undetected'] = stats.get('undetected', 0)
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Aviso: Não foi possível processar o relatório VT para o hash {file_hash}: {e}")
    return vt_features


def train():
    extractor = StaticFeatureExtractor()
    all_files_features = []
    
    print("--- Iniciando Treinamento Avançado (Pré-processamento e Métricas) ---")
    
    # ... (lógica de coleta de dados com os.walk() continua a mesma) ...
    print("Processando amostras de MALWARE...")
    for root, dirs, files in os.walk(MALWARE_DIR):
        for filename in files:
            filepath = os.path.join(root, filename)
            static_features = extractor.extract(filepath)
            if static_features:
                file_hash = get_sha256_hash(filepath)
                if file_hash:
                    vt_features = get_vt_features(file_hash)
                    combined_features = {**static_features, **vt_features}
                    combined_features['label'] = 1
                    all_files_features.append(combined_features)

    print("Processando amostras de GOODWARE...")
    for root, dirs, files in os.walk(GOODWARE_DIR):
        for filename in files:
            filepath = os.path.join(root, filename)
            static_features = extractor.extract(filepath)
            if static_features:
                file_hash = get_sha256_hash(filepath)
                if file_hash:
                    vt_features = get_vt_features(file_hash)
                    combined_features = {**static_features, **vt_features}
                    combined_features['label'] = 0
                    all_files_features.append(combined_features)
    
    if not all_files_features:
        print("Nenhum arquivo executável válido foi encontrado para treinamento.")
        return

    dataset = pd.DataFrame(all_files_features).fillna(0)
    dataset.to_csv(DATASET_OUTPUT_PATH, index=False)
    print(f"\nDataset enriquecido criado com {len(dataset)} amostras.")
    
    X = dataset.drop('label', axis=1)
    y = dataset['label']
    
    if len(y.unique()) < 2:
        print("ERRO: O dataset contém apenas uma classe. Não é possível treinar o modelo.")
        return
        
    X.head(1).to_csv(COLUMNS_OUTPUT_PATH, index=False)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("Aplicando padronização nas features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("Iniciando treinamento do modelo...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train_scaled, y_train)

    print("\n--- Avaliação Detalhada do Modelo ---")

    train_accuracy = accuracy_score(y_train, model.predict(X_train_scaled))
    test_accuracy = accuracy_score(y_test, model.predict(X_test_scaled))
    print(f"Acurácia no conjunto de TREINO: {train_accuracy*100:.2f}%")
    print(f"Acurácia no conjunto de TESTE: {test_accuracy*100:.2f}%")
    
    print("\nRelatório de Classificação (Teste):")
    report = classification_report(y_test, model.predict(X_test_scaled), target_names=['Goodware (0)', 'Malware (1)'])
    print(report)
    
    print("Matriz de Confusão (Teste):")
    print(confusion_matrix(y_test, model.predict(X_test_scaled), labels=[0, 1]))
    
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)
        
    joblib.dump(model, MODEL_OUTPUT_PATH)
    joblib.dump(scaler, SCALER_OUTPUT_PATH) 
    print(f"\nNovo modelo salvo em '{MODEL_OUTPUT_PATH}'")
    print(f"Scaler salvo em '{SCALER_OUTPUT_PATH}'")

if __name__ == '__main__':
    train()