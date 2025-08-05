import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
from av_core.feature_extractors.static_features import StaticFeatureExtractor

# --- Configurações ---
MALWARE_DIR = "data/malware/"
GOODWARE_DIR = "data/goodware/"
MODEL_OUTPUT_PATH = "av_core/models/static_classifier.joblib"
COLUMNS_OUTPUT_PATH = "av_core/models/model_columns.csv"
DATASET_OUTPUT_PATH = "dataset.csv"

def train():
    """Função principal para criar o dataset e treinar o modelo."""
    extractor = StaticFeatureExtractor()
    all_files_features = []
    
    print("Iniciando extração de features...")
    # Extrai features de malware
    for filename in os.listdir(MALWARE_DIR):
        features = extractor.extract(os.path.join(MALWARE_DIR, filename))
        if features:
            features['label'] = 1
            all_files_features.append(features)

    # Extrai features de goodware
    for filename in os.listdir(GOODWARE_DIR):
        features = extractor.extract(os.path.join(GOODWARE_DIR, filename))
        if features:
            features['label'] = 0
            all_files_features.append(features)

    if not all_files_features:
        print("Nenhum arquivo válido encontrado nas pastas 'data'. Abortando.")
        return

    # Cria o DataFrame
    dataset = pd.DataFrame(all_files_features).fillna(0)
    dataset.to_csv(DATASET_OUTPUT_PATH, index=False)
    print(f"Dataset criado com {len(dataset)} amostras.")
    
    # Prepara para o treinamento
    X = dataset.drop('label', axis=1)
    y = dataset['label']
    
    # Salva as colunas para uso na predição
    X.head(1).to_csv(COLUMNS_OUTPUT_PATH, index=False)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("Iniciando treinamento do modelo...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    accuracy = accuracy_score(y_test, model.predict(X_test))
    print(f"Treinamento concluído. Acurácia: {accuracy*100:.2f}%")
    
    # Salva o modelo treinado
    joblib.dump(model, MODEL_OUTPUT_PATH)
    print(f"Modelo salvo em '{MODEL_OUTPUT_PATH}'")

if __name__ == '__main__':
    # Para treinar, execute: python -m av_core.trainer
    train()