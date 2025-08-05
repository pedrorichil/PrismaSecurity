import joblib
import pandas as pd
from av_core.feature_extractors.static_features import StaticFeatureExtractor

class StaticAnalyzer:
    """Carrega o modelo de IA estático e realiza predições."""
    
    def __init__(self, model_path, columns_path):
        try:
            self.model = joblib.load(model_path)
            self.model_columns = pd.read_csv(columns_path).columns.tolist()
            self.extractor = StaticFeatureExtractor()
        except FileNotFoundError:
            self.model = None
            self.model_columns = None
            print(f"AVISO: Modelo ou arquivo de colunas não encontrado. A análise estática está desativada.")

    def scan(self, file_path):
        """
        Escaneia um arquivo e retorna um dicionário com o veredito.
        Vereditos: "Clean", "Malicious", "Error", "Not_Supported"
        """
        if not self.model:
            return {"file": file_path, "verdict": "Error", "reason": "Model not loaded"}

        features = self.extractor.extract(file_path)

        if features is None:
            return {"file": file_path, "verdict": "Not_Supported", "reason": "Not a valid PE file"}
        
        # Garante que o dataframe tem as mesmas colunas do treino
        features_df = pd.DataFrame([features])
        live_df = features_df.reindex(columns=self.model_columns, fill_value=0)

        prediction = self.model.predict(live_df)[0]
        probability = self.model.predict_proba(live_df)[0]

        if prediction == 1:
            verdict = "Malicious"
            confidence = probability[1]
        else:
            verdict = "Clean"
            confidence = probability[0]
            
        return {
            "file": file_path, 
            "verdict": verdict, 
            "confidence": f"{confidence*100:.2f}%"
        }