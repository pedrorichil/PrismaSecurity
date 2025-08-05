import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QPushButton, QVBoxLayout, 
                             QWidget, QFileDialog, QLabel, QTextBrowser)
from av_core.analysis_engine.static_analyzer import StaticAnalyzer

class PrismaSecurityApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PrismaSecurity")
        self.setGeometry(100, 100, 500, 400)

        # Inicializa o motor de análise
        MODEL_PATH = "av_core/models/static_classifier.joblib"
        COLUMNS_PATH = "av_core/models/model_columns.csv"
        self.analyzer = StaticAnalyzer(model_path=MODEL_PATH, columns_path=COLUMNS_PATH)

        # Layout
        layout = QVBoxLayout()
        
        self.status_label = QLabel("Bem-vindo ao PrismaSecurity. Pronto para escanear.")
        layout.addWidget(self.status_label)

        self.scan_button = QPushButton("Escanear Arquivo")
        self.scan_button.clicked.connect(self.scan_file)
        layout.addWidget(self.scan_button)

        self.result_browser = QTextBrowser()
        layout.addWidget(self.result_browser)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def scan_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Selecionar Arquivo para Escanear")
        if file_path:
            self.status_label.setText(f"Analisando: {file_path}...")
            QApplication.processEvents() # Atualiza a UI
            
            result = self.analyzer.scan(file_path)
            
            self.display_result(result)
            self.status_label.setText("Análise concluída. Pronto para o próximo.")

    def display_result(self, result):
        html_result = f"""
        <h3>Resultado da Análise</h3>
        <p><b>Arquivo:</b> {result.get('file', 'N/A')}</p>
        <p><b>Veredito:</b> <font color='{'red' if result.get('verdict') == 'Malicious' else 'green'}'>{result.get('verdict', 'N/A')}</font></p>
        <p><b>Confiança:</b> {result.get('confidence', 'N/A')}</p>
        <p><b>Detalhes:</b> {result.get('reason', 'Análise de modelo de IA.')}</p>
        """
        self.result_browser.setHtml(html_result)

def launch_ui():
    app = QApplication(sys.argv)
    window = PrismaSecurityApp()
    window.show()
    sys.exit(app.exec())