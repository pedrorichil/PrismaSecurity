import pefile
import math

class StaticFeatureExtractor:
    """Extrai características estáticas de um arquivo executável PE."""

    def get_entropy(self, data):
        """Calcula a entropia de um conjunto de dados."""
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy

    def extract(self, file_path):
        """
        Extrai um dicionário de features do arquivo.
        Retorna None se o arquivo não for um PE válido.
        """
        try:
            pe = pefile.PE(file_path, fast_load=True)
            features = {
                'Machine': pe.FILE_HEADER.Machine,
                'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
                'Characteristics': pe.FILE_HEADER.Characteristics,
                'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
                'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
                'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
                'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
                'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
                'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
                'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
                'NumberOfSections': pe.FILE_HEADER.NumberOfSections,
                'Imports_len': len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
                'Entropy': self.get_entropy(pe.get_memory_mapped_image())
            }
            return features
        except pefile.PEFormatError:
            return None