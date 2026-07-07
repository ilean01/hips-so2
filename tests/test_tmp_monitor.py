import os
import stat
import tempfile
import unittest
from pathlib import Path

from detection.tmp_monitor import analizar_archivo_tmp, escanear_tmp


class TestTmpMonitor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HIPS_LOG_DIR"] = self.temp_dir.name

        self.tmp_simulado = Path(self.temp_dir.name) / "tmp"
        self.tmp_simulado.mkdir()

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.pop("HIPS_LOG_DIR", None)

    def test_detecta_archivo_oculto(self):
        archivo = self.tmp_simulado / ".secreto"
        archivo.write_text("dato oculto", encoding="utf-8")

        alertas = analizar_archivo_tmp(str(archivo))
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("archivo_oculto_tmp", tipos)

    def test_detecta_extension_sospechosa(self):
        archivo = self.tmp_simulado / "script.sh"
        archivo.write_text("#!/bin/bash\necho test", encoding="utf-8")

        alertas = analizar_archivo_tmp(str(archivo))
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("extension_sospechosa_tmp", tipos)

    def test_detecta_ejecutable(self):
        archivo = self.tmp_simulado / "ejecutable"
        archivo.write_text("binario falso", encoding="utf-8")
        archivo.chmod(0o755)

        alertas = analizar_archivo_tmp(str(archivo))
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("ejecutable_en_tmp", tipos)

    def test_detecta_world_writable(self):
        archivo = self.tmp_simulado / "publico.txt"
        archivo.write_text("modificable por todos", encoding="utf-8")
        archivo.chmod(0o666)

        alertas = analizar_archivo_tmp(str(archivo))
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("archivo_world_writable_tmp", tipos)

    def test_detecta_nombre_sospechoso(self):
        archivo = self.tmp_simulado / "reverse_shell.py"
        archivo.write_text("print('test')", encoding="utf-8")

        alertas = analizar_archivo_tmp(str(archivo))
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("nombre_sospechoso_tmp", tipos)

    def test_escanear_tmp_registra_alertas(self):
        archivo = self.tmp_simulado / "backdoor.sh"
        archivo.write_text("#!/bin/bash\necho backdoor", encoding="utf-8")
        archivo.chmod(0o755)

        alertas = escanear_tmp(str(self.tmp_simulado))

        self.assertGreaterEqual(len(alertas), 1)


if __name__ == "__main__":
    unittest.main()
