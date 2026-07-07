import os
import tempfile
import unittest
from pathlib import Path

from detection.file_integrity import (
    calcular_sha256,
    crear_baseline,
    guardar_baseline,
    cargar_baseline,
    verificar_integridad,
)


class TestFileIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HIPS_LOG_DIR"] = self.temp_dir.name

        self.archivo = Path(self.temp_dir.name) / "archivo_importante.txt"
        self.archivo.write_text("contenido original", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.pop("HIPS_LOG_DIR", None)

    def test_calcular_sha256_devuelve_hash(self):
        resultado = calcular_sha256(str(self.archivo))

        self.assertEqual(len(resultado), 64)

    def test_crear_guardar_y_cargar_baseline(self):
        baseline = crear_baseline([str(self.archivo)])
        ruta_baseline = Path(self.temp_dir.name) / "baseline.json"

        guardar_baseline(baseline, str(ruta_baseline))
        baseline_cargado = cargar_baseline(str(ruta_baseline))

        self.assertIn(str(self.archivo), baseline_cargado)
        self.assertEqual(baseline_cargado[str(self.archivo)]["estado"], "ok")

    def test_detecta_archivo_modificado(self):
        baseline = crear_baseline([str(self.archivo)])

        self.archivo.write_text("contenido alterado", encoding="utf-8")

        alertas = verificar_integridad(baseline)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "archivo_modificado")

    def test_detecta_archivo_eliminado(self):
        baseline = crear_baseline([str(self.archivo)])

        self.archivo.unlink()

        alertas = verificar_integridad(baseline)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "archivo_eliminado")


if __name__ == "__main__":
    unittest.main()
