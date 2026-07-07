import json
import os
import tempfile
import unittest
from pathlib import Path

from core.hips_logger import log_alarma, log_prevencion


class TestHipsLogger(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HIPS_LOG_DIR"] = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.pop("HIPS_LOG_DIR", None)

    def test_log_alarma_crea_registro_json(self):
        log_alarma(
            modulo="archivos",
            severidad="alta",
            evento="cambio_detectado",
            detalle="Cambio sospechoso en /etc/passwd",
            extra={"archivo": "/etc/passwd"}
        )

        log_path = Path(self.temp_dir.name) / "alarmas.log"
        self.assertTrue(log_path.exists())

        linea = log_path.read_text(encoding="utf-8").strip()
        registro = json.loads(linea)

        self.assertEqual(registro["modulo"], "archivos")
        self.assertEqual(registro["severidad"], "alta")
        self.assertEqual(registro["evento"], "cambio_detectado")
        self.assertEqual(registro["extra"]["archivo"], "/etc/passwd")

    def test_log_prevencion_crea_registro_json(self):
        log_prevencion(
            modulo="procesos",
            severidad="critica",
            evento="proceso_finalizado",
            detalle="Se finalizó un proceso sospechoso",
            extra={"pid": 1234}
        )

        log_path = Path(self.temp_dir.name) / "prevencion.log"
        self.assertTrue(log_path.exists())

        linea = log_path.read_text(encoding="utf-8").strip()
        registro = json.loads(linea)

        self.assertEqual(registro["modulo"], "procesos")
        self.assertEqual(registro["severidad"], "critica")
        self.assertEqual(registro["evento"], "proceso_finalizado")
        self.assertEqual(registro["extra"]["pid"], 1234)


if __name__ == "__main__":
    unittest.main()
