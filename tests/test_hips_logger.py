import json
import os
import re
import tempfile
import unittest
from pathlib import Path

from core.hips_logger import log_alarma, log_prevencion


class TestHipsLogger(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HIPS_LOG_DIR"] = self.temp_dir.name
        self.log_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.pop("HIPS_LOG_DIR", None)

    def test_log_alarma_crea_registro_formato_obligatorio(self):
        log_alarma(
            modulo="system_logs",
            severidad="alta",
            evento="sudo_fallido",
            detalle="Se detectó un intento fallido de sudo",
            extra={"ip_origen": "10.0.0.25"}
        )

        contenido = (self.log_dir / "alarmas.log").read_text(encoding="utf-8").strip()

        self.assertRegex(
            contenido,
            r"^\d{2}/\d{2}/\d{4} :: SUDO_FALLIDO :: 10\.0\.0\.25$"
        )

    def test_log_alarma_usa_na_si_no_hay_ip(self):
        log_alarma(
            modulo="sniffers",
            severidad="alta",
            evento="sniffer_detectado",
            detalle="Se detectó tcpdump",
            extra={"herramienta": "tcpdump"}
        )

        contenido = (self.log_dir / "alarmas.log").read_text(encoding="utf-8").strip()

        self.assertRegex(
            contenido,
            r"^\d{2}/\d{2}/\d{4} :: SNIFFER_DETECTADO :: N/A$"
        )

    def test_log_alarma_crea_detalle_json(self):
        log_alarma(
            modulo="tmp_monitor",
            severidad="media",
            evento="ejecutable_en_tmp",
            detalle="Archivo ejecutable detectado",
            extra={"archivo": "/tmp/test.sh"}
        )

        contenido = (self.log_dir / "alarmas_detalle.jsonl").read_text(encoding="utf-8").strip()
        registro = json.loads(contenido)

        self.assertEqual(registro["modulo"], "tmp_monitor")
        self.assertEqual(registro["evento"], "ejecutable_en_tmp")
        self.assertEqual(registro["extra"]["archivo"], "/tmp/test.sh")

    def test_log_prevencion_crea_registro_json(self):
        log_prevencion(
            modulo="prevention",
            severidad="alta",
            evento="bloquear_ip",
            detalle="IP bloqueada",
            extra={"ip": "10.0.0.25"}
        )

        contenido = (self.log_dir / "prevencion.log").read_text(encoding="utf-8").strip()
        registro = json.loads(contenido)

        self.assertEqual(registro["modulo"], "prevention")
        self.assertEqual(registro["evento"], "bloquear_ip")
        self.assertEqual(registro["extra"]["ip"], "10.0.0.25")


if __name__ == "__main__":
    unittest.main()
