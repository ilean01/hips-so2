import os
import tempfile
import unittest
from pathlib import Path

from prevention.actions import (
    validar_ip,
    bloquear_ip,
    finalizar_proceso,
    cuarentenar_archivo,
)


class TestPreventionActions(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HIPS_LOG_DIR"] = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.pop("HIPS_LOG_DIR", None)

    def test_valida_ip_correcta(self):
        self.assertTrue(validar_ip("192.168.1.10"))

    def test_rechaza_ip_invalida(self):
        self.assertFalse(validar_ip("999.168.1.10"))

    def test_bloquear_ip_dry_run(self):
        accion = bloquear_ip("10.0.0.50", dry_run=True)

        self.assertEqual(accion["accion"], "bloquear_ip")
        self.assertEqual(accion["ip"], "10.0.0.50")
        self.assertTrue(accion["dry_run"])
        self.assertFalse(accion["ejecutado"])

    def test_bloquear_ip_invalida_lanza_error(self):
        with self.assertRaises(ValueError):
            bloquear_ip("10.0.0.999", dry_run=True)

    def test_finalizar_proceso_dry_run(self):
        accion = finalizar_proceso(1234, dry_run=True)

        self.assertEqual(accion["accion"], "finalizar_proceso")
        self.assertEqual(accion["pid"], 1234)
        self.assertFalse(accion["ejecutado"])

    def test_finalizar_proceso_pid_invalido(self):
        with self.assertRaises(ValueError):
            finalizar_proceso(-1, dry_run=True)

    def test_cuarentenar_archivo_dry_run_no_mueve(self):
        archivo = Path(self.temp_dir.name) / "sospechoso.sh"
        archivo.write_text("#!/bin/bash\necho test", encoding="utf-8")

        accion = cuarentenar_archivo(
            str(archivo),
            ruta_cuarentena=str(Path(self.temp_dir.name) / "cuarentena"),
            dry_run=True
        )

        self.assertTrue(archivo.exists())
        self.assertFalse(accion["ejecutado"])
        self.assertEqual(accion["accion"], "cuarentenar_archivo")

    def test_cuarentenar_archivo_real_mueve_a_cuarentena(self):
        archivo = Path(self.temp_dir.name) / "malware_falso.sh"
        archivo.write_text("#!/bin/bash\necho malware falso", encoding="utf-8")

        cuarentena = Path(self.temp_dir.name) / "cuarentena"

        accion = cuarentenar_archivo(
            str(archivo),
            ruta_cuarentena=str(cuarentena),
            dry_run=False
        )

        self.assertFalse(archivo.exists())
        self.assertTrue(Path(accion["destino"]).exists())
        self.assertTrue(accion["ejecutado"])


if __name__ == "__main__":
    unittest.main()
