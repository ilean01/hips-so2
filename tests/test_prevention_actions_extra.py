import os
import shutil
import tempfile
import unittest

LOG_DIR_TEST = tempfile.mkdtemp(prefix="hips_test_logs_")
os.environ["HIPS_LOG_DIR"] = LOG_DIR_TEST

from prevention.actions import (
    bloquear_usuario,
    documentar_integridad_archivo,
    reiniciar_postfix,
    limpiar_cola_correo,
    desactivar_modo_promiscuo,
)


class TestPreventionActionsExtra(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(LOG_DIR_TEST, ignore_errors=True)

    def test_no_bloquea_usuario_protegido(self):
        accion = bloquear_usuario("ile", dry_run=False)

        self.assertFalse(accion["ejecutado"])
        self.assertEqual(accion["motivo"], "usuario_protegido")

    def test_documentar_integridad_dry_run(self):
        accion = documentar_integridad_archivo(
            "/etc/passwd",
            motivo="prueba",
            dry_run=True
        )

        self.assertEqual(accion["accion"], "documentar_integridad_archivo")
        self.assertFalse(accion["ejecutado"])

    def test_reiniciar_postfix_dry_run(self):
        accion = reiniciar_postfix(dry_run=True)

        self.assertEqual(accion["accion"], "reiniciar_postfix")
        self.assertFalse(accion["ejecutado"])

    def test_limpiar_cola_correo_dry_run(self):
        accion = limpiar_cola_correo(dry_run=True)

        self.assertEqual(accion["accion"], "limpiar_cola_correo")
        self.assertFalse(accion["ejecutado"])

    def test_desactivar_promiscuo_dry_run(self):
        accion = desactivar_modo_promiscuo("eth0", dry_run=True)

        self.assertEqual(accion["accion"], "desactivar_modo_promiscuo")
        self.assertFalse(accion["ejecutado"])


if __name__ == "__main__":
    unittest.main()
