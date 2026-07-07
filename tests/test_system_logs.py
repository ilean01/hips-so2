import os
import tempfile
import unittest

from detection.system_logs import analizar_linea_log, analizar_logs_sistema


class TestSystemLogs(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HIPS_LOG_DIR"] = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.pop("HIPS_LOG_DIR", None)

    def test_detecta_segfault(self):
        linea = "kernel: app[1234]: segfault at 0 ip 00007f error 4"
        alerta = analizar_linea_log(linea)

        self.assertIsNotNone(alerta)
        self.assertEqual(alerta["tipo"], "segfault_detectado")

    def test_detecta_oom(self):
        linea = "kernel: Out of memory: Killed process 2222 (python)"
        alerta = analizar_linea_log(linea)

        self.assertIsNotNone(alerta)
        self.assertEqual(alerta["tipo"], "oom_detectado")

    def test_detecta_servicio_fallido(self):
        linea = "systemd[1]: Failed to start PostgreSQL database server."
        alerta = analizar_linea_log(linea)

        self.assertIsNotNone(alerta)
        self.assertEqual(alerta["tipo"], "servicio_fallido")

    def test_detecta_selinux_denied(self):
        linea = "audit: AVC denied { read } for pid=123 comm=python"
        alerta = analizar_linea_log(linea)

        self.assertIsNotNone(alerta)
        self.assertEqual(alerta["tipo"], "selinux_denied")

    def test_analiza_varias_lineas(self):
        contenido = "\n".join([
            "systemd[1]: Started PostgreSQL database server.",
            "sudo: pam_unix(sudo:auth): authentication failure",
            "kernel: app[777]: segfault at 0 ip 00007f error 4",
            "normal log line without problem",
        ])

        alertas = analizar_logs_sistema(contenido)

        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertEqual(len(alertas), 2)
        self.assertIn("sudo_fallido", tipos)
        self.assertIn("segfault_detectado", tipos)


if __name__ == "__main__":
    unittest.main()
