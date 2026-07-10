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

    def test_detecta_scanner_http_patron_sospechoso(self):
        linea = '203.0.113.20 - - [09/Jul/2026:10:00:00 -0300] "GET /wp-admin/setup-config.php HTTP/1.1" 404 120 "-" "nikto"'
        alerta = analizar_linea_log(linea)

        self.assertIsNotNone(alerta)
        self.assertEqual(alerta["tipo"], "scanner_http")
        self.assertEqual(alerta["ip"], "203.0.113.20")

    def test_detecta_scanner_http_por_muchos_404(self):
        contenido = "\n".join([
            '203.0.113.21 - - [09/Jul/2026:10:00:00 -0300] "GET /noexiste1 HTTP/1.1" 404 120',
            '203.0.113.21 - - [09/Jul/2026:10:00:01 -0300] "GET /noexiste2 HTTP/1.1" 404 120',
            '203.0.113.21 - - [09/Jul/2026:10:00:02 -0300] "GET /noexiste3 HTTP/1.1" 404 120',
        ])

        alertas = analizar_logs_sistema(contenido, umbral_http_404=3)
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("scanner_http", tipos)
        self.assertEqual(alertas[-1]["ip"], "203.0.113.21")
        self.assertEqual(alertas[-1]["cantidad_404"], 3)


if __name__ == "__main__":
    unittest.main()
