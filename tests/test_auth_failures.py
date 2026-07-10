import os
import tempfile
import unittest
from pathlib import Path

from detection.auth_failures import (
    es_intento_fallido,
    extraer_ip,
    extraer_usuario,
    analizar_log_auth,
)


class TestAuthFailures(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HIPS_LOG_DIR"] = self.temp_dir.name

        self.log_auth = Path(self.temp_dir.name) / "secure.log"

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.pop("HIPS_LOG_DIR", None)

    def test_detecta_linea_failed_password(self):
        linea = "Jul 7 sshd[123]: Failed password for invalid user admin from 192.168.1.50 port 22 ssh2"
        self.assertTrue(es_intento_fallido(linea))

    def test_extrae_ip(self):
        linea = "Failed password for root from 10.0.0.15 port 22 ssh2"
        self.assertEqual(extraer_ip(linea), "10.0.0.15")

    def test_genera_alerta_si_supera_umbral(self):
        contenido = "\n".join([
            "Jul 7 sshd[1]: Failed password for root from 192.168.1.50 port 22 ssh2",
            "Jul 7 sshd[2]: Failed password for root from 192.168.1.50 port 22 ssh2",
            "Jul 7 sshd[3]: Invalid user test from 192.168.1.50 port 22",
            "Jul 7 sshd[4]: Failed publickey for root from 192.168.1.50 port 22 ssh2",
            "Jul 7 sshd[5]: authentication failure from 192.168.1.50",
        ])

        self.log_auth.write_text(contenido, encoding="utf-8")

        alertas = analizar_log_auth(str(self.log_auth), umbral=5)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["ip"], "192.168.1.50")
        self.assertEqual(alertas[0]["cantidad"], 5)

    def test_no_alerta_si_no_supera_umbral(self):
        contenido = "\n".join([
            "Jul 7 sshd[1]: Failed password for root from 192.168.1.51 port 22 ssh2",
            "Jul 7 sshd[2]: Failed password for root from 192.168.1.51 port 22 ssh2",
        ])

        self.log_auth.write_text(contenido, encoding="utf-8")

        alertas = analizar_log_auth(str(self.log_auth), umbral=5)

        self.assertEqual(len(alertas), 0)

    def test_detecta_credential_stuffing(self):
        contenido = "\n".join([
            "Jul 7 sshd[1]: Invalid user admin from 203.0.113.10 port 22",
            "Jul 7 sshd[2]: Invalid user soporte from 203.0.113.10 port 22",
            "Jul 7 sshd[3]: Failed password for root from 203.0.113.10 port 22 ssh2",
            "Jul 7 sshd[4]: Failed publickey for backup from 203.0.113.10 port 22 ssh2",
        ])

        self.log_auth.write_text(contenido, encoding="utf-8")

        alertas = analizar_log_auth(
            str(self.log_auth),
            umbral=99,
            umbral_usuarios=4
        )

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "credential_stuffing")
        self.assertEqual(alertas[0]["ip"], "203.0.113.10")
        self.assertEqual(alertas[0]["cantidad_usuarios"], 4)


if __name__ == "__main__":
    unittest.main()
