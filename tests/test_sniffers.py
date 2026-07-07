import os
import tempfile
import unittest

from detection.sniffers import detectar_sniffers_en_texto, analizar_procesos_sniffers


class TestSniffers(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HIPS_LOG_DIR"] = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.pop("HIPS_LOG_DIR", None)

    def test_detecta_tcpdump(self):
        procesos = "root 1234 0.0 tcpdump -i enp0s3"
        alertas = detectar_sniffers_en_texto(procesos)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["herramienta"], "tcpdump")

    def test_detecta_tshark(self):
        procesos = "user 2222 0.0 tshark -i eth0"
        alertas = detectar_sniffers_en_texto(procesos)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["herramienta"], "tshark")

    def test_no_detecta_proceso_normal(self):
        procesos = "root 1000 0.0 /usr/sbin/sshd\npostgres 2000 postmaster"
        alertas = detectar_sniffers_en_texto(procesos)

        self.assertEqual(len(alertas), 0)

    def test_analizar_registra_alerta(self):
        procesos = "root 3333 0.0 wireshark"
        alertas = analizar_procesos_sniffers(procesos)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "sniffer_detectado")


if __name__ == "__main__":
    unittest.main()
