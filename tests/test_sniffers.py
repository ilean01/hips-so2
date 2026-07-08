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
        salida = "1234 root 0.0 0.1 tcpdump /usr/sbin/tcpdump -i lo"
        alertas = detectar_sniffers_en_texto(salida)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "sniffer_detectado")
        self.assertEqual(alertas[0]["herramienta"], "tcpdump")

    def test_detecta_tshark(self):
        salida = "2222 root 0.0 0.1 tshark /usr/bin/tshark -i enp0s3"
        alertas = detectar_sniffers_en_texto(salida)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["herramienta"], "tshark")

    def test_no_detecta_proceso_normal(self):
        salida = "3333 ile 0.0 0.1 firefox /usr/lib64/firefox/firefox"
        alertas = detectar_sniffers_en_texto(salida)

        self.assertEqual(len(alertas), 0)

    def test_no_detecta_wrapper_sudo_con_tcpdump_en_argumentos(self):
        salida = "4444 root 0.0 0.1 sudo sudo timeout 60 /usr/sbin/tcpdump -i lo"
        alertas = detectar_sniffers_en_texto(salida)

        self.assertEqual(len(alertas), 0)

    def test_no_detecta_wrapper_timeout_con_tcpdump_en_argumentos(self):
        salida = "5555 root 0.0 0.1 timeout timeout 60 /usr/sbin/tcpdump -i lo"
        alertas = detectar_sniffers_en_texto(salida)

        self.assertEqual(len(alertas), 0)

    def test_analizar_registra_alerta(self):
        salida = "6666 root 0.0 0.1 tcpdump /usr/sbin/tcpdump -i lo"
        alertas = analizar_procesos_sniffers(salida)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["herramienta"], "tcpdump")


if __name__ == "__main__":
    unittest.main()
