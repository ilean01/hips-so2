import os
import tempfile
import unittest

from detection.ddos_monitor import (
    extraer_ips,
    extraer_ip_remota,
    extraer_estado,
    analizar_conexiones_red,
)


class TestDdosMonitor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HIPS_LOG_DIR"] = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.pop("HIPS_LOG_DIR", None)

    def test_extrae_ips(self):
        linea = "ESTAB 0 0 192.168.1.10:22 10.0.0.50:50500"
        ips = extraer_ips(linea)

        self.assertEqual(ips, ["192.168.1.10", "10.0.0.50"])

    def test_extrae_ip_remota(self):
        linea = "ESTAB 0 0 192.168.1.10:22 10.0.0.50:50500"
        ip = extraer_ip_remota(linea)

        self.assertEqual(ip, "10.0.0.50")

    def test_extrae_estado(self):
        linea = "SYN-RECV 0 0 192.168.1.10:80 10.0.0.99:44444"
        estado = extraer_estado(linea)

        self.assertEqual(estado, "SYN-RECV")

    def test_detecta_muchas_conexiones_desde_ip(self):
        lineas = []

        for puerto in range(10000, 10005):
            lineas.append(f"ESTAB 0 0 192.168.1.10:80 10.0.0.50:{puerto}")

        salida = "\n".join(lineas)

        alertas = analizar_conexiones_red(salida, umbral_conexiones=5, umbral_syn=99)
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("muchas_conexiones_desde_ip", tipos)

    def test_detecta_posible_syn_flood(self):
        lineas = []

        for puerto in range(20000, 20004):
            lineas.append(f"SYN-RECV 0 0 192.168.1.10:80 10.0.0.99:{puerto}")

        salida = "\n".join(lineas)

        alertas = analizar_conexiones_red(salida, umbral_conexiones=99, umbral_syn=4)
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("posible_syn_flood", tipos)

    def test_no_alerta_con_pocas_conexiones(self):
        salida = "ESTAB 0 0 192.168.1.10:22 10.0.0.20:50500"

        alertas = analizar_conexiones_red(salida, umbral_conexiones=5, umbral_syn=5)

        self.assertEqual(len(alertas), 0)


if __name__ == "__main__":
    unittest.main()
