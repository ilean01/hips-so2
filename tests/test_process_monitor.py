import os
import tempfile
import unittest

from detection.process_monitor import detectar_procesos_sospechosos, analizar_procesos


class TestProcessMonitor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HIPS_LOG_DIR"] = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.pop("HIPS_LOG_DIR", None)

    def test_detecta_netcat(self):
        salida = "1234 root 0.0 0.1 nc nc -lvnp 4444"
        alertas = detectar_procesos_sospechosos(salida)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "proceso_sospechoso")

    def test_detecta_cpu_alta(self):
        salida = "2222 ile 95.0 1.0 python python script.py"
        alertas = detectar_procesos_sospechosos(salida, cpu_umbral=80.0)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "cpu_alta")

    def test_detecta_memoria_alta(self):
        salida = "3333 ile 1.0 90.0 java java app.jar"
        alertas = detectar_procesos_sospechosos(salida, memoria_umbral=80.0)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "memoria_alta")

    def test_no_detecta_proceso_normal(self):
        salida = "4444 postgres 0.1 0.5 postgres postmaster"
        alertas = detectar_procesos_sospechosos(salida)

        self.assertEqual(len(alertas), 0)

    def test_analizar_procesos_registra_alerta(self):
        salida = "5555 root 0.0 0.1 nmap nmap -sS 127.0.0.1"
        alertas = analizar_procesos(salida)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "proceso_sospechoso")


if __name__ == "__main__":
    unittest.main()
