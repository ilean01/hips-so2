import os
import tempfile
import unittest

from detection.user_monitor import (
    parsear_passwd,
    crear_baseline_usuarios,
    detectar_cambios_usuarios,
    analizar_usuarios,
)


PASSWD_BASE = """root:x:0:0:root:/root:/bin/bash
postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash
hips_svc:x:987:986:HIPS Service:/nonexistent:/usr/sbin/nologin
ile:x:1000:1000:Ile:/home/ile:/bin/bash
"""


class TestUserMonitor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HIPS_LOG_DIR"] = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.pop("HIPS_LOG_DIR", None)

    def test_parsea_passwd(self):
        usuarios = parsear_passwd(PASSWD_BASE)

        self.assertIn("root", usuarios)
        self.assertEqual(usuarios["root"]["uid"], 0)

    def test_detecta_usuario_nuevo(self):
        baseline = crear_baseline_usuarios(PASSWD_BASE)
        passwd_actual = PASSWD_BASE + "intruso:x:2000:2000:Intruso:/home/intruso:/bin/bash\n"

        alertas = detectar_cambios_usuarios(baseline, passwd_actual)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "usuario_nuevo")

    def test_detecta_usuario_eliminado(self):
        baseline = crear_baseline_usuarios(PASSWD_BASE)
        passwd_actual = """root:x:0:0:root:/root:/bin/bash
postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash
hips_svc:x:987:986:HIPS Service:/nonexistent:/usr/sbin/nologin
"""

        alertas = detectar_cambios_usuarios(baseline, passwd_actual)

        tipos = [alerta["tipo"] for alerta in alertas]
        self.assertIn("usuario_eliminado", tipos)

    def test_detecta_uid_0_no_root(self):
        baseline = crear_baseline_usuarios(PASSWD_BASE)
        passwd_actual = PASSWD_BASE + "backdoor:x:0:0:Backdoor:/root:/bin/bash\n"

        alertas = detectar_cambios_usuarios(baseline, passwd_actual)

        tipos = [alerta["tipo"] for alerta in alertas]
        self.assertIn("usuario_uid_0", tipos)

    def test_detecta_shell_interactiva_agregada(self):
        baseline = crear_baseline_usuarios(PASSWD_BASE)
        passwd_actual = PASSWD_BASE.replace(
            "hips_svc:x:987:986:HIPS Service:/nonexistent:/usr/sbin/nologin",
            "hips_svc:x:987:986:HIPS Service:/nonexistent:/bin/bash"
        )

        alertas = detectar_cambios_usuarios(baseline, passwd_actual)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "shell_interactiva_agregada")

    def test_analizar_usuarios_registra_alerta(self):
        baseline = crear_baseline_usuarios(PASSWD_BASE)
        passwd_actual = PASSWD_BASE + "intruso:x:2000:2000:Intruso:/home/intruso:/bin/bash\n"

        alertas = analizar_usuarios(baseline, passwd_actual)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "usuario_nuevo")


if __name__ == "__main__":
    unittest.main()
