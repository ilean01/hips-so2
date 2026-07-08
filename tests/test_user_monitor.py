import os
import tempfile
import unittest

from detection.user_monitor import (
    parsear_passwd,
    crear_baseline_usuarios,
    detectar_cambios_usuarios,
    analizar_usuarios,
    parsear_who,
    detectar_usuarios_conectados,
    analizar_usuarios_conectados,
)


PASSWD_BASE = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
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

        self.assertEqual(usuarios["root"]["uid"], 0)
        self.assertEqual(usuarios["ile"]["shell"], "/bin/bash")

    def test_detecta_usuario_nuevo(self):
        baseline = crear_baseline_usuarios(PASSWD_BASE)
        actual = PASSWD_BASE + "intruso:x:2000:2000:Intruso:/home/intruso:/bin/bash\n"

        alertas = detectar_cambios_usuarios(baseline, actual)

        self.assertEqual(alertas[0]["tipo"], "usuario_nuevo")

    def test_detecta_usuario_eliminado(self):
        baseline = crear_baseline_usuarios(PASSWD_BASE)
        actual = PASSWD_BASE.replace("ile:x:1000:1000:Ile:/home/ile:/bin/bash\n", "")

        alertas = detectar_cambios_usuarios(baseline, actual)

        self.assertTrue(any(alerta["tipo"] == "usuario_eliminado" for alerta in alertas))

    def test_detecta_uid_0_no_root(self):
        baseline = crear_baseline_usuarios(PASSWD_BASE)
        actual = PASSWD_BASE + "backdoor:x:0:0:Backdoor:/root:/bin/bash\n"

        alertas = detectar_cambios_usuarios(baseline, actual)

        self.assertTrue(any(alerta["tipo"] == "usuario_uid_0" for alerta in alertas))

    def test_detecta_shell_interactiva_agregada(self):
        base = PASSWD_BASE + "servicio:x:1500:1500:Servicio:/srv:/usr/sbin/nologin\n"
        baseline = crear_baseline_usuarios(base)
        actual = PASSWD_BASE + "servicio:x:1500:1500:Servicio:/srv:/bin/bash\n"

        alertas = detectar_cambios_usuarios(baseline, actual)

        self.assertTrue(any(alerta["tipo"] == "shell_interactiva_agregada" for alerta in alertas))

    def test_analizar_usuarios_registra_alerta(self):
        baseline = crear_baseline_usuarios(PASSWD_BASE)
        actual = PASSWD_BASE + "intruso:x:2000:2000:Intruso:/home/intruso:/bin/bash\n"

        alertas = analizar_usuarios(baseline, actual)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "usuario_nuevo")

    def test_parsea_who_local(self):
        salida = "ile tty2 2026-07-08 14:00 (local)"
        sesiones = parsear_who(salida)

        self.assertEqual(len(sesiones), 1)
        self.assertEqual(sesiones[0]["usuario"], "ile")
        self.assertEqual(sesiones[0]["origen"], "local")

    def test_detecta_origen_login_inusual(self):
        salida = "ile pts/0 2026-07-08 14:00 (203.0.113.10)"
        alertas = detectar_usuarios_conectados(
            salida,
            origenes_permitidos={"local", "127.0.0.1"}
        )

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "origen_login_inusual")

    def test_detecta_login_fuera_horario(self):
        salida = "ile tty2 2026-07-08 02:00 (local)"
        alertas = detectar_usuarios_conectados(
            salida,
            origenes_permitidos={"local"},
            hora_inicio=6,
            hora_fin=23
        )

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "login_fuera_horario")

    def test_no_alerta_usuario_local_en_horario(self):
        salida = "ile tty2 2026-07-08 14:00 (local)"
        alertas = detectar_usuarios_conectados(
            salida,
            origenes_permitidos={"local"},
            hora_inicio=6,
            hora_fin=23
        )

        self.assertEqual(alertas, [])

    def test_analizar_usuarios_conectados_registra_alerta(self):
        salida = "ile pts/0 2026-07-08 14:00 (203.0.113.10)"
        alertas = analizar_usuarios_conectados(
            salida,
            origenes_permitidos={"local"},
            registrar_alertas=True
        )

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "origen_login_inusual")


if __name__ == "__main__":
    unittest.main()
