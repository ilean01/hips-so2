import unittest

from db.repository import (
    insertar_alarma,
    insertar_evento_sistema,
    insertar_accion_prevencion,
    obtener_configuracion_modulos,
)


class FakeCursor:
    def __init__(self):
        self.sql = None
        self.params = None
        self.fetchone_result = [1]
        self.fetchall_result = []

    def execute(self, sql, params=None):
        self.sql = sql
        self.params = params

    def fetchone(self):
        return self.fetchone_result

    def fetchall(self):
        return self.fetchall_result

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class FakeConnection:
    def __init__(self):
        self.cursor_obj = FakeCursor()
        self.commits = 0

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.commits += 1


class TestDbRepository(unittest.TestCase):
    def test_insertar_alarma(self):
        conexion = FakeConnection()

        alarma_id = insertar_alarma(
            conexion,
            tipo_alarma="archivo_modificado",
            modulo="integridad_archivos",
            descripcion="Archivo crítico modificado",
            severidad="ALTA",
            ip_origen="10.0.0.50"
        )

        self.assertEqual(alarma_id, 1)
        self.assertIn("INSERT INTO alarmas", conexion.cursor_obj.sql)
        self.assertEqual(conexion.commits, 1)

    def test_insertar_evento_sistema(self):
        conexion = FakeConnection()

        evento_id = insertar_evento_sistema(
            conexion,
            modulo="system_logs",
            evento="servicio_fallido",
            detalle="Falló un servicio"
        )

        self.assertEqual(evento_id, 1)
        self.assertIn("INSERT INTO eventos_sistema", conexion.cursor_obj.sql)
        self.assertEqual(conexion.commits, 1)

    def test_insertar_accion_prevencion(self):
        conexion = FakeConnection()

        accion_id = insertar_accion_prevencion(
            conexion,
            alarma_id=1,
            accion="bloquear_ip",
            resultado="dry_run",
            detalle="Se simuló bloqueo de IP"
        )

        self.assertEqual(accion_id, 1)
        self.assertIn("INSERT INTO acciones_prevencion", conexion.cursor_obj.sql)
        self.assertEqual(conexion.commits, 1)

    def test_obtener_configuracion_modulos(self):
        conexion = FakeConnection()
        conexion.cursor_obj.fetchall_result = [
            ("auth_failures", True, 60, 5, "{}"),
            ("ddos_monitor", True, 30, 50, "{}"),
        ]

        configuraciones = obtener_configuracion_modulos(conexion)

        self.assertEqual(len(configuraciones), 2)
        self.assertEqual(configuraciones[0]["modulo"], "auth_failures")
        self.assertEqual(configuraciones[0]["umbral"], 5)
        self.assertEqual(configuraciones[1]["modulo"], "ddos_monitor")


if __name__ == "__main__":
    unittest.main()
