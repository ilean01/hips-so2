import unittest

from core.alert_service import (
    normalizar_severidad,
    extraer_ip_origen,
    construir_descripcion,
    registrar_alerta_db,
    registrar_alertas_db,
)


class FakeCursor:
    def __init__(self):
        self.sqls = []
        self.params = []
        self.fetchone_results = [None, [10], None, [10], None, [10], None, [10]]

    def execute(self, sql, params=None):
        self.sqls.append(sql)
        self.params.append(params)

    def fetchone(self):
        if self.fetchone_results:
            return self.fetchone_results.pop(0)
        return [10]

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


class TestAlertService(unittest.TestCase):
    def test_normaliza_severidad(self):
        self.assertEqual(normalizar_severidad("alta"), "ALTA")
        self.assertEqual(normalizar_severidad("critica"), "CRITICA")
        self.assertEqual(normalizar_severidad(None), "MEDIA")
        self.assertEqual(normalizar_severidad("rara"), "MEDIA")

    def test_extrae_ip_origen(self):
        alerta = {
            "tipo": "multiples_intentos_fallidos",
            "ip": "10.0.0.50"
        }

        self.assertEqual(extraer_ip_origen(alerta), "10.0.0.50")

    def test_construye_descripcion_con_extra(self):
        alerta = {
            "detalle": "Archivo modificado",
            "extra": {
                "archivo": "/etc/passwd"
            }
        }

        descripcion = construir_descripcion(alerta)

        self.assertIn("Archivo modificado", descripcion)
        self.assertIn("/etc/passwd", descripcion)

    def test_registra_alerta_db(self):
        conexion = FakeConnection()

        alerta_id = registrar_alerta_db(
            conexion,
            modulo="auth_failures",
            alerta={
                "tipo": "multiples_intentos_fallidos",
                "severidad": "alta",
                "detalle": "Muchos intentos fallidos",
                "ip": "10.0.0.50"
            }
        )

        self.assertEqual(alerta_id, 10)
        self.assertEqual(conexion.commits, 2)
        self.assertIn("SELECT id", conexion.cursor_obj.sqls[0])
        self.assertIn("INSERT INTO alarmas", conexion.cursor_obj.sqls[1])
        self.assertIn("SELECT id", conexion.cursor_obj.sqls[2])
        self.assertIn("INSERT INTO eventos_sistema", conexion.cursor_obj.sqls[3])

    def test_registra_varias_alertas_db(self):
        conexion = FakeConnection()

        ids = registrar_alertas_db(
            conexion,
            modulo="tmp_monitor",
            alertas=[
                {"tipo": "ejecutable_en_tmp", "detalle": "Ejecutable en tmp"},
                {"tipo": "archivo_oculto_tmp", "detalle": "Archivo oculto en tmp"},
            ]
        )

        self.assertEqual(ids, [10, 10])
        self.assertEqual(conexion.commits, 4)


if __name__ == "__main__":
    unittest.main()
