import unittest

from core.engine import (
    contar_alertas,
    generar_resumen,
    procesar_alertas,
)


class FakeCursor:
    def __init__(self):
        self.fetchone_result = [99]
        self.sqls = []

    def execute(self, sql, params=None):
        self.sqls.append(sql)

    def fetchone(self):
        return self.fetchone_result

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


class TestEngine(unittest.TestCase):
    def test_contar_alertas(self):
        alertas_por_modulo = {
            "auth_failures": [
                {"tipo": "multiples_intentos_fallidos"},
                {"tipo": "multiples_intentos_fallidos"},
            ],
            "tmp_monitor": [
                {"tipo": "ejecutable_en_tmp"},
            ],
        }

        self.assertEqual(contar_alertas(alertas_por_modulo), 3)

    def test_generar_resumen(self):
        alertas_por_modulo = {
            "auth_failures": [
                {"tipo": "multiples_intentos_fallidos"},
                {"tipo": "multiples_intentos_fallidos"},
            ],
            "tmp_monitor": [
                {"tipo": "ejecutable_en_tmp"},
            ],
        }

        resumen = generar_resumen(alertas_por_modulo)

        self.assertEqual(resumen["total_alertas"], 3)
        self.assertEqual(resumen["modulos"]["auth_failures"]["cantidad"], 2)
        self.assertEqual(
            resumen["modulos"]["auth_failures"]["tipos"]["multiples_intentos_fallidos"],
            2
        )

    def test_procesar_alertas_sin_db(self):
        alertas_por_modulo = {
            "system_logs": [
                {"tipo": "servicio_fallido", "detalle": "Falló un servicio"},
            ]
        }

        resultado = procesar_alertas(alertas_por_modulo)

        self.assertEqual(resultado["resumen"]["total_alertas"], 1)
        self.assertIsNone(resultado["persistencia"])

    def test_procesar_alertas_con_db(self):
        conexion = FakeConnection()

        alertas_por_modulo = {
            "ddos_monitor": [
                {
                    "tipo": "posible_syn_flood",
                    "severidad": "critica",
                    "detalle": "Muchos SYN desde una IP",
                    "ip": "10.0.0.99"
                }
            ]
        }

        resultado = procesar_alertas(
            alertas_por_modulo,
            conexion=conexion,
            guardar_en_db=True
        )

        self.assertEqual(resultado["resumen"]["total_alertas"], 1)
        self.assertEqual(resultado["persistencia"]["ddos_monitor"]["ids"], [99])
        self.assertEqual(conexion.commits, 2)

    def test_procesar_alertas_con_db_sin_conexion_da_error(self):
        with self.assertRaises(ValueError):
            procesar_alertas(
                {"tmp_monitor": [{"tipo": "ejecutable_en_tmp"}]},
                guardar_en_db=True
            )


if __name__ == "__main__":
    unittest.main()
