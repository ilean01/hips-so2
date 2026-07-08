import unittest
from unittest.mock import patch

import hips


class TestHipsCli(unittest.TestCase):
    def test_construir_parser(self):
        parser = hips.construir_parser()
        opciones = parser.parse_args(["--json", "--sin-logs"])

        self.assertTrue(opciones.json)
        self.assertTrue(opciones.sin_logs)
        self.assertFalse(opciones.guardar_db)

    @patch("hips.procesar_alertas")
    @patch("hips.ejecutar_ciclo_deteccion")
    def test_ejecutar_hips_sin_db(self, mock_runner, mock_procesar):
        mock_runner.return_value = {
            "tmp_monitor": [
                {"tipo": "ejecutable_en_tmp", "detalle": "Ejecutable en tmp"}
            ]
        }

        mock_procesar.return_value = {
            "resumen": {
                "total_alertas": 1,
                "modulos": {
                    "tmp_monitor": {
                        "cantidad": 1,
                        "tipos": {
                            "ejecutable_en_tmp": 1
                        }
                    }
                }
            },
            "persistencia": None
        }

        resultado = hips.ejecutar_hips(["--sin-logs"])

        self.assertEqual(resultado["resumen"]["total_alertas"], 1)
        mock_runner.assert_called_once_with(registrar_alertas_logs=False)
        mock_procesar.assert_called_once()

    @patch("hips.procesar_alertas")
    @patch("hips.ejecutar_ciclo_deteccion")
    def test_ejecutar_hips_json(self, mock_runner, mock_procesar):
        mock_runner.return_value = {}

        mock_procesar.return_value = {
            "resumen": {
                "total_alertas": 0,
                "modulos": {}
            },
            "persistencia": None
        }

        resultado = hips.ejecutar_hips(["--json", "--sin-logs"])

        self.assertEqual(resultado["resumen"]["total_alertas"], 0)

    def test_main_devuelve_cero_si_no_hay_error(self):
        with patch("hips.ejecutar_hips") as mock_ejecutar:
            mock_ejecutar.return_value = {
                "resumen": {
                    "total_alertas": 0,
                    "modulos": {}
                },
                "persistencia": None
            }

            self.assertEqual(hips.main(), 0)


if __name__ == "__main__":
    unittest.main()
