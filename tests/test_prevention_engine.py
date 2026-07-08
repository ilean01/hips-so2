import unittest
from unittest.mock import patch

from prevention.engine import extraer_archivo, extraer_ip, extraer_pid, prevenir_alertas


class TestPreventionEngine(unittest.TestCase):
    def test_extrae_pid_desde_linea_ps(self):
        alerta = {
            "proceso": "25045 tcpdump 0.0 0.1 tcpdump /usr/sbin/tcpdump -i lo"
        }

        self.assertEqual(extraer_pid(alerta), 25045)

    def test_extrae_archivo_tmp_desde_detalle(self):
        alerta = {
            "detalle": "Archivo ejecutable detectado en tmp: /tmp/hips_test.sh"
        }

        self.assertEqual(extraer_archivo(alerta), "/tmp/hips_test.sh")

    def test_extrae_ip_no_bloquea_localhost(self):
        alerta = {
            "ip_origen": "127.0.0.1"
        }

        self.assertIsNone(extraer_ip(alerta))

    @patch("prevention.engine.finalizar_proceso")
    def test_previene_sniffer_finalizando_pid(self, mock_finalizar):
        mock_finalizar.return_value = {
            "accion": "finalizar_proceso",
            "pid": 25045,
            "dry_run": False,
            "ejecutado": True,
        }

        resultado = prevenir_alertas({
            "sniffers": [
                {
                    "tipo": "sniffer_detectado",
                    "proceso": "25045 root 0.0 0.1 tcpdump /usr/sbin/tcpdump -i lo"
                }
            ]
        }, dry_run=False)

        mock_finalizar.assert_called_once_with(25045, dry_run=False)
        self.assertEqual(resultado["total_acciones"], 1)
        self.assertEqual(resultado["acciones"][0]["accion"]["accion"], "finalizar_proceso")

    @patch("prevention.engine.cuarentenar_archivo")
    def test_previene_tmp_cuarentenando_archivo(self, mock_cuarentena):
        mock_cuarentena.return_value = {
            "accion": "cuarentenar_archivo",
            "origen": "/tmp/hips_test.sh",
            "dry_run": False,
            "ejecutado": True,
        }

        resultado = prevenir_alertas({
            "tmp_monitor": [
                {
                    "tipo": "ejecutable_en_tmp",
                    "detalle": "Archivo ejecutable detectado en tmp: /tmp/hips_test.sh"
                }
            ]
        }, dry_run=False)

        mock_cuarentena.assert_called_once_with("/tmp/hips_test.sh", dry_run=False)
        self.assertEqual(resultado["total_acciones"], 1)

    @patch("prevention.engine.bloquear_ip")
    def test_previene_ddos_bloqueando_ip(self, mock_bloquear):
        mock_bloquear.return_value = {
            "accion": "bloquear_ip",
            "ip": "203.0.113.10",
            "dry_run": False,
            "ejecutado": True,
        }

        resultado = prevenir_alertas({
            "ddos_monitor": [
                {
                    "tipo": "muchas_conexiones_desde_ip",
                    "ip_origen": "203.0.113.10"
                }
            ]
        }, dry_run=False)

        mock_bloquear.assert_called_once_with("203.0.113.10", dry_run=False)
        self.assertEqual(resultado["total_acciones"], 1)


if __name__ == "__main__":
    unittest.main()
