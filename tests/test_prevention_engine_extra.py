import unittest
from unittest.mock import patch

from prevention.engine import prevenir_alertas


class TestPreventionEngineExtra(unittest.TestCase):
    @patch("prevention.engine.bloquear_usuario")
    def test_user_monitor_bloquea_usuario_sospechoso(self, mock_bloquear):
        mock_bloquear.return_value = {
            "accion": "bloquear_usuario",
            "usuario": "intruso",
            "dry_run": False,
            "ejecutado": True,
        }

        resultado = prevenir_alertas({
            "user_monitor": [
                {
                    "tipo": "usuario_nuevo",
                    "usuario": "intruso",
                    "detalle": "Se detectó un usuario nuevo: intruso",
                }
            ]
        }, dry_run=False)

        mock_bloquear.assert_called_once_with("intruso", dry_run=False)
        self.assertEqual(resultado["acciones"][0]["accion"]["accion"], "bloquear_usuario")

    @patch("prevention.engine.documentar_integridad_archivo")
    def test_integridad_documenta_prevencion(self, mock_documentar):
        mock_documentar.return_value = {
            "accion": "documentar_integridad_archivo",
            "archivo": "/etc/hips_integrity_test.conf",
            "dry_run": False,
            "ejecutado": True,
        }

        resultado = prevenir_alertas({
            "integridad_archivos": [
                {
                    "tipo": "archivo_modificado",
                    "archivo": "/etc/hips_integrity_test.conf",
                    "detalle": "Archivo modificado",
                }
            ]
        }, dry_run=False)

        mock_documentar.assert_called_once()
        self.assertEqual(resultado["acciones"][0]["accion"]["accion"], "documentar_integridad_archivo")

    @patch("prevention.engine.desactivar_modo_promiscuo")
    def test_sniffer_promiscuo_desactiva_interfaz(self, mock_promisc):
        mock_promisc.return_value = {
            "accion": "desactivar_modo_promiscuo",
            "interfaz": "ens33",
            "dry_run": False,
            "ejecutado": True,
        }

        resultado = prevenir_alertas({
            "sniffers": [
                {
                    "tipo": "interfaz_promiscua",
                    "interfaz": "ens33",
                    "detalle": "Interfaz en modo promiscuo detectada: ens33",
                }
            ]
        }, dry_run=False)

        mock_promisc.assert_called_once_with("ens33", dry_run=False)
        self.assertEqual(resultado["acciones"][0]["accion"]["accion"], "desactivar_modo_promiscuo")

    @patch("prevention.engine.limpiar_cola_correo")
    def test_mail_queue_limpia_cola_alta(self, mock_limpiar):
        mock_limpiar.return_value = {
            "accion": "limpiar_cola_correo",
            "dry_run": False,
            "ejecutado": True,
        }

        resultado = prevenir_alertas({
            "mail_queue": [
                {
                    "tipo": "cola_correo_alta",
                    "cantidad": 50,
                    "detalle": "La cola de correo tiene 50 mensajes pendientes",
                }
            ]
        }, dry_run=False)

        mock_limpiar.assert_called_once_with(dry_run=False)
        self.assertEqual(resultado["acciones"][0]["accion"]["accion"], "limpiar_cola_correo")

    @patch("prevention.engine.cuarentenar_archivo")
    def test_tmp_monitor_no_cuarentena_dos_veces_mismo_archivo(self, mock_cuarentena):
        mock_cuarentena.return_value = {
            "accion": "cuarentenar_archivo",
            "origen": "/tmp/archivo_sospechoso.sh",
            "destino": "/var/quarantine/hips/archivo_sospechoso.sh.hash.quarantine",
            "dry_run": False,
            "ejecutado": True,
        }

        resultado = prevenir_alertas({
            "tmp_monitor": [
                {
                    "tipo": "extension_sospechosa_tmp",
                    "archivo": "/tmp/archivo_sospechoso.sh",
                    "detalle": "Archivo con extensión sospechosa",
                },
                {
                    "tipo": "ejecutable_en_tmp",
                    "archivo": "/tmp/archivo_sospechoso.sh",
                    "detalle": "Archivo ejecutable detectado",
                },
            ]
        }, dry_run=False)

        self.assertEqual(mock_cuarentena.call_count, 1)
        self.assertEqual(resultado["acciones"][0]["accion"]["accion"], "cuarentenar_archivo")
        self.assertEqual(resultado["acciones"][1]["accion"]["accion"], "archivo_ya_prevenido")
        self.assertTrue(resultado["acciones"][1]["accion"]["ejecutado"])


if __name__ == "__main__":
    unittest.main()
