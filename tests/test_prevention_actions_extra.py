import unittest
from unittest.mock import patch

from prevention.actions import (
    bloquear_usuario,
    documentar_integridad_archivo,
    reiniciar_postfix,
    limpiar_cola_correo,
    desactivar_modo_promiscuo,
)


class TestPreventionActionsExtra(unittest.TestCase):
    @patch("prevention.actions.log_prevencion")
    def test_no_bloquea_usuario_protegido(self, mock_log):
        accion = bloquear_usuario("ile", dry_run=False)

        self.assertFalse(accion["ejecutado"])
        self.assertEqual(accion["motivo"], "usuario_protegido")
        mock_log.assert_called_once()

    @patch("prevention.actions.log_prevencion")
    def test_documentar_integridad_dry_run(self, mock_log):
        accion = documentar_integridad_archivo(
            "/etc/passwd",
            motivo="prueba",
            dry_run=True
        )

        self.assertEqual(accion["accion"], "documentar_integridad_archivo")
        self.assertFalse(accion["ejecutado"])
        mock_log.assert_called_once()

    @patch("prevention.actions.log_prevencion")
    def test_reiniciar_postfix_dry_run(self, mock_log):
        accion = reiniciar_postfix(dry_run=True)

        self.assertEqual(accion["accion"], "reiniciar_postfix")
        self.assertFalse(accion["ejecutado"])
        mock_log.assert_called_once()

    @patch("prevention.actions.log_prevencion")
    def test_limpiar_cola_correo_dry_run(self, mock_log):
        accion = limpiar_cola_correo(dry_run=True)

        self.assertEqual(accion["accion"], "limpiar_cola_correo")
        self.assertFalse(accion["ejecutado"])
        mock_log.assert_called_once()

    @patch("prevention.actions.log_prevencion")
    def test_desactivar_promiscuo_dry_run(self, mock_log):
        accion = desactivar_modo_promiscuo("eth0", dry_run=True)

        self.assertEqual(accion["accion"], "desactivar_modo_promiscuo")
        self.assertFalse(accion["ejecutado"])
        mock_log.assert_called_once()


if __name__ == "__main__":
    unittest.main()
