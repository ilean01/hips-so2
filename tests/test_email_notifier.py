import os
import tempfile
import unittest
from pathlib import Path

from core.email_notifier import construir_cuerpo_email, enviar_email_admin


class TestEmailNotifier(unittest.TestCase):
    def test_construir_cuerpo_email_incluye_alertas(self):
        alertas = {
            "tmp_monitor": [
                {
                    "tipo": "ejecutable_en_tmp",
                    "detalle": "Archivo ejecutable detectado en tmp"
                }
            ]
        }

        cuerpo = construir_cuerpo_email(alertas, hostname="host-prueba")

        self.assertIn("Alerta del sistema HIPS", cuerpo)
        self.assertIn("host-prueba", cuerpo)
        self.assertIn("tmp_monitor", cuerpo)
        self.assertIn("ejecutable_en_tmp", cuerpo)

    def test_no_envia_si_no_hay_alertas(self):
        resultado = enviar_email_admin(
            {},
            admin_email="admin@localhost",
            sendmail_path="/bin/false"
        )

        self.assertFalse(resultado["enviado"])
        self.assertEqual(resultado["motivo"], "sin_alertas")

    def test_no_envia_si_no_hay_admin_email(self):
        resultado = enviar_email_admin(
            {"tmp_monitor": [{"tipo": "ejecutable_en_tmp", "detalle": "x"}]},
            admin_email="",
            sendmail_path="/bin/false"
        )

        self.assertFalse(resultado["enviado"])
        self.assertEqual(resultado["motivo"], "admin_email_no_configurado")

    def test_envia_email_con_sendmail_falso(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            salida = tmp_path / "mensaje.txt"
            sendmail_fake = tmp_path / "sendmail_fake.sh"

            sendmail_fake.write_text(
                "#!/bin/bash\n"
                f"cat > {salida}\n"
                "exit 0\n",
                encoding="utf-8"
            )
            sendmail_fake.chmod(0o755)

            resultado = enviar_email_admin(
                {
                    "system_logs": [
                        {
                            "tipo": "sudo_fallido",
                            "detalle": "Se detectó sudo fallido"
                        }
                    ]
                },
                admin_email="admin@localhost",
                sendmail_path=str(sendmail_fake)
            )

            self.assertTrue(resultado["enviado"])
            contenido = salida.read_text(encoding="utf-8")

            self.assertIn("To: admin@localhost", contenido)
            self.assertIn("[HIPS]", contenido)
            self.assertIn("sudo_fallido", contenido)


if __name__ == "__main__":
    unittest.main()
