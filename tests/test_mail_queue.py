import os
import tempfile
import unittest

from detection.mail_queue import (
    cola_esta_vacia,
    contar_mensajes_cola,
    analizar_cola_correo,
)


MAILQ_SIMULADA = """-Queue ID- --Size-- ----Arrival Time---- -Sender/Recipient-------
A1B2C3D4E     1234 Tue Jul 7 10:00:00  user@example.com
                                         destino1@example.net
B2C3D4E5F     2048 Tue Jul 7 10:01:00  user@example.com
                                         destino2@example.net
C3D4E5F6A      512 Tue Jul 7 10:02:00  user@example.com
                                         destino3@example.net
"""


class TestMailQueue(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HIPS_LOG_DIR"] = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.pop("HIPS_LOG_DIR", None)

    def test_detecta_cola_vacia(self):
        salida = "Mail queue is empty"
        self.assertTrue(cola_esta_vacia(salida))
        self.assertEqual(contar_mensajes_cola(salida), 0)

    def test_cuenta_mensajes_por_queue_id(self):
        cantidad = contar_mensajes_cola(MAILQ_SIMULADA)
        self.assertEqual(cantidad, 3)

    def test_alerta_por_cola_alta(self):
        alertas = analizar_cola_correo(MAILQ_SIMULADA, umbral_cola=3)
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("cola_correo_alta", tipos)

    def test_detecta_correo_diferido(self):
        salida = MAILQ_SIMULADA + "\n(deferred: Connection timed out with mail.example.net)\n"
        alertas = analizar_cola_correo(salida, umbral_cola=99)
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("correo_diferido", tipos)
        self.assertIn("error_conexion_correo", tipos)

    def test_detecta_rebote(self):
        salida = MAILQ_SIMULADA + "\nMAILER-DAEMON user unknown\n"
        alertas = analizar_cola_correo(salida, umbral_cola=99)
        tipos = [alerta["tipo"] for alerta in alertas]

        self.assertIn("rebote_correo", tipos)

    def test_detecta_envio_masivo_correo(self):
        contenido = "\n".join([
            "Jul 11 postfix/smtp[1]: ABC001: from=<spamtest@local>, to=<a@example.com>, status=sent",
            "Jul 11 postfix/smtp[2]: ABC002: from=<spamtest@local>, to=<b@example.com>, status=sent",
            "Jul 11 postfix/smtp[3]: ABC003: from=<spamtest@local>, to=<c@example.com>, status=sent",
            "Jul 11 postfix/smtp[4]: ABC004: from=<spamtest@local>, to=<d@example.com>, status=sent",
            "Jul 11 postfix/smtp[5]: ABC005: from=<spamtest@local>, to=<e@example.com>, status=sent",
        ])

        alertas = analizar_cola_correo(
            contenido,
            registrar_alertas=False,
            umbral_envio_masivo=5
        )

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "envio_masivo_correo")
        self.assertEqual(alertas[0]["remitente"], "spamtest@local")
        self.assertEqual(alertas[0]["cantidad"], 5)


if __name__ == "__main__":
    unittest.main()
