import unittest

from web.app import crear_app


def datos_fake():
    return {
        "alarmas": [
            {
                "id": 1,
                "timestamp": "2026-07-08 17:00:00",
                "tipo_alarma": "sudo_fallido",
                "modulo": "system_logs",
                "severidad": "ALTA",
                "ip_origen": None,
                "resuelta": False,
                "descripcion": "Se detectó sudo fallido",
            }
        ],
        "eventos": [
            {
                "id": 1,
                "timestamp": "2026-07-08 17:00:00",
                "modulo": "system_logs",
                "evento": "alerta_registrada",
                "detalle": "Se registró alerta",
            }
        ],
        "alarmas_por_modulo": [
            {"modulo": "system_logs", "cantidad": 1}
        ],
        "alarmas_por_severidad": [
            {"severidad": "ALTA", "cantidad": 1}
        ],
        "modulos": [
            {
                "modulo": "system_logs",
                "habilitado": True,
                "intervalo_segundos": 60,
                "umbral": None,
            }
        ],
    }


class TestWebApp(unittest.TestCase):
    def setUp(self):
        self.resueltas = []

        def resolver_fake(alarma_id):
            self.resueltas.append(alarma_id)

        self.app = crear_app(
            dashboard_provider=datos_fake,
            resolver_provider=resolver_fake
        )
        self.app.config["TESTING"] = True
        self.app.config["HIPS_WEB_USER"] = "admin"
        self.app.config["HIPS_WEB_PASSWORD"] = "secreto"
        self.client = self.app.test_client()

    def test_login_page(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"HIPS", response.data)

    def test_dashboard_requiere_login(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_login_correcto_muestra_dashboard(self):
        response = self.client.post(
            "/login",
            data={"usuario": "admin", "password": "secreto"},
            follow_redirects=True
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Dashboard HIPS", response.data)
        self.assertIn(b"sudo_fallido", response.data)


    def test_marcar_alarma_resuelta(self):
        self.client.post(
            "/login",
            data={"usuario": "admin", "password": "secreto"},
            follow_redirects=True
        )

        response = self.client.post(
            "/alarmas/1/resolver",
            follow_redirects=True
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.resueltas, [1])

    def test_login_incorrecto_muestra_error(self):
        response = self.client.post(
            "/login",
            data={"usuario": "admin", "password": "mal"},
            follow_redirects=True
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Usuario o contrase", response.data)


if __name__ == "__main__":
    unittest.main()
