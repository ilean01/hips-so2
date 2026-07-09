import unittest

from detection.sniffers import detectar_interfaces_promiscuas


class TestSniffersPromisc(unittest.TestCase):
    def test_detecta_interfaz_promiscua(self):
        salida = "2: ens33: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000"
        alertas = detectar_interfaces_promiscuas(salida, interfaces_permitidas={"lo"})

        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "interfaz_promiscua")
        self.assertEqual(alertas[0]["interfaz"], "ens33")

    def test_ignora_interfaz_permitida(self):
        salida = "1: lo: <LOOPBACK,PROMISC,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000"
        alertas = detectar_interfaces_promiscuas(salida, interfaces_permitidas={"lo"})

        self.assertEqual(alertas, [])


if __name__ == "__main__":
    unittest.main()
