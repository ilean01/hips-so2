#!/usr/bin/env bash
set -u

PROY="${HIPS_PROYECTO_DIR:-/home/ile/hips-so2}"

echo "=============================================================="
echo " LIMPIEZA DEMO MAESTRA HIPS"
echo "=============================================================="

cd "$PROY" || {
  echo "ERROR: no encuentro el proyecto en $PROY"
  exit 1
}

echo
echo "=== 1) Pausar HIPS automatico ==="
sudo systemctl stop hips.timer 2>/dev/null || true

echo
echo "=== 2) Matar procesos falsos de sniffers/demo ==="
sudo pkill -f "tcpdump -i lo" 2>/dev/null || true
pkill -f "wireshark 600" 2>/dev/null || true
pkill -f "ethereal 600" 2>/dev/null || true
pkill -f "tshark 600" 2>/dev/null || true

echo
echo "=== 3) Eliminar archivos temporales de pruebas ==="
sudo rm -f /tmp/hips_tcpdump_demo.pcap 2>/dev/null || true
sudo rm -f /tmp/hips_tcpdump_demo.log 2>/dev/null || true
sudo rm -f /tmp/.hips_alarmas_test.sh 2>/dev/null || true
sudo rm -f /tmp/.update_hidden.sh 2>/dev/null || true
sudo rm -f /tmp/.update.sh 2>/dev/null || true
sudo rm -f /tmp/hips_prueba_tmp_monitor* 2>/dev/null || true
sudo rm -f /tmp/hips_prueba2_* 2>/dev/null || true
sudo rm -f /tmp/.x_hidden_tmp.sh 2>/dev/null || true
sudo rm -rf "$PROY/.tmp_tests" 2>/dev/null || true

echo
echo "=== 4) Eliminar tareas cron falsas de demo ==="
sudo rm -f /etc/cron.d/hips_cron_test 2>/dev/null || true
sudo rm -f /etc/cron.d/hips_prueba_cron_monitor 2>/dev/null || true
sudo rm -f /etc/cron.d/hips_cron_test_demo 2>/dev/null || true
sudo rm -f /etc/cron.d/hips_cron_demo 2>/dev/null || true

echo
echo "=== 5) Limpiar logs falsos usados por la demo ==="
sudo bash -c ': > /var/log/named/query.log' 2>/dev/null || true
sudo bash -c ': > /var/log/httpd/access.log' 2>/dev/null || true
sudo bash -c ': > /var/log/maillog' 2>/dev/null || true

echo
echo "=== 6) Limpiar cola de correo acumulada ==="
sudo systemctl reset-failed postfix 2>/dev/null || true
sudo systemctl start postfix 2>/dev/null || true
sudo postsuper -d ALL deferred 2>/dev/null || true
sudo postsuper -d ALL hold 2>/dev/null || true
sudo postsuper -d ALL 2>/dev/null || true
sudo systemctl restart postfix 2>/dev/null || true

echo
echo "=== 7) Limpiar IPs falsas bloqueadas en firewall ==="
for ip in \
  203.0.113.10 \
  203.0.113.55 \
  203.0.113.56 \
  203.0.113.57 \
  203.0.113.58 \
  203.0.113.60 \
  203.0.113.61 \
  203.0.113.70 \
  203.0.113.77 \
  203.0.113.80 \
  203.0.113.90 \
  203.0.113.99 \
  198.51.100.25
do
  sudo firewall-cmd --permanent --remove-rich-rule="rule family=\"ipv4\" source address=\"$ip\" reject" 2>/dev/null || true
done

sudo firewall-cmd --reload 2>/dev/null || true

echo
echo "=== 8) Eliminar usuarios temporales de pruebas si existen ==="
for u in $(getent passwd | cut -d: -f1 | grep -E '^hips_(pwd|mail|demo|test)_' || true); do
  echo "Eliminando usuario temporal: $u"
  sudo userdel -r "$u" 2>/dev/null || true
done

echo
echo "=== 9) Dejar email admin local para evitar cola externa ==="
if [ -f /etc/hips/hips.env ]; then
  sudo cp /etc/hips/hips.env "/etc/hips/hips.env.bak_limpieza_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
  sudo sed -i 's/^HIPS_ADMIN_EMAIL=.*/HIPS_ADMIN_EMAIL=ile/' /etc/hips/hips.env 2>/dev/null || true
fi

echo
echo "=== 10) Verificacion final ==="
echo "--- Postfix ---"
systemctl is-active postfix 2>/dev/null || true

echo "--- Cola de correo ---"
mailq 2>/dev/null || true

echo "--- Firewall rich rules ---"
sudo firewall-cmd --list-rich-rules 2>/dev/null || true

echo "--- HIPS web ---"
systemctl is-active hips-web.service 2>/dev/null || true

echo
echo "=== 11) Reactivar HIPS automatico ==="
sudo systemctl start hips.timer 2>/dev/null || true
systemctl is-active hips.timer 2>/dev/null || true

echo
echo "=============================================================="
echo " LIMPIEZA FINALIZADA"
echo "=============================================================="
