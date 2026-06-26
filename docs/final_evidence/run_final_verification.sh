#!/bin/bash

PROJECT_DIR="/home/hector/hips-project"
PYTHON="$PROJECT_DIR/venv/bin/python"

cd "$PROJECT_DIR" || exit 1

echo "===== VERIFICACION FINAL HIPS ====="
echo "Fecha: $(date)"
echo

echo "===== 1. ESTADO GIT ====="
git status
echo

echo "===== 2. ULTIMOS COMMITS ====="
git log --oneline -10
echo

echo "===== 3. VERIFICAR QUE .env NO ESTE VERSIONADO ====="
if git ls-files .env | grep -q ".env"; then
    echo "ERROR: .env esta versionado"
else
    echo "OK: .env no esta versionado"
fi
echo

echo "===== 4. ARCHIVOS PRINCIPALES ====="
ls -l README.md .env.example .gitignore
echo

echo "===== 5. DOCUMENTACION ====="
ls -l docs/postgresql_cis_hardening.md
ls -l docs/rocky_hardening.md
ls -l docs/manual_usuario.md
ls -l docs/checklist_final_entrega.md
ls -l docs/test_evidence/phase12_test_summary.md
ls -l docs/test_evidence/phase12_full_test_output.txt
echo

echo "===== 6. SINTAXIS PYTHON ====="
$PYTHON -m py_compile alerts/logger.py alerts/mailer.py
$PYTHON -m py_compile db/connection.py db/repository.py
$PYTHON -m py_compile prevention/*.py
$PYTHON -m py_compile detection/*.py
$PYTHON -m py_compile web/app.py
echo "OK: sintaxis Python correcta"
echo

echo "===== 7. SERVICIO POSTGRESQL ====="
sudo systemctl is-enabled postgresql
sudo systemctl is-active postgresql
echo

echo "===== 8. TABLAS POSTGRESQL ====="
sudo -u postgres psql -d hips_db -c "\dt"
echo

echo "===== 9. ULTIMAS ALARMAS EN POSTGRESQL ====="
sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, ip_origen, modulo FROM alarmas ORDER BY id DESC LIMIT 10;"
echo

echo "===== 10. ULTIMAS PREVENCIONES EN POSTGRESQL ====="
sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, ip_origen, accion, resultado FROM acciones_prevencion ORDER BY id DESC LIMIT 10;"
echo

echo "===== 11. LOGS DEL HIPS ====="
sudo ls -l /var/log/hips/
echo

echo "===== 12. ULTIMAS ALARMAS EN LOG ====="
sudo tail -n 10 /var/log/hips/alarmas.log
echo

echo "===== 13. ULTIMAS PREVENCIONES EN LOG ====="
sudo tail -n 10 /var/log/hips/prevencion.log
echo

echo "===== 14. ULTIMOS EMAILS GENERADOS ====="
sudo tail -n 10 /var/log/hips/emails.log
echo

echo "===== 15. DASHBOARD ====="
echo "Dashboard Flask disponible ejecutando: python web/app.py"
echo "URL esperada: http://IP_DEL_SERVIDOR:5000"
echo

echo "===== FIN VERIFICACION FINAL ====="
