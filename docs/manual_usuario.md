# Manual de uso del HIPS

## 1. Activar entorno

    cd ~/hips-project
    source venv/bin/activate

## 2. Verificar PostgreSQL

    sudo systemctl status postgresql

## 3. Verificar logs del HIPS

    sudo ls -l /var/log/hips/

## 4. Ejecutar dashboard

    cd ~/hips-project
    source venv/bin/activate
    python web/app.py

Luego ingresar desde el navegador a:

    http://IP_DEL_SERVIDOR:5000

## 5. Revisar alarmas

Desde consola:

    sudo tail -n 50 /var/log/hips/alarmas.log

Desde PostgreSQL:

    sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, ip_origen, modulo FROM alarmas ORDER BY id DESC LIMIT 20;"

## 6. Revisar prevenciones

Desde consola:

    sudo tail -n 50 /var/log/hips/prevencion.log

Desde PostgreSQL:

    sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, ip_origen, accion, resultado FROM acciones_prevencion ORDER BY id DESC LIMIT 20;"

## 7. Revisar emails simulados

    sudo tail -n 50 /var/log/hips/emails.log

## 8. Ejecutar pruebas finales

    cd ~/hips-project
    source venv/bin/activate
    sudo docs/test_evidence/run_phase12_tests.sh > docs/test_evidence/phase12_full_test_output.txt 2>&1

## 9. Archivos de evidencia

- docs/postgresql_cis_hardening.md
- docs/rocky_hardening.md
- docs/rocky_hardening_evidence.txt
- docs/test_evidence/phase12_test_summary.md
- docs/test_evidence/phase12_full_test_output.txt

## 10. Recomendación de seguridad

No subir el archivo `.env` al repositorio. Usar `.env.example` como plantilla.
