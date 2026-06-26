#!/bin/bash

echo "===== HARDENING ROCKY LINUX - EVIDENCIA ====="
echo
echo "Fecha:"
date
echo

echo "1. Sistema operativo:"
cat /etc/os-release
echo

echo "2. SELinux:"
getenforce
echo

echo "3. Firewalld:"
systemctl is-enabled firewalld 2>/dev/null
systemctl is-active firewalld 2>/dev/null
firewall-cmd --list-all 2>/dev/null
echo

echo "4. SSH - root login:"
grep -Ei "^PermitRootLogin|^PasswordAuthentication" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
echo

echo "5. Auditd:"
systemctl is-enabled auditd 2>/dev/null
systemctl is-active auditd 2>/dev/null
echo

echo "6. Chronyd:"
systemctl is-enabled chronyd 2>/dev/null
systemctl is-active chronyd 2>/dev/null
chronyc tracking 2>/dev/null
echo

echo "7. Rsyslog:"
systemctl is-enabled rsyslog 2>/dev/null
systemctl is-active rsyslog 2>/dev/null
echo

echo "8. Permisos archivos sensibles:"
ls -l /etc/passwd /etc/shadow /etc/group /etc/gshadow
echo

echo "9. Usuarios con UID 0:"
awk -F: '($3 == 0) {print}' /etc/passwd
echo

echo "10. Puertos en escucha:"
ss -tulpen
echo

echo "11. Actualizaciones disponibles:"
dnf check-update 2>/dev/null | head -n 30
echo

echo "12. Estado PostgreSQL:"
systemctl is-enabled postgresql 2>/dev/null || true
systemctl is-active postgresql 2>/dev/null || true
systemctl list-units --type=service | grep -i postgres || true
echo

echo "===== FIN DE EVIDENCIA ====="
