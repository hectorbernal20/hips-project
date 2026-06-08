from detection.access_monitor import detect_failed_logins


def test_detect_failed_logins(tmp_path):
    log_file = tmp_path / "secure"

    log_file.write_text(
        "\n".join([
            "Jun 08 10:00:00 rocky sshd[100]: Failed password for invalid user admin from 192.168.56.10 port 50500 ssh2",
            "Jun 08 10:01:00 rocky sshd[101]: Failed password for invalid user admin from 192.168.56.10 port 50501 ssh2",
            "Jun 08 10:02:00 rocky sshd[102]: Failed password for invalid user admin from 192.168.56.10 port 50502 ssh2",
            "Jun 08 10:03:00 rocky sshd[103]: Failed password for invalid user admin from 192.168.56.10 port 50503 ssh2",
            "Jun 08 10:04:00 rocky sshd[104]: Failed password for invalid user admin from 192.168.56.10 port 50504 ssh2",
            "Jun 08 10:05:00 rocky sshd[105]: Failed password for invalid user admin from 192.168.56.10 port 50505 ssh2",
        ]),
        encoding="utf-8"
    )

    alarms = detect_failed_logins(str(log_file), threshold=5, window_minutes=10)

    assert len(alarms) == 1
    assert alarms[0]["tipo_alarma"] == "ACCESO_INVALIDO_REPETIDO"
    assert alarms[0]["ip_origen"] == "192.168.56.10"
