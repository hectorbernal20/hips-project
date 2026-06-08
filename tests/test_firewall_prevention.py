from prevention.firewall import block_ip


def test_block_ip_dry_run():
    result = block_ip("10.10.10.10", dry_run=True)

    assert result["blocked"] is False
    assert "DRY RUN" in result["reason"]
    assert "firewall-cmd" in result["command"]


def test_block_ip_whitelist():
    result = block_ip("192.168.56.1", dry_run=True)

    assert result["blocked"] is False
    assert result["command"] is None
    assert "whitelist" in result["reason"]
