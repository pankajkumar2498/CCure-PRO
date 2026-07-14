import pytest
from fastapi import HTTPException
from unittest.mock import MagicMock

from core.utils import InputValidator
from core.quota import check_scan_quota


def test_parse_custom_ports_success():
    # Single port
    assert InputValidator.parse_custom_ports("22") == [22]
    # List of ports
    assert InputValidator.parse_custom_ports("22,80,443") == [22, 80, 443]
    # Range of ports
    assert InputValidator.parse_custom_ports("80-83") == [80, 81, 82, 83]
    # Mixed list & range
    assert InputValidator.parse_custom_ports("22,80-83,443") == [
        22,
        80,
        81,
        82,
        83,
        443,
    ]
    # Spaces handling
    assert InputValidator.parse_custom_ports("  22, 80 - 83 ,  443 ") == [
        22,
        80,
        81,
        82,
        83,
        443,
    ]


def test_parse_custom_ports_value_errors():
    # Malformed format
    with pytest.raises(ValueError, match="Invalid characters"):
        InputValidator.parse_custom_ports("22a")
    with pytest.raises(ValueError, match="Invalid range format"):
        InputValidator.parse_custom_ports("80-80-80")
    with pytest.raises(ValueError, match="Invalid range bounds"):
        InputValidator.parse_custom_ports("80-abc")

    # Range start > end
    with pytest.raises(ValueError, match="Range start must be <= end"):
        InputValidator.parse_custom_ports("80-79")

    # Out of bounds
    with pytest.raises(ValueError, match="Ports must be between 1 and 65535"):
        InputValidator.parse_custom_ports("0")
    with pytest.raises(ValueError, match="Ports must be between 1 and 65535"):
        InputValidator.parse_custom_ports("65536")

    # Duplicate ports
    with pytest.raises(ValueError, match="Duplicate port detected"):
        InputValidator.parse_custom_ports("22,22")
    with pytest.raises(ValueError, match="Duplicate port detected"):
        InputValidator.parse_custom_ports("80-85,83")


def test_parse_custom_ports_sensitive_ports_allowed():
    # Sensitive ports should parse successfully without error
    assert InputValidator.parse_custom_ports("2375,6443,10250") == [2375, 6443, 10250]


def test_parse_exclude_ports_success():
    assert InputValidator.parse_exclude_ports("") == []
    assert InputValidator.parse_exclude_ports("   ") == []
    assert InputValidator.parse_exclude_ports("22") == [22]
    assert InputValidator.parse_exclude_ports("22,80,443") == [22, 80, 443]
    assert InputValidator.parse_exclude_ports("80-83") == [80, 81, 82, 83]
    assert InputValidator.parse_exclude_ports("  22, 80 - 83 ,  443 ") == [
        22,
        80,
        81,
        82,
        83,
        443,
    ]


def test_parse_exclude_ports_errors():
    with pytest.raises(ValueError, match="Invalid characters"):
        InputValidator.parse_exclude_ports("22a")
    with pytest.raises(ValueError, match="Invalid range format"):
        InputValidator.parse_exclude_ports("80-80-80")
    with pytest.raises(ValueError, match="Invalid range bounds"):
        InputValidator.parse_exclude_ports("80-abc")
    with pytest.raises(ValueError, match="Range start must be <= end"):
        InputValidator.parse_exclude_ports("80-79")
    with pytest.raises(ValueError, match="Ports must be between 1 and 65535"):
        InputValidator.parse_exclude_ports("0")
    with pytest.raises(ValueError, match="Duplicate port detected"):
        InputValidator.parse_exclude_ports("22,22")


def test_check_scan_quota_custom_ports():
    # Mock database and organization
    mock_db = MagicMock()
    mock_org = MagicMock()
    mock_org.plan = "community"

    # Configure mock DB query
    mock_db.query.return_value.filter.return_value.first.return_value = mock_org

    # 1. Under Community limit (<= 100 ports)
    # 100 ports is fine
    custom_ports_ok = ",".join(str(p) for p in range(1, 101))
    # This shouldn't raise any exception
    check_scan_quota(mock_db, org_id="org-1", custom_ports=custom_ports_ok)

    # Over Community limit (> 100 ports)
    custom_ports_too_many = ",".join(str(p) for p in range(1, 102))
    with pytest.raises(HTTPException) as exc_info:
        check_scan_quota(mock_db, org_id="org-1", custom_ports=custom_ports_too_many)
    assert exc_info.value.status_code == 400
    assert "allows a maximum of 100 ports" in exc_info.value.detail

    # 2. Under Pro limit (<= 1000 ports)
    mock_org.plan = "pro"
    custom_ports_pro_ok = ",".join(
        str(p) for p in range(1, 1001) if p not in (2375, 2376)
    )  # avoid blacklist
    check_scan_quota(mock_db, org_id="org-1", custom_ports=custom_ports_pro_ok)

    # Over Pro limit (> 1000 ports)
    # Let's generate 1002 ports (excluding blacklisted ports to only trigger limit)
    blacklisted = {2375, 2376, 6443, 10250}
    pro_ports_list = []
    p = 1
    while len(pro_ports_list) < 1002:
        if p not in blacklisted:
            pro_ports_list.append(p)
        p += 1
    custom_ports_pro_too_many = ",".join(str(x) for x in pro_ports_list)
    with pytest.raises(HTTPException) as exc_info:
        check_scan_quota(
            mock_db, org_id="org-1", custom_ports=custom_ports_pro_too_many
        )
    assert exc_info.value.status_code == 400
    assert "allows a maximum of 1,000 ports" in exc_info.value.detail

    # 3. Enterprise limit (<= 65535 ports)
    mock_org.plan = "enterprise"
    # An enterprise user can scan 10000 ports
    custom_ports_ent_ok = ",".join(
        str(x) for x in range(1, 2000) if x not in (2375, 2376, 6443, 10250)
    )
    check_scan_quota(mock_db, org_id="org-1", custom_ports=custom_ports_ent_ok)

    # Verify sensitive ports parse fine during check_scan_quota too
    check_scan_quota(mock_db, org_id="org-1", custom_ports="22,6443,80")
