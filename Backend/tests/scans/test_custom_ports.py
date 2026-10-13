import pytest
from core.utils import InputValidator


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
    with pytest.raises(ValueError, match="Malformed port"):
        InputValidator.parse_custom_ports("22a")
    with pytest.raises(ValueError, match="Malformed port range"):
        InputValidator.parse_custom_ports("80-80-80")
    with pytest.raises(ValueError, match="Malformed port range"):
        InputValidator.parse_custom_ports("80-abc")

    # Range start > end
    with pytest.raises(ValueError, match="greater than"):
        InputValidator.parse_custom_ports("80-79")

    # Out of bounds
    with pytest.raises(ValueError, match="must be between 1 and 65535"):
        InputValidator.parse_custom_ports("0")
    with pytest.raises(ValueError, match="must be between 1 and 65535"):
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
    with pytest.raises(ValueError, match="Malformed port"):
        InputValidator.parse_exclude_ports("22a")
    with pytest.raises(ValueError, match="Malformed port range"):
        InputValidator.parse_exclude_ports("80-80-80")
    with pytest.raises(ValueError, match="Malformed port range"):
        InputValidator.parse_exclude_ports("80-abc")
    with pytest.raises(ValueError, match="greater than"):
        InputValidator.parse_exclude_ports("80-79")
    with pytest.raises(ValueError, match="must be between 1 and 65535"):
        InputValidator.parse_exclude_ports("0")
    with pytest.raises(ValueError, match="Duplicate port detected"):
        InputValidator.parse_exclude_ports("22,22")
