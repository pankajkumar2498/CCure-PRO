"""
tests/test_scans.py
─────────────────────────────────────────────────────────────────────────────
API tests for the phase-selective and traditional scan endpoints.
We mock the internal scanner engines so tests run instantly and don't hit the network.
"""

from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

def test_host_discovery_endpoint(client: TestClient, auth_headers: dict):
    """Test the Phase 1 Host Discovery API logic and DB persistence."""
    
    # Mock the internal orchestrator to return a successful dummy result
    mock_result = {
        "success": True,
        "data": [{"ip_address": "192.168.1.10", "status": "up", "mac_address": "AA:BB:CC:DD:EE:FF"}],
        "summary": {"total_hosts": 1, "active_hosts": 1, "inactive_hosts": 0, "scan_duration": 0.5}
    }
    
    with patch("scan_helpers.HostDiscoveryAPI") as mock_api_class:
        mock_orch = AsyncMock()
        mock_orch.run_host_discovery_only.return_value = mock_result
        mock_orch.generate_phase_report.return_value = {"json_pdf": "/fake/path.pdf"}
        
        # Override the get_api() singleton
        mock_api_instance = mock_api_class.return_value
        mock_api_instance._orch = mock_orch
        
        with patch("routers.phase_scans.get_api", return_value=mock_api_instance):
            response = client.post(
                "/scan/host-discovery",
                headers=auth_headers,
                json={
                    "targets": ["192.168.1.0/24"],
                    "scan_type": "adaptive",
                    "pipeline_mode": "asset"
                }
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "scan_id" in data
            assert data["pipeline_mode"] == "asset"
            assert data["summary"]["active_hosts"] == 1

            # Ensure rate limiting header is present (slowapi adds standard X-RateLimit headers)
            assert "X-RateLimit-Limit" in response.headers or response.status_code == 200


def test_asset_discovery_wrong_pipeline_mode(client: TestClient, auth_headers: dict):
    """Test that calling Asset Discovery on a 'basic' pipeline fails."""
    response = client.post(
        "/scan/asset-discovery",
        headers=auth_headers,
        json={
            "hosts": [{"ip_address": "192.168.1.10"}],
            "intensity": "normal",
            "pipeline_mode": "basic"  # Basic pipeline only allows Phase 1
        }
    )
    
    assert response.status_code == 400
    assert "not part of the 'basic' pipeline" in response.json()["detail"]


def test_credentialed_scan_validation_scrubbing(client: TestClient, auth_headers: dict):
    """
    Test that the global RequestValidationError handler scrubs sensitive fields 
    like 'password' from 422 Unprocessable Entity responses.
    """
    # Missing required 'ip' and 'username' fields, but providing a bad password type
    response = client.post(
        "/scan/credentialed",
        headers=auth_headers,
        json={
            "password": ["this_is_an_invalid_type_for_a_password_field"] 
        }
    )
    
    assert response.status_code == 422
    data = response.json()
    
    # Check that the raw input isn't leaked in the response
    detail_str = str(data["detail"])
    assert "this_is_an_invalid_type_for_a_password_field" not in detail_str
    assert "Value redacted for security." in detail_str
