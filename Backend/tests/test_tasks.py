import pytest
from unittest.mock import MagicMock, patch
from core.tasks import run_host_discovery_task

@pytest.fixture
def mock_db():
    return MagicMock()

@pytest.fixture
def mock_orch():
    with patch('core.tasks._orch') as m:
        yield m

def test_run_host_discovery_task_success(mock_orch, mock_db):
    """Verify that the discovery task calls the orchestrator and updates the DB."""
    # Setup mock returns
    mock_orch.run_host_discovery_only.return_value = {
        "success": True,
        "data": [{"ip": "192.168.1.1", "is_active": True}],
        "summary": {"total_hosts": 1, "active_hosts": 1}
    }
    
    # We patch the DB Session and helpers
    with patch('core.tasks.SessionLocal', return_value=mock_db), \
         patch('core.tasks.create_scan') as mock_create, \
         patch('core.tasks.update_scan_phase') as mock_update, \
         patch('core.tasks.resolve_report_context', return_value={}):
        
        mock_scan = MagicMock()
        mock_scan.id = "test-uuid"
        mock_create.return_value = mock_scan
        
        # Execute task
        result = run_host_discovery_task(
            user_id="user-1",
            targets=["192.168.1.1"],
            scan_type="adaptive",
            pipeline_mode="basic",
            discovery_intensity="normal"
        )
        
        # Assertions
        assert result["success"] is True
        assert result["scan_id"] == "test-uuid"
        mock_orch.run_host_discovery_only.assert_called_once()
        mock_update.assert_called_once()
        mock_db.close.assert_called_once()

def test_run_host_discovery_task_failure(mock_orch, mock_db):
    """Verify that the task handles orchestrator failure and marks scan as failed."""
    mock_orch.run_host_discovery_only.return_value = {
        "success": False,
        "error": "Network unreachable"
    }
    
    with patch('core.tasks.SessionLocal', return_value=mock_db), \
         patch('core.tasks.create_scan') as mock_create, \
         patch('core.tasks.mark_scan_failed') as mock_mark_failed:
        
        mock_scan = MagicMock()
        mock_scan.id = "test-uuid"
        mock_create.return_value = mock_scan
        
        result = run_host_discovery_task(
            user_id="user-1",
            targets=["1.1.1.1"],
            scan_type="adaptive",
            pipeline_mode="basic",
            discovery_intensity="normal"
        )
        
        assert result["success"] is False
        assert result["error"] == "Network unreachable"
        mock_mark_failed.assert_called_once()
