import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from core.tasks import run_host_discovery_task


@pytest.fixture
def mock_db():
    return MagicMock()


@pytest.fixture
def mock_orch():
    with patch("core.tasks._new_orchestrator") as m:
        mock_instance = MagicMock()
        m.return_value = mock_instance
        yield mock_instance


def test_run_host_discovery_task_success(mock_orch, mock_db):
    """Verify that the discovery task calls the orchestrator and updates the DB."""
    # Setup mock returns
    mock_orch.run_host_discovery_only = AsyncMock(
        return_value={
            "success": True,
            "data": [{"ip": "10.180.6.14", "is_active": True}],
            "summary": {"total_hosts": 1, "active_hosts": 1},
        }
    )

    # Set up mock scan row returned by DB query
    mock_scan = MagicMock()
    mock_scan.id = "test-uuid"
    mock_scan.options = {}
    mock_scan.active_hosts = 1
    mock_scan.total_hosts = 1
    mock_scan.status = "complete"

    mock_db.query().filter().first.return_value = mock_scan

    # We patch the DB Session and helpers
    with patch("core.tasks.SessionLocal", return_value=mock_db), patch(
        "core.tasks.create_completed_scan", return_value=mock_scan
    ) as mock_create, patch(
        "scans.db_helpers.update_scan_phase1", return_value=mock_scan
    ) as mock_update, patch(
        "core.tasks._update_task_id"
    ), patch(
        "core.tasks._check_cancelled", return_value=False
    ), patch(
        "core.tasks.resolve_pipeline_mode", return_value="basic"
    ), patch(
        "core.tasks.get_terminal_phase", return_value=1
    ), patch(
        "core.tasks.resolve_report_context", return_value={}
    ), patch(
        "core.redis_client.publish_progress_sync"
    ), patch(
        "core.tasks._chain_topology_if_needed"
    ):

        # Execute task
        result = run_host_discovery_task(
            user_id="user-1",
            targets=["10.180.6.14"],
            scan_type="adaptive",
            pipeline_mode="basic",
            discovery_intensity="normal",
            scan_id="test-uuid",
        )

        # Assertions
        assert result["success"] is True
        mock_orch.run_host_discovery_only.assert_called_once()
        mock_update.assert_called_once()
        mock_db.close.assert_called_once()


def test_run_host_discovery_task_failure(mock_orch, mock_db):
    """Verify that the task handles orchestrator failure and marks scan as failed."""
    mock_orch.run_host_discovery_only = AsyncMock(
        return_value={
            "success": False,
            "error": "Network unreachable",
        }
    )

    mock_scan = MagicMock()
    mock_scan.id = "test-uuid"
    mock_scan.options = {}

    mock_db.query().filter().first.return_value = mock_scan

    with patch("core.tasks.SessionLocal", return_value=mock_db), patch(
        "core.tasks.create_completed_scan", return_value=mock_scan
    ) as mock_create, patch("core.tasks._update_task_id"), patch(
        "core.tasks._check_cancelled", return_value=False
    ), patch(
        "core.tasks.resolve_pipeline_mode", return_value="basic"
    ), patch(
        "core.tasks.get_terminal_phase", return_value=1
    ), patch(
        "core.tasks.mark_scan_failed"
    ) as mock_mark_failed:

        result = run_host_discovery_task(
            user_id="user-1",
            targets=["1.1.1.1"],
            scan_type="adaptive",
            pipeline_mode="basic",
            discovery_intensity="normal",
            scan_id="test-uuid",
        )

        assert result["success"] is False
        assert result["error"] == "Network unreachable"
        mock_mark_failed.assert_called_once()
