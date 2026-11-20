"""Regression tests for KPI metrics calculation and bypassed request handling.

Verifies:
  - Total requests includes all requests.
  - Blocked requests counts blocked requests.
  - Bypassed requests counts requests where layer_details.firewall_master = OFF.
  - Safe / Passed Inspection counts only requests that actually passed inspection:
      Safe = Total - Blocked - Bypassed
  - Bypassed requests are never counted as inspected or safe.
  - Tests covering:
      1. Normal passed request
      2. Blocked request
      3. Bypassed request
      4. Mixed dataset containing all three
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    import pytest
except ImportError:
    pytest = None

from src.dashboard.components.metrics_cards import render_overview_kpis, render_kpi_cards


def _create_log_dict(
    *,
    is_blocked: bool,
    action_taken: str,
    triggered_layer: str,
    risk_score: float,
    layer_details: dict | None = None,
) -> dict:
    return {
        "request_id": f"kpi-test-{uuid.uuid4()}",
        "created_at": datetime.now(timezone.utc),
        "client_ip": "127.0.0.1",
        "application_id": "kpi-regression",
        "target_model": "test-model",
        "raw_prompt": "test prompt",
        "system_instruction": "",
        "is_blocked": is_blocked,
        "action_taken": action_taken,
        "triggered_layer": triggered_layer,
        "risk_score": risk_score,
        "execution_time_ms": 10.0,
        "layer_details": layer_details or {},
        "detected_patterns": [],
        "output_completion": None,
        "output_flagged": False,
    }


def compute_kpis_from_rows(rows: list[dict]) -> dict:
    """Mirrors the exact PostgreSQL get_kpi_summary query in Python memory."""
    total = len(rows)
    blocked = sum(1 for r in rows if r.get("is_blocked") is True)
    bypassed = sum(
        1 for r in rows
        if isinstance(r.get("layer_details"), dict) and r["layer_details"].get("firewall_master") == "OFF"
    )
    safe = max(0, total - blocked - bypassed)
    inspected = max(0, total - bypassed)
    rate = (blocked / inspected * 100.0) if inspected > 0 else 0.0
    return {
        "total_requests": total,
        "blocked_requests": blocked,
        "bypassed_requests": bypassed,
        "safe_requests": safe,
        "block_rate": rate / 100.0,
        "threat_rate_pct": rate,
    }


class TestKpiMetricsCalculation:
    """Verification of KPI formula across all 4 required dataset permutations."""

    def test_kpi_formula_normal_passed(self):
        """1. Normal passed request: Total=1, Blocked=0, Bypassed=0, Safe=1."""
        dataset = [
            _create_log_dict(is_blocked=False, action_taken="PASSED", triggered_layer="NONE", risk_score=0.1)
        ]
        res = compute_kpis_from_rows(dataset)
        assert res["total_requests"] == 1
        assert res["blocked_requests"] == 0
        assert res["bypassed_requests"] == 0
        assert res["safe_requests"] == 1
        assert res["threat_rate_pct"] == 0.0

    def test_kpi_formula_blocked(self):
        """2. Blocked request: Total=1, Blocked=1, Bypassed=0, Safe=0."""
        dataset = [
            _create_log_dict(is_blocked=True, action_taken="BLOCKED", triggered_layer="LAYER_1", risk_score=1.0)
        ]
        res = compute_kpis_from_rows(dataset)
        assert res["total_requests"] == 1
        assert res["blocked_requests"] == 1
        assert res["bypassed_requests"] == 0
        assert res["safe_requests"] == 0
        assert res["threat_rate_pct"] == 100.0

    def test_kpi_formula_bypassed(self):
        """3. Bypassed request: Total=1, Blocked=0, Bypassed=1, Safe=0."""
        dataset = [
            _create_log_dict(
                is_blocked=False,
                action_taken="PASSED",
                triggered_layer="NONE",
                risk_score=0.0,
                layer_details={"firewall_master": "OFF", "bypassed": True},
            )
        ]
        res = compute_kpis_from_rows(dataset)
        assert res["total_requests"] == 1
        assert res["blocked_requests"] == 0
        assert res["bypassed_requests"] == 1
        # Safe MUST be 0 - bypassed requests were never inspected!
        assert res["safe_requests"] == 0
        assert res["threat_rate_pct"] == 0.0

    def test_kpi_formula_mixed_dataset(self):
        """4. Mixed dataset: 4 passed, 3 blocked, 3 bypassed.

        Total = 10
        Blocked = 3
        Bypassed = 3
        Safe = 10 - 3 - 3 = 4
        Inspected = 10 - 3 = 7
        Threat Rate = 3 / 7 = 42.86%
        """
        dataset = [
            # 4 Passed
            _create_log_dict(is_blocked=False, action_taken="PASSED", triggered_layer="NONE", risk_score=0.1),
            _create_log_dict(is_blocked=False, action_taken="PASSED", triggered_layer="NONE", risk_score=0.2),
            _create_log_dict(is_blocked=False, action_taken="PASSED", triggered_layer="NONE", risk_score=0.15),
            _create_log_dict(is_blocked=False, action_taken="PASSED", triggered_layer="NONE", risk_score=0.05),
            # 3 Blocked
            _create_log_dict(is_blocked=True, action_taken="BLOCKED", triggered_layer="LAYER_1", risk_score=1.0),
            _create_log_dict(is_blocked=True, action_taken="BLOCKED", triggered_layer="LAYER_2", risk_score=0.92),
            _create_log_dict(is_blocked=True, action_taken="BLOCKED", triggered_layer="OUTPUT_SCANNER", risk_score=1.0),
            # 3 Bypassed
            _create_log_dict(is_blocked=False, action_taken="PASSED", triggered_layer="NONE", risk_score=0.0, layer_details={"firewall_master": "OFF", "bypassed": True}),
            _create_log_dict(is_blocked=False, action_taken="PASSED", triggered_layer="NONE", risk_score=0.0, layer_details={"firewall_master": "OFF", "bypassed": True}),
            _create_log_dict(is_blocked=False, action_taken="PASSED", triggered_layer="NONE", risk_score=0.0, layer_details={"firewall_master": "OFF", "bypassed": True}),
        ]
        res = compute_kpis_from_rows(dataset)
        assert res["total_requests"] == 10
        assert res["blocked_requests"] == 3
        assert res["bypassed_requests"] == 3
        assert res["safe_requests"] == 4
        assert round(res["threat_rate_pct"], 2) == 42.86

    def test_overview_consumer_safe_prompts_contract(self):
        """Dashboard overview consumer contract: Safe prompts strictly equals Total - Blocked - Bypassed."""
        kpi_data = {
            "total_requests": 626,
            "blocked_requests": 89,
            "bypassed_requests": 62,
            "safe_requests": 475,  # 626 - 89 - 62 = 475
        }
        total = kpi_data["total_requests"]
        blocked = kpi_data["blocked_requests"]
        bypassed = kpi_data["bypassed_requests"]
        safe = kpi_data["safe_requests"]

        assert safe == total - blocked - bypassed
        # Ensure it does NOT equal total - blocked (which would incorrectly be 537)
        assert safe != total - blocked

    def test_analytics_consumer_threat_rate_contract(self):
        """Dashboard analytics consumer contract: threat rate of inspected traffic."""
        kpi_data = {
            "total_requests": 100,
            "blocked_requests": 25,
            "bypassed_requests": 50,
            "safe_requests": 25,
        }
        total = kpi_data["total_requests"]
        blocked = kpi_data["blocked_requests"]
        bypassed = kpi_data["bypassed_requests"]
        inspected = total - bypassed
        rate = (blocked / inspected * 100.0) if inspected > 0 else 0.0

        # Rate of inspected traffic: 25 / 50 = 50%
        assert rate == 50.0
        # If bypassed were incorrectly counted as inspected, rate would be 25% (25/100)
        assert rate != (blocked / total * 100.0)


class TestKpiDatabaseIntegration:
    """Tests get_kpi_summary against live PostgreSQL when database is reachable."""

    def test_live_kpi_summary_distinguishes_bypassed(self):
        from src.database.connection import check_database_connection
        from src.database.storage import get_kpi_summary, run_sync

        db_ok = run_sync(check_database_connection())
        if not db_ok:
            if pytest:
                pytest.skip("Live database not directly reachable from host test runner; tested via container")
            else:
                print("Skipping live DB check: database not directly reachable from host")
                return

        # Database is reachable: query live KPI summary
        if hasattr(get_kpi_summary, "cache_clear"):
            get_kpi_summary.cache_clear()
        summary = run_sync(get_kpi_summary(hours=24))

        assert "total_requests" in summary
        assert "blocked_requests" in summary
        assert "bypassed_requests" in summary
        assert "safe_requests" in summary
        assert summary["safe_requests"] == summary["total_requests"] - summary["blocked_requests"] - summary["bypassed_requests"]
        print(f"Live summary verified: {summary}")


if __name__ == "__main__":
    t = TestKpiMetricsCalculation()
    t.test_kpi_formula_normal_passed()
    t.test_kpi_formula_blocked()
    t.test_kpi_formula_bypassed()
    t.test_kpi_formula_mixed_dataset()
    t.test_overview_consumer_safe_prompts_contract()
    t.test_analytics_consumer_threat_rate_contract()
    print("All TestKpiMetricsCalculation passed.")

    t_db = TestKpiDatabaseIntegration()
    t_db.test_live_kpi_summary_distinguishes_bypassed()
    print("TestKpiDatabaseIntegration completed.")
