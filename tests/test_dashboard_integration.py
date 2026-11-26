"""Unit and integration tests for SHEBA SHIELD master dashboard components.
Verifies all components, charts, database queries, and configuration logic.
"""

from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

from src.dashboard.assets import get_crest_data_uri
from src.dashboard.components.charts import (
    latency_chart,
    layer_distribution_chart,
    overview_categories_chart,
    overview_traffic_chart,
    risk_score_histogram,
    threat_volume_chart,
)
from src.dashboard.components.drawer import _badge, _render_layer_trace, _risk_bar
from src.dashboard.components.metrics_cards import (
    format_count,
    format_latency,
    format_rate,
)
from src.dashboard.styles import MASTER_CSS

# Dynamically import numbered Streamlit pages
threat_logs_mod = importlib.import_module("src.dashboard.pages.2_Threat_Logs")
neutralize_formula = threat_logs_mod.neutralize_formula
rows_to_csv = threat_logs_mod.rows_to_csv

config_mod = importlib.import_module("src.dashboard.pages.3_Configuration")
_password_matches = config_mod._password_matches
validate_rule = config_mod.validate_rule
validate_settings = config_mod.validate_settings


def test_master_css_contains_design_system():
    assert "--bg: #070B16" in MASTER_CSS or "--bg:#070B16" in MASTER_CSS
    assert "--gold: #D9AE5B" in MASTER_CSS or "--gold:#D9AE5B" in MASTER_CSS
    assert "Cinzel" in MASTER_CSS
    assert ".hero" in MASTER_CSS
    assert ".pipeline" in MASTER_CSS
    assert ".kpi" in MASTER_CSS
    assert ".badge" in MASTER_CSS


def test_mobile_navigation_header_overrides_hidden_streamlit_header():
    mobile_header_css = MASTER_CSS.split(".mobile-nav-header {", 1)[1].split("}", 1)[0]

    assert "visibility: visible !important;" in mobile_header_css
    assert "height: auto !important;" in mobile_header_css
    assert "min-height: 60px !important;" in mobile_header_css


def test_crest_asset_loaded():
    uri = get_crest_data_uri()
    assert uri.startswith("data:image/png;base64,")
    assert len(uri) > 1000


def test_metric_card_formatters():
    assert format_count(1250) == "1,250"
    assert format_count(None) == "—"
    assert format_rate(0.125) == "12.5%"
    assert format_rate(12.5) == "12.5%"
    assert format_latency(24.5) == "24.5 ms"
    assert format_latency(1500) == "1.50 s"


def test_charts_generate_valid_figures():
    # Traffic
    data_points = [
        {"time": "2026-11-19T00:00:00", "total": 100, "blocked": 10, "safe": 90},
        {"time": "2026-11-19T01:00:00", "total": 120, "blocked": 15, "safe": 105},
    ]
    traffic_fig = overview_traffic_chart(data_points)
    assert traffic_fig is not None
    assert len(traffic_fig.data) == 2

    # Categories
    cats = {"Jailbreak": 45, "Prompt leak": 25, "System override": 18, "PII": 9}
    cat_fig = overview_categories_chart(cats)
    assert cat_fig is not None
    assert cat_fig.data[0].hole == 0.68

    # Volume
    vol_fig = threat_volume_chart(data_points)
    assert vol_fig is not None

    # Layer
    layers = {"LAYER_1": 10, "LAYER_2": 20, "LAYER_3": 5, "OUTPUT_SCANNER": 2}
    layer_fig = layer_distribution_chart(layers)
    assert layer_fig is not None

    # Risk
    bins = [{"low": 0.1, "count": 15}, {"low": 0.8, "count": 4}]
    risk_fig = risk_score_histogram(bins)
    assert risk_fig is not None

    # Latency
    lat_data = [{"time": "2026-11-19T00:00:00", "avg_latency_ms": 25.0, "p95_latency_ms": 80.0}]
    lat_fig = latency_chart(lat_data)
    assert lat_fig is not None

    # Latency with avg_ms and p95_ms keys (as returned by _query_latency)
    lat_query_data = [{"bucket_start": "2026-11-19T00:00:00", "avg_ms": 54.2, "p95_ms": 180.5}]
    lat_fig2 = latency_chart(lat_query_data)
    assert lat_fig2 is not None
    assert len(lat_fig2.data) == 2
    assert lat_fig2.data[0].name == "Average"
    assert lat_fig2.data[1].name == "p95"

    # Risk score histogram explicitly produces 10 bins (0.0 to 0.9)
    risk_bins = [{"bin_start": 0.0, "count": 30}, {"bin_start": 0.8, "count": 6}, {"bin_start": 0.9, "count": 16}]
    risk_fig2 = risk_score_histogram(risk_bins)
    assert len(risk_fig2.data[0].x) == 10
    assert list(risk_fig2.data[0].x) == ["0.0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9"]


def test_drawer_components():
    badge_html = _badge("BLOCKED")
    assert "b-blocked" in badge_html
    assert "BLOCKED" in badge_html

    risk_html = _risk_bar(0.92)
    assert "0.92" in risk_html
    assert "var(--danger)" in risk_html

    trace_html = _render_layer_trace({
        "action_taken": "BLOCKED",
        "triggered_layer": "LAYER_2",
        "risk_score": 0.94,
    })
    assert "LAYER_1" in trace_html
    assert "LAYER_2" in trace_html
    assert "Clear" in trace_html


def test_threat_logs_formula_neutralization():
    assert neutralize_formula("=SUM(A1:A10)") == "'=SUM(A1:A10)"
    assert neutralize_formula("+12345") == "'+12345"
    assert neutralize_formula("-calc") == "'-calc"
    assert neutralize_formula("@admin") == "'@admin"
    assert neutralize_formula("normal prompt") == "normal prompt"

    csv_data = rows_to_csv([{"prompt": "=cmd|' /C calc'!A0", "risk": 0.9}])
    assert b"'=cmd" in csv_data


def test_configuration_validation():
    # Password matching (constant time)
    assert _password_matches("secret123", "secret123") is True
    assert _password_matches("wrong", "secret123") is False

    # Setting validation
    valid_settings = {
        "pipeline": {
            "layer_1_enabled": True,
            "layer_2_enabled": True,
            "layer_3_enabled": True,
            "output_scanner_enabled": True,
        },
        "layer_2": {"high_confidence_threshold": 0.85, "low_confidence_threshold": 0.35},
        "output_scanner": {"on_detect": "redact"},
    }
    assert validate_settings(valid_settings) == []

    invalid_settings = dict(valid_settings)
    invalid_settings["layer_2"] = {"high_confidence_threshold": 0.20, "low_confidence_threshold": 0.80}
    assert len(validate_settings(invalid_settings)) > 0

    # Rule validation
    valid_rule = {
        "rule_id": "RULE_TEST_01",
        "rule_type": "REGEX",
        "category": "JAILBREAK",
        "severity": "HIGH",
        "pattern": r"\btest\b",
        "description": "Test rule",
    }
    assert validate_rule(valid_rule) == []

    invalid_rule = {
        "rule_id": "invalid-id",
        "rule_type": "UNKNOWN",
        "category": "INVALID",
        "severity": "LOW",
        "pattern": "",
    }
    assert len(validate_rule(invalid_rule)) > 0
