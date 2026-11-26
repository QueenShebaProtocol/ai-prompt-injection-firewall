import asyncio
from types import SimpleNamespace

import pytest

from src import main
from src.engine.pipeline import PipelineConfig


@pytest.mark.parametrize(
    "layer_2_enabled, layer_3_enabled, layer_2_loaded, expected_warning",
    [
        (True, True, True, None),
        (
            False,
            True,
            False,
            "Layer 2 is disabled; prompts that pass Layer 1 are evaluated by Layer 3.",
        ),
        (
            False,
            False,
            False,
            "Only Layer 1 can inspect prompts; Layer 2 and Layer 3 are disabled.",
        ),
        (
            True,
            False,
            True,
            "Layer 3 is disabled; uncertain Layer 2 results are blocked.",
        ),
        (
            True,
            False,
            False,
            "Layer 2 is unavailable and Layer 3 is disabled; prompts not blocked by Layer 1 are rejected.",
        ),
    ],
)
def test_health_status_describes_layer_configuration(
    monkeypatch,
    layer_2_enabled,
    layer_3_enabled,
    layer_2_loaded,
    expected_warning,
):
    config = PipelineConfig(
        layer_2_enabled=layer_2_enabled,
        layer_3_enabled=layer_3_enabled,
    )
    monkeypatch.setattr(main, "get_pipeline_config", lambda: config)
    monkeypatch.setattr(
        main,
        "get_classifier",
        lambda: SimpleNamespace(status=lambda: {"loaded": layer_2_loaded}),
    )
    monkeypatch.setattr(main.layer1_engine, "_rules", [{"rule_id": "test"}])

    status = asyncio.run(main.root())

    assert status["security_warning"] == expected_warning
