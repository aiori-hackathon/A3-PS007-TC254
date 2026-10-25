import pytest
from pathlib import Path
from network.lab_status import LabStatusManager
from network.lab_teardown import LabTeardownManager, LabTeardownError
from network.lab_config import Priv6LabConfig

def test_attack_preflight_blocked_when_lab_down(tmp_path: Path):
    nonexistent_manifest = str(tmp_path / "absent_manifest.json")
    cfg = Priv6LabConfig(manifest_path=nonexistent_manifest, bridge_name="p6g-nonexistent-br")
    status_mgr = LabStatusManager(cfg)

    ok, msg = status_mgr.preflight_attack_check()
    assert ok is False
    assert "Attack blocked" in msg

def test_teardown_refused_without_manifest(tmp_path: Path):
    nonexistent_manifest = str(tmp_path / "absent_manifest.json")
    cfg = Priv6LabConfig(manifest_path=nonexistent_manifest, bridge_name="p6g-nonexistent-br")
    teardown_mgr = LabTeardownManager(cfg)

    with pytest.raises(LabTeardownError) as exc_info:
        teardown_mgr.teardown_lab(force=False)
    assert "Refusing unsafe cleanup" in str(exc_info.value)
