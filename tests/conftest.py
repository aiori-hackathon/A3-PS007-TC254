import os
import pytest
import pytest_asyncio
from pathlib import Path

from config.app_config import settings, LabConfig, DetectionRules
from backend.storage.database import Database

@pytest.fixture(scope="session")
def lab_config() -> LabConfig:
    return settings.load_lab_config()

@pytest.fixture(scope="session")
def detection_rules() -> DetectionRules:
    return settings.load_detection_rules()

@pytest_asyncio.fixture
async def temp_db(tmp_path: Path):
    db_file = tmp_path / "test_priv6guard.db"
    db = Database(str(db_file))
    await db.init_db()
    return db
