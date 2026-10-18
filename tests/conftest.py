import copy
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> dict:
    with open(FIXTURES / f"{name}.json", encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture
def fixture():
    def _fixture(name: str) -> dict:
        return copy.deepcopy(load(name))

    return _fixture


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
