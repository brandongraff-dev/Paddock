# This file is deliberately present: fixtures contain tests/ and conftest.py that pytest must not
# collect (contract 3.12).
import pytest


@pytest.fixture
def anything():
    return undefined_name_for_the_lint_exclusion_probe
