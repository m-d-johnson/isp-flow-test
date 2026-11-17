import importlib.util
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "isp-flow-test.py")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")


def load_script():
    """Import isp-flow-test.py as a module (its name has a hyphen, so plain import won't do)."""
    spec = importlib.util.spec_from_file_location("isp_flow_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["isp_flow_test"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def ift():
    """A fresh copy of the script per test, so module state (TARGETS, BUDGET, caches) can't leak."""
    return load_script()
