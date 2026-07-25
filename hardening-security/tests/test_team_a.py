"""Pytest wrapper for Team A hardening + security tests."""
import sys, os
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "hw-track-1-sensors"))
sys.path.insert(0, os.path.join(ROOT, "hw-track-2-security-boot"))
sys.path.insert(0, os.path.join(ROOT, "hw-track-3-connectivity"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hardening_security_tests import *


# ---- pulled into a module so pytest discovers them ----
