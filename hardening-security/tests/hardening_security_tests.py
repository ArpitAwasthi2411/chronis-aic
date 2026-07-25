"""Team A hardening & security — all deliverables as pytest assertions."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'hw-track-1-sensors'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'hw-track-2-security-boot'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'hw-track-3-connectivity'))

from fuzzing.fuzz_harness import run_all_fuzzers, Severity
from security_attacks.attack_suite import run_all_security_attacks
from chaos_run.chaos_run import run_chaos


def test_fuzzing_zero_crashes():
    reports = run_all_fuzzers(verbose=False)
    total_crashes = sum(r.crashes for r in reports)
    assert total_crashes == 0, f"Fuzzing found {total_crashes} crashes"


def test_fuzzing_zero_silent_bad():
    reports = run_all_fuzzers(verbose=False)
    total_silent = sum(r.silent_bads for r in reports)
    assert total_silent == 0, f"Fuzzing found {total_silent} silent-bad behaviors"


def test_security_zero_vulnerabilities():
    suite = run_all_security_attacks(verbose=False)
    vulns = [r for r in suite.results if r.succeeded]
    assert len(vulns) == 0, f"Security found vulnerabilities: {[v.attack_name for v in vulns]}"


def test_chaos_zero_crashes():
    result = run_chaos(verbose=False)
    assert result["crashes"] == 0


def test_chaos_zero_rule_violations():
    result = run_chaos(verbose=False)
    assert result["rule_violations"] == 0


def test_chaos_sufficient_coverage():
    result = run_chaos(verbose=False)
    assert result["total_ticks"] >= 1000, f"Only {result['total_ticks']} ticks — need >= 1000"
