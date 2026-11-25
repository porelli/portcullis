#!/usr/bin/env python3
"""Unit tests for tests/e2e/scenarios.py (E2E_SCENARIOS, ci.yml's
`scenarios` input): names from check() names, setup always runs, the
needs() closure, the per-job check, unknown names refused.

Run: python3 tests/test_e2e_scenarios.py (or python3 -m pytest -q tests/)
"""
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "e2e"))
os.environ.pop("E2E_SCENARIOS", None)
import scenarios  # noqa: E402


class Keys(unittest.TestCase):
    def test_names(self):
        k = scenarios.keys
        self.assertEqual(k("4 mail_password_flow"), ["4", "mail_password_flow"])
        self.assertEqual(k("3 gtube_rejected_at_data, between_thresholds_to_junk"),
                         ["3", "gtube_rejected_at_data", "between_thresholds_to_junk"])
        self.assertEqual(k("1 exchange_both_ways (dkim ed25519 + rsa, spf, dmarc; the DMARC report)"),
                         ["1", "exchange_both_ways"])
        self.assertEqual(k("cross_domain_sso: a stale ext cookie signs in again"), ["cross_domain_sso"])
        self.assertEqual(k("imp_refused_concurrent + imp_next_bound (reuse): a second start"),
                         ["imp_refused_concurrent", "imp_next_bound"])
        self.assertEqual(k("fourth_refused / remove: at 3 the page offers no + Add"), ["fourth_refused", "remove"])
        self.assertEqual(k("reclassify (1): with the key's entry gone"), ["reclassify"])
        self.assertEqual(k("login_theme_brand"), ["login_theme_brand"])

    def test_setup_has_no_key(self):
        for n in ("alice, bob and carol: setup link → passkey → portal", "the session reaches the app",
                  "X.509 login via Keycloak satisfies a YubiKey-certificate template",
                  "headscale is wired as a VPN provider and its map is fresh"):
            self.assertEqual(scenarios.keys(n), [], n)


RUNNER = textwrap.dedent('''
    state = {}
    def needs(*k): pass
    def check(name, fn): pass
    def main():
        def a():
            state["made_by_a"] = 1
        check("a_first: makes state", a)
        def b():
            needs("made_by_a")
            state["b1"], state["b2"] = 1, 2
        check("b_second: needs a", b)
        def c():
            needs("b2")
        check("c_third: needs b", c)
        check("d_alone: nothing", lambda: helper())
        check("prose check, always runs", a)
    def helper():
        pass
''')


class Closure(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.p = Path(self.d.name) / "e2e_fake.py"
        self.p.write_text(RUNNER)

    def tearDown(self):
        self.d.cleanup()

    def test_known(self):
        self.assertEqual(scenarios.known([self.p])["e2e_fake.py"], {"a_first", "b_second", "c_third", "d_alone"})

    def test_transitive(self):
        self.assertEqual(scenarios.closure({"c_third"}, [self.p]), {"a_first", "b_second", "c_third"})
        self.assertEqual(scenarios.closure({"d_alone"}, [self.p]), {"d_alone"})


class Wanted(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("E2E_SCENARIOS", None)
        scenarios._WANT = None

    def test_empty_runs_all(self):
        scenarios._WANT = None
        self.assertTrue(scenarios.wanted("5 revoke_within_8s"))

    def test_filter(self):
        os.environ["E2E_SCENARIOS"] = "4"
        scenarios._WANT = None
        self.assertTrue(scenarios.wanted("4 mail_password_flow"))
        self.assertTrue(scenarios.wanted("setup: people, mail domains"))
        self.assertTrue(scenarios.wanted("alice, bob and carol: setup link"))
        self.assertFalse(scenarios.wanted("5 revoke_within_8s"))


def cli(*args, env=None):
    e = dict(os.environ, **(env or {}))
    return subprocess.run([sys.executable, str(HERE / "e2e" / "scenarios.py"), *args], capture_output=True, text=True, env=e)


class Cli(unittest.TestCase):
    def test_check_known_and_unknown(self):
        ok = cli("check", "--jobs", "e2e-mail", "--scenarios", "4,members_only_list")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("e2e_mail.py: 4 members_only_list", ok.stdout)
        bad = cli("check", "--jobs", "e2e-mail", "--scenarios", "4 no_such_scenario")
        self.assertEqual(bad.returncode, 1)
        self.assertIn("no_such_scenario", bad.stderr)
        # a name of another job's runner is unknown for this job
        other = cli("check", "--jobs", "e2e-mail", "--scenarios", "replay_refused")
        self.assertEqual(other.returncode, 1)
        self.assertEqual(cli("check", "--jobs", "e2e-signin", "--scenarios", "replay_refused").returncode, 0)

    def test_every_e2e_job_has_runners(self):
        per_job = scenarios.job_runners(HERE.parent / ".github/workflows/ci.yml")
        for job in ("e2e-mail", "e2e-signin", "e2e-ai", "e2e-vpn", "e2e-folders", "e2e-filesharing",
                    "e2e-settings", "e2e-instances", "e2e", "e2e-ha-k3d"):
            self.assertTrue(per_job.get(job), job)

    def test_ha_k3d_scenarios(self):
        # Task 33 part A: the job runs tests/e2e/e2e_ha.py, which knows every
        # k3d scenario (each check gated by scenarios.skip, below).
        per_job = scenarios.job_runners(HERE.parent / ".github/workflows/ci.yml")
        self.assertIn(HERE / "e2e" / "e2e_ha.py", per_job.get("e2e-ha-k3d", []))
        names = scenarios.known([HERE / "e2e" / "e2e_ha.py"])["e2e_ha.py"]
        for n in ("ha_cnpg_failover", "ha_signin_continuity", "ha_sentinel_promotion", "ha_vault_leader_loss",
                  "ha_hub_lease_handover", "ha_dns_failover", "ha_n_minus_1", "ha_published_docs",
                  "ha_dns_failover_sites", "ha_coredns_node_kill", "ha_dns_failover_nodeadm_node"):
            self.assertIn(n, names)
        ok = cli("check", "--jobs", "e2e-ha-k3d", "--scenarios", "ha_cnpg_failover")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(cli("check", "--jobs", "e2e-k3s", "--scenarios", "ha_cnpg_failover").returncode, 1)

    def test_import_refuses_unknown(self):
        r = subprocess.run([sys.executable, "-c", "import scenarios"], cwd=HERE / "e2e", capture_output=True,
                           text=True, env=dict(os.environ, E2E_SCENARIOS="no_such_scenario"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown scenario", r.stderr)

    def test_every_runner_check_is_gated(self):
        # every runner that defines check() must start it with scenarios.skip
        for p in sorted((HERE / "e2e").glob("e2e_*.py")):
            src = p.read_text()
            if "\ndef check(name: str, fn) -> None:\n" in src:
                self.assertIn("def check(name: str, fn) -> None:\n    if scenarios.skip(name):", src, p.name)


if __name__ == "__main__":
    unittest.main()
