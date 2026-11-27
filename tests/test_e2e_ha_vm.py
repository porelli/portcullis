#!/usr/bin/env python3
"""Unit tests for tests/e2e/e2e_ha_vm.py's pure helpers (no VM, no cluster):
the writer log's one-history judgement (ha_vm_partition, power_off,
disk_kill), etcd member names (ha_vm_etcd_remove_member), the redaction of
setup links and join codes, the WireGuard route parse (ha_vm_nat_relay) and
the victim rotation's back-off wait. Run by CI unit-tests; stdlib only."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "e2e"))

_d = tempfile.mkdtemp()
os.chmod(_d, 0o700)
(Path(_d) / "inventory.json").write_text(json.dumps({
    "user": "ubuntu", "domain": "ha.example.test", "lan_cidr": "10.0.0.0/16",
    "vms": [{"vm": "vm1", "node": "node-1", "role": "first", "site": "main", "public": "192.0.2.1", "private": "10.0.0.1"},
            {"vm": "vm2", "node": "vm2", "role": "server", "site": "main", "public": "192.0.2.2", "private": "10.0.0.2"},
            {"vm": "vm3", "node": "vm3", "role": "server", "site": "main", "public": "192.0.2.3", "private": "10.0.0.3"},
            {"vm": "vm4", "node": "vm4", "role": "agent", "site": "edge", "public": "192.0.2.4", "private": "10.1.0.4"}]}))
os.environ["E2E_HA_VM_DIR"] = _d
os.environ.pop("E2E_SCENARIOS", None)
import e2e_ha_vm as m  # noqa: E402


class LogConsistent(unittest.TestCase):
    def test_one_history_passes(self):
        m.log_consistent([(1, 100, "a"), (2, 101, "a"), (3, 140, "b"), (4, 141, "b")])

    def test_gap_fails(self):
        with self.assertRaisesRegex(AssertionError, "one history"):
            m.log_consistent([(1, 100, "a"), (3, 140, "b")])

    def test_repeat_fails(self):  # a fork: two writers continued the same seq
        with self.assertRaisesRegex(AssertionError, "one history"):
            m.log_consistent([(1, 100, "a"), (2, 101, "a"), (2, 102, "b")])

    def test_old_writer_back_fails(self):
        with self.assertRaisesRegex(AssertionError, "wrote again"):
            m.log_consistent([(1, 100, "a"), (2, 140, "b"), (3, 141, "a")])

    def test_overlap_fails(self):  # two writers at once (b started before a's last line)
        with self.assertRaisesRegex(AssertionError, "overlap"):
            m.log_consistent([(1, 100, "a"), (2, 150, "a"), (3, 120, "b")])

    def test_must_start_at_one(self):
        with self.assertRaisesRegex(AssertionError, "starts at 5"):
            m.log_consistent([(5, 100, "a"), (6, 101, "a")])

    def test_empty_fails(self):
        with self.assertRaises(AssertionError):
            m.log_consistent([])


class EtcdMembers(unittest.TestCase):
    def test_member_of(self):
        members = ["node-1-1a2b3c", "vm2-4d5e6f", "vm3-2-aa11bb"]
        self.assertTrue(m.member_of("node-1", members))
        self.assertTrue(m.member_of("vm3-2", members))
        self.assertFalse(m.member_of("vm3", ["node-1-1a2b3c", "vm2-4d5e6f"]))
        # a prefix that isn't a name boundary doesn't count
        self.assertFalse(m.member_of("vm", members))


class Redact(unittest.TestCase):
    def test_links_and_codes(self):
        text = "see https://enroll.ha.example.test/invite/AbCdEf0123456789_-xyzAbCdEf0123456789_-xyzAB and pcj2.QUJDREVGR0hJSktMTU5PUFFSU1RVVldY"
        out = m.redact(text)
        self.assertNotIn("AbCdEf0123456789", out)
        self.assertNotIn("QUJDREVGR0hJSktM", out)
        self.assertIn("/invite/<redacted>", out)
        self.assertIn("<join code>", out)


class WgRoute(unittest.TestCase):
    def route(self, allowed: str, mesh: str) -> str:
        real = m.vm
        m.vm = lambda h, cmd, **kw: allowed
        try:
            return m.wg_route("vm4", mesh)
        finally:
            m.vm = real

    def test_direct(self):
        a = "keyA=\t10.215.0.1/32\nkeyB=\t10.215.0.2/32\nkeyC=\t10.215.0.3/32\n"
        self.assertEqual(self.route(a, "10.215.0.2"), "10.215.0.2")

    def test_through_the_gateway(self):
        a = "keyA=\t10.215.0.1/32 10.215.0.2/32 10.42.1.0/24\nkeyC=\t10.215.0.3/32\n"
        self.assertEqual(self.route(a, "10.215.0.2"), "10.215.0.1")

    def test_absent(self):
        self.assertEqual(self.route("keyA=\t10.215.0.1/32\n", "10.215.0.2"), "")


class FreshVictim(unittest.TestCase):
    def setUp(self):
        self.real = (m.storage_servers, m.time.sleep, m.note)
        self.slept = []
        m.storage_servers = lambda: ["node-1", "vm2", "vm3"]
        m.time.sleep = self.slept.append
        m.note = lambda _t: None
        m.last_cut.clear()

    def tearDown(self):
        m.storage_servers, m.time.sleep, m.note = self.real
        m.last_cut.clear()

    def test_never_vm1_and_least_recent(self):
        m.last_cut.update({"vm2": m.time.time() - 3600})
        self.assertEqual(m.fresh_victim(), "vm3")  # never cut beats long ago
        self.assertEqual(self.slept, [])

    def test_waits_out_the_backoff(self):
        now = m.time.time()
        m.last_cut.update({"vm2": now - 60, "vm3": now - 120})
        self.assertEqual(m.fresh_victim(), "vm3")
        self.assertEqual(len(self.slept), 1)
        self.assertGreater(self.slept[0], m.BACKOFF_S - 130)

    def test_no_wait_without_fencing(self):
        now = m.time.time()
        m.last_cut.update({"vm2": now - 60, "vm3": now - 120})
        self.assertEqual(m.fresh_victim(need_fence=False), "vm3")
        self.assertEqual(self.slept, [])



class ScenarioSelection(unittest.TestCase):
    """main() under E2E_SCENARIOS: every check() it names is defined (VM run 8
    died on a NameError, ha_vm_disk_full deleted by an edit, after the two
    drills before it), and each subset runs exactly its drills plus the ones
    their needs() pull in. main() runs with the cluster, the browser and
    check() stubbed: check() records what would run."""

    ALL = ["ha_vm_pebble_issue_sni", "ha_vm_same_site_reach", "ha_vm_partition", "ha_vm_power_off",
           "ha_vm_disk_kill", "ha_vm_disk_full", "ha_vm_lose_small", "ha_vm_rolling_upgrade",
           "ha_vm_site_uplink_down", "ha_vm_site_down", "ha_vm_nat_relay", "ha_vm_front_door_node",
           "ha_vm_front_door_nodeadm_one_node", "ha_vm_cert_renew_leader_move", "ha_vm_interrupted_removal",
           "ha_vm_revoke_restarts", "ha_vm_etcd_remove_member"]
    PULLED = {"ha_vm_etcd_remove_member": {"ha_vm_revoke_restarts"}}

    def run_main(self, subset):
        import contextlib
        import types
        ran = []
        saved = {k: getattr(m, k) for k in ("check", "_hub_secret", "retarget_api", "fixtures_ok", "helper_image")}
        saved_report = m.e2e_ha.report
        pw = types.ModuleType("playwright.sync_api")
        pw.sync_playwright = lambda: contextlib.nullcontext(object())
        mods = {"playwright": types.ModuleType("playwright"), "playwright.sync_api": pw}
        old_mods = {k: sys.modules.get(k) for k in mods}
        old_env = os.environ.get(m.scenarios.ENV)
        try:
            sys.modules.update(mods)
            if subset:
                os.environ[m.scenarios.ENV] = ",".join(subset)
            else:
                os.environ.pop(m.scenarios.ENV, None)
            m.scenarios._WANT = None

            def check(name, fn):
                self.assertTrue(callable(fn), name)
                key = name.split(":")[0]
                if key.startswith("ha_vm_"):
                    self.assertEqual(fn.__name__, key, f"check {key!r} runs {fn.__name__}")
                if not m.scenarios.skip(name):
                    ran.append(key)
            m.check = check
            m._hub_secret = lambda: "x"
            m.retarget_api = lambda *a, **k: None
            m.fixtures_ok = lambda: None
            m.helper_image = lambda: "img@sha256:" + "0" * 64
            m.e2e_ha.report = lambda: 0
            with open(os.devnull, "w") as dn, contextlib.redirect_stdout(dn):
                self.assertEqual(m.main(), 0)
        finally:
            for k, v in saved.items():
                setattr(m, k, v)
            m.e2e_ha.report = saved_report
            for k, v in old_mods.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
            if old_env is None:
                os.environ.pop(m.scenarios.ENV, None)
            else:
                os.environ[m.scenarios.ENV] = old_env
            m.scenarios._WANT = None
        return ran

    def expect(self, subset):
        want = set(subset)
        for s in subset:
            want |= self.PULLED.get(s, set())
        return ["admin signs in (a setup link, a virtual passkey) through a main ingress node"] + [n for n in self.ALL if n in want]

    def test_all(self):
        self.assertEqual(self.run_main([]), ["admin signs in (a setup link, a virtual passkey) through a main ingress node"] + self.ALL)

    def test_each_single(self):
        for n in self.ALL:
            with self.subTest(n):
                self.assertEqual(self.run_main([n]), self.expect([n]))

    def test_run_8_subset_and_prefixes(self):
        six = ["ha_vm_power_off", "ha_vm_disk_kill", "ha_vm_front_door_nodeadm_one_node",
               "ha_vm_interrupted_removal", "ha_vm_revoke_restarts", "ha_vm_etcd_remove_member"]
        for k in range(1, len(six) + 1):
            with self.subTest(k=k):
                self.assertEqual(self.run_main(six[:k]), self.expect(six[:k]))

if __name__ == "__main__":
    unittest.main()
