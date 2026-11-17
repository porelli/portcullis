#!/usr/bin/env python3
"""The wg and link jobs' metric_relabel_configs in
monitoring/prometheus/prometheus.yml, applied to sample series the way
Prometheus does (keep / drop only: any other action fails the test, so a
new rule can't be misread). wg's /metrics also carries the worker agents'
families (contract §17.2): job link keeps only those and wg_link_*, job wg
keeps neither, nor any server-labelled series.

Run: python3 tests/test_prometheus_relabel.py (stdlib + yq or PyYAML)
"""
import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

CFG = Path(__file__).resolve().parent.parent / "monitoring" / "prometheus" / "prometheus.yml"


def load() -> dict:
    try:
        import yaml
        return yaml.safe_load(CFG.read_text())
    except ImportError:
        yq = shutil.which("yq")
        if not yq:
            if os.environ.get("CI"):
                raise
            raise unittest.SkipTest("neither PyYAML nor yq")
        return json.loads(subprocess.run([yq, "-o=json", str(CFG)], check=True, capture_output=True, text=True).stdout)


def job(cfg: dict, name: str) -> dict:
    return next(j for j in cfg["scrape_configs"] if j["job_name"] == name)


def kept(rules: list, series: dict) -> bool:
    for r in rules:
        action = r.get("action", "replace")
        if action not in ("keep", "drop"):
            raise AssertionError(f"unsupported relabel action {action!r}: extend the test")
        val = r.get("separator", ";").join(series.get(s, "") for s in r["source_labels"])
        hit = re.fullmatch(r.get("regex", "(.*)"), val) is not None
        if (action == "keep") != hit:
            return False
    return True


class RelabelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg = load()
        cls.wg = job(cfg, "wg")["metric_relabel_configs"]
        cls.link = job(cfg, "link")["metric_relabel_configs"]

    def test_wg_keeps_its_own(self):
        for s in ({"__name__": "wg_peers"}, {"__name__": "wg_handshake_age_seconds", "peer": "p"},
                  {"__name__": "go_goroutines"}):
            self.assertTrue(kept(self.wg, s), s)

    def test_wg_drops_worker_series(self):
        for s in ({"__name__": "portcullis_agent_up", "server": "w1"},
                  {"__name__": "wg_link_peer_ready", "server": "w1"},
                  # forged families with a server label (an agent's)
                  {"__name__": "portcullis_status_ok", "server": "w1"},
                  {"__name__": "portcullis_backup_last_success_timestamp_seconds", "server": "w1"},
                  {"__name__": "go_goroutines", "server": "w1"}):
            self.assertFalse(kept(self.wg, s), s)

    def test_link_keeps_only_link_and_agent(self):
        self.assertTrue(kept(self.link, {"__name__": "portcullis_agent_up", "server": "w1"}))
        self.assertTrue(kept(self.link, {"__name__": "wg_link_open_streams"}))
        for s in ({"__name__": "portcullis_status_ok", "server": "w1"}, {"__name__": "go_goroutines"},
                  {"__name__": "wg_peers"}):
            self.assertFalse(kept(self.link, s), s)


if __name__ == "__main__":
    unittest.main()
