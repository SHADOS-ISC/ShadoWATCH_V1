import os, sys, time, json, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.update(MISP_URL="https://misp.example", MISP_KEY="test-key")
import requests
import misp_ioc_dashboard as d


class FakeResp:
    status_code = 200

    def __init__(self, data): self._d = data
    def json(self): return self._d


class FakeSession:
    def __init__(self): self.headers = {}
    def post(self, url, json=None, **kw):
        now = str(int(time.time()))
        if "events/restSearch" in url:
            if "eventid" in json:   # lookup of events outside the window
                return FakeResp({"response": [{"Event": {"id": i, "info": "old event", "Orgc": {"name": "abuse.ch"}}} for i in json["eventid"]]})
            return FakeResp({"response": [{"Event": {"id": "1", "timestamp": now, "date": "2026-01-01", "info": "recent",
                                                     "threat_level_id": "2", "attribute_count": "1", "Orgc": {"name": "Infoblox"}}}]})
        return FakeResp({"response": {"Attribute": [
            {"event_id": "1", "type": "ip-dst", "value": "203.0.113.5", "timestamp": now, "comment": "Cobalt Strike C2"},
            {"event_id": "77", "type": "sha256", "value": "a" * 64, "timestamp": now, "comment": ""}]}})


class Tests(unittest.TestCase):
    def test_demo_builds_and_renders(self):
        data = d.build(d.demo(), False)
        for k in ("kpi", "top", "actors", "hist", "sec", "new"):
            self.assertIn(k, data)
        page = d.TEMPLATE.replace("__DATA__", json.dumps(data))
        self.assertIn("ShadoWATCH", page)
        self.assertNotIn("__DATA__", page)

    def test_source_lookup_for_events_outside_window(self):
        real = requests.Session
        requests.Session = FakeSession
        try:
            raw = d.collect(False)
        finally:
            requests.Session = real
        self.assertEqual(len(raw["events"]), 1)          # counts stay on the window
        self.assertIn("77", raw["evx"])                  # but the old event is resolved
        data = d.build(raw, False)
        self.assertEqual(dict(data["src"]).get("abuse.ch"), 1)
        self.assertNotIn("?", dict(data["src"]))

    def test_no_internal_defaults(self):
        src = open(os.path.join(os.path.dirname(d.__file__), "misp_ioc_dashboard.py")).read()
        self.assertNotIn("172" + ".19.", src)   # built dynamically so this test does not match itself


if __name__ == "__main__":
    unittest.main()
