import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from fake_osv import ADVISORIES, FakeOsv, _record
from paddock_cli.osvclient import OsvClient, fixed_versions, key_of, nearest_fix

PKGS = [("npm", "lodash", "4.17.20"), ("npm", "left-pad", "1.3.0")]


def test_query_finds_vulns_and_caches(tmp_path):
    fake = FakeOsv()
    c = OsvClient(transport=fake, cache=tmp_path)
    res = c.query(PKGS)
    assert [v["id"] for v in res.vulns[key_of(*PKGS[0])]] == ["GHSA-35jh-r3h4-6jhm"]
    assert key_of(*PKGS[1]) in res.checked and key_of(*PKGS[1]) not in res.vulns
    n = len(fake.calls)
    again = OsvClient(transport=fake, cache=tmp_path).query(PKGS)
    assert len(fake.calls) == n, "a warm cache must not hit the network"
    assert again.vulns.keys() == res.vulns.keys()


def test_offline_uses_only_the_cache(tmp_path):
    fake = FakeOsv()
    OsvClient(transport=fake, cache=tmp_path).query(PKGS[:1])
    calls = len(fake.calls)
    off = OsvClient(transport=fake, cache=tmp_path, offline=True)
    res = off.query([*PKGS, ("PyPI", "requests", "2.19.0")])
    assert len(fake.calls) == calls
    assert key_of(*PKGS[0]) in res.vulns
    assert key_of("PyPI", "requests", "2.19.0") in res.unchecked
    assert any("offline cache" in n for n in res.notes)


def test_stale_entries_are_refreshed_online_but_used_offline(tmp_path):
    fake = FakeOsv()
    OsvClient(transport=fake, cache=tmp_path, ttl_s=0).query(PKGS[:1])
    calls = len(fake.calls)
    OsvClient(transport=fake, cache=tmp_path, ttl_s=0).query(PKGS[:1])
    assert len(fake.calls) > calls                      # ttl 0: always refresh
    calls = len(fake.calls)
    OsvClient(transport=fake, cache=tmp_path, ttl_s=0, offline=True).query(PKGS[:1])
    assert len(fake.calls) == calls                     # offline ignores the ttl


def test_network_failure_falls_back_to_stale_cache(tmp_path):
    fake = FakeOsv()
    OsvClient(transport=fake, cache=tmp_path, ttl_s=0).query(PKGS[:1])
    fake.fail = True
    res = OsvClient(transport=fake, cache=tmp_path, ttl_s=0).query([*PKGS[:1], PKGS[1]])
    assert key_of(*PKGS[0]) in res.vulns                # stale answer beats nothing
    assert key_of(*PKGS[1]) in res.unchecked            # never seen: honestly unknown
    assert any("OSV" in n for n in res.notes)


def test_real_http_path_against_a_local_server(tmp_path):
    """The urllib transport speaks the real OSV wire format (no external network)."""
    fake = FakeOsv()
    seen: list[str] = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, obj):
            data = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            seen.append(self.path)
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self._send(fake("POST", "http://x" + self.path, body))

        def do_GET(self):
            seen.append(self.path)
            self._send(fake("GET", "http://x" + self.path, None))

    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        c = OsvClient(base_url=f"http://127.0.0.1:{srv.server_port}", cache=tmp_path)
        res = c.query(PKGS[:1])
    finally:
        srv.shutdown()
    assert key_of(*PKGS[0]) in res.vulns
    assert "/v1/querybatch" in seen and any(p.startswith("/v1/vulns/") for p in seen)


def test_fixed_versions_ignore_git_ranges_and_normalise_pypi_names():
    rec = _record(next(a for a in ADVISORIES if a["pkg"] == "requests" and "2.20.0" in str(a["ranges"])))
    assert fixed_versions(rec, "PyPI", "Requests") == ["2.20.0"]
    rec["affected"][0]["ranges"].append({"type": "GIT", "events": [{"fixed": "deadbeef"}]})
    assert fixed_versions(rec, "PyPI", "requests") == ["2.20.0"]


def test_go_fixes_get_the_v_prefix_go_mod_needs_and_maven_flavours_are_kept():
    go = {"id": "G", "affected": [{"package": {"ecosystem": "Go", "name": "m/x"}, "ranges": [
        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.9.1"}]}]}]}
    assert nearest_fix("v1.9.0", [go], "Go", "m/x") == ("v1.9.1", True)
    mvn = {"id": "M", "affected": [{"package": {"ecosystem": "Maven", "name": "g:a"}, "ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "32.0.1"}]}]}]}
    assert nearest_fix("31.1-jre", [mvn], "Maven", "g:a") == ("32.0.1-jre", True)
    both = {"id": "M2", "affected": [{"package": {"ecosystem": "Maven", "name": "g:a"}, "ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "32.0.0-android"},
                                         {"fixed": "32.0.0-jre"}]}]}]}
    assert nearest_fix("31.1-jre", [both], "Maven", "g:a") == ("32.0.0-jre", True)


def test_nearest_fix_takes_the_nearest_per_advisory_then_the_highest():
    recs = [_record(a) for a in ADVISORIES if a["pkg"] == "requests"]
    assert nearest_fix("2.19.0", recs, "PyPI", "requests") == ("2.31.0", True)
    # a multi-range advisory: the fix below the current version must not be chosen
    minimist = {"id": "X", "affected": [{"package": {"ecosystem": "npm", "name": "minimist"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.2.4"},
                                                          {"introduced": "1.0.0"}, {"fixed": "1.2.6"}]}]}]}
    assert nearest_fix("1.2.5", [minimist], "npm", "minimist") == ("1.2.6", True)
    nofix = {"id": "Y", "affected": [{"package": {"ecosystem": "npm", "name": "p"}, "ranges": [
        {"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
    assert nearest_fix("1.0.0", [nofix], "npm", "p") == (None, False)
