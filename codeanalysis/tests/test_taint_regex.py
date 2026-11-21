from __future__ import annotations

from app.sast import taint_fallback as tf


def _classes(path, src, lang):
    hits = tf.scan_regex(path, src, lang)
    return {h["rule_class"] for h in hits}, hits


def test_js_sql_injection_template_literal():
    src = (
        "app.get('/u', (req, res) => {\n"
        "  db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n"
        "});\n"
    )
    classes, _ = _classes("a.js", src, "javascript")
    assert "sql_injection" in classes


def test_js_command_injection():
    src = (
        "const cp = require('child_process');\n"
        "app.post('/r', (req, res) => { cp.exec('ls ' + req.body.dir); });\n"
    )
    classes, _ = _classes("a.js", src, "javascript")
    assert "command_injection" in classes


def test_js_ssrf():
    src = "const r = await fetch(req.query.target);\n"
    classes, _ = _classes("a.js", src, "javascript")
    assert "ssrf" in classes


def test_js_weak_crypto():
    src = "const h = crypto.createHash('md5').update(p).digest('hex');\n"
    classes, _ = _classes("a.js", src, "javascript")
    assert "weak_crypto" in classes


def test_js_hardcoded_secret():
    src = "const apiKey = 'AKIAJQ0123456789secret';\n"
    classes, _ = _classes("a.js", src, "javascript")
    assert "hardcoded_secret" in classes


def test_js_env_secret_not_flagged():
    src = "const apiKey = process.env.API_KEY;\n"
    classes, _ = _classes("a.js", src, "javascript")
    assert "hardcoded_secret" not in classes


def test_go_command_injection():
    src = (
        "func h(w http.ResponseWriter, r *http.Request) {\n"
        "  exec.Command(\"sh\", \"-c\", r.FormValue(\"cmd\")).Run()\n"
        "}\n"
    )
    classes, _ = _classes("a.go", src, "go")
    assert "command_injection" in classes


def test_go_sql_injection_sprintf():
    src = (
        "func h(r *http.Request) {\n"
        "  q := fmt.Sprintf(\"SELECT * FROM t WHERE id=%s\", r.FormValue(\"id\"))\n"
        "  db.Query(q)\n"
        "}\n"
    )
    classes, _ = _classes("a.go", src, "go")
    assert "sql_injection" in classes


def test_go_weak_crypto():
    src = "h := md5.New()\n"
    classes, _ = _classes("a.go", src, "go")
    assert "weak_crypto" in classes


def test_clean_js_has_no_findings():
    src = (
        "function add(a, b) { return a + b; }\n"
        "module.exports = { add };\n"
    )
    _, hits = _classes("clean.js", src, "javascript")
    assert hits == []


def test_scan_files_routes_by_extension():
    files = {
        "v.py": "import os\ndef h(request):\n    os.system(request.args.get('x'))\n",
        "v.js": "db.query(`x ${req.query.y}`);\n",
        "readme.md": "# not scanned",
    }
    hits = tf.scan_files(files)
    langs = {h["language"] for h in hits}
    assert "python" in langs and "javascript" in langs
    assert all(h["file"] != "readme.md" for h in hits)


# --------------------------------------------------------------------------- #
# Rule-pack integrity + coverage added with the bundled rules file
# --------------------------------------------------------------------------- #

def test_rules_file_ships_and_is_populated():
    # The rules once went missing (a stray gitignore) and the scanner silently
    # found nothing. Guard against that ever happening quietly again.
    rules = tf._rules()
    assert len(rules["python_sources"]) >= 10
    assert len(rules["regex_rules"]) >= 15
    import re
    for r in rules["regex_rules"]:
        re.compile(r["pattern"])
        assert r["class"] and r["severity"] and r["cwe"].startswith("CWE-")


def test_js_tls_verification_disabled():
    classes, _ = _classes("a.js", "https.request({ host, rejectUnauthorized: false });\n", "javascript")
    assert "insecure_transport" in classes


def test_go_tls_verification_disabled():
    src = "tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}\n"
    classes, _ = _classes("a.go", src, "go")
    assert "insecure_transport" in classes


def test_js_eval_of_request_input():
    classes, _ = _classes("a.js", "app.get('/x', (req) => eval(req.query.code));\n", "javascript")
    assert "code_injection" in classes


def test_known_key_format_in_any_language():
    for path, lang in (("a.js", "javascript"), ("a.go", "go")):
        classes, _ = _classes(path, 'x := "ghp_' + "a1B2" * 9 + '"\n', lang)
        assert "hardcoded_secret" in classes


def test_regexp_exec_is_not_command_injection():
    src = "const m = /id=(\\d+)/.exec(req.query.q);\nconst n = pattern.exec(req.body.s);\n"
    classes, _ = _classes("a.js", src, "javascript")
    assert "command_injection" not in classes


def test_identifier_values_are_not_secrets():
    src = "const map = {\n  certificate: 'cert_added',\n  secret_candidate: 'secret_found',\n};\n"
    _, hits = _classes("a.ts", src, "typescript")
    assert hits == []


def test_window_match_reported_once_on_its_own_line():
    src = "const a = 1;\nconst b = 2;\nconst h = crypto.createHash('md5');\n"
    _, hits = _classes("a.js", src, "javascript")
    assert [h["start_line"] for h in hits] == [3]
