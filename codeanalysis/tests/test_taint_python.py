from __future__ import annotations

from app.sast import taint_fallback as tf


def _classes(src, path="v.py"):
    hits = tf.scan_python(path, src)
    return {h["rule_class"] for h in hits}, hits


def test_sql_injection_string_built_query():
    src = (
        "def h(request):\n"
        "    q = \"SELECT * FROM t WHERE x='\" + request.args.get('x') + \"'\"\n"
        "    conn.cursor().execute(q)\n"
    )
    classes, hits = _classes(src)
    assert "sql_injection" in classes
    assert any(h["cwe"] == "CWE-89" for h in hits)


def test_command_injection_concatenated_input():
    src = (
        "import os\n"
        "def h(request):\n"
        "    os.system('ping ' + request.args.get('host'))\n"
    )
    classes, hits = _classes(src)
    assert "command_injection" in classes
    assert any(h["sink"] == "os.system" for h in hits)


def test_path_traversal_open_request_input():
    src = (
        "def h(request):\n"
        "    return open(request.args.get('f')).read()\n"
    )
    classes, _ = _classes(src)
    assert "path_traversal" in classes


def test_insecure_deserialization_pickle_and_yaml():
    src = (
        "import pickle, yaml\n"
        "def h(data, s):\n"
        "    pickle.loads(data)\n"
        "    yaml.load(s)\n"
    )
    classes, hits = _classes(src)
    assert "insecure_deserialization" in classes
    rules = {h["rule"] for h in hits}
    assert "insecure-deserialization" in rules and "yaml-unsafe-load" in rules


def test_yaml_safe_loader_is_not_flagged():
    src = (
        "import yaml\n"
        "def h(s):\n"
        "    return yaml.load(s, Loader=yaml.SafeLoader)\n"
    )
    classes, _ = _classes(src)
    assert "insecure_deserialization" not in classes


def test_ssrf_requests_user_url():
    src = (
        "import requests\n"
        "def h(request):\n"
        "    return requests.get(request.args.get('url'))\n"
    )
    classes, _ = _classes(src)
    assert "ssrf" in classes


def test_weak_crypto_md5():
    src = (
        "import hashlib\n"
        "def h(pw):\n"
        "    return hashlib.md5(pw.encode()).hexdigest()\n"
    )
    classes, hits = _classes(src)
    assert "weak_crypto" in classes
    assert any(h["cwe"] == "CWE-327" for h in hits)


def test_hardcoded_secret_assignment():
    src = "API_KEY = 'sk-live-01HZabcDEFsecretvalue'\n"
    classes, hits = _classes(src)
    assert "hardcoded_secret" in classes
    assert any(h["cwe"] == "CWE-798" for h in hits)


def test_clean_python_has_no_findings():
    src = (
        "import os\n"
        "def h(name):\n"
        "    safe = os.path.join('/data', os.path.basename(name))\n"
        "    with open(safe) as fh:\n"
        "        return fh.read()\n"
        "API_KEY = os.getenv('API_KEY')\n"
    )
    classes, hits = _classes(src)
    assert hits == [], f"unexpected findings: {classes}"


def test_dataflow_steps_recorded():
    src = (
        "import os\n"
        "def h(request):\n"
        "    cmd = request.args.get('c')\n"
        "    os.system(cmd)\n"
    )
    _, hits = _classes(src)
    ci = [h for h in hits if h["rule_class"] == "command_injection"][0]
    steps = {s["step"] for s in ci["dataflow"]}
    assert "source" in steps and "sink" in steps


def test_broken_python_returns_no_hits():
    assert tf.scan_python("x.py", "def (:\n bad") == []


def test_env_config_is_not_an_ssrf_source():
    src = (
        "import os\n"
        "from urllib.request import urlopen\n"
        "ORCH = os.environ.get('ORCH_URL', 'http://localhost')\n"
        "def ping():\n"
        "    return urlopen(ORCH + '/healthz')\n"
    )
    classes, _ = _classes(src)
    assert "ssrf" not in classes


def test_secret_names_match_identifier_segments_only():
    src = (
        "queue_passive = 'queue:passive'\n"
        "token_type = 'bearer'\n"
        "tokenizer_name = 'bert-base-uncased-v2'\n"
        "db_password = 'Hunter2-Prod-9931'\n"
    )
    _, hits = _classes(src)
    assert [h["start_line"] for h in hits] == [4]
