"""Small but realistic scanner outputs for the ingest tests."""
from __future__ import annotations

import json

SARIF = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [
            {"id": "py/sql-injection", "name": "SqlInjection",
             "shortDescription": {"text": "SQL query built from user input"},
             "help": {"text": "Use parameterised queries."},
             "helpUri": "https://codeql.github.com/codeql-query-help/python/py-sql-injection/",
             "properties": {"security-severity": "8.8", "tags": ["security", "external/cwe/cwe-089"]}},
            {"id": "py/unused-import", "shortDescription": {"text": "Unused import"},
             "defaultConfiguration": {"level": "note"}},
        ]}},
        "versionControlProvenance": [{"repositoryUri": "https://user:pw@github.com/acme/web.git"}],
        "results": [
            {"ruleId": "py/sql-injection", "level": "error", "message": {"text": "Query built from request.args"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/db.py"},
                                                 "region": {"startLine": 42, "endLine": 43}}}]},
            {"ruleId": "py/unused-import", "message": {"text": "import os is unused"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/util.py"},
                                                 "region": {"startLine": 1}}}]},
            {"ruleId": "py/sql-injection", "level": "error", "message": {"text": "dismissed"},
             "suppressions": [{"kind": "inSource"}],
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/old.py"}}}]},
            {"message": {"text": "no rule id"}},
        ],
    }],
}

TRIVY = {
    "SchemaVersion": 2, "ArtifactName": "registry.example.com/acme/api:1.4.2", "ArtifactType": "container_image",
    "Results": [
        {"Target": "acme/api:1.4.2 (debian 12.5)", "Class": "os-pkgs", "Type": "debian", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "3.0.11",
             "FixedVersion": "3.0.13", "Severity": "HIGH", "Title": "openssl: buffer overflow",
             "Description": "A buffer overflow.", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-0001",
             "CVSS": {"nvd": {"V3Score": 7.5}}},
            {"VulnerabilityID": "CVE-2024-0002", "PkgName": "openssl", "InstalledVersion": "3.0.11",
             "Severity": "LOW", "Title": "openssl: minor"},
            {"PkgName": "broken"},
        ]},
        {"Target": "Dockerfile", "Class": "config", "Type": "dockerfile", "Misconfigurations": [
            {"ID": "DS002", "Title": "Image user should not be root", "Description": "Running as root.",
             "Resolution": "Add a USER instruction", "Severity": "HIGH", "Status": "FAIL",
             "CauseMetadata": {"StartLine": 1}},
            {"ID": "DS999", "Title": "passes", "Severity": "LOW", "Status": "PASS"},
        ]},
        {"Target": "config/.env", "Class": "secret", "Secrets": [
            {"RuleID": "aws-access-key-id", "Category": "AWS", "Severity": "CRITICAL", "Title": "AWS Access Key ID",
             "StartLine": 3, "Match": "AWS_ACCESS_KEY_ID=********"},
        ]},
    ],
}

GRYPE = {
    "matches": [
        {"vulnerability": {"id": "CVE-2021-44228", "severity": "Critical", "description": "Log4Shell",
                           "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                           "cvss": [{"metrics": {"baseScore": 10.0}}],
                           "fix": {"versions": ["2.15.0"], "state": "fixed"}},
         "relatedVulnerabilities": [{"id": "GHSA-jfh8-c2jp-5v3q"}],
         "artifact": {"name": "log4j-core", "version": "2.14.1", "type": "java-archive",
                      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}},
        {"vulnerability": {"id": "GHSA-xxxx-yyyy-zzzz", "severity": "Medium"},
         "artifact": {"name": "lodash", "version": "4.17.20", "type": "npm"}},
        {"vulnerability": {}},
    ],
    "source": {"type": "directory", "target": "."},
    "descriptor": {"name": "grype", "version": "0.74.0"},
}

SEMGREP = {
    "version": "1.60.0",
    "results": [
        {"check_id": "python.django.security.injection.sql.sql-injection", "path": "../../etc/shadow",
         "start": {"line": 10, "col": 1}, "end": {"line": 12, "col": 5},
         "extra": {"message": "Detected SQL string formatting.\nUse parameters.", "severity": "ERROR",
                   "lines": "cur.execute('SELECT ' + x)",
                   "metadata": {"cwe": ["CWE-89: SQL Injection"], "confidence": "HIGH",
                                "references": ["https://owasp.org/Top10/A03_2021-Injection"]}}},
        {"check_id": "generic.style", "path": "src/a.py", "start": {"line": 1}, "end": {"line": 1},
         "extra": {"message": "style nit", "severity": "INFO", "metadata": {}}},
        {"path": "no-check-id.py"},
    ],
    "errors": [],
}

NUCLEI_LINES = [
    {"template-id": "CVE-2023-1234", "info": {"name": "Acme Widget RCE", "severity": "critical",
                                               "description": "RCE in widget", "reference": ["https://example.com/adv"],
                                               "tags": ["cve", "rce"],
                                               "classification": {"cve-id": ["CVE-2023-1234"], "cvss-score": 9.8}},
     "type": "http", "host": "https://app.example.com", "matched-at": "https://app.example.com/widget/run",
     "ip": "203.0.113.7", "curl-command": "curl -H 'Authorization: Bearer SECRET' ..."},
    {"template-id": "exposed-panel", "info": {"name": "Admin panel", "severity": "info"},
     "host": "app.example.com", "matched-at": "app.example.com:8443"},
    {"template-id": "x"},
]
NUCLEI = "\n".join(json.dumps(x) for x in NUCLEI_LINES) + "\n"

ZAP = {
    "@programName": "ZAP", "@version": "2.14.0", "@generated": "Mon, 1 Jan 2026",
    "site": [{
        "@name": "https://shop.example.com", "@host": "shop.example.com",
        "alerts": [
            {"pluginid": "10038", "alert": "Content Security Policy (CSP) Header Not Set", "riskcode": "2",
             "confidence": "3", "riskdesc": "Medium (High)", "desc": "<p>CSP is missing.</p>",
             "solution": "<p>Set the header.</p>",
             "reference": "<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP</p>", "cweid": "693",
             "count": "2", "instances": [{"uri": "https://shop.example.com/", "method": "GET"},
                                          {"uri": "https://u:p@shop.example.com/cart", "method": "GET"}]},
            {"pluginid": "10020", "alert": "Missing Anti-clickjacking Header", "riskcode": "1", "instances": []},
            "garbage",
        ],
    }],
}

OCSF = [
    {"class_uid": 2002, "class_name": "Vulnerability Finding", "severity_id": 4, "severity": "High",
     "metadata": {"version": "1.3.0", "product": {"name": "Qualys"}},
     "finding_info": {"title": "OpenSSL heap overflow", "uid": "q-1", "desc": "bad"},
     "vulnerabilities": [{"cve": {"uid": "CVE-2022-0778", "cvss": [{"base_score": 7.5}]},
                          "affected_packages": [{"name": "openssl", "version": "1.1.1"}]}],
     "device": {"hostname": "db1.example.com", "ip": "10.0.0.5"}},
    {"class_uid": 2004, "severity_id": 2, "finding_info": {"title": "Suspicious login", "uid": "d-9"},
     "resources": [{"name": "i-0abc123", "type": "ec2"}]},
    {"class_uid": 3002, "message": "auth event"},
    {"nope": 1},
]

CSV = (
    "asset,title,severity,cve,cvss,remediation,file,line,component,version\n"
    "host1.example.com,Outdated nginx,high,CVE-2021-23017,8.1,Upgrade nginx,,,nginx,1.18.0\n"
    "10.1.2.3,Telnet open,medium,,,Disable telnet,,,,\n"
    "acme/web,Hardcoded password,critical,,,Rotate it,config/app.py,12,,\n"
    ",missing asset,low,,,,,,,\n"
    "h.example.com,bad sev,catastrophic,,,,,,,\n"
)

CYCLONEDX = {
    "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
    "metadata": {"component": {"type": "application", "name": "acme-web", "bom-ref": "root"}},
    "components": [
        {"type": "library", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2", "bom-ref": "e"},
        {"type": "library", "name": "qs", "version": "6.11.0", "purl": "pkg:npm/qs@6.11.0", "bom-ref": "q"},
    ],
    "dependencies": [{"ref": "root", "dependsOn": ["e"]}, {"ref": "e", "dependsOn": ["q"]}],
    "vulnerabilities": [{"id": "CVE-2022-24999", "ratings": [{"severity": "high", "score": 7.5}],
                         "affects": [{"ref": "q"}]}],
}

SPDX = {
    "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "acme-api",
    "packages": [
        {"SPDXID": "SPDXRef-root", "name": "acme-api"},
        {"SPDXID": "SPDXRef-flask", "name": "flask", "versionInfo": "2.3.0",
         "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/flask@2.3.0"}]},
    ],
    "relationships": [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-root"},
        {"spdxElementId": "SPDXRef-root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-flask"},
    ],
}


def jbytes(doc) -> bytes:
    return json.dumps(doc).encode()
