"""paddock codeanalysis service.

Two static-analysis capabilities over the owner's own first-party source:

  * REACHABILITY -- build a per-language call graph of first-party code and
    decide, for each known dependency vulnerability, whether the vulnerable
    symbol is actually callable from an application entrypoint. Drops the noise
    of vulns in code paths that are never exercised.
  * SAST -- find first-party code weaknesses via taint/dataflow: run Semgrep
    when it is installed, else a bundled source->sink taint scanner.

INVARIANT (defensive, detection-only). This service analyses source code to
find where the owner is EXPOSED. Source files are untrusted DATA. It MUST NOT,
under any circumstances:
  * execute, import, evaluate (eval/exec), or otherwise RUN any analysed
    source file or the code it references -- source is parsed as text / AST
    only, and written to a temp dir purely so an external scanner can read it;
  * generate, craft, or suggest exploits, payloads, or attack automation;
  * publish, upload, or claim anything anywhere.
Reachability reads source read-only via Python's ``ast`` and lightweight text
scans. The only optional outbound traffic is Semgrep's registry rule fetch
(``--config auto``), which degrades to the bundled rules offline. Anything
offensive is out of scope; if such code appears here, delete it.
"""

__version__ = "0.1.0"
