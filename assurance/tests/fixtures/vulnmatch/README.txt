Real-format excerpts used by tests/test_vulnmatch.py (public data, probed 2026-11-26; no secrets, no hosts):

  kev.excerpt.json              CISA KEV catalogue (2 entries)
  debian-tracker.excerpt.json   Debian security tracker, three source packages
  DSA.excerpt.list              Debian DSA list excerpt (dating source)
  alma9-errata.excerpt.json     AlmaLinux 9 errata.json excerpt (dating + fixed EVR)
  dpkg-query.bookworm.txt       dpkg-query output of a Debian 12 host (name, version, arch, status, source, source version)
  rpm-qa.alma9.txt              rpm -qa output of an AlmaLinux 9 host (name, epoch, version, release, arch, sourcerpm)
  os-release.samples.txt        os-release samples including a derivative that must read distro_unsupported
  rpmvercmp.vectors.txt         89 rpmvercmp rows (a|b|expected) from rpm's tests/rpmvercmp.at
Feed ingestion lives in intel; these files only feed a tiny loader inside the test module.
