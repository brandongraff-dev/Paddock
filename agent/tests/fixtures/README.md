# Collector fixtures

Every collector parser is a pure function over text, so these files drive the tests with no OS.
**Real** means captured from a real command on a real host; **synthetic** means hand-written to
the documented format of the tool (the tool was not available to capture). Synthetic files are
never evidence that a tool prints exactly this, only that the parser handles the documented form.

## `ubuntu2404/` (real, Ubuntu 24.04.5 LTS, x86_64, no hostnames or addresses of interest)

| file | source |
|---|---|
| `os-release.ubuntu2404.txt` | `/etc/os-release` |
| `proc_net_tcp.container.txt`, `proc_net_udp.container.txt` | `/proc/net/tcp`, `/proc/net/udp` of a container (no `tcp6`: IPv6 absent) |
| `nft_unshare_out.txt`, `nft_json_unshare.json`, `mk_nft.sh` | `nft list ruleset` / `nft -j list ruleset` (nftables 1.0.9) in a fresh network namespace loaded by `mk_nft.sh` (policy drop, lo/ct/set/range/mark rules) |
| `iptables_save_unshare.txt`, `mk_ipt.sh` | `iptables-save` (iptables 1.8.10 nf_tables) in a fresh namespace loaded by `mk_ipt.sh` |
| `dpkg_query_sample.ubuntu2404.tsv` | first rows of `dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t${source:Package}\t${source:Version}\n'` |
| `dpkg_query_full.ubuntu2404.tsv` | the full 837-row output of the same command (epoch, `:amd64` multiarch qualifiers, source name/version differing from the binary) |
| `apt_get_s_dist_upgrade.ubuntu2404.txt` | `apt-get -s -o Debug::NoLocking=1 dist-upgrade` with 18 pending upgrades: `-updates` and `-security` pockets, third-party (`Docker CE:noble`) origins, trailing `[]` / `[libheif1:amd64 ]` groups, 2 phased/kept back |

Not captured here (no such binary or privilege in the capture container): `sshd -T` (no OpenSSH
server installed), `ufw`, `firewalld`, iptables-legacy, `dnf`, `rpm`.

## `synthetic/`

* `sshd/`: `sshd_T.*.txt` (the key/value form of `sshd -T` on OpenSSH 9.6 and 7.x, hardened, keyboard-
  interactive-over-PAM), `sshd_config.*` and the Ubuntu cloud drop-ins `50-cloud-init.conf`,
  `60-cloudimg-settings.conf` (first-value-wins across `Include`), `passwd.sample`. **No real `sshd -T`
  was captured: the required `-C` keys and non-root behaviour are from the OpenSSH manual and unverified.**
* `firewall/`: `ufw_*` (ufw status verbose, `iptables-save`/`ip6tables-save` of a ufw host), `firewalld_*`
  (firewalld's nft ruleset: input policy accept, final unconditional reject, `ct status dnat accept`),
  `docker_*` (DNAT in nat, published ports), `k8s_*` (KUBE- chains), `fail2ban_nft.json` (dynamic set),
  `legacy_open_iptables_save.txt` (policy ACCEPT).
* `patch/`: `apt_sim_*` (apt simulation outputs, Debian security pocket), `dnf_updateinfo_security.el9.txt`,
  `yum_check_update_el7.txt`, `rpm_qa_el9.tsv`, `dpkg_status_sample.txt`, `os-release.{rhel9,debian12}.txt`,
  `apt_config_periodic.txt`, `dnf_automatic.conf`.

Regenerating the real ones: run the commands above as root on the target distro; sanitise hostnames and
addresses to RFC 5737 / RFC 3849 ranges and usernames to generic names before committing.
