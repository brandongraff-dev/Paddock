# Host posture payload, schema 2 (`paddock.host.posture/v2`)

This is the exact shape produced by `paddock_agent.collectors.collect_all(ctx)` and signed by the
agent (envelope: `docs/ASSURANCE_P2.md` section 2). The server stores the bytes it received
(`payload_b64`, never re-serialised) and validates them with `extra=forbid` Pydantic models built from
this file. **Anything not listed here is rejected.** Python >= 3.8 produced it; JSON has no floats.

## 0. Conventions

* **Encoding**: `paddock_agent.collectors.payload_bytes(payload)` = `json.dumps(payload, sort_keys=True,
  separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")`. Keys are strings; values are
  `int | str | bool | null | list | object`. **No floats anywhere.** Lists are sorted (see each field) so the
  same host state gives the same bytes (only `self.collectors.*.ms` and counters change run to run).
* **Strings** are printable (control characters replaced by `?`), valid UTF-8, length-capped as stated.
* **"may be absent"** means the key is not present in the object at all (not `null`). "nullable" means the key
  is always present and may be `null`.
* **Never emitted**: command lines, environments, key material, file contents (only sha256 and counts),
  the raw machine id, hostnames of peers, `/etc/shadow` anything.
* Size: the whole payload must stay <= 2 MiB (envelope limit). The package list (<= 8000 rows, about 80 bytes
  each) is the only large field and is sent only when its digest changed.

## 1. Top level

```
{ "schema": 2,
  "collected_at": "YYYY-MM-DDTHH:MM:SSZ",      # agent clock, UTC, whole seconds
  "sections": { "sshd": S, "listeners": S, "firewall": S, "patch": S, "self": S } }
```

All five section keys are always present. `COLLECTOR_VERSIONS` (envelope `collectors` map) is
`{"sshd":"1","listeners":"1","firewall":"1","patch":"1","self":"1"}`.

## 2. Section (`S`): tri-state, never an empty ok on failure

Exactly one of:

```
{"s":"ok",          "v":{...}, "conf":"exact"|"approximate", "partial":bool}
{"s":"unavailable", "reason": U}
{"s":"error",       "reason": E, "detail": "<= 120 chars"}
```

* `U` in `tool_missing | permission_denied | not_applicable | unsupported_platform | daemon_not_running |
  unmanaged_kernel | containerised_agent | no_data`.
* `E` in `timeout | exit_nonzero | parse_error | truncated | exception`. `detail` never contains command
  output beyond a short tail of stderr and never an exception message.
* Evaluator mapping: `ok` => evaluate (`partial: true` or `conf: approximate` => the field is not usable
  for a `HOLDS`); `unavailable(not_applicable)` => N/A; every other `unavailable` and every `error` =>
  `UNKNOWN`. A collector that raises, overruns its budget (90 s each, 240 s total) or returns a malformed
  Section becomes `error(exception|timeout)`; one failing collector never stops the post.
* `partial: true` means the data is real but incomplete (unreadable pid dirs, a missing UDP table,
  a sub-block of `patch` that failed, an unreadable firewall family). Treat as `UNKNOWN` for any invariant that
  needs completeness.

## 3. `sections.sshd`

`unavailable`: `tool_missing` (no usable OpenSSH `sshd` binary and none of the evidence below), `no_data` (evidence
that an SSH server may exist, but no usable OpenSSH binary: unknown, NOT "not installed"), `containerised_agent`,
`unsupported_platform`. `error`: `parse_error` when `sshd -T` printed something unparseable or a value outside the
allowlist's domain.

**`tool_missing` is not an absence claim.** It means only "no OpenSSH `sshd` we can trust, and nothing that
looks like an SSH server": the evidence that turns it into `no_data` is a `/etc/ssh/sshd_config` or `/etc/dropbear`,
an ssh/dropbear unit file, a process whose `comm` or `exe` basename contains `ssh` or `dropbear` (any case), an
`sshd` in `/usr/local/{sbin,bin}` that failed the trust check, a TCP listener on 22, and any non-loopback TCP
listener that is unattributed, belongs to a program that is not on the short allow-list of programs known not to
be (or front) an SSH server (`postgres`, `mysqld`, `mariadbd`, `mongod`, `redis-server`, `memcached`, `named`,
`unbound`, `dnsmasq`, ...: so `docker-proxy`, `rootlessport`, `kube-proxy`, nginx, haproxy, socat, gitea, teleport,
sftpgo and every unlisted name make it `no_data`), or whose table is partial or unreadable. `tool_missing` therefore
needs every public TCP listener to belong to a listed non-SSH program. Even so it is not proof: a consumer must not
conclude "no SSH server" from `tool_missing`.

**Which binary is run.** The `sshd` that a root-owned process named `sshd` is running (`/proc/<pid>/exe`, not
deleted), else `sshd` from the fixed system PATH `/usr/sbin:/usr/bin:/sbin:/bin`, else `/usr/local/{sbin,bin}/sshd`
only when the file and every directory above it up to `/usr` are root-owned and not group/world writable.

`ok.v` (all keys always present):

| field | type | notes |
|---|---|---|
| `installed` | bool | always `true` in an `ok` |
| `source` | `"sshd_T"` \| `"text"` | `text` = `sshd -T` failed (not root, no host keys, timeout...) and the config files were parsed; **`text` always has `conf: approximate`** |
| `version` | str \| null | e.g. `"9.6p1"` from `ssh -V` / `sshd -V` |
| `binary` | str | path of the sshd binary |
| `socket_activated` | bool | `ssh.socket`/`sshd.socket` is enabled (Port/ListenAddress may then be ignored; use `listeners`) |
| `config` | object | allowlisted effective global config, below |
| `probes` | object | `{addrs: [str] sorted, users_probed: int, users_total: int, planned: int, done: int, deltas: [D]}`; `users_probed` excludes the nonexistent user; `users_total` = login users on the host (uid != 0, login shell), **including login-shell rows dropped because their name cannot be passed as `-C user=`** |
| `match` | object | `{blocks: int, criteria: [str] sorted, known: bool, unprobed: bool, unprobed_reasons: [str] sorted}` |
| `files` | [`{path: str, sha256: str\|null, size: int}`] | `sshd_config` and every `Include`d file read (<= 64); `sha256: null` = unreadable |
| `daemon` | object | the RUNNING sshd, to compare with what `sshd -T` says about the files (below). Always present |
| `truncated` | [str] sorted | **may be absent.** Present (non-empty) iff a `config` value was cut: a list past 50 items or an item past its length cap (`allowusers`, `allowgroups`, `denyusers`, `denygroups`, `listenaddress`, `authorizedkeysfile`, `port`) or `authenticationmethods` past 200 characters. A cut value is a sorted prefix, not the truth: **treat every key named here as Unknown.** The section is then `conf: approximate` (`match.unprobed_reasons` has `config_truncated`) |

`D` (probe delta) = `{user: str, addr: str, delta: {key: value|null}}`: only keys whose probed value differs
from the global value; `null` = the key is absent in the probe. `user` is `"<nonexistent>"` for the made-up
user. Sorted by `(user, addr)`. Probe matrix: users {root, up to 20 login users by uid, literal `Match User`
names (<= 10, any case), up to 20 representatives of `Match User/Group` selections (below), a nonexistent user} x addresses {203.0.113.7, 10.255.255.1, plus one representative per atom of
every `Match Address` CIDR (<= 12)}, each as `sshd -T -C user=U,host=probe.invalid,addr=A`; <= 150 runs.

`config` keys (every key may be absent; absent in `source: sshd_T` means this sshd did not print it, absent in
`source: text` means "not set in the global section, so the compiled-in default applies": the server must not
assume a default for `text`):

* `"yes" | "no"`: `passwordauthentication`, `kbdinteractiveauthentication` (`challengeresponseauthentication`
  is folded into it), `pubkeyauthentication`, `permitemptypasswords`, `usepam`, `x11forwarding`,
  `permituserenvironment`, `hostbasedauthentication`, `gssapiauthentication`, `strictmodes`.
* enums: `permitrootlogin` in `yes|no|prohibit-password|forced-commands-only` (`without-password` is normalised
  to `prohibit-password`), `addressfamily` in `any|inet|inet6`, `allowtcpforwarding` in
  `yes|no|all|local|remote`, `loglevel` in `quiet|fatal|error|info|verbose|debug|debug1|debug2|debug3`.
* ints (0..999999999): `maxauthtries`, `logingracetime`, `maxsessions`.
* `authenticationmethods`: str, lowercased, <= 200 chars (`"any"` or e.g. `"publickey,password"`).
* sorted unique lists, <= 50 items: `port` (ints 1..65535), `listenaddress` (lowercased str <= 80),
  `allowusers`, `allowgroups`, `denyusers`, `denygroups` (str <= 80; names only, patterns kept verbatim).
* `authorizedkeysfile`: list of str <= 120 (file order, <= 50). `authorizedkeyscommand`: `"none" | "set"`
  (presence only, never the command).

**Which users are probed when a `Match User` or `Match Group` criterion exists.** A user's result under
`sshd -T -C user=U` depends only on which user/group criteria it satisfies, so the agent evaluates every criterion
(OpenSSH `match_pattern_list` semantics: case-sensitive, `*` `?`, a matching `!pattern` wins; for groups the
user's primary group from `/etc/passwd` plus every `/etc/group` membership) for every `/etc/passwd` account of
**any shell** and probes the lowest-uid account of each distinct satisfaction vector that root, the 20 login users
and the literal names do not already cover (nologin SFTP accounts are the usual case). If the user and group
databases cannot be enumerated from `/etc/passwd` and `/etc/group` the answer is `nss_users_unknown`, not exact.

`daemon` = `{found: bool, masters: int, pid: int|null, start_epoch: int|null, reexec_epoch: int|null,
config_path: str|null, config_default: bool|null, options_override: bool|null, binary_matches: bool|null,
config_mtime: int|null, reload_pending: bool|null}` (all keys always present, `null` = could not tell):
`masters` is the number of root-owned `sshd` processes whose parent is not an `sshd` (listeners); `pid` the lowest;
`start_epoch` its start time (`/proc/stat` btime + `/proc/<pid>/stat` starttime / CLK_TCK, UTC seconds);
`reexec_epoch` the mtime of `/run/sshd.pid` (or `/var/run/sshd.pid`) when it names that pid (sshd rewrites it when
it re-executes on SIGHUP, which keeps the process start time); `config_path` the `-f` path of the command line (path
only, validated) and `config_default` whether the daemon uses `/etc/ssh/sshd_config`; `options_override` whether the
command line carries `-o`, `-p`, `-4` or `-6` (only the boolean, never the content); `binary_matches` whether the
running executable is the binary `sshd -T` was run with (false when it was deleted/replaced on disk);
`config_mtime` the newest change time (the later of mtime and ctime, so `cp -p`, `rsync -a`, `tar` and `touch -d`
cannot hide a write) of `sshd_config`, the `Include`d files and every directory an `Include` reads from, also when no
file is left in it (a deleted drop-in shows only on the directory; for a directory that is gone, its parent).
The command line is read like getopt (`-Df /path`, `-Df/path`, `-Do Opt=v`, `-D4`; an option letter sshd does not
document counts as an override).
`reload_pending` is **true** when `config_mtime` is after `max(start_epoch, reexec_epoch)` (an edit not yet loaded)
or the daemon runs another config file or extra options; **false** only on positive evidence (config older than the
last (re)start, or socket-activated with no master); **null** when it cannot be determined (no daemon process
visible, unreadable `/proc`). `sshd -T` describes the on-disk files, `daemon` is the only evidence about what runs;
a consumer must treat `reload_pending != false` as Unknown for "the effective sshd configuration". A reload that
does not rewrite the pid file keeps `reload_pending` true until the daemon is restarted.

`match.unprobed_reasons` enumeration: `text_source`, `users_over_cap` (a `Match User/Group` exists and the host
has more than 20 login users, or more than 10 literal `Match User` names, or more than 20 selection classes need
a probe), `nss_users_unknown` (a user/group criterion exists and `nsswitch.conf` passwd/group names a source other
than `files`/`compat`/`systemd`, systemd userdb/homed data exists, NIS `+`/`-` rows are present, or `/etc/group` is
unreadable), `user_name_unprobeable` (an account whose name cannot be passed as `-C user=` would be selected by a
criterion no probed account represents), `user_pattern` (`Match User` with a `user@host` pattern), `config_truncated`
(see `truncated`), `reload_pending`, `daemon_config_differs` (the daemon runs another `-f` file or `-o/-p/-4/-6`),
`daemon_binary_differs`, `daemon_ambiguous` (more than one listener `sshd`), `criterion_<name>` (host, localaddress, localport, rdomain, exec, ...: cannot be
probed), `address_pattern` (a `Match Address` pattern that is not a CIDR), `address_atoms` (more than 12
atoms), `config_unreadable`, `passwd_unreadable`, `probe_cap`, `probe_budget`, `probe_failed`,
`probe_incomplete`, `unexplained_delta` (probes disagree although the text shows no `Match` block: the text view
is wrong). **`conf` is `exact` iff `source == "sshd_T"` and `match.unprobed == false`.** `match.known: false`
means a config file could not be read, so `match.criteria` may be incomplete.

Cannot see: AuthorizedKeysCommand results, PAM modules, SSSD/LDAP users (flagged `nss_users_unknown` when a
user/group criterion exists), sshd in containers, non-OpenSSH daemons (Dropbear), per-user `authorized_keys`
options, `Match` criteria evaluated on the daemon's side only (`exec`, `host`, `localport`, ...).

## 4. `sections.listeners`

`unavailable`: `containerised_agent`, `unsupported_platform` (no `/proc/net/tcp`), `permission_denied`.
`error`: `truncated` (a `/proc/net` table over 8 MiB), `exception`.
`partial: true` when a data line of `/proc/net/*` could not be parsed, `/proc/net/udp` is missing, **more than 2000
distinct listeners exist (a bounded sample is kept, `dropped` says how many were cut)** or the pid attribution scan
ran out of the collector's time budget. A missing `tcp6`/`udp6` means IPv6 is disabled (`ipv6: false`), not an error.
Over the cap the sample is prioritised: wildcard binds and privileged ports (< 1024) first, other non-loopback
binds next, loopback last (a local user can open any number of loopback ports); the kept rows are sorted as below.
Addresses are decoded in the host's byte order (the kernel prints each 32-bit word in host order).

`ok.v` = `{count: int, listeners: [L] , ipv6: bool, bindv6only: 0|1|null,
attribution: {status: "ok"|"partial"|"denied", unreadable_pids: int, unattributed: int}, dropped?: int}`;
`dropped` is **absent unless > 0**: the number of distinct listeners left out of `listeners` (then `partial` is true
and the table is a sample, not the host's listener set).

* `attribution.status`: `ok` every listener mapped to a pid; `partial` some; `denied` none (not root:
  `/proc/*/fd` unreadable). Missing attribution is **never** a missing listener.
* A listener `L` (sorted by `(port, proto, ip)`; deduplicated across SO_REUSEPORT sockets):

| field | type | notes |
|---|---|---|
| `proto` | `"tcp"\|"udp"` | tcp = LISTEN (`0A`); udp = bound and unconnected (`07`, zero remote) |
| `ip` | str | canonical text; IPv4-mapped IPv6 is shown as IPv4; `::`/`0.0.0.0` are wildcards |
| `port` | int 1..65535 | |
| `bind_class` | `wildcard4\|wildcard6\|loopback\|specific` | |
| `uid` | int | socket owner |
| `pid` | int \| null | lowest pid holding the socket |
| `n_pids` | int | pids holding it |
| `comm` | str \| null | <= 16 |
| `exe` | str \| null | <= 256, `" (deleted)"` stripped |
| `exe_deleted` | bool | the binary was deleted/replaced while running |
| `exe_sha256` | str(64) \| null | null when unreadable or larger than 128 MiB |
| `unit` | str \| null | systemd `*.service`/`*.scope` from `/proc/PID/cgroup`, <= 96 |
| `container` | str \| null | first 12 hex of a 64-hex container id found in the cgroup path |

`bindv6only` is `/proc/sys/net/ipv6/bindv6only` (a `::` listener also accepts IPv4 when it is `0`).
Cannot see: other network namespaces, DNAT-only ports (docker without userland-proxy, kube-proxy), eBPF
services. A listener table is "complete" for coverage only when `partial == false`.

## 5. `sections.firewall`

`unavailable`: `permission_denied` (no root and no CAP_NET_ADMIN, or the tool said so), `tool_missing` (no
`nft` and no iptables save tool, or nothing readable), `containerised_agent`, `unsupported_platform`.
`error`: `timeout`, `exit_nonzero`, `parse_error`, `truncated` (more than 2000 modelled rules, or the model
walk step budget `WALK_BUDGET` was spent: layered conditional jumps no longer stall the agent).
`ok.partial` is `true` iff an enabled address family could not be read (`families.<f>.read == false`).
`ok.conf` is `exact` iff `flat_view.confidence == "exact"`.

Sources: `nft -j list ruleset` (also covers iptables-nft) plus, only when
`/proc/net/ip{,6}_tables_names` lists loaded legacy tables, `iptables-legacy-save` / `ip6tables-legacy-save`
(or a legacy-flavoured `iptables-save`). With no `nft` binary while `nf_tables` is loaded (or the module list is
unreadable) a native nftables ruleset cannot be excluded, so the family is `read: false`. ufw and firewalld are
recorded as `frontends` only, never as truth. Dormant nft tables are ignored.

`ok.v` (the **canonical model**, produced by `paddock_agent.collectors.fwmodel.build_model`):

```
{ "v": 1,
  "backend": "nft" | "legacy" | "mixed" | "none",
  "frontends": [ {"name":"ufw","state":"active|inactive|unknown","default_incoming":"deny|allow|reject|unknown","rules":int<=1000},
                 {"name":"firewalld","state":"running|not_running|unknown","default_zone":str|null} ],   # sorted by name
  "ipv6_enabled": bool,                    # a non-loopback address in /proc/net/if_inet6 (the truth; all/disable_ipv6 is
                                           # ignored). If it cannot be told (unreadable/truncated file, stack visible but
                                           # no if_inet6) this is true and confidence is "unknown" ("ipv6_state_unknown")
  "families": { "ip4": F, "ip6": F },
  "flat_view": { "default_input_policy": "accept|drop|reject|unknown",
                 "rules": [ {"src_cidr": str|"any", "proto": str|"any", "port_lo": int, "port_hi": int,
                             "action": "accept|drop|reject"} ],      # <= 200, informational only
                 "confidence": "exact" | "approximate" | "unknown" },
  "confidence_reasons": [str],             # sorted, <= 16, why it is not exact
  "opaque_features": [str], "dataplane": [str], "other_hooks": [str],   # sorted
  "rule_count": int }
F = { "read": bool, "effective_default": "accept|drop|reject|unknown",
      "chains": [ { "name": str, "hook": "input"|null, "prio": int|null, "policy": "accept"|"drop"|null,
                    "base": bool, "rules": [R] } ] }          # input base chains and the chains reachable from them
R = { "m": M, "v": V, "opaque_reason": str }                  # opaque_reason may be absent
M = { "iif": str, "oif": str, "src": [cidr], "dst": [cidr], "proto": str, "sport": [[lo,hi]], "dport": [[lo,hi]],
      "ct": [str], "icmp": [int], "dtype": [str] }            # every key may be absent; {} = unconditional
V = "accept" | "drop" | "reject" | "return" | "jump:<chain name>" | "goto:<chain name>" | "opaque"
```

* Chain `name` is unique across the model: nft `"<family>.<table>.<chain>"` (e.g. `inet.filter.input`),
  legacy `"legacy4.filter.INPUT"` / `"legacy6.filter.INPUT"`. A rule in an `inet` table appears in both
  `ip4` and `ip6` (restricted to its family). `jump:`/`goto:` targets use the same names.
* **First-match semantics**; several input base chains (different tables/priorities) are ANDed: a packet is
  accepted only if every base chain accepts it, dropped if any chain drops it. `policy` applies when a chain ends.
* `ct` values: `established|invalid|new|related|untracked`. `dtype`: `anycast|broadcast|local|multicast|unicast`.
  `proto` is a lower-case name (`tcp`, `udp`, `icmp`, `icmpv6`, `sctp`, ...) or `p<number>`.
* `opaque_reason` on a rule means: it has an unmodelled extra condition (the rule *may* match packets inside
  `m`); the reason is a short comma-joined list (<= 3), e.g. `meta_mark`, `m_set`, `limit`, `dynamic_set`,
  `negated_iif`, `iif_pattern`, `ct_status`. `v: "opaque"` means the action itself is unknown (NFQUEUE, TPROXY,
  synproxy, unknown statement). The rule cap is 2000 reachable rules.
* `nft -j` elides some implied dependencies; they are restored: `reject with icmp` is IPv4-only, `reject with
  icmpv6` IPv6-only (`reject`/`icmpx` are family-neutral, `tcp reset` implies tcp).
* **`effective_default`**: the verdict for a packet no conditional rule mentions. In a base chain whose policy is
  accept, every way control can reach that policy counts as an accept path: a conditional `return`, a chain entered
  by `goto` that returns or falls off its end, or a chain end with no terminating rule. An unconditional `jump`/`goto`
  into a chain counts as terminating only if that chain can never return (no `return` before its terminator and no
  `goto` into a chain that may return); otherwise control comes back and falls off the base chain. A conditional `ct state new
  return` therefore keeps the default from being `drop`. It is `drop`/`reject` only if
  some input base chain reaches an unconditional drop/reject (or a drop policy) with every conditional rule treated as
  no-match, at least one packet falls through every conditional rule, and the chain's accept rules do not cover all
  new inbound TCP/UDP on every interface class; `accept` when every base chain's residual walk accepts (also when
  the family has no input chain); anything uncertain is `unknown`. It is `unknown` whenever `read` is false or
  `confidence == "unknown"`. firewalld (policy accept + final unconditional reject) and ufw (policy drop) are `drop`/`reject`
  and exact.
* **`flat_view.confidence`** is `exact` only if every traversed rule uses supported matchers (iif/oif, CIDRs,
  proto, port set/range, ct state, icmp type, addrtype, static named sets, jump/goto depth <= 8, accept/drop/reject/
  return) and there is no NAT rewriting, no unreadable family, no unparsed input and plain netfilter dataplane.
  `approximate`: some rule is opaque (ipset, mark, ct helper, owner, recent, limit, geoip, physdev, tcp flags,
  dynamic/map sets, NFQUEUE, TPROXY, `th sport/dport` outside a prior `meta l4proto` port-protocol match
  (`payload_th_dport`), `ip6 nexthdr X` on a non-accept verdict (`ip6_nexthdr`: only the immediate next header),
  an unknown `reject with` type (`reject_type`), a conditional `return` with an opaque condition that reaches an
  accept policy (`opaque_return`)...), any DNAT/REDIRECT/TPROXY exists in any table (or IPVS is loaded), a jump
  is unresolved or too deep, or `notrack` is used. `unknown`: a needed family is unreadable, input was unparsed
  (`problems`), the IPv6 state could not be determined, or the dataplane is K8s/Calico/Cilium/Flannel/Weave/CNI. **Never derive HOLDS from
  `approximate` or `unknown`.**
* **Known limit (not detectable from `nft -j`)**: nft drops the `ip6 nexthdr X` dependency of a following `X`
  payload match (`ip6 nexthdr tcp tcp dport 22 drop` prints exactly like `meta l4proto tcp tcp dport 22 drop`),
  although the kernel checks only the *immediate* next header: IPv6 packets with extension headers bypass it. Such a
  drop is modelled as a definite deny of IPv6 tcp/22; a consumer that needs more must not take an IPv6 port drop as
  proof against packets with extension headers.
* `opaque_features` includes `nat_rewrite`, `ipvs`, `notrack`, `assumes_no_dnat_without_rule` (a firewalld
  `ct status dnat accept` rule was dropped because no rule rewrites addresses), `unparsed_rule`.
  `dataplane` in `k8s|cilium|calico|flannel|weave|cni`. `other_hooks` lists unmodelled hooks (`forward`, `output`,
  `prerouting`, ...): they can only add drops, so ignoring them over-approximates acceptance.

### 5.1 Server-side reuse (`paddock_agent.collectors.fwmodel`, stdlib only, importable without the agent)

* `default_inbound_all_families(model) -> "deny" | "allow" | "unknown"`: `deny` only for an exact model whose every
  enabled family has `effective_default` drop/reject; `allow` when an enabled family accepts; else `unknown`.
  (This is the registry field `host.fw.default_inbound_all_families`.)
* `evaluate(model["families"]["ip4"|"ip6"], pkt) -> "allow" | "deny" | "maybe"` walks every input base chain with
  first-match semantics. `pkt` keys, all optional (absent = unknown, explored both ways): `src`, `dst` (IP
  strings), `proto`, `sport`, `dport` (int), `ct` (e.g. `"new"`), `iif` (an interface name, or
  `fwmodel.IIF_EXTERNAL` for "some non-loopback interface, name unknown"), `oif`, `icmp` (int), `dtype`
  (e.g. `"local"`). `deny` only if no path accepts, `allow` only if every path accepts; an opaque rule can only widen
  `deny` to `maybe`. Callers must still require `flat_view.confidence == "exact"` before treating `deny` as closed.
* `src_partition(family, fam) -> [(representative_ip, [cidr, ...])]`: partition of the source address space by every
  CIDR in the rules (<= 4096 atoms) plus a public and an RFC1918 representative.

## 6. `sections.patch` (lite: facts only, no matching, no verdicts)

`unavailable`: `containerised_agent`, `unsupported_platform`, or (when neither the identity nor the package list can
be read) the manifest's reason. `error`: when both `os` and `manifest` failed with an error. Otherwise `ok` with
`conf: "exact"` and `partial: true` iff any sub-block below is not `ok`.

`ok.v` has exactly the keys `os, manifest, pending, auto_update, kernel, reboot`. Each is a sub-block
`{"state": "ok"|"unavailable"|"error", ...}`; failures carry `reason` (same enumerations as 2) and, for errors,
`detail`, and never any of the data fields of the ok form. (`kernel` unavailable may still carry `running` and
`livepatch`.)

* **`os`** (ok): `id` str\|null, `id_like` [str] sorted, `version_id` str\|null, `codename` str\|null, `pretty_name`
  str\|null (<= 80), `family` `debian|rhel|suse|alpine|other`, `arch` str\|null.
* **`manifest`** (ok): `mgr` `dpkg|rpm`, `count` int, `sha256` str(64) (digest of the sorted package rows, sent every
  time), `held` int, `full` bool, `packages` (**present only when `full`**): sorted list of
  `[name, version, arch, source_name, source_version]` (rpm version = `[epoch:]version-release`; dpkg binary
  names have `:arch` stripped; only installed packages). Truncation (> 8000 packages, or output over the 8 MiB cap)
  is `error(truncated)`, never a silent cut; any unparsable line is `error(parse_error)`; an empty list is an error.
  The agent sends `full: true` when `ctx.known_manifest_sha != sha256` (or `ctx.force_full_manifest`).
* **`pending`** (ok): `mgr` `apt|dnf|yum`, `total` int, `security` int, `security_pkgs` [str] sorted <= 200,
  `kept_back` int, `removals` int, `metadata_age_s` int\|null (apt only: seconds since the package lists were refreshed).
  apt uses `apt-get -s dist-upgrade` (never `update`), counting a package as security when any origin suite ends in
  `-security`; dnf uses `dnf -C updateinfo list --security`; yum `-C --security check-update`. Cache-only dnf with no
  cache is `unavailable(no_data)`, never zero. Stale metadata silently under-counts: the server must check
  `metadata_age_s`.
* **`auto_update`** (ok): dpkg: `mgr: "unattended-upgrades"`, `installed` bool, `interval_days` int\|null,
  `timer_enabled` bool. rpm: `mgr` `dnf-automatic|yum-cron|none`, `installed` bool, `apply` bool\|null,
  `timer_enabled` bool\|null.
* **`kernel`** (ok): `running` str, `package` str, `package_version` str, `installed` [str] <= 20, `livepatch` bool
  (a livepatch makes any kernel verdict approximate). `unavailable(unmanaged_kernel)`: the running kernel is
  owned by no installed package (also carries `running`, `livepatch`).
* **`reboot`** (ok): `required` bool, `pkgs` [str] <= 50, `source` `file|needs-restarting`.
  `/var/run/reboot-required` present => required. On dpkg hosts absence means "not signalled" (Debian without
  update-notifier-common never writes it). `needs-restarting -r` rc 1 => required, rc 0 => not, any other rc =>
  `error(exit_nonzero)`.

## 7. `sections.self`

Always `ok`, `conf: exact`, `partial: false` (sent even when every collector failed, so the server can tell a collector
error from agent silence). `v`:

| field | type | notes |
|---|---|---|
| `agent_version` | str | <= 32 |
| `python` | str | interpreter version |
| `platform` | str | `sys.platform`, <= 16 |
| `collectors` | `{sshd,listeners,firewall,patch: {status: "ok"\|"unavailable"\|"error", ms: int, reason: str\|null}}` | `reason` is the Section's reason; `ms` wall time |
| `caps` | `{cap_eff: str(16 hex)\|null, net_admin: bool, sys_ptrace: bool, dac_read_search: bool}` | `CapEff` of the agent |
| `is_root` | bool | |
| `containerised` | bool | |
| `boot_id` | str \| null | `/proc/sys/kernel/random/boot_id`, lower-case uuid |
| `machine_id_hash` | str(64) \| null | `sha256(machine_salt + "\n" + machine-id)`; **never the raw id** |
| `uptime_s` | int \| null | |
| `seq` | int | the envelope seq this payload will carry (`Ctx.seq`) |
| `key_id` | str | <= 64 |
| `payload_bytes` | int | size of the four data sections' canonical bytes |
| `clock_skew_ms` | int \| null | server `Date` minus local time, RTT-corrected (`Ctx.clock_skew_ms`) |
| `imds_enabled` | bool | whether the opt-in cloud metadata request is on (P2 collectors make no such request) |

## 8. Driving it

```python
from paddock_agent.runner import Ctx
from paddock_agent.collectors import collect_all, payload_bytes
ctx = Ctx(state_dir, agent_version, seq=0, key_id="", machine_salt=b"", clock_skew_ms=None,
          enable_imds=False, now=None)           # now: None | int epoch seconds | callable
ctx.known_manifest_sha = "<sha256 the server last acknowledged>"   # or None => send the full list
raw = payload_bytes(collect_all(ctx))             # the exact bytes to hash and sign
```

`Ctx` also accepts (keyword, for tests and containers) `proc_root`, `host_root`, `runner`, `is_root`,
`containerised`, `collector_budget_s`, `total_budget_s`, `platform`. Programs run only through
`paddock_agent.runner.run_command` (fixed PATH, `LC_ALL=C`, `shell=False`, stdin `/dev/null`, 4 MiB output
cap, process-group kill on timeout; returns `{rc, out, err_tail, timed_out, missing, truncated}`).
