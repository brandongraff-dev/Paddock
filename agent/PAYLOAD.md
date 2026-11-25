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

`unavailable`: `tool_missing` (no sshd binary and no sshd evidence), `no_data` (evidence of an SSH server such as
`/etc/ssh/sshd_config`, an `sshd`/`dropbear` process or a listener on 22, but no OpenSSH binary found, i.e.
unknown, NOT "not installed"), `containerised_agent`, `unsupported_platform`. `error`: `parse_error` when
`sshd -T` printed something unparseable or a value outside the allowlist's domain.

`ok.v` (all keys always present):

| field | type | notes |
|---|---|---|
| `installed` | bool | always `true` in an `ok` |
| `source` | `"sshd_T"` \| `"text"` | `text` = `sshd -T` failed (not root, no host keys, timeout...) and the config files were parsed; **`text` always has `conf: approximate`** |
| `version` | str \| null | e.g. `"9.6p1"` from `ssh -V` / `sshd -V` |
| `binary` | str | path of the sshd binary |
| `socket_activated` | bool | `ssh.socket`/`sshd.socket` is enabled (Port/ListenAddress may then be ignored; use `listeners`) |
| `config` | object | allowlisted effective global config, below |
| `probes` | object | `{addrs: [str] sorted, users_probed: int, users_total: int, planned: int, done: int, deltas: [D]}`; `users_probed` excludes the nonexistent user; `users_total` = login users on the host (uid != 0, login shell) |
| `match` | object | `{blocks: int, criteria: [str] sorted, known: bool, unprobed: bool, unprobed_reasons: [str] sorted}` |
| `files` | [`{path: str, sha256: str\|null, size: int}`] | `sshd_config` and every `Include`d file read (<= 64); `sha256: null` = unreadable |

`D` (probe delta) = `{user: str, addr: str, delta: {key: value|null}}`: only keys whose probed value differs
from the global value; `null` = the key is absent in the probe. `user` is `"<nonexistent>"` for the made-up
user. Sorted by `(user, addr)`. Probe matrix: users {root, up to 20 login users by uid, literal `Match User`
names (<= 10), a nonexistent user} x addresses {203.0.113.7, 10.255.255.1, plus one representative per atom of
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

`match.unprobed_reasons` enumeration: `text_source`, `users_over_cap` (a `Match User/Group` exists and the host
has more than 20 login users), `criterion_<name>` (host, localaddress, localport, rdomain, exec, ...: cannot be
probed), `address_pattern` (a `Match Address` pattern that is not a CIDR), `address_atoms` (more than 12
atoms), `config_unreadable`, `passwd_unreadable`, `probe_cap`, `probe_budget`, `probe_failed`,
`probe_incomplete`, `unexplained_delta` (probes disagree although the text shows no `Match` block: the text view
is wrong). **`conf` is `exact` iff `source == "sshd_T"` and `match.unprobed == false`.** `match.known: false`
means a config file could not be read, so `match.criteria` may be incomplete.

Cannot see: AuthorizedKeysCommand results, PAM modules, SSSD/LDAP users, sshd in containers, non-OpenSSH
daemons (Dropbear), per-user `authorized_keys` options.

## 4. `sections.listeners`

`unavailable`: `containerised_agent`, `unsupported_platform` (no `/proc/net/tcp`), `permission_denied`.
`error`: `truncated` (more than 2000 distinct listeners, or a `/proc/net` table over 8 MiB), `exception`.
`partial: true` when a data line of `/proc/net/*` could not be parsed or `/proc/net/udp` is missing. A missing
`tcp6`/`udp6` means IPv6 is disabled (`ipv6: false`), not an error.

`ok.v` = `{count: int, listeners: [L] , ipv6: bool, bindv6only: 0|1|null,
attribution: {status: "ok"|"partial"|"denied", unreadable_pids: int, unattributed: int}}`.

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
`error`: `timeout`, `exit_nonzero`, `parse_error`, `truncated` (more than 2000 modelled rules).
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
  "ipv6_enabled": bool,                    # a non-loopback v6 address exists and disable_ipv6 != 1
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
* **`effective_default`**: the verdict for a packet no conditional rule mentions. It is `drop`/`reject` only if
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
  dynamic/map sets, NFQUEUE, TPROXY...), any DNAT/REDIRECT/TPROXY exists in any table (or IPVS is loaded), a jump
  is unresolved or too deep, or `notrack` is used. `unknown`: a needed family is unreadable, input was unparsed
  (`problems`), or the dataplane is K8s/Calico/Cilium/Flannel/Weave/CNI. **Never derive HOLDS from
  `approximate` or `unknown`.**
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
