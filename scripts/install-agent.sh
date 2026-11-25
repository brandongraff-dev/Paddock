#!/bin/sh
# Paddock fleet host agent installer (docs/AGENT_V2.md, docs/ASSURANCE_P2.md E7 and section 8).
#
#   sudo sh ./install-agent.sh --server https://paddock.example.com
#   printf %s "$TOKEN" | sudo sh ./install-agent.sh --server https://paddock.example.com
#   sh ./install-agent.sh --server https://paddock.example.com --dry-run
#   sudo sh ./install-agent.sh --uninstall [--purge --yes]
#
# Run it with `sh ./install-agent.sh`: a file fetched with curl or wget is not executable.
#
# What it does, in this order, and stops at the first thing that does not check out:
#   1. checks it runs as root on a systemd Linux with Python >= 3.8 (a dry run needs none of that),
#   2. downloads the PINNED release's paddock-agent.pyz and SHA256SUMS (never "latest"),
#   3. verifies the cosign (sigstore) bundle over SHA256SUMS when `cosign` is installed (or always, with
#      --require-cosign), then the archive's sha256 against it (and against --sha256 when given),
#   4. installs the archive root-owned, sets PADDOCK_SERVER in /etc/paddock-agent/agent.env (mode 0600; any other
#      line you put there is kept) and writes the hardened systemd unit (one root process, docs/ASSURANCE_P2.md
#      section 8),
#   5. enrolls the host with a ONE-TIME token, then enables and (re)starts the service and checks it is active.
#
# The enrollment token is a secret and is NEVER an argument (argv is readable by every local user in
# `ps` and /proc): it is read from $PADDOCK_ENROLL_TOKEN, from stdin, or from a hidden prompt, and is
# handed to the agent on stdin. It is read first, before anything is downloaded or installed, and taken out of
# the environment before any other program runs. This script refuses --token. It is never written to a file or
# a log. Do not use `sudo PADDOCK_ENROLL_TOKEN=...`: that puts the token in sudo's argv.
#
# Signature check: without `cosign` only the sha256 from the same release is checked, which detects a
# corrupt or swapped archive but NOT a compromised release. Install cosign 2.4 or newer (the release is signed
# with 2.5.2; an older cosign may not read the bundle, and then the install is refused) and pass
# --require-cosign to make its absence an error, and/or pin the digest out of band with --sha256.
#
# Options:
#   --server URL       Paddock orchestrator base URL (https://; http:// only for loopback). Required to install.
#   --version TAG      release tag to install (default: the tag this script is pinned to, see PINNED_TAG)
#   --repo OWNER/NAME  GitHub repository to download from (default brandongraff-dev/paddock)
#   --base-url URL     download directory instead of the GitHub release (https://, or file:// for a mirror/tests)
#   --sha256 HEX       also require the archive to have exactly this sha256. Take it from a source independent of
#                      the download (your own build, docs/AGENT_V2.md section 2, or a host that verified the
#                      signature): the digest in the release notes comes from the same release and proves nothing.
#   --require-cosign   fail unless cosign is installed and its verification passes
#   --no-enroll        install only; enroll later with `paddock enroll`
#   --no-start         do not enable/start/restart the service
#   --reenroll         enroll even though this host already holds credentials (needs a re-key token)
#   --hostname NAME    hostname to enroll as (default: this host's name)
#   --prefix DIR       install prefix (default /usr/local): archive in DIR/lib/paddock-agent, command DIR/bin/paddock
#                      (a small wrapper that runs the archive with the interpreter this installer verified; an
#                      existing DIR/bin/paddock that is not ours, such as the Paddock CLI, is never overwritten)
#   --root DIR         staging root: prefix every path with DIR and never touch systemd (packaging, tests)
#   --python PATH      interpreter to run the agent with (default: python3 from PATH; must be >= 3.8)
#   --dry-run          print what would happen; change nothing, use no network, read no token
#   --uninstall        stop and remove the service, unit, archive and our own command (credentials/keys are kept)
#   --purge            with --uninstall: also delete /var/lib/paddock-agent (the key!) and /etc/paddock-agent
#   --yes              do not ask for confirmation (required for --purge without a terminal)
#   -h, --help         this text
#
# Uninstalling does NOT revoke the agent on the server: revoke it in Paddock (docs/AGENT_V2.md).
set -eu
umask 022

# The token may be handed over in the environment. Take it out of the environment before ANY other command
# runs, so curl, cosign, sha256sum and the downloaded archive never inherit it. It is passed to the agent on
# stdin, once, at the end. The variables this script uses to hold the token are unset first: a name the caller
# exported (ENV_TOKEN, TOKEN) would otherwise stay exported when the script assigns the token to it.
unset ENV_TOKEN TOKEN
ENV_TOKEN="${PADDOCK_ENROLL_TOKEN:-}"
unset PADDOCK_ENROLL_TOKEN

# Cleanup runs on EVERY way out, from the very start: it gives the terminal its echo back (the hidden token prompt
# turns it off) and removes the work directory. INT and TERM must exit (a handler that only cleans up would let the
# script carry on); the EXIT trap then runs cleanup. QUIT (Ctrl-backslash) and HUP get the same treatment: without a
# handler sh/dash die on them WITHOUT running the EXIT trap, which left the terminal with echo off.
TTY_SAVED=""
WORK=""
cleanup() {
  if [ -n "$TTY_SAVED" ]; then stty "$TTY_SAVED" 2>/dev/null || true; TTY_SAVED=""; fi
  if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 131' QUIT
trap 'exit 129' HUP

# Rewritten to the release's own tag in the copy that is attached to a release (release.yml), so a
# downloaded installer installs the archive it was published with. A checkout pins to the tag below.
PINNED_TAG="v0.2.0"

REPO="${PADDOCK_REPO:-brandongraff-dev/paddock}"
TAG="${PADDOCK_AGENT_VERSION:-$PINNED_TAG}"
BASE_URL="${PADDOCK_AGENT_BASE_URL:-}"
SERVER="${PADDOCK_SERVER:-}"
PREFIX="/usr/local"
ROOT=""
PYTHON_BIN=""
EXPECT_SHA=""
HOSTNAME_OVERRIDE=""
REQUIRE_COSIGN=0
NO_ENROLL=0
NO_START=0
REENROLL=0
DRY_RUN=0
UNINSTALL=0
PURGE=0
YES=0

SERVICE=paddock-agent
STATE_DIR_ABS=/var/lib/paddock-agent
CONF_DIR_ABS=/etc/paddock-agent
UNIT_DIR_ABS=/etc/systemd/system
OIDC_ISSUER="https://token.actions.githubusercontent.com"

if [ -t 1 ]; then B='\033[1m'; Y='\033[33m'; R='\033[31m'; N='\033[0m'; else B=''; Y=''; R=''; N=''; fi
say()  { printf '%b\n' "$*"; }
step() { say "${B}==>${N} $*"; }
warn() { say "${Y}warning:${N} $*" >&2; }
die()  { say "${R}error:${N} $*" >&2; exit 1; }
plan() { say "[dry-run] $*"; }

usage() {
  if [ -f "$0" ]; then
    sed -n '2,/^set -eu/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
  else
    say "see the header of scripts/install-agent.sh for the options"
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --server)         [ $# -ge 2 ] || die "--server needs a value";   SERVER="$2"; shift ;;
    --version)        [ $# -ge 2 ] || die "--version needs a value";  TAG="$2"; shift ;;
    --repo)           [ $# -ge 2 ] || die "--repo needs a value";     REPO="$2"; shift ;;
    --base-url)       [ $# -ge 2 ] || die "--base-url needs a value"; BASE_URL="$2"; shift ;;
    --sha256)         [ $# -ge 2 ] || die "--sha256 needs a value";   EXPECT_SHA="$2"; shift ;;
    --prefix)         [ $# -ge 2 ] || die "--prefix needs a value";   PREFIX="$2"; shift ;;
    --root)           [ $# -ge 2 ] || die "--root needs a value";     ROOT="$2"; shift ;;
    --python)         [ $# -ge 2 ] || die "--python needs a value";   PYTHON_BIN="$2"; shift ;;
    --hostname)       [ $# -ge 2 ] || die "--hostname needs a value"; HOSTNAME_OVERRIDE="$2"; shift ;;
    --require-cosign) REQUIRE_COSIGN=1 ;;
    --no-enroll)      NO_ENROLL=1 ;;
    --no-start)       NO_START=1 ;;
    --reenroll)       REENROLL=1 ;;
    --dry-run)        DRY_RUN=1 ;;
    --uninstall)      UNINSTALL=1 ;;
    --purge)          PURGE=1 ;;
    --yes|-y)         YES=1 ;;
    -h|--help)        usage; exit 0 ;;
    --token|--token=*|--enroll-token|--enroll-token=*)
      die "enrollment tokens are never accepted as arguments (argv is visible to every local user): set PADDOCK_ENROLL_TOKEN, or pipe the token on stdin" ;;
    fet_*)            die "enrollment tokens are never accepted as arguments (argv is visible to every local user): set PADDOCK_ENROLL_TOKEN, or pipe the token on stdin" ;;
    *)                die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# validation (everything below is printed, written to a path or put in a URL, so it is constrained)
# ---------------------------------------------------------------------------
case "$REPO" in */*) : ;; *) die "--repo must look like OWNER/NAME" ;; esac
case "$REPO" in *[!A-Za-z0-9._/-]*|*..*) die "--repo contains unexpected characters" ;; esac
case "$TAG" in ''|*[!A-Za-z0-9._-]*) die "--version contains unexpected characters" ;; esac
case "$TAG" in v[0-9]*) : ;; *) die "--version must be a release tag such as v0.2.0 (there is no 'latest': an installer must be pinned)" ;; esac
case "$PREFIX" in /*) : ;; *) die "--prefix must be an absolute path" ;; esac
case "$PREFIX" in *[!A-Za-z0-9._/-]*) die "--prefix contains unexpected characters" ;; esac
if [ -n "$ROOT" ]; then
  case "$ROOT" in /*) : ;; *) die "--root must be an absolute path" ;; esac
  case "$ROOT" in *[!A-Za-z0-9._/-]*) die "--root contains unexpected characters" ;; esac
fi
if [ -n "$EXPECT_SHA" ]; then
  case "$EXPECT_SHA" in *[!0-9a-fA-F]*) die "--sha256 must be 64 hex characters" ;; esac
  [ "${#EXPECT_SHA}" -eq 64 ] || die "--sha256 must be 64 hex characters"
fi
if [ -n "$HOSTNAME_OVERRIDE" ]; then
  case "$HOSTNAME_OVERRIDE" in *[!A-Za-z0-9._:-]*) die "--hostname may only contain letters, digits and . _ : -" ;; esac
fi
[ "$PURGE" = 0 ] || [ "$UNINSTALL" = 1 ] || die "--purge only makes sense with --uninstall"
if [ -n "$PYTHON_BIN" ]; then
  case "$PYTHON_BIN" in *[!A-Za-z0-9._/+-]*) die "--python contains unexpected characters" ;; esac
fi

if [ -z "$BASE_URL" ]; then
  BASE_URL="https://github.com/$REPO/releases/download/$TAG"
fi
case "$BASE_URL" in
  https://*|file:///*) : ;;
  *) die "--base-url must be https:// (or file:///... for a local mirror): the archive and its checksums must not travel in clear text" ;;
esac
case "$BASE_URL" in *[!A-Za-z0-9._~:/%+=,-]*) die "--base-url contains unexpected characters (no credentials, query or fragment)" ;; esac
BASE_URL="${BASE_URL%/}"

# --server: https only, except an exact loopback host (a local test server); no credentials, query or fragment.
validate_server() {
  case "$SERVER" in
    '')        die "--server is required (the Paddock orchestrator URL, e.g. https://paddock.example.com)" ;;
    https://*) : ;;
    http://localhost|http://localhost:*|http://localhost/*|http://127.0.0.1|http://127.0.0.1:*|http://127.0.0.1/*) : ;;
    http://*)  die "--server must be https:// (plain http:// is only accepted for localhost or 127.0.0.1)" ;;
    *)         die "--server must start with https://" ;;
  esac
  case "$SERVER" in *[!A-Za-z0-9._:/-]*) die "--server contains unexpected characters (no credentials, query or fragment)" ;; esac
  SERVER="${SERVER%/}"
}

# ---------------------------------------------------------------------------
# paths (all of them go through P so --root can stage an install without touching the host)
# ---------------------------------------------------------------------------
P() { printf '%s%s' "$ROOT" "$1"; }
LIB_DIR="$PREFIX/lib/paddock-agent"
PYZ_ABS="$LIB_DIR/paddock-agent.pyz"
LINK_ABS="$PREFIX/bin/paddock"
ENV_FILE_ABS="$CONF_DIR_ABS/agent.env"
UNIT_ABS="$UNIT_DIR_ABS/$SERVICE.service"

have() { command -v "$1" >/dev/null 2>&1; }

# Test-only: with --root (which never touches systemd) this names a stand-in for `systemctl`, so the service
# steps can be exercised against a recording fake. Without --root, or without this variable, the real systemctl.
SYSTEMCTL=systemctl
SYSTEMD_MANAGED=0
if [ -z "$ROOT" ]; then
  SYSTEMD_MANAGED=1
elif [ -n "${PADDOCK_INSTALL_TEST_SYSTEMCTL:-}" ]; then
  case "$PADDOCK_INSTALL_TEST_SYSTEMCTL" in /*) : ;; *) die "PADDOCK_INSTALL_TEST_SYSTEMCTL must be an absolute path" ;; esac
  SYSTEMCTL="$PADDOCK_INSTALL_TEST_SYSTEMCTL"
  SYSTEMD_MANAGED=1
fi
SETTLE_SECS="${PADDOCK_INSTALL_SETTLE_SECS:-3}"
case "$SETTLE_SECS" in ''|*[!0-9]*) die "PADDOCK_INSTALL_SETTLE_SECS must be a whole number of seconds" ;; esac

# The `paddock` command is a tiny wrapper (not a symlink to the archive, whose #! line would pick whatever
# python3 is first on PATH instead of the interpreter this installer verified). The marker line is how we
# recognise our own file later: we never replace, or on uninstall delete, a `paddock` that is not ours.
WRAPPER_MARK="# paddock-agent wrapper written by install-agent.sh"
link_present() { p="$(P "$LINK_ABS")"; [ -e "$p" ] || [ -L "$p" ]; }
link_is_ours() { # a wrapper carrying our marker, or the symlink to our archive that older installers made
  p="$(P "$LINK_ABS")"
  if [ -L "$p" ]; then
    [ "$(readlink "$p" 2>/dev/null || true)" = "$PYZ_ABS" ]
  elif [ -f "$p" ]; then
    n=0
    l=""
    while [ "$n" -lt 4 ] && { IFS= read -r l || [ -n "$l" ]; }; do
      [ "$l" != "$WRAPPER_MARK" ] || return 0
      n=$((n + 1))
    done <"$p"
    return 1
  else
    return 1
  fi
}

# Refuse to install through a symlink, into a directory somebody else owns, or into one that others can write.
# strict also refuses group-writable (the directories this installer creates for itself); shared directories such
# as /usr/local/bin are group-writable on some distributions, so only world-writable is refused there.
check_dir() { # check_dir PATH strict|shared
  d="$(P "$1")"
  [ ! -L "$d" ] || die "$d is a symlink: refusing to install through it"
  [ -d "$d" ] || die "$d is not a directory"
  me="$(id -u)"
  [ -n "$(find "$d" -prune -user "$me" 2>/dev/null)" ] || die "$d is not owned by uid $me: refusing to install into it"
  [ -z "$(find "$d" -prune -perm -0002 2>/dev/null)" ] || die "$d is world-writable: refusing to install into it"
  if [ "$2" = strict ] && [ -n "$(find "$d" -prune -perm -0020 2>/dev/null)" ]; then
    die "$d is group-writable: refusing to install into it"
  fi
}

# The unit is written here, not downloaded: it is the file whose directives are the safety story.
# agent/systemd/paddock-agent.service is the same text with the default paths (a test enforces it).
emit_unit() { # emit_unit PYTHON PYZ
  cat <<EOF
# Paddock fleet host agent: one root process, sandboxed (docs/ASSURANCE_P2.md section 8, owner decision O2).
# scripts/install-agent.sh writes this unit with the interpreter and archive paths it installed; a test
# keeps the two byte-identical apart from those two paths. The enrollment token is never in a unit.
[Unit]
Description=Paddock fleet host agent
Documentation=https://github.com/brandongraff-dev/paddock/blob/main/docs/AGENT_V2.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$1 $2 run
EnvironmentFile=-$CONF_DIR_ABS/agent.env
Restart=on-failure
RestartSec=10
# exit status 7 = the server requires re-enrollment: stop instead of hammering it
RestartPreventExitStatus=7
StateDirectory=paddock-agent
StateDirectoryMode=0700
# --- sandboxing ---
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$STATE_DIR_ABS
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ProtectKernelTunables=yes
SystemCallFilter=@system-service
# DAC_READ_SEARCH and SYS_PTRACE read root-only host state; NET_ADMIN reaches nft and iptables-nft over netlink.
# NOT CAP_NET_RAW: legacy iptables (iptables-legacy) opens a raw socket, so on a host whose firewall is legacy
# iptables the firewall facts read UNKNOWN and block_ip fails under this unit (docs/AGENT_V2.md section 3).
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
}

find_python() {
  if [ -n "$PYTHON_BIN" ]; then
    cand="$PYTHON_BIN"
  else
    cand="$(command -v python3 2>/dev/null || true)"
  fi
  [ -n "$cand" ] || { echo ""; return 0; }
  # an absolute path goes into the unit, so a later PATH change cannot swap the interpreter
  case "$cand" in /*) : ;; *) cand="$(command -v "$cand" 2>/dev/null || true)" ;; esac
  echo "$cand"
}

python_ok() { # python_ok PATH -> 0 when it is >= 3.8
  "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1
}

sha256_of() {
  if have sha256sum; then sha256sum "$1" | awk '{print $1}'
  elif have shasum; then shasum -a 256 "$1" | awk '{print $1}'
  else die "need sha256sum or shasum to verify the download"
  fi
}

fetch() { # fetch URL DEST  (https via curl or wget, file:// by copy; never follows a downgrade)
  case "$1" in
    file://*) cp "${1#file://}" "$2" ;;
    *)
      if have curl; then
        curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --connect-timeout 20 -o "$2" "$1"
      elif have wget; then
        wget -q --https-only --tries=3 -O "$2" "$1"
      else
        die "need curl or wget to download the release"
      fi ;;
  esac
}

confirm() { # confirm "question" -> 0 on yes
  [ "$YES" = 1 ] && return 0
  [ -t 0 ] || die "$1 -- refusing without a terminal; pass --yes to confirm"
  printf '%s [y/N] ' "$1" >&2
  read -r ans || ans=""
  case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# The enrollment token: environment (already moved to ENV_TOKEN above), else stdin, else a hidden prompt. Never
# argv, never echoed. `read` returns 1 on a last line with no newline (what `printf %s "$TOKEN" |` sends) but
# still fills the variable, so a non-empty value is kept.
TOKEN=""
read_token() {
  if [ -n "$ENV_TOKEN" ]; then
    TOKEN="$ENV_TOKEN"
    ENV_TOKEN=""
  elif [ ! -f "$0" ]; then
    # `curl ... | sh`: stdin IS the script, so it cannot also carry the token
    die "when the installer is piped into sh, stdin is the script and cannot also carry the token: download the script and run it from the file with the token on stdin (printf %s \"\$TOKEN\" | sudo sh ./install-agent.sh --server URL). Never put the token in a command line or after 'sudo VAR=': both end up in argv, which every local user can read"
  elif [ -t 0 ]; then
    printf 'Enrollment token (input hidden): ' >&2
    TTY_SAVED="$(stty -g 2>/dev/null || true)"     # the traps above give the echo back on any exit
    stty -echo 2>/dev/null || true
    IFS= read -r TOKEN || [ -n "$TOKEN" ] || TOKEN=""
    if [ -n "$TTY_SAVED" ]; then stty "$TTY_SAVED" 2>/dev/null || true; TTY_SAVED=""; fi
    printf '\n' >&2
  else
    IFS= read -r TOKEN || [ -n "$TOKEN" ] || TOKEN=""
  fi
  # strip whitespace, then require the documented shape (fet_<12 hex>_<secret>) without ever printing it
  TOKEN="$(printf '%s' "$TOKEN" | tr -d '[:space:]')"
  case "$TOKEN" in
    fet_????????????_*) : ;;
    '') die "no enrollment token: pipe it on stdin or set PADDOCK_ENROLL_TOKEN (mint one with POST /v1/fleet/enroll-tokens, docs/AGENT_V2.md)" ;;
    *)  TOKEN=""; die "that does not look like a Paddock enrollment token (expected fet_<12 hex>_<secret>)" ;;
  esac
  case "$TOKEN" in *[!A-Za-z0-9_-]*) TOKEN=""; die "the enrollment token contains unexpected characters" ;; esac
}

# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------
do_uninstall() {
  step "Uninstalling the Paddock agent"
  if [ "$DRY_RUN" = 1 ]; then
    [ -n "$ROOT" ] || plan "systemctl disable --now $SERVICE"
    plan "remove $(P "$UNIT_ABS") and $(P "$LIB_DIR"), and $(P "$LINK_ABS") only if it is this agent's own command"
    plan "keep $(P "$STATE_DIR_ABS") (the signing key and credentials) and $(P "$CONF_DIR_ABS")"
    if [ "$PURGE" = 1 ]; then plan "PURGE: delete $(P "$STATE_DIR_ABS") and $(P "$CONF_DIR_ABS")"; fi
    plan "the agent is NOT revoked on the server: revoke it in Paddock (docs/AGENT_V2.md)"
    return 0
  fi
  if [ "$PURGE" = 1 ]; then
    confirm "Delete $(P "$STATE_DIR_ABS") (this host's signing key and credentials) and $(P "$CONF_DIR_ABS")?" || die "aborted"
  fi
  if [ -z "$ROOT" ]; then
    [ "$(id -u)" = 0 ] || die "run as root (sudo) to uninstall"
    if have systemctl; then
      systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
    fi
  fi
  rm -f "$(P "$UNIT_ABS")"
  if link_is_ours; then
    rm -f "$(P "$LINK_ABS")"
  elif link_present; then
    warn "kept $(P "$LINK_ABS"): it is not this agent's command"
  fi
  rm -rf "$(P "$LIB_DIR")"
  if [ -z "$ROOT" ] && have systemctl; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
  if [ "$PURGE" = 1 ]; then
    rm -rf "$(P "$STATE_DIR_ABS")" "$(P "$CONF_DIR_ABS")"
    say "   purged state and configuration"
  else
    say "   kept $(P "$STATE_DIR_ABS") and $(P "$CONF_DIR_ABS") (use --purge to delete them)"
  fi
  warn "the agent is still registered on the server: revoke it in Paddock so its key and token stop working"
  say "done."
}

if [ "$UNINSTALL" = 1 ]; then
  do_uninstall
  exit 0
fi

# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------
validate_server

PYTHON="$(find_python)"
UNIT_TEXT_PYTHON="${PYTHON:-/usr/bin/python3}"

if [ "$DRY_RUN" = 1 ]; then
  step "Dry run: nothing is downloaded, written or started"
  plan "release        : $REPO $TAG (pinned; there is no 'latest')"
  plan "download from  : $BASE_URL/paddock-agent.pyz"
  plan "                 $BASE_URL/SHA256SUMS"
  if have cosign; then
    plan "                 $BASE_URL/SHA256SUMS.sigstore.json"
    plan "cosign verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG --certificate-oidc-issuer $OIDC_ISSUER SHA256SUMS"
  elif [ "$REQUIRE_COSIGN" = 1 ]; then
    plan "cosign is NOT installed and --require-cosign is set: a real run would stop here"
  else
    plan "cosign not installed: only the sha256 from the same release would be checked (install cosign for a signature check)"
  fi
  [ -z "$EXPECT_SHA" ] || plan "require the archive sha256 to equal the pinned $EXPECT_SHA"
  plan "verify         : sha256 of paddock-agent.pyz against SHA256SUMS; abort on any mismatch"
  plan "interpreter    : ${PYTHON:-python3 (not found on this machine)} (must be >= 3.8)"
  plan "install        : $(P "$PYZ_ABS") (root, 0755) and the wrapper command $(P "$LINK_ABS") (only if nothing else is there)"
  plan "write          : $(P "$ENV_FILE_ABS") (mode 0600) with PADDOCK_SERVER=$SERVER; other lines already in it are kept"
  plan "write          : $(P "$UNIT_ABS") with exactly these contents:"
  emit_unit "$UNIT_TEXT_PYTHON" "$PYZ_ABS" | sed 's/^/[dry-run]     | /'
  if [ "$NO_ENROLL" = 1 ]; then
    plan "enroll         : skipped (--no-enroll); run \`paddock enroll\` later"
  else
    if [ -n "$ENV_TOKEN" ]; then
      plan "enroll         : with the token in \$PADDOCK_ENROLL_TOKEN (not shown), handed to the agent on stdin"
    else
      plan "enroll         : read a one-time token from stdin or a hidden prompt; it is never an argument"
    fi
  fi
  if [ "$NO_START" = 1 ] || [ "$SYSTEMD_MANAGED" = 0 ]; then
    plan "service        : not started"
  else
    plan "service        : systemctl daemon-reload; systemctl enable $SERVICE; systemctl restart $SERVICE; check it is active"
  fi
  say "dry run complete: no changes made."
  exit 0
fi

# ---- real run ----
if [ -z "$ROOT" ]; then
  [ "$(id -u)" = 0 ] || die "run as root (sudo sh ./install-agent.sh ...): the agent reads root-only host state"
  [ "$(uname -s)" = Linux ] || die "the agent supports Linux only"
  [ -d /run/systemd/system ] || die "systemd is required (no /run/systemd/system); use --no-start with --root to stage files only"
fi
[ -n "$PYTHON" ] || die "python3 not found (the agent needs Python >= 3.8; on RHEL 8 install the python39 module)"
# the interpreter goes into the unit and into the paddock wrapper, so it must be a plain path
case "$PYTHON" in *[!A-Za-z0-9._/+-]*) die "the interpreter path $PYTHON contains unexpected characters (letters, digits and . _ / + - only)" ;; esac
python_ok "$PYTHON" || die "$PYTHON is older than Python 3.8; install a newer interpreter and pass --python"
have cosign || [ "$REQUIRE_COSIGN" = 0 ] || die "--require-cosign was given but cosign is not installed"
have find || die "need find to check the install directories"

# Decide about enrollment and read the token NOW, before anything is downloaded or written: a missing or
# malformed token must not leave a half-installed host behind.
enrolled=0
if [ -f "$(P "$STATE_DIR_ABS")/credentials.json" ] && [ "$REENROLL" = 0 ]; then
  enrolled=1
fi
if [ "$NO_ENROLL" = 0 ] && [ "$enrolled" = 0 ]; then
  step "Reading the enrollment token"
  read_token
fi
ENV_TOKEN=""

WORK="$(mktemp -d "${TMPDIR:-/tmp}/paddock-agent-install.XXXXXX")"        # removed by cleanup (EXIT trap)

step "Downloading $REPO $TAG"
fetch "$BASE_URL/paddock-agent.pyz" "$WORK/paddock-agent.pyz" || die "could not download $BASE_URL/paddock-agent.pyz"
fetch "$BASE_URL/SHA256SUMS" "$WORK/SHA256SUMS" || die "could not download $BASE_URL/SHA256SUMS"

if have cosign; then
  step "Verifying the sigstore signature of SHA256SUMS"
  fetch "$BASE_URL/SHA256SUMS.sigstore.json" "$WORK/SHA256SUMS.sigstore.json" || die "could not download the signature bundle $BASE_URL/SHA256SUMS.sigstore.json"
  cosign verify-blob \
    --bundle "$WORK/SHA256SUMS.sigstore.json" \
    --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$WORK/SHA256SUMS" >/dev/null 2>"$WORK/cosign.err" || { cat "$WORK/cosign.err" >&2; die "the signature on SHA256SUMS did not verify: not installing (cosign 2.4 or newer is expected; an older one may not read the bundle)"; }
  say "   signature OK (signed by the $REPO release workflow for $TAG)"
else
  warn "cosign is not installed: the signature was NOT checked. Only the sha256 from the same release will be verified, which does not protect against a compromised release. Install cosign (2.4 or newer) and use --require-cosign, or pin the digest with --sha256."
fi

step "Verifying the archive checksum"
WANT="$(awk '$2 == "paddock-agent.pyz" || $2 == "*paddock-agent.pyz" {print $1}' "$WORK/SHA256SUMS" | head -n 1)"
[ -n "$WANT" ] || die "SHA256SUMS has no entry for paddock-agent.pyz"
case "$WANT" in *[!0-9a-fA-F]*) die "SHA256SUMS is malformed" ;; esac
[ "${#WANT}" -eq 64 ] || die "SHA256SUMS is malformed"
GOT="$(sha256_of "$WORK/paddock-agent.pyz")"
[ "$GOT" = "$WANT" ] || die "checksum mismatch for paddock-agent.pyz (expected $WANT, got $GOT): not installing"
if [ -n "$EXPECT_SHA" ]; then
  lc_expect="$(printf '%s' "$EXPECT_SHA" | tr 'A-F' 'a-f')"
  [ "$GOT" = "$lc_expect" ] || die "the archive's sha256 ($GOT) is not the one you pinned with --sha256: not installing"
fi
say "   sha256 $GOT"

step "Checking the archive runs"
"$PYTHON" "$WORK/paddock-agent.pyz" --version >/dev/null 2>&1 || die "the downloaded archive does not run under $PYTHON"

step "Installing"
mkdir -p "$(P "$PREFIX/lib")"
check_dir "$PREFIX/lib" shared           # the parent too, before anything is created inside it: whoever owns it could swap the archive dir
mkdir -p "$(P "$LIB_DIR")" "$(P "$PREFIX/bin")" "$(P "$CONF_DIR_ABS")" "$(P "$UNIT_DIR_ABS")" "$(P "$STATE_DIR_ABS")"
check_dir "$LIB_DIR" strict
check_dir "$PREFIX/bin" shared
check_dir "$CONF_DIR_ABS" strict
check_dir "$UNIT_DIR_ABS" shared
check_dir "$STATE_DIR_ABS" strict
chmod 0755 "$(P "$LIB_DIR")"
rm -f "$(P "$PYZ_ABS").new"
cp "$WORK/paddock-agent.pyz" "$(P "$PYZ_ABS").new"
chmod 0755 "$(P "$PYZ_ABS").new"
mv "$(P "$PYZ_ABS").new" "$(P "$PYZ_ABS")"
say "   $(P "$PYZ_ABS")"

LINK_P="$(P "$LINK_ABS")"
if link_present && ! link_is_ours; then
  warn "not overwriting $LINK_P: it is not this agent's command (the Paddock CLI uses the same name). Run the agent with: $PYTHON $PYZ_ABS <command>"
else
  rm -f "$LINK_P.new"
  # shellcheck disable=SC2016  # the "$@" is meant to be written literally into the wrapper
  { printf '#!/bin/sh\n%s\n' "$WRAPPER_MARK"; printf 'exec %s %s "$@"\n' "'$PYTHON'" "'$PYZ_ABS'"; } >"$LINK_P.new"
  chmod 0755 "$LINK_P.new"
  mv -f "$LINK_P.new" "$LINK_P"
  say "   $LINK_P"
fi

chmod 0700 "$(P "$CONF_DIR_ABS")"
chmod 0700 "$(P "$STATE_DIR_ABS")"
# agent.env: set PADDOCK_SERVER, keep every other line (PADDOCK_CA_FILE, PADDOCK_ENABLE_IMDS, intervals, ...)
ENV_DST="$(P "$ENV_FILE_ABS")"
ENV_TMP="$ENV_DST.new"
(
  umask 077
  printf '# written by install-agent.sh; no secrets belong here\nPADDOCK_SERVER=%s\n' "$SERVER" >"$ENV_TMP"
  if [ -f "$ENV_DST" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      case "$line" in
        "# written by install-agent.sh; no secrets belong here") : ;;
        PADDOCK_SERVER=*|[[:space:]]*PADDOCK_SERVER=*) : ;;
        *) printf '%s\n' "$line" >>"$ENV_TMP" ;;
      esac
    done <"$ENV_DST"
  fi
)
mv "$ENV_TMP" "$ENV_DST"
chmod 0600 "$ENV_DST"
say "   $ENV_DST"

emit_unit "$PYTHON" "$PYZ_ABS" >"$(P "$UNIT_ABS").new"
chmod 0644 "$(P "$UNIT_ABS").new"
mv "$(P "$UNIT_ABS").new" "$(P "$UNIT_ABS")"
say "   $(P "$UNIT_ABS")"
if [ "$SYSTEMD_MANAGED" = 1 ]; then "$SYSTEMCTL" daemon-reload; fi

if [ "$enrolled" = 1 ]; then
  say "   this host is already enrolled (credentials found); keeping them (use --reenroll with a re-key token to replace)"
fi

# the archive was replaced under a possibly running agent: say so when we are not about to restart it
warn_if_still_running() {
  if "$SYSTEMCTL" is-active --quiet "$SERVICE" >/dev/null 2>&1; then
    warn "$SERVICE is still running the previous archive and unit (it was not restarted): run: systemctl restart $SERVICE"
  fi
}

if [ "$NO_ENROLL" = 0 ] && [ "$enrolled" = 0 ]; then
  step "Enrolling this host"
  # a running agent holds the state directory, and `enroll --force` refuses while it does
  if [ "$REENROLL" = 1 ] && [ "$SYSTEMD_MANAGED" = 1 ]; then "$SYSTEMCTL" stop "$SERVICE" >/dev/null 2>&1 || true; fi
  set -- enroll --token-stdin
  [ "$REENROLL" = 0 ] || set -- "$@" --force
  [ -z "$HOSTNAME_OVERRIDE" ] || set -- "$@" --hostname "$HOSTNAME_OVERRIDE"
  # printf is a shell builtin: the token is not in any process's argv. The agent reads it from stdin.
  if ! printf '%s\n' "$TOKEN" | PADDOCK_STATE_DIR="$(P "$STATE_DIR_ABS")" PADDOCK_SERVER="$SERVER" \
        "$PYTHON" "$(P "$PYZ_ABS")" "$@"; then
    TOKEN=""
    die "enrollment failed (the token may be spent, expired or revoked; mint a new one). The agent is installed but not started."
  fi
  TOKEN=""
  enrolled=1
fi

if [ "$SYSTEMD_MANAGED" = 0 ]; then
  say "staged under $ROOT: systemd was not touched"
elif [ "$NO_START" = 1 ]; then
  say "installed; not started (--no-start). Start with: systemctl enable --now $SERVICE"
  warn_if_still_running
elif [ "$enrolled" = 0 ]; then
  say "installed; not started because the host is not enrolled. Run: paddock enroll, then: systemctl enable --now $SERVICE"
  warn_if_still_running
else
  step "Starting the service"
  # restart, not `enable --now`: that leaves an already running agent on the old archive and unit
  "$SYSTEMCTL" enable "$SERVICE"
  "$SYSTEMCTL" restart "$SERVICE"
  sleep "$SETTLE_SECS"
  if ! "$SYSTEMCTL" is-active --quiet "$SERVICE"; then
    state="$("$SYSTEMCTL" is-active "$SERVICE" 2>/dev/null || true)"
    die "$SERVICE is not running after the restart (state: ${state:-unknown}); the files are installed. See: journalctl -u $SERVICE -n 50"
  fi
  say "   $SERVICE is running; check it with: systemctl status $SERVICE && paddock status"
fi
say "done."
