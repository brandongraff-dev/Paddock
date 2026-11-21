#!/bin/sh
# Paddock one-line installer (single-node "lite" stack).
#
#   curl -fsSL https://raw.githubusercontent.com/brandongraff-dev/cybersec/main/scripts/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --dir /srv/paddock --active
#
# What it does: checks Docker, downloads Paddock, generates strong secrets into
# .env (never overwriting ones you already have), starts the lite stack, waits
# until it is healthy and prints the URL and the admin credentials.
#
# Safe to re-run: existing .env values, containers and data are kept.
# Needs no root unless your Docker setup does (it never escalates itself).
#
# Options:
#   --dir DIR        install directory            (default: $HOME/paddock, or $PADDOCK_HOME)
#   --ref REF        git branch or tag to install (default: main, or $PADDOCK_REF)
#   --repo OWNER/R   GitHub repository            (default: brandongraff-dev/cybersec, or $PADDOCK_REPO)
#   --active         also start the active worker (polite HTTP/TLS/port probing)
#   --upgrade        re-download the sources even if the directory already has them
#   --no-start       prepare files and secrets, do not start containers
#   --wait SECONDS   how long to wait for health (default 300)
#   --dry-run        print what would happen; change nothing, no network
#   --uninstall      stop and remove the containers (data volume and .env are kept)
#   --purge          with --uninstall: also delete the data volume and the install directory
#   --yes            do not ask for confirmation (required for --purge without a terminal)
#   -h, --help       this text
#
# Environment for testing / air-gapped use: PADDOCK_SRC_DIR (copy sources from a
# local directory instead of downloading), PADDOCK_API_URL, PADDOCK_UI_URL,
# PADDOCK_SHA256 (pin the downloaded tarball).
set -eu

REPO="${PADDOCK_REPO:-brandongraff-dev/cybersec}"
REF="${PADDOCK_REF:-main}"
DIR="${PADDOCK_HOME:-${HOME:-.}/paddock}"
API_URL="${PADDOCK_API_URL:-http://127.0.0.1:8080}"
UI_URL="${PADDOCK_UI_URL:-http://localhost:3000}"
WAIT=300
ACTIVE=0
UPGRADE=0
NO_START=0
DRY_RUN=0
UNINSTALL=0
PURGE=0
YES=0

COMPOSE_FILE=docker-compose.lite.yml
OVERRIDE_FILE=docker-compose.install.yml
PROJECT=paddock-lite

if [ -t 1 ]; then B='\033[1m'; G='\033[32m'; Y='\033[33m'; R='\033[31m'; N='\033[0m'; else B=''; G=''; Y=''; R=''; N=''; fi
say()  { printf '%b\n' "$*"; }
step() { say "${B}==>${N} $*"; }
warn() { say "${Y}warning:${N} $*" >&2; }
die()  { say "${R}error:${N} $*" >&2; exit 1; }
plan() { say "[dry-run] $*"; }

usage() {
  if [ -f "$0" ]; then
    sed -n '2,/^set -eu/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
  else
    say "see the header of scripts/install.sh for the options (--dir --ref --active --upgrade --no-start --wait --dry-run --uninstall --purge --yes)"
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dir)       [ $# -ge 2 ] || die "--dir needs a value";  DIR="$2"; shift ;;
    --ref)       [ $# -ge 2 ] || die "--ref needs a value";  REF="$2"; shift ;;
    --repo)      [ $# -ge 2 ] || die "--repo needs a value"; REPO="$2"; shift ;;
    --wait)      [ $# -ge 2 ] || die "--wait needs a value"; WAIT="$2"; shift ;;
    --active)    ACTIVE=1 ;;
    --upgrade)   UPGRADE=1 ;;
    --no-start)  NO_START=1 ;;
    --dry-run)   DRY_RUN=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --purge)     PURGE=1 ;;
    --yes|-y)    YES=1 ;;
    -h|--help)   usage; exit 0 ;;
    *)           die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

case "$WAIT" in ''|*[!0-9]*) die "--wait must be a number of seconds" ;; esac
case "$REPO" in */*) : ;; *) die "--repo must look like OWNER/NAME" ;; esac
case "$REPO$REF" in *[!A-Za-z0-9._/-]*) die "--repo/--ref contain unexpected characters" ;; esac
[ "$PURGE" = 0 ] || [ "$UNINSTALL" = 1 ] || die "--purge only makes sense with --uninstall"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# 24 alphanumeric characters (safe in URLs, shells and compose files).
rand_pw() {
  LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-24}"
}

# 32 random bytes as urlsafe base64 (the format PADDOCK_SECRET_KEY expects).
rand_key() {
  if have openssl; then
    openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'
  else
    head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '\n'
  fi
}

env_get() { # env_get KEY  -> value from $DIR/.env (empty if unset)
  [ -f "$DIR/.env" ] || return 0
  sed -n "s/^$1=//p" "$DIR/.env" | tail -n 1
}

# env_ensure KEY GENERATOR: set KEY only when it is missing, empty or still the
# placeholder from .env.example. An existing real value is never touched.
env_ensure() {
  cur="$(env_get "$1")"
  case "$cur" in
    ''|change-me*)
      val="$($2)"
      if grep -q "^$1=" "$DIR/.env" 2>/dev/null; then
        # rewrite in place without sed (values may contain / & etc.)
        awk -v k="$1" -v v="$val" 'BEGIN{FS=OFS="="} $1==k{print k"="v; next} {print}' \
          "$DIR/.env" >"$DIR/.env.tmp" && mv "$DIR/.env.tmp" "$DIR/.env" && chmod 600 "$DIR/.env"
      else
        printf '%s=%s\n' "$1" "$val" >>"$DIR/.env"
      fi
      say "   generated $1"
      ;;
    *) say "   kept existing $1" ;;
  esac
}

compose() {
  if [ "$ACTIVE" = 1 ]; then
    docker compose -p "$PROJECT" --project-directory "$DIR" -f "$DIR/$COMPOSE_FILE" -f "$DIR/$OVERRIDE_FILE" \
      --profile active "$@"
  else
    docker compose -p "$PROJECT" --project-directory "$DIR" -f "$DIR/$COMPOSE_FILE" -f "$DIR/$OVERRIDE_FILE" \
      "$@"
  fi
}

looks_like_install() { [ -f "$DIR/$COMPOSE_FILE" ]; }

check_docker() {
  have docker || die "Docker is not installed. Install Docker Engine or Docker Desktop first: https://docs.docker.com/get-docker/"
  docker compose version >/dev/null 2>&1 || die "'docker compose' (Compose v2) is required: https://docs.docker.com/compose/install/"
  if ! docker info >/dev/null 2>&1; then
    die "cannot talk to the Docker daemon. Start Docker, or add your user to the 'docker' group (or re-run this installer with sudo)."
  fi
  say "   docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo ok), compose ok"
}

fetch_sources() {
  if [ -n "${PADDOCK_SRC_DIR:-}" ]; then
    [ -f "$PADDOCK_SRC_DIR/$COMPOSE_FILE" ] || die "PADDOCK_SRC_DIR has no $COMPOSE_FILE"
    mkdir -p "$DIR"
    cp -R "$PADDOCK_SRC_DIR"/. "$DIR"/
    return
  fi
  have curl || die "curl is required to download Paddock"
  have tar  || die "tar is required"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT INT TERM
  url="https://codeload.github.com/$REPO/tar.gz/$REF"
  say "   downloading $url"
  curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$tmp/src.tgz" "$url" || die "download failed: $url"
  if [ -n "${PADDOCK_SHA256:-}" ]; then
    got="$( (sha256sum "$tmp/src.tgz" 2>/dev/null || shasum -a 256 "$tmp/src.tgz") | awk '{print $1}')"
    [ "$got" = "$PADDOCK_SHA256" ] || die "checksum mismatch (expected $PADDOCK_SHA256, got $got)"
  fi
  mkdir -p "$tmp/x" "$DIR"
  tar -xzf "$tmp/src.tgz" -C "$tmp/x" --strip-components=1
  [ -f "$tmp/x/$COMPOSE_FILE" ] || die "the download does not contain $COMPOSE_FILE (wrong --repo/--ref?)"
  cp -R "$tmp/x"/. "$DIR"/
}

write_override() {
  # Wires the secrets the lite compose file does not pass through by itself.
  cat >"$DIR/$OVERRIDE_FILE" <<'YAML'
# Written by scripts/install.sh. Passes the generated secrets to the orchestrator.
services:
  orchestrator:
    environment:
      JWT_SECRET: ${JWT_SECRET:?run scripts/install.sh to generate secrets}
      PADDOCK_SECRET_KEY: ${PADDOCK_SECRET_KEY:?run scripts/install.sh to generate secrets}
      AUDIT_HMAC_KEY: ${AUDIT_HMAC_KEY:?run scripts/install.sh to generate secrets}
YAML
}

wait_healthy() {
  have curl || { warn "curl not found; skipping the health wait"; return 0; }
  step "waiting for Paddock to become healthy (up to ${WAIT}s)"
  i=0
  while [ "$i" -lt "$WAIT" ]; do
    if curl -fsS --max-time 3 "$API_URL/healthz" >/dev/null 2>&1 \
       && curl -fsS --max-time 3 -o /dev/null "$UI_URL/" 2>/dev/null; then
      say "   healthy after ${i}s"
      return 0
    fi
    i=$((i + 3))
    sleep 3
  done
  warn "not healthy after ${WAIT}s. Inspect with: docker compose -p $PROJECT -f $DIR/$COMPOSE_FILE logs --tail=100"
  return 1
}

# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
  step "uninstalling Paddock from $DIR"
  if [ "$DRY_RUN" = 1 ]; then
    if [ "$PURGE" = 1 ]; then
      plan "docker compose -p $PROJECT down -v (deletes the database volume)"
      plan "rm -rf $DIR (after confirmation)"
    else
      plan "docker compose -p $PROJECT down (keeps the data volume and $DIR/.env)"
    fi
    exit 0
  fi
  looks_like_install || die "$DIR does not look like a Paddock install (no $COMPOSE_FILE); nothing done"
  have docker || die "docker not found"
  [ -f "$DIR/$OVERRIDE_FILE" ] || write_override
  if [ ! -f "$DIR/.env" ]; then      # compose still interpolates required vars on `down`
    for k in POSTGRES_PASSWORD JWT_SECRET PADDOCK_SECRET_KEY AUDIT_HMAC_KEY; do export "$k=unused"; done
  fi
  if [ "$PURGE" = 1 ]; then
    if [ "$YES" = 0 ]; then
      ( : </dev/tty ) 2>/dev/null || die "--purge deletes ALL Paddock data; re-run with --yes to confirm"
      printf 'This permanently deletes the Paddock database volume and %s. Type "delete" to continue: ' "$DIR" >/dev/tty
      read -r ans </dev/tty
      [ "$ans" = "delete" ] || die "aborted"
    fi
    compose down -v --remove-orphans || true
    case "$DIR" in ''|/|"${HOME:-/nonexistent}") die "refusing to delete '$DIR'" ;; esac
    rm -rf "$DIR"
    say "${G}removed${N} containers, data volume and $DIR"
  else
    compose down --remove-orphans || true
    say "${G}stopped${N}. Data volume and $DIR/.env are kept; re-run the installer to start again."
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# install / re-run
# ---------------------------------------------------------------------------
step "checking prerequisites"
if [ "$DRY_RUN" = 1 ]; then
  plan "check: docker, 'docker compose' v2, reachable daemon, curl, tar"
else
  check_docker
fi

step "installing into $DIR"
if [ "$DRY_RUN" = 1 ]; then
  if [ -f "$DIR/$COMPOSE_FILE" ] && [ "$UPGRADE" = 0 ]; then
    plan "sources already present in $DIR: keep them (use --upgrade to refresh)"
  elif [ -n "${PADDOCK_SRC_DIR:-}" ]; then
    plan "copy sources from $PADDOCK_SRC_DIR to $DIR"
  else
    plan "download https://codeload.github.com/$REPO/tar.gz/$REF and unpack into $DIR"
  fi
  plan "create $DIR/.env from .env.example (mode 600) if missing"
  for k in POSTGRES_PASSWORD PADDOCK_APP_DB_PASSWORD ADMIN_BOOTSTRAP_PASSWORD SERVICE_API_KEY JWT_SECRET PADDOCK_SECRET_KEY AUDIT_HMAC_KEY; do
    plan "generate $k only if it is not already set"
  done
  plan "write $DIR/$OVERRIDE_FILE (passes JWT_SECRET, PADDOCK_SECRET_KEY, AUDIT_HMAC_KEY to the orchestrator)"
  if [ "$NO_START" = 1 ]; then
    plan "(--no-start) stop here"
  else
    if [ "$ACTIVE" = 1 ]; then prof=" --profile active"; else prof=""; fi
    plan "docker compose -p $PROJECT -f $COMPOSE_FILE -f $OVERRIDE_FILE$prof up -d --build"
    plan "wait for $API_URL/healthz and $UI_URL/ (up to ${WAIT}s)"
    plan "print the URL and the admin credentials"
  fi
  exit 0
fi

if looks_like_install && [ "$UPGRADE" = 0 ]; then
  say "   sources already present (use --upgrade to refresh them)"
else
  fetch_sources
fi
looks_like_install || die "$DIR has no $COMPOSE_FILE after install"

# A database volume without its .env means the old passwords are lost: Postgres
# would keep the old one and the stack could never connect.
if [ ! -f "$DIR/.env" ] && have docker \
   && docker volume ls -q 2>/dev/null | grep -qx "${PROJECT}_pg_data"; then
  die "a Paddock database volume exists but $DIR/.env is missing, so its passwords are unknown. Restore the .env, or remove the old data with: sh install.sh --uninstall --purge --dir $DIR"
fi

step "generating secrets (existing values are never overwritten)"
if [ ! -f "$DIR/.env" ]; then
  if [ -f "$DIR/.env.example" ]; then cp "$DIR/.env.example" "$DIR/.env"; else : >"$DIR/.env"; fi
fi
chmod 600 "$DIR/.env"
env_ensure POSTGRES_PASSWORD rand_pw
env_ensure PADDOCK_APP_DB_PASSWORD rand_pw
env_ensure ADMIN_BOOTSTRAP_PASSWORD rand_pw
env_ensure SERVICE_API_KEY rand_key
env_ensure JWT_SECRET rand_key
env_ensure PADDOCK_SECRET_KEY rand_key
env_ensure AUDIT_HMAC_KEY rand_key
write_override

if [ "$NO_START" = 1 ]; then
  say "${G}prepared${N} $DIR (not started). Start with:"
  say "   cd $DIR && docker compose -p $PROJECT -f $COMPOSE_FILE -f $OVERRIDE_FILE up -d --build"
  exit 0
fi

step "starting Paddock (first run builds the images; this can take several minutes)"
compose up -d --build

healthy=0
wait_healthy && healthy=1

ADMIN_PW="$(env_get ADMIN_BOOTSTRAP_PASSWORD)"
say ""
if [ "$healthy" = 1 ]; then say "${G}${B}Paddock is running.${N}"; else say "${Y}${B}Paddock started but is not healthy yet.${N}"; fi
say ""
say "   URL:       $UI_URL"
say "   Username:  admin"
say "   Password:  $ADMIN_PW"
say ""
say "   The password is stored in $DIR/.env (ADMIN_BOOTSTRAP_PASSWORD). After you sign in, the"
say "   first-run wizard (/setup) walks you through adding a domain and a first scan."
say "   Connect your tools:  Integrations > Connect anything  (docs/CONNECT.md)"
say "   Stop:      sh install.sh --uninstall --dir $DIR"
say "   Upgrade:   sh install.sh --upgrade --dir $DIR"
[ "$healthy" = 1 ] || exit 1
