#!/usr/bin/env bash
#
# fake-op.sh — a 1Password CLI (op) stand-in for gog tests.
#
# It implements the subset of the op CLI that the 1Password keyring backend
# and `gog auth doctor` use, storing items as one JSON file per item under
# GOG_FAKE_OP_STATE_DIR:
#
#   <state>/fake_<base64url(title)>.json
#
# answering in the same on-the-wire format the real op CLI uses, so the Go
# backend sees genuine payloads. Failure behaviour is driven by
# GOG_FAKE_OP_MODE ("an op that can also fail"):
#
#   locked       vault is locked                 -> locked
#   ratelimited  429 too many requests           -> rate_limited
#   permission   permission denied               -> permission
#   notsignedin  not currently signed in         -> not_signed_in
#   notfound     no item matching                -> not_found
#   generic      something went wrong            -> generic
#   timeout      (sleeps then exits late)        -> timeout
#
# Commands (matching the Go backend's exact argv):
#   op --version
#   op whoami [--format json]
#   op item list [--format json]
#   op item get <uuid> --format json [--reveal]
#   op item create [--vault <v>] - --format json       (JSON template on stdin)
#   op item edit <uuid> [--vault <v>] --format json    (JSON template on stdin)
#   op item delete <uuid>
#
# POSIX-ish bash only; tests skip on hosts without bash.

set -euo pipefail

STATE_DIR="${GOG_FAKE_OP_STATE_DIR:-}"
MODE="${GOG_FAKE_OP_MODE:-}"

# --- helpers ---------------------------------------------------------------

b64url() { printf '%s' "$1" | base64 | tr -d '\n' | tr '/+' '_-' | tr -d '='; }

json_escape() {
  s="$1"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

op_error() {
  printf '[ERROR] 2026/01/02 15:04:05 %s\n' "$2" >&2
  exit 1
}

# fail exits with a realistic op error of the configured class.
fail() {
  [[ -z "$MODE" || "$MODE" == "none" || "$MODE" == "validate-template-field-ids" || "$MODE" == "validate-api-credential-template" || "$MODE" == "validate-edit-preserves-schema" ]] && return 0
  case "$MODE" in
    locked)      op_error locked      "1Password vault is locked; run 'op unlock' to unlock your vault" ;;
    ratelimited) op_error ratelimited "429 Too Many Requests: rate limit exceeded for this service account token" ;;
    permission)  op_error permission  "permission denied: service account does not have permission to access this vault" ;;
    notsignedin) op_error notsignedin "not currently signed in. Please run 'op signin' first." ;;
    notfound)    op_error notfound    "no item matching query" ;;
    timeout)     sleep 1; printf '[ERROR] 2026/01/02 15:04:05 timeout\n' >&2; exit 124 ;;
    generic)     op_error generic    "something went wrong while we tried to process your request" ;;
    *)           op_error generic    "unknown fake mode: $MODE" ;;
  esac
}

ensure_state_dir() { [[ -d "$STATE_DIR" ]] || mkdir -p "$STATE_DIR"; }

require_vault() {
  [[ "${GOG_FAKE_OP_REQUIRE_VAULT:-}" == "1" ]] || return 0
  for a in "${@:3}"; do
    [[ "$a" == "--vault" ]] && return 0
  done
  op_error permission "vault must be explicitly selected"
}

item_files() { find "$STATE_DIR" -maxdepth 1 -name 'fake_*.json' -type f 2>/dev/null || true; }

uuid_of() { grep -o '"id":"[^"]*"' "$1" | head -n1 | cut -d'"' -f4; }
title_of() { grep -o '"title":"[^"]*"' "$1" | head -n1 | cut -d'"' -f4; }
vault_of() { grep -o '"name":"[^"]*"' "$1" | head -n1 | cut -d'"' -f4; }

template_field() {
  node -e '
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => { input += chunk; });
    process.stdin.on("end", () => {
      const item = JSON.parse(input);
      const field = process.argv[1];
      if (field === "title") process.stdout.write(item.title || "");
      else process.stdout.write((item.fields || []).find(f => f.id === field || f.label === field)?.value || "");
    });
  ' "$1"
}

template_has_blank_field_id() {
  node -e '
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => { input += chunk; });
    process.stdin.on("end", () => {
      const item = JSON.parse(input);
      process.exit((item.fields || []).some(f => !f.id) ? 0 : 1);
    });
  '
}

template_is_api_credential() {
  node -e '
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => { input += chunk; });
    process.stdin.on("end", () => {
      const fields = new Map((JSON.parse(input).fields || []).map(f => [f.id, f]));
      process.exit(fields.has("notesPlain") && fields.has("credential") && fields.get("notesPlain").value === "gog_keyring=1" ? 0 : 1);
    });
  '
}

template_preserves_api_credential_schema() {
  node -e '
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => { input += chunk; });
    process.stdin.on("end", () => {
      const item = JSON.parse(input);
      const fields = new Map((item.fields || []).map(f => [f.id, f]));
      const credential = fields.get("credential");
      process.exit(
        item.category === "API_CREDENTIAL" &&
        Array.isArray(item.sections) &&
        item.sections.some(s => s.id === "metadata") &&
        credential?.purpose === "PASSWORD" &&
        fields.has("notesPlain") && fields.has("username") && fields.has("type")
          ? 0
          : 1,
      );
    });
  '
}

# emit_item prints the item JSON for id/title/vault/credential.
emit_item() {
  printf '{"id":"%s","category":"API_CREDENTIAL","title":"%s","vault":{"id":"fakevault","name":"%s"},"fields":[' \
    "$1" "$(json_escape "$2")" "$(json_escape "$3")"
  printf '{"id":"credential","label":"credential","purpose":"PASSWORD","type":"CONCEALED","value":"%s"},' "$(json_escape "$4")"
  printf '{"id":"gog_keyring","label":"gog_keyring","type":"TEXT","value":"1"}'
  printf ']}'
}

# find_item_by_uuid prints the item file whose "id" equals UUID, exits 1 if none.
find_item_by_uuid() {
  uuid="$1"
  f=""
  for f in $(item_files); do
    if grep -q "\"id\":\"$uuid\"" "$f"; then printf '%s' "$f"; return 0; fi
  done
  return 1
}

is_uuidish() { [[ "$1" =~ ^[a-zA-Z0-9_-]{8,}$ ]]; }

# --- commands --------------------------------------------------------------

case "$1" in
  --version)
    printf '2.30.0\n'
    exit 0
    ;;
  whoami)
    fail
    printf '{"url":"my.1password.com","email":"fake@gog.test","user_uuid":"FAKEUSER","account_uuid":"FAKEACCT","account":{"id":"FAKEACCT","name":"Fake","domain":"my.1password.com"}}\n'
    exit 0
    ;;
esac

if [[ "${1:-}" == "item" && "${2:-}" == "template" && "${3:-}" == "get" ]]; then
  printf '%s\n' '{"category":"API_CREDENTIAL","fields":[{"id":"notesPlain","label":"notesPlain","type":"STRING","value":""},{"id":"username","label":"username","type":"STRING","value":""},{"id":"credential","label":"credential","type":"CONCEALED","value":""},{"id":"type","label":"type","type":"MENU","value":""}]}'
  exit 0
fi

item_sub="${2:-}"

if [[ "${1:-}" == "item" && -z "$item_sub" ]]; then
  op_error generic "op item requires a subcommand"
fi

if [[ "${1:-}" == "item" && "$item_sub" == "list" ]]; then
  fail
  require_vault "$@"
  out='['
  first=1
  f=""
  for f in $(item_files); do
    title=$(title_of "$f")
    id=$(uuid_of "$f")
    [[ -n "$title" && -n "$id" ]] || continue
    if (( first )); then first=0; else out+=','; fi
    out+="{\"id\":\"$id\",\"title\":\"$(json_escape "$title")\",\"vault\":{\"id\":\"fakevault\",\"name\":\"Private\"}}"
  done
  printf '%s]\n' "$out"
  exit 0
fi

if [[ "${1:-}" == "item" && "$item_sub" == "get" ]]; then
  fail
  require_vault "$@"
  ref="${3:-}"
  is_uuidish "$ref" || op_error generic "op item get requires a UUID"
  target=""
  if target=$(find_item_by_uuid "$ref"); then
    cat "$target"
    exit 0
  fi
  op_error notfound "no item matching UUID $ref"
fi

if [[ "${1:-}" == "item" && "$item_sub" == "create" ]]; then
  fail
  require_vault "$@"
  title="" vault="" credval="" prev=""
  for a in "${@:3}"; do
    case "$a" in
      --title|--vault|--category|--format) prev="$a" ;;
      --field) op_error generic "unknown flag: --field" ;;
      *)
        if [[ "$prev" == "--title" ]]; then title="$a"; prev=""
        elif [[ "$prev" == "--vault" ]]; then vault="$a"; prev=""
        elif [[ "$a" == "-" ]]; then
          template=$(cat)
          if [[ "$MODE" == "validate-template-field-ids" ]] && printf '%s' "$template" | template_has_blank_field_id; then
            op_error generic "Validation: fields have non-unique name"
          fi
          if [[ "$MODE" == "validate-api-credential-template" ]] && ! printf '%s' "$template" | template_is_api_credential; then
            op_error generic "Validation: API Credential template must retain built-in fields"
          fi
          title=$(printf '%s' "$template" | template_field title)
          credval=$(printf '%s' "$template" | template_field credential)
        elif [[ "$a" == *=* ]]; then
          k="${a%%=*}"
          v="${a#*=}"
          [[ "$k" == "credential" ]] && credval="$v"
        fi
        ;;
    esac
  done
  [[ -n "$title" ]] || op_error generic "op item create requires --title"
  id="fake_$(b64url "$title")"
  name="${vault:-Private}"
  ensure_state_dir
  emit_item "$id" "$title" "$name" "$credval" > "$STATE_DIR/$id.json"
  emit_item "$id" "$title" "$name" "$credval"
  printf '\n'
  exit 0
fi

if [[ "${1:-}" == "item" && "$item_sub" == "edit" ]]; then
  fail
  require_vault "$@"
  ref="${3:-}"
  is_uuidish "$ref" || op_error generic "op item edit requires a UUID"
  target=""
  if ! target=$(find_item_by_uuid "$ref"); then
    op_error notfound "no item matching UUID $ref"
  fi
  newval="" prev=""
  for a in "${@:4}"; do
    case "$a" in
      --field) op_error generic "unknown flag: --field" ;;
      *) if [[ "$a" == "-" ]]; then
           template=$(cat)
           if [[ "$MODE" == "validate-edit-preserves-schema" ]] && ! printf '%s' "$template" | template_preserves_api_credential_schema; then
             op_error generic "Validation: API Credential edit must preserve the complete item schema"
           fi
           newval=$(printf '%s' "$template" | template_field credential)
         elif [[ "$a" == *=* ]]; then
           k="${a%%=*}"
           v="${a#*=}"
           [[ "$k" == "credential" ]] && newval="$v"
         fi
         ;;
    esac
  done
  id=$(uuid_of "$target")
  title=$(title_of "$target")
  name=$(vault_of "$target")
  emit_item "$id" "$title" "$name" "$newval" > "$STATE_DIR/$id.json"
  emit_item "$id" "$title" "$name" "$newval"
  printf '\n'
  exit 0
fi

if [[ "${1:-}" == "item" && "$item_sub" == "delete" ]]; then
  fail
  require_vault "$@"
  uuid="${3:-}"
  is_uuidish "$uuid" || op_error generic "op item delete requires a UUID"
  target=""
  if target=$(find_item_by_uuid "$uuid"); then
    rm -f "$target"
    printf '[SUCCESS] removed item with UUID %s\n' "$uuid"
    exit 0
  fi
  op_error notfound "no item matching UUID $uuid"
fi

op_error generic "unhandled fake-op command: $*"
