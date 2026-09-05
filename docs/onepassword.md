---
title: 1Password keyring backend
description: "Store gog refresh tokens in a 1Password vault via the op CLI instead of the OS keychain."
---

# 1Password keyring backend

gog can store its auth tokens and secrets in a [1Password](https://1password.com/)
vault instead of the OS keychain or an encrypted file. The backend shells out to
the official `op` CLI (version 2, `op item list/get/create/edit/delete`) so it
needs no SDK and no Go module dependency. Use it when you already centralize
secrets in 1Password and want gog's refresh tokens alongside them.

## Enable

```bash
gog auth keyring onepassword
```

`gog auth keyring` with no argument prints the current backend, source, and
config path. The backend is stored as `keyring_backend: "onepassword"` in
`config.json`. See [`gog auth keyring`](commands/gog-auth-keyring.md) and the
`keyring_backend` example in [`auth-clients.md`](auth-clients.md#config-example)
for the other backends (`auto`, `keychain`, `file`).

## Requirements

- The `op` CLI must be installed and able to reach a vault. gog supports both
  desktop-backed sessions and service-account tokens (below).
- For writes, the service account or signed-in user needs **write** permission
  on the target vault. Prefer a dedicated vault for gog so the items are
  auditable as a group.
- Service accounts are rate-limited (below); keep the token file mode
  `0600` and store it outside the repo.

## Storage schema

gog stores each keyring entry as a single **API Credential** item, one item per
token, in the vault named by `op_vault` (default: 1Password's own default
vault):

- **Item title** is the gog keyring key, e.g. `token:default:user@example.com`,
  `token-sub:work:0123456789`, `default_account:work`, or
  `tracking/user@example.com/tracking_key`.
- **Field** `credential` (`CONCEALED`) holds the stored bytes verbatim.
- **Field** `gog_keyring` = `1` is a schema marker so gog items are identifiable
  in the 1Password UI.
- **Reference** form: `op://<vault>/<item>/credential`.

The keyring key namespace maps 1:1 onto gog's flat keyring keys, mirroring the
keychain/file backends, so every token is independently revocable and auditable.
Items are addressed by their 1Password **UUID**, not their title: gog keeps a
per-run mapping from `op item list`, so a lookup costs one `op item get` read
instead of the multi-read fuzzy title search `op` performs for names. Titles are
human-readable gog keys; the UUID is only the addressing key.

## Configuration

Every `GOG_OP_*` variable is optional; unset/empty values fall back to
`config.json`, then to sane defaults. Env wins over config, matching the keyring
backend and password resolution order.

| Setting | Env variable | config.json key | Default |
| --- | --- | --- | --- |
| op binary | `GOG_OP_BIN` | `op_bin` | resolved on `PATH` |
| target vault | `GOG_OP_VAULT` | `op_vault` | 1Password default vault |
| service-account token file | `GOG_OP_TOKEN_FILE` | `op_token_file` | none (desktop auth) |
| in-process cache TTL | `GOG_OP_CACHE_TTL` | — | `30s` |
| per-command timeout | `GOG_OP_TIMEOUT` | — | `30s` |

A configured `GOG_OP_BIN`/`op_bin` is pinned verbatim, including an absolute
path that is not on `PATH` (mirroring OpenClaw's binary-pinning model); shipped
values without a path separator are resolved with `exec.LookPath`.

### OpenClaw gateway-launched processes

An OpenClaw gateway launch agent may not read the interactive shell's
environment. Configure the token **file path** in gog's persisted
`config.json` so gateway-launched and interactive `gog` use the same backend:

```json
{
  "keyring_backend": "onepassword",
  "op_vault": "OpenClaw",
  "op_token_file": "/path/to/service-account-token"
}
```

The path must be readable by the gateway user and the file should be mode
`0600`. Do not put the token value in gog or OpenClaw configuration. gog reads
the file when it invokes `op` and injects the value only into that child
process; the gateway and its other children do not receive
`OP_SERVICE_ACCOUNT_TOKEN`.

`GOG_OP_TOKEN_FILE` is an intentional process-environment override for a
managed service deployment. It takes precedence over `op_token_file`, but the
OpenClaw Gmail integration does not configure it itself. Do **not** edit
OpenClaw-generated files such as `ai.openclaw.gateway.env`; configure gog or a
user-owned service wrapper instead.

## Service accounts

When `GOG_OP_TOKEN_FILE` (or `op_token_file`) points at a token file, gog reads
the token and exports its contents to each `op` subprocess as
`OP_SERVICE_ACCOUNT_TOKEN`. The file path is never logged. For this
service-account mode, gog also sets these child-process isolation flags:

| Child-only variable | Value | Purpose |
| --- | --- | --- |
| `OP_LOAD_DESKTOP_APP_SETTINGS` | `false` | OpenClaw-documented compatibility workaround: do not load desktop-app settings |
| `OP_BIOMETRIC_UNLOCK_ENABLED` | `false` | Do not attempt biometric unlock |

These variables (including `OP_SERVICE_ACCOUNT_TOKEN`) are applied only to the
spawned `op` process. They do not modify the environment of the gog process,
OpenClaw gateway, or the parent shell. The token value and token-file contents
are never written to logs or command-line arguments. `op` accepts the token
value through `OP_SERVICE_ACCOUNT_TOKEN`; `op_token_file` is gog configuration
that supplies that value and is not passed to `op` as a path.

`OP_LOAD_DESKTOP_APP_SETTINGS` is not documented in 1Password's public CLI
environment-variable reference. gog uses it because OpenClaw documents it for
service-account isolation and it avoids desktop-integration initialization in
that environment.

Without a token file, gog does not set any of these variables and relies on
`op`'s own auth (the desktop app or an interactive `op signin`) as configured
separately.

Service-account rate limits are roughly **1000 reads + 100 writes per hour** and
**1000 requests/day**. gog mitigates this with a bounded in-process cache: reads
within the cache TTL (default `30s`) cost no `op` call, and writes refresh the
affected cache entries so the verified refresh-token path stays consistent.

## Write-path cost

| Operation | `op` calls (cold) | with cache |
| --- | --- | --- |
| `Auth.Open` (keyring open) | 0 | 0 |
| `Get` once per key | 2 (`item list` + `item get`) | 0 within TTL |
| `Get` (UUID already known) | 1 | 0 |
| `Keys` / list | 1 | 0 within TTL |
| `Set` new key | 2 (`item list` + `item create`) | 1 on repeat |
| `Set` existing key | 1 (`item edit`) | 0 |
| `Remove` | 1-2 | 1 |

## Diagnostics

`gog auth doctor` includes read-only 1Password checks. They resolve the binary,
read its version, verify sign-in via `op whoami`, and report vault, token
source, cache TTL, timeout, and rate-limit posture — without creating or editing
items, so they are safe to run even when a vault is locked or no token is
configured. See [`gog auth doctor`](commands/gog-auth-doctor.md).

Diagnostics surfaced to stderr include `op.bin`, `op.vault`, `op.token_source`,
`op.version`, `op.signed_in`, `op.cache_ttl`, `op.timeout`, and `op.rate_limits`
entries when `--json` is used.

## Troubleshooting

- **Vault locked** — gog surfaces the `locked` class and a hint to unlock the
  1Password desktop app (or run `op signin`).
- **Not signed in** — `not_signed_in`; run `op signin` or configure a service
  account token file.
- **Rate limited** — `rate_limited`; wait for the hourly bucket. The cache
  defaults are tuned to avoid tripping this for scheduled syncs.
- **Permission denied** — `permission`; grant the service account/user write
  access to the vault, or dedicate a vault to gog.
- **No items** — missing keys map to `keyring.ErrKeyNotFound`, so
  `gog auth status` and token removal behave like the keychain/file backends.
