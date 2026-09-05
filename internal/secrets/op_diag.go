package secrets

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

// OPDiagStatus mirrors the doctor's ok/warn/error vocabulary so `gog auth
// doctor` can render 1Password checks uniformly without importing cmd.
const (
	OPDiagOK    = "ok"
	OPDiagWarn  = "warn"
	OPDiagError = "error"
)

// OPDiagEntry is one doctor check for the 1Password backend.
type OPDiagEntry struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

// OPDiagnostics produces read-only 1Password health checks for `gog auth
// doctor`. Unlike the storage backend it never creates or edits items: it
// resolves the binary, reads its version, verifies read access to the
// configured vault, and reports token/cache/timeout configuration. Diagnostics
// are safe to run even when a vault is locked or no token is configured.
func OPDiagnostics(ctx context.Context, options OpenOptions) []OPDiagEntry {
	cfg, err := resolveOnePasswordConfig(options)
	if err != nil {
		return []OPDiagEntry{{
			Name: "op.config", Status: OPDiagError, Detail: err.Error(),
			Hint: "Fix GOG_OP_* environment or config.json op_* keys",
		}}
	}

	bin, source, err := resolveOPBin(cfg.bin, exec.LookPath)
	if err != nil {
		return []OPDiagEntry{{Name: "op.bin", Status: OPDiagError, Detail: err.Error(), Hint: OPErrorHint(err)}}
	}
	cfg.bin = bin
	cfg.binSource = source
	cfg = cfg.withDefaults()

	ring := &onePasswordKeyring{cfg: cfg, cache: newOPCache(opCacheMaxEntries, opDefaultCacheTTL)}
	entries := []OPDiagEntry{
		{Name: "op.bin", Status: OPDiagOK, Detail: bin + " (source: " + source + ")"},
		{Name: "op.vault", Status: OPDiagOK, Detail: vaultLabel(cfg.vault), Hint: "Vault items are addressed by UUID inside the configured vault; use a dedicated vault for gog if WRITE access is restricted elsewhere"},
		{Name: "op.token_source", Status: OPDiagOK, Detail: tokenSourceLabel(cfg.tokenFile), Hint: "Service-account tokens are exported into the op subprocess; the token file path is never logged"},
	}

	version, versionErr := ring.runOp(ctx, "--version")
	if versionErr != nil {
		entries = append(entries, OPDiagEntry{
			Name: "op.version", Status: OPDiagError, Detail: versionErr.Error(), Hint: OPErrorHint(versionErr),
		})
	} else {
		entries = append(entries, OPDiagEntry{Name: "op.version", Status: OPDiagOK, Detail: "op " + strings.TrimSpace(firstLine(version))})
	}

	// Listing items is the read-only proof that authentication can reach the
	// configured vault. Do not use `op whoami`: it proves only CLI identity and
	// can succeed when the target vault is locked or inaccessible.
	reachabilityArgs := append([]string{"item", "list", "--format", "json"}, ring.vaultArgs()...)
	if _, reachabilityErr := ring.runOp(ctx, reachabilityArgs...); reachabilityErr != nil {
		entries = append(entries, OPDiagEntry{
			Name: "op.reachability", Status: OPDiagError, Detail: reachabilityErr.Error(), Hint: OPErrorHint(reachabilityErr),
		})
	} else {
		entries = append(entries, OPDiagEntry{
			Name: "op.reachability", Status: OPDiagOK, Detail: "vault is reachable for read access",
		})
	}

	entries = append(entries,
		OPDiagEntry{Name: "op.cache_ttl", Status: OPDiagOK, Detail: cfg.cacheTTL.String() + " in-process TTL", Hint: "Short-lived gog invocations reuse op reads within the TTL so service-account rate limits are not hit on every call"},
		OPDiagEntry{Name: "op.timeout", Status: OPDiagOK, Detail: cfg.timeout.String() + " per-command timeout"},
		OPDiagEntry{Name: "op.rate_limits", Status: OPDiagOK, Detail: "service-account tokens: ~1000 reads + 100 writes/hour, 1000 requests/day", Hint: "gog persists refreshed refresh tokens on every token refresh; budget writes for scheduled syncs"},
	)

	return entries
}

// OPErrorHint extracts the actionable hint from a classified op error, if any.
func OPErrorHint(err error) string {
	var opErr *opError
	if errors.As(err, &opErr) {
		return opErr.Hint
	}

	return ""
}

func vaultLabel(vault string) string {
	if strings.TrimSpace(vault) == "" {
		return "(1Password default vault)"
	}

	return "op --vault " + vault
}

func tokenSourceLabel(tokenFile string) string {
	if strings.TrimSpace(tokenFile) == "" {
		return "op's own auth (desktop app / op signin)"
	}

	// Keep the configured path private: it can disclose filesystem layout and
	// is not needed to explain how op authentication is being supplied.
	return "OP_SERVICE_ACCOUNT_TOKEN from configured token file"
}
