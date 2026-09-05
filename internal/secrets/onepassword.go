package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/99designs/keyring"

	"github.com/openclaw/gogcli/internal/config"
)

const (
	// KeyringBackendOnePassword is the sole accepted keyring_backend value
	// (GOG_KEYRING_BACKEND / keyring_backend) that routes gog's secret storage
	// through the op CLI. Only this and the other normal keyring backend names
	// are valid; see docs/onepassword.md.
	KeyringBackendOnePassword = "onepassword"
)

// op CLI environment and option names. GOG_OP_* mirrors the options used by
// the OpenClaw gateway when it spawns gog (see docs/onepassword.md).
const (
	opBinEnv        = "GOG_OP_BIN"
	opVaultEnv      = "GOG_OP_VAULT"
	opTokenFileEnv  = "GOG_OP_TOKEN_FILE" //nolint:gosec // G101: env var name, not a credential
	opCacheTTLEnv   = "GOG_OP_CACHE_TTL"
	opTimeoutEnv    = "GOG_OP_TIMEOUT"
	opBinSourceEnv  = "env"
	opBinSourceCfg  = "config"
	opBinSourcePath = "path"
	opBinSourceHard = "internal"
)

const (
	// opDefaultTimeout bounds every op subprocess. The op CLI can block while
	// waiting on a desktop unlock prompt, and gog must not hang on it.
	opDefaultTimeout = 30 * time.Second
	// opDefaultCacheTTL is how long in-process uuid/lookup/value entries are
	// reused before gog goes back to 1Password. Service accounts are
	// rate-limited, so short-lived gog invocations should not re-read the same
	// item on every call.
	opDefaultCacheTTL = 30 * time.Second
	// opCacheMaxEntries bounds the number of cached items to protect against
	// unbounded growth in long-lived gog processes.
	opCacheMaxEntries = 256
)

// Storage schema (onePasswordKeyring):
//
// gog stores each keyring entry as a single 1Password API Credential item, one
// item per token, inside the vault named by op_vault (default: 1Password's own
// default vault):
//
//	item title  = the gog keyring key (e.g. "token:default:user@example.com",
//	              "token-sub:work:0123456789", "default_account:work",
//	              "tracking/user@example.com/tracking_key")
//	field       = "credential" (CONCEALED) holds the stored bytes verbatim
//	field       = "gog_keyring" = "1" (schema marker so items are auditable)
//	reference   = op://<vault>/<item>/credential  (see docs/onepassword.md)
//
// The keyring key namespace maps 1:1 onto gog's flat keyring keys, so every
// token is independently revocable and auditable in 1Password, mirroring the
// keychain/file backends. Items are addressed by their 1Password UUID (not
// their title) so a lookup costs one read instead of the 3-read fuzzy search
// op incurs for names; see onePasswordConfig below.

// opErrorClass distinguishes failure modes gog understands from the op CLI so
// it can give actionable guidance and map missing items onto
// keyring.ErrKeyNotFound.
type opErrorClass string

const (
	opClassGeneric      opErrorClass = "generic"
	opClassNotFound     opErrorClass = "not_found"
	opClassLocked       opErrorClass = "locked"
	opClassNotSignedIn  opErrorClass = "not_signed_in"
	opClassRateLimited  opErrorClass = "rate_limited"
	opClassPermission   opErrorClass = "permission"
	opClassTimeout      opErrorClass = "timeout"
	opClassBinMissing   opErrorClass = "bin_missing"
	opClassTokenMissing opErrorClass = "token_missing"
)

// opError is an op CLI failure with machine-readable classification and a
// human hint. Errors are intentionally compared/matched by class, not text.
type opError struct {
	Class  opErrorClass
	Bin    string
	Detail string
	Hint   string
}

func (e *opError) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("1Password (op): %s: %s\n%s", e.Detail, e.Bin, e.Hint)
	}

	return fmt.Sprintf("1Password (op): %s: %s", e.Detail, e.Bin)
}

func (e *opError) Unwrap() error {
	if e.Class == opClassNotFound {
		return keyring.ErrKeyNotFound
	}

	return nil
}

// classifyOPError inspects op's stderr output (leaving stdout to the caller)
// and returns a classified, wrappable error. Real op failures look like:
//
//	[ERROR] 2026/01/02 15:04:05 message text...
//
// and the marker phrases below are matchers used by upstream OpenClaw plugins
// and the op CLI itself. Unknown failures classify as generic.
func classifyOPError(stderr string, bin string) *opError {
	msg := strings.ToLower(stderr)

	switch {
	case strings.Contains(msg, "rate limit") || strings.Contains(msg, "too many requests") || strings.Contains(msg, "429"):
		return &opError{
			Class: opClassRateLimited, Bin: bin, Detail: "1Password service account is rate-limited",
			Hint: "Wait for the 1Password rate-limit window (Personal/Families: 1000 reads + 100 writes/hour, 1000 requests/day per token) and retry. No automated retry loop is attempted.",
		}
	case strings.Contains(msg, "locked") || strings.Contains(msg, "unlock"):
		return &opError{
			Class: opClassLocked, Bin: bin, Detail: "1Password vault is locked",
			Hint: "Unlock 1Password (desktop app or `op unlock`), or use a service account with OP_SERVICE_ACCOUNT_TOKEN set.",
		}
	case strings.Contains(msg, "not currently signed in") || strings.Contains(msg, "signed in") || strings.Contains(msg, "sign in"):
		return &opError{
			Class: opClassNotSignedIn, Bin: bin, Detail: "not signed in to 1Password",
			Hint: "Sign in with `op signin` (desktop app) or set OP_SERVICE_ACCOUNT_TOKEN.",
		}
	case strings.Contains(msg, "permission") || strings.Contains(msg, "forbidden") || strings.Contains(msg, "denied") || strings.Contains(msg, "not authorized"):
		return &opError{
			Class: opClassPermission, Bin: bin, Detail: "insufficient 1Password permissions",
			Hint: "Give the service account WRITE permission to the gog vault; gog persists refreshed refresh tokens on every token refresh.",
		}
	case strings.Contains(msg, "not found") || strings.Contains(msg, "could not be found") || strings.Contains(msg, "no such item") || strings.Contains(msg, "cannot find") || strings.Contains(msg, "no item"):
		return &opError{Class: opClassNotFound, Bin: bin, Detail: "1Password item not found"}
	default:
		return &opError{Class: opClassGeneric, Bin: bin, Detail: "op command failed with stderr " + strings.TrimSpace(stderr)}
	}
}

// onePasswordConfig is the fully-resolved tuning for a 1Password backend,
// independent of OpenOptions so tests can build minimal instances.
type onePasswordConfig struct {
	bin        string        // absolute op binary path (opBin)
	binSource  string        // where bin was resolved from (opBinSource*)
	vault      string        // 1Password vault name or UUID; "" = op default
	tokenFile  string        // optional service-account token file/link
	cacheTTL   time.Duration // in-process read cache TTL (0 = disabled)
	timeout    time.Duration // per-op subprocess timeout (0 = disabled)
	maxEntries int
}

func (c onePasswordConfig) withDefaults() onePasswordConfig {
	if c.cacheTTL <= 0 {
		c.cacheTTL = opDefaultCacheTTL
	}

	if c.timeout <= 0 {
		c.timeout = opDefaultTimeout
	}

	if c.maxEntries <= 0 {
		c.maxEntries = opCacheMaxEntries
	}

	return c
}

func opTokenChildEnv(tokenFile string) ([]string, error) {
	if strings.TrimSpace(tokenFile) == "" {
		return nil, nil
	}

	data, err := os.ReadFile(tokenFile) //nolint:gosec // path is config-controlled, not user-controlled
	if err != nil {
		return nil, fmt.Errorf("read 1Password service account token file %s: %w", tokenFile, err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return nil, &opError{
			Class: opClassTokenMissing, Bin: tokenFile,
			Detail: "1Password service account token file is empty",
			Hint:   "Point GOG_OP_TOKEN_FILE at the token file exported by the OpenClaw gateway, or unset it and rely on op's own auth.",
		}
	}

	// The child op inherits the environment, so isolate service-account use
	// from the local desktop app. This matches OpenClaw's documented
	// service-account execution model and prevents a headless gog invocation
	// from waiting on desktop-app integration or biometric prompts.
	return []string{
		"OP_SERVICE_ACCOUNT_TOKEN=" + token,
		"OP_LOAD_DESKTOP_APP_SETTINGS=false",
		"OP_BIOMETRIC_UNLOCK_ENABLED=false",
	}, nil
}

// onePasswordKeyring implements keyring.Keyring by shelling out to the op CLI.
// It deliberately avoids the 99designs/keyring backend registry: this backend
// ships in normal builds with zero 1Password SDK dependency and is wired in
// openKeyringWithOptions when the resolved backend is "onepassword".
type onePasswordKeyring struct {
	cfg   onePasswordConfig
	cache *opCache
}

// newOnePasswordKeyring resolves the op binary/vault/token-file options and
// returns a ready-to-use backend. It performs no op subprocess calls (op's own
// auth always works without a token when the desktop app is present).
func newOnePasswordKeyring(options OpenOptions) (keyring.Keyring, error) {
	cfg, err := resolveOnePasswordConfig(options)
	if err != nil {
		return nil, err
	}

	bin, source, err := resolveOPBin(cfg.bin, exec.LookPath)
	if err != nil {
		return nil, err
	}
	cfg.bin = bin
	cfg.binSource = source
	cfg = cfg.withDefaults()

	return &onePasswordKeyring{cfg: cfg, cache: newOPCache(cfg.maxEntries, cfg.cacheTTL)}, nil
}

// resolveOPBin pins the op executable. An explicitly configured path (config
// op_bin / GOG_OP_BIN) is used verbatim — including an absolute path that is
// not on PATH — mirroring OpenClaw's security model for pinning binaries;
// otherwise op is resolved on PATH.
func resolveOPBin(configured string, lookPath func(string) (string, error)) (string, string, error) {
	if exe := strings.TrimSpace(configured); exe != "" {
		if lookPath == nil {
			lookPath = exec.LookPath
		}

		if strings.ContainsRune(exe, os.PathSeparator) {
			if _, statErr := os.Stat(exe); statErr != nil {
				return "", "", &opError{
					Class: opClassBinMissing, Bin: exe,
					Detail: "configured op binary not found",
					Hint:   "Pin the absolute op path in config op_bin or GOG_OP_BIN, e.g. /opt/homebrew/Caskroom/1password-cli/2.39.0/op",
				}
			}

			return exe, opBinSourceCfg, nil
		}

		if resolved, pathErr := lookPath(exe); pathErr == nil {
			return resolved, opBinSourceCfg, nil
		}

		return "", "", &opError{
			Class: opClassBinMissing, Bin: exe,
			Detail: "configured op binary not found",
			Hint:   "Pin the absolute op path in config op_bin or GOG_OP_BIN, e.g. /opt/homebrew/Caskroom/1password-cli/2.39.0/op",
		}
	}

	if lookPath == nil {
		lookPath = exec.LookPath
	}

	if exe, err := lookPath("op"); err == nil {
		return exe, opBinSourcePath, nil
	}

	return "", "", &opError{
		Class: opClassBinMissing, Bin: "op",
		Detail: "op CLI not found on PATH",
		Hint:   "Install the 1Password CLI (https://developer.1password.com/docs/cli/get-started) or set GOG_OP_BIN to its absolute path",
	}
}

// resolveOnePasswordConfig merges GOG_OP_* env (captured in OpenOptions) with
// config.json op_bin/op_vault/op_token_file. Env wins over config, matching the
// keyring backend and password resolution order.
func resolveOnePasswordConfig(options OpenOptions) (onePasswordConfig, error) {
	cfg := onePasswordConfig{
		bin:       strings.TrimSpace(options.OPBin),
		vault:     strings.TrimSpace(options.OPVault),
		tokenFile: strings.TrimSpace(options.OPTokenFile),
		cacheTTL:  options.OPCacheTTL,
		timeout:   options.OPTimeout,
	}
	if strings.TrimSpace(cfg.bin) != "" {
		cfg.binSource = opBinSourceEnv
	}

	if options.Config != nil {
		file, err := options.Config.Read()
		if err != nil {
			return onePasswordConfig{}, fmt.Errorf("resolve onepassword options: %w", err)
		}

		if cfg.bin == "" {
			cfg.bin = strings.TrimSpace(file.OPBin)
			if cfg.bin != "" {
				cfg.binSource = opBinSourceCfg
			}
		}

		if cfg.vault == "" {
			cfg.vault = strings.TrimSpace(file.OPVault)
		}

		if cfg.tokenFile == "" {
			cfg.tokenFile = strings.TrimSpace(file.OPTokenFile)
		}
	}

	return cfg, nil
}

// runOp executes the op CLI with the configured binary, vault-visible
// environment, token-file export, and a bounded timeout. On success it returns
// stdout (JSON payloads). On failure it returns a classified opError.
func (k *onePasswordKeyring) runOp(ctx context.Context, args ...string) (string, error) {
	return k.runOpInput(ctx, nil, args...)
}

// runOpInput executes op with an optional JSON item template on stdin. Using a
// template is the supported op mechanism for secret writes: assignment
// statements put refresh tokens and client secrets in the child process argv.
func (k *onePasswordKeyring) runOpInput(ctx context.Context, input []byte, args ...string) (string, error) {
	if k.cfg.bin == "" {
		return "", &opError{Class: opClassBinMissing, Bin: k.cfg.bin, Detail: "op binary not resolved"}
	}

	timeout := k.cfg.timeout
	if timeout <= 0 {
		timeout = opDefaultTimeout
	}
	runCtx := ctx
	cancel := func() {}

	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
	}

	defer cancel()

	cmd := exec.CommandContext(runCtx, k.cfg.bin, args...) //nolint:gosec // bin is operator-pinned config
	cmd.Env = os.Environ()
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}

	if childEnv, err := opTokenChildEnv(k.cfg.tokenFile); err != nil {
		return "", err
	} else {
		cmd.Env = append(cmd.Env, childEnv...)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	slog.Debug("op command started",
		"bin", filepath.Base(k.cfg.bin),
		"args", opTraceArgs(args),
		"token_injection", strings.TrimSpace(k.cfg.tokenFile) != "",
		"token_source", opTraceTokenSource(k.cfg.tokenFile),
	)

	err := cmd.Run()
	if err != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			slog.Debug("op command completed", "bin", filepath.Base(k.cfg.bin), "status", "timeout")
			return "", &opError{
				Class: opClassTimeout, Bin: k.cfg.bin,
				Detail: fmt.Sprintf("op command timed out after %s", timeout),
				Hint:   "The op CLI may be waiting on a desktop unlock prompt; increase GOG_OP_TIMEOUT or use a service account.",
			}
		}

		opErr := classifyOPError(stderr.String(), k.cfg.bin)
		slog.Debug("op command completed", "bin", filepath.Base(k.cfg.bin), "status", "error", "class", opErr.Class)
		return "", opErr
	}
	slog.Debug("op command completed", "bin", filepath.Base(k.cfg.bin), "status", "success")

	return stdout.String(), nil
}

func opTraceArgs(args []string) []string {
	traceArgs := make([]string, len(args))
	for i, arg := range args {
		if i > 0 && args[i-1] == "--field" {
			traceArgs[i] = redactOPTraceValue(arg)
			continue
		}

		if name, _, ok := strings.Cut(arg, "="); ok && opTraceSensitiveName(name) {
			traceArgs[i] = name + "=<redacted>"
			continue
		}

		traceArgs[i] = arg
	}

	return traceArgs
}

func redactOPTraceValue(value string) string {
	if name, _, ok := strings.Cut(value, "="); ok {
		return name + "=<redacted>"
	}

	return "<redacted>"
}

func opTraceSensitiveName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.Contains(name, "token") || strings.Contains(name, "secret") ||
		strings.Contains(name, "credential") || strings.Contains(name, "password")
}

func opTraceTokenSource(tokenFile string) string {
	if strings.TrimSpace(tokenFile) == "" {
		return ""
	}

	if base := filepath.Base(tokenFile); base != "" && base != "." && base != string(filepath.Separator) {
		return base
	}

	return "configured"
}

// vaultFor builds the --vault flag value for op subprocesses.
func (k *onePasswordKeyring) vaultArgs() []string {
	if strings.TrimSpace(k.cfg.vault) == "" {
		return nil
	}

	return []string{"--vault", k.cfg.vault}
}

// ---- item JSON parsing ----------------------------------------------------

type opListItem struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Vault struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"vault"`
}

type opField struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type opFullItem struct {
	ID       string `json:"id,omitempty"`
	Title    string `json:"title"`
	Category string `json:"category,omitempty"`
	Vault    struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"vault"`
	Fields []opField `json:"fields"`
}

// opCredentialField extracts the value stored in the credential field,
// preferring the canonical field id then matching by label.
func credentialValue(item opFullItem) string {
	for _, f := range item.Fields {
		if f.ID == "credential" {
			return f.Value
		}
	}

	for _, f := range item.Fields {
		if strings.EqualFold(strings.TrimSpace(f.Label), "credential") {
			return f.Value
		}
	}

	return ""
}

// ---- keyring.Keyring implementation ---------------------------------------

// Get returns the credential value for key, or keyring.ErrKeyNotFound when the
// item does not exist. Reads are served from the bounded in-process cache when
// fresh; otherwise the item is resolved by UUID and fetched once.
func (k *onePasswordKeyring) Get(key string) (keyring.Item, error) {
	if canonical, ok := onePasswordLegacyTokenAlias(key); ok {
		return k.Get(canonical)
	}
	if _, subject, ok := parseSubjectTokenKey(key); ok {
		return k.getTokenBySubject(key, subject)
	}

	if value, ok := k.cache.value(key); ok {
		return keyring.Item{Key: key, Data: []byte(value)}, nil
	}

	uuid, ok := k.cache.uuid(key)
	if !ok {
		items, err := k.list()
		if err != nil {
			return keyring.Item{}, err
		}
		uuid, _ = items[key]
	}

	if uuid == "" {
		return keyring.Item{}, fmt.Errorf("%w: no 1Password item for %q", keyring.ErrKeyNotFound, key)
	}

	item, err := k.fetchByUUID(uuid)
	if err != nil {
		return keyring.Item{}, err
	}
	value := credentialValue(item)
	k.cache.store(key, uuid, value)

	if value == "" {
		return keyring.Item{}, fmt.Errorf("%w: empty credential field for %q", keyring.ErrKeyNotFound, key)
	}

	return keyring.Item{Key: key, Data: []byte(value)}, nil
}

func (k *onePasswordKeyring) fetchByUUID(uuid string) (opFullItem, error) {
	raw, err := k.fetchRawByUUID(uuid)
	if err != nil {
		return opFullItem{}, err
	}
	var item opFullItem
	if err := json.Unmarshal(raw, &item); err != nil {
		return opFullItem{}, fmt.Errorf("decode op item get JSON: %w (%s)", err, firstLine(string(raw)))
	}
	return item, nil
}

// fetchRawByUUID returns the complete item document for write paths that must
// preserve op's category-specific schema. Do not round-trip it through
// opFullItem: that read model intentionally omits fields that op validates.
func (k *onePasswordKeyring) fetchRawByUUID(uuid string) ([]byte, error) {
	args := append([]string{"item", "get", uuid}, k.vaultArgs()...)
	args = append(args, "--format", "json", "--reveal")
	out, err := k.runOp(context.Background(), args...)
	if err != nil {
		return nil, err
	}
	if !json.Valid([]byte(out)) {
		return nil, fmt.Errorf("decode op item get JSON: invalid JSON (%s)", firstLine(out))
	}
	return []byte(out), nil
}

func (k *onePasswordKeyring) GetMetadata(key string) (keyring.Metadata, error) {
	if _, err := k.Get(key); err != nil {
		return keyring.Metadata{}, err
	}
	return keyring.Metadata{Item: &keyring.Item{Key: key}}, nil
}

func (k *onePasswordKeyring) Set(item keyring.Item) error {
	if onePasswordTokenAlias(item.Key) {
		// OAuth aliases are virtual for this new backend. KeyringStore verifies
		// alias writes by reading them back, and Get resolves them to the
		// canonical item without creating or touching a separate vault item.
		return nil
	}
	items, err := k.list()
	if err != nil {
		return err
	}
	uuid := items[item.Key]
	if uuid == "" {
		err = k.createItem(item.Key, string(item.Data))
	} else {
		err = k.editItem(uuid, string(item.Data))
	}
	if err != nil {
		return err
	}
	k.cache.store(item.Key, uuid, string(item.Data))
	return nil
}

func (k *onePasswordKeyring) createItem(title string, value string) error {
	template, err := k.apiCredentialTemplate(title, value)
	if err != nil {
		return err
	}
	args := append([]string{"item", "create"}, k.vaultArgs()...)
	args = append(args, "-", "--format", "json")
	out, err := k.runOpInput(context.Background(), template, args...)
	if err != nil {
		return err
	}
	var created opFullItem
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		return fmt.Errorf("decode op item create JSON: %w (%s)", err, firstLine(out))
	}
	k.cache.store(title, created.ID, value)
	return nil
}

// apiCredentialTemplate starts with op's built-in API Credential template.
// API Credential has required built-in fields; a hand-written partial template
// is rejected by current op releases. The gog marker lives in notesPlain rather
// than a custom field so the item retains that schema unchanged.
func (k *onePasswordKeyring) apiCredentialTemplate(title string, value string) ([]byte, error) {
	out, err := k.runOp(context.Background(), "item", "template", "get", "API Credential")
	if err != nil {
		return nil, fmt.Errorf("get 1Password API Credential template: %w", err)
	}
	var item map[string]any
	if err := json.Unmarshal([]byte(out), &item); err != nil {
		return nil, fmt.Errorf("decode 1Password API Credential template: %w", err)
	}
	item["title"] = title
	fields, ok := item["fields"].([]any)
	if !ok {
		return nil, errors.New("1Password API Credential template has no fields")
	}
	var credential, notes bool
	for _, rawField := range fields {
		field, ok := rawField.(map[string]any)
		if !ok {
			continue
		}
		switch field["id"] {
		case "credential":
			field["value"] = value
			credential = true
		case "notesPlain":
			field["value"] = "gog_keyring=1"
			notes = true
		}
	}
	if !credential || !notes {
		return nil, errors.New("1Password API Credential template is missing credential or notesPlain field")
	}
	template, err := json.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("encode 1Password API Credential template: %w", err)
	}
	return template, nil
}

func (k *onePasswordKeyring) editItem(uuid string, value string) error {
	raw, err := k.fetchRawByUUID(uuid)
	if err != nil {
		return err
	}
	var item map[string]any
	if err := json.Unmarshal(raw, &item); err != nil {
		return fmt.Errorf("decode op item edit template: %w", err)
	}
	fields, ok := item["fields"].([]any)
	if !ok {
		return errors.New("op item edit template has no fields")
	}
	found := false
	for _, rawField := range fields {
		field, ok := rawField.(map[string]any)
		if !ok {
			continue
		}
		id, _ := field["id"].(string)
		label, _ := field["label"].(string)
		if id == "credential" || strings.EqualFold(label, "credential") {
			field["value"] = value
			found = true
			break
		}
	}
	if !found {
		return errors.New("op item edit template is missing credential field")
	}
	template, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("encode op item template: %w", err)
	}
	args := append([]string{"item", "edit", uuid}, k.vaultArgs()...)
	args = append(args, "-", "--format", "json")
	if _, err := k.runOpInput(context.Background(), template, args...); err != nil {
		return err
	}
	return nil
}

func (k *onePasswordKeyring) Remove(key string) error {
	if onePasswordTokenAlias(key) {
		// There are no physical alias items in the onepassword schema.
		return nil
	}
	return k.removePhysicalAlias(key)
}

func (k *onePasswordKeyring) removePhysicalAlias(key string) error {
	items, err := k.list()
	if err != nil {
		return err
	}
	uuid := items[key]
	if uuid == "" {
		return fmt.Errorf("%w: no 1Password item for %q", keyring.ErrKeyNotFound, key)
	}
	args := append([]string{"item", "delete", uuid}, k.vaultArgs()...)
	if _, err := k.runOp(context.Background(), args...); err != nil {
		return err
	}
	k.cache.delete(key)
	return nil
}

func (k *onePasswordKeyring) Keys() ([]string, error) {
	items, err := k.list()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(items))
	for title := range items {
		keys = append(keys, title)
	}
	sort.Strings(keys)
	return keys, nil
}

func (k *onePasswordKeyring) list() (map[string]string, error) {
	if cached, ok := k.cache.list(); ok {
		return cached, nil
	}
	args := append([]string{"item", "list", "--format", "json"}, k.vaultArgs()...)
	out, err := k.runOp(context.Background(), args...)
	if err != nil {
		return nil, err
	}
	var items []opListItem
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		return nil, fmt.Errorf("decode op item list JSON: %w (%s)", err, firstLine(out))
	}
	byTitle := make(map[string]string, len(items))
	for _, item := range items {
		byTitle[item.Title] = item.ID
	}
	k.cache.storeList(byTitle)
	return byTitle, nil
}

func onePasswordLegacyTokenAlias(key string) (string, bool) {
	client, email, ok := ParseTokenKey(key)
	if !ok || client != config.DefaultClientName || key != legacyTokenKey(email) {
		return "", false
	}
	return tokenKey(config.DefaultClientName, email), true
}

func onePasswordTokenAlias(key string) bool {
	if _, _, ok := parseSubjectTokenKey(key); ok {
		return true
	}
	_, ok := onePasswordLegacyTokenAlias(key)
	return ok
}

func (k *onePasswordKeyring) getTokenBySubject(alias, subject string) (keyring.Item, error) {
	items, err := k.list()
	if err != nil {
		return keyring.Item{}, err
	}
	for title, uuid := range items {
		client, _, ok := ParseTokenKey(title)
		if !ok || !onePasswordCanonicalTokenKey(title) || client == "" {
			continue
		}
		item, err := k.fetchByUUID(uuid)
		if err != nil {
			return keyring.Item{}, err
		}
		value := credentialValue(item)
		var token storedToken
		if json.Unmarshal([]byte(value), &token) == nil && strings.TrimSpace(token.Subject) == subject {
			k.cache.store(alias, "", value)
			return keyring.Item{Key: alias, Data: []byte(value)}, nil
		}
	}
	return keyring.Item{}, fmt.Errorf("%w: no 1Password token for subject %q", keyring.ErrKeyNotFound, subject)
}

func onePasswordCanonicalTokenKey(key string) bool {
	client, email, ok := ParseTokenKey(key)
	return ok && client != "" && email != "" && key == tokenKey(client, email)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
