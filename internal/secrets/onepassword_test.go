package secrets

import (
	"bytes"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/99designs/keyring"

	"github.com/openclaw/gogcli/internal/config"
)

// fakeOPBinPath locates the fake op test binary shipped in testdata. Tests
// shell out to it exactly like production does, so the payloads and failure
// modes are the ones the real op CLI is expected to emit.
func fakeOPBinPath(tb testing.TB) string {
	tb.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("runtime.Caller failed")
	}

	return filepath.Join(filepath.Dir(file), "testdata", "op", "fake-op.sh")
}

// withFakeOP routes the op backend's subprocesses to a dedicated state dir
// and optional failure mode. Env is inherited by the fake-op child (runOp
// builds its environment from os.Environ).
func withFakeOP(tb testing.TB, stateDir string, mode string) {
	tb.Helper()

	tb.Setenv("GOG_FAKE_OP_STATE_DIR", stateDir)
	tb.Setenv("GOG_FAKE_OP_MODE", mode)
}

func testOPOpenOptions(tb testing.TB, stateDir string, mode string, ttl time.Duration) OpenOptions {
	tb.Helper()

	withFakeOP(tb, stateDir, mode)

	return OpenOptions{
		OPBin:      fakeOPBinPath(tb),
		OPCacheTTL: ttl,
		OPTimeout:  time.Second,
		Layout: config.Layout{
			ConfigDir: tb.TempDir(),
			DataDir:   tb.TempDir(),
		},
	}
}

// fakeOPItemPath mirrors the fake binary's item filename
// <state>/fake_<base64url(title)>.json.
func fakeOPItemPath(stateDir string, key string) string {
	return filepath.Join(stateDir, "fake_"+base64.RawURLEncoding.EncodeToString([]byte(key))+".json")
}

func opErrorClassOf(err error) (opErrorClass, bool) {
	var opErr *opError
	if errors.As(err, &opErr) {
		return opErr.Class, true
	}

	return "", false
}

func TestOnePasswordRunOpTraceRedactsSecrets(t *testing.T) {
	stateDir := t.TempDir()
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	const serviceToken = "service-account-token-value"
	const credentialValue = "oauth-refresh-token-value"
	if err := os.WriteFile(tokenFile, []byte(serviceToken), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	opts := testOPOpenOptions(t, stateDir, "none", 0)
	opts.OPTokenFile = tokenFile
	ring, err := newOnePasswordKeyring(opts)
	if err != nil {
		t.Fatalf("newOnePasswordKeyring: %v", err)
	}

	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	if err := ring.Set(keyring.Item{Key: "token:default:user@example.com", Data: []byte(credentialValue)}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got := logs.String()
	for _, secret := range []string{serviceToken, credentialValue, tokenFile} {
		if strings.Contains(got, secret) {
			t.Errorf("trace leaked secret %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "op command started") {
		t.Errorf("trace did not log command start: %s", got)
	}
	if !strings.Contains(got, "op command completed") {
		t.Errorf("trace did not log command completion: %s", got)
	}
	if !strings.Contains(got, "service-account-token") {
		t.Errorf("trace did not identify token source by basename: %s", got)
	}
	if !strings.Contains(got, "item create - --format json") {
		t.Errorf("trace did not show the stdin-template command shape: %s", got)
	}
	if strings.Contains(got, "credential=") {
		t.Errorf("trace exposed a credential assignment instead of using stdin: %s", got)
	}
}

func TestOnePasswordKeyringRoundTrip(t *testing.T) {
	stateDir := t.TempDir()

	ring, err := newOnePasswordKeyring(testOPOpenOptions(t, stateDir, "none", 0))
	if err != nil {
		t.Fatalf("newOnePasswordKeyring: %v", err)
	}

	key := "token:default:user@example.com"
	secret := "ya29.fake-token-value"

	if err = ring.Set(keyring.Item{Key: key, Data: []byte(secret)}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	item, err := ring.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if item.Key != key || string(item.Data) != secret {
		t.Fatalf("unexpected item: key=%q data=%q", item.Key, item.Data)
	}

	md, err := ring.GetMetadata(key)
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}

	metaItem := md.Item
	if metaItem == nil || metaItem.Key != key {
		t.Fatalf("unexpected metadata: %+v", md)
	}

	keys, err := ring.Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}

	if want := []string{key}; !slices.Equal(keys, want) {
		t.Fatalf("Keys: got %v, want %v", keys, want)
	}

	if err := ring.Remove(key); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if _, err := ring.Get(key); !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("expected not found after remove, got %v", err)
	}
}

func TestOnePasswordCreateTemplateAssignsUniqueIDsToAllFields(t *testing.T) {
	stateDir := t.TempDir()
	ring, err := newOnePasswordKeyring(testOPOpenOptions(t, stateDir, "validate-template-field-ids", 0))
	if err != nil {
		t.Fatalf("newOnePasswordKeyring: %v", err)
	}

	err = ring.Set(keyring.Item{Key: "token:default:user@example.com", Data: []byte("refresh-token")})
	if err != nil {
		t.Fatalf("Set rejected a template with unique field IDs: %v", err)
	}
}

func TestOnePasswordCreateUsesAPICredentialTemplate(t *testing.T) {
	stateDir := t.TempDir()
	ring, err := newOnePasswordKeyring(testOPOpenOptions(t, stateDir, "validate-api-credential-template", 0))
	if err != nil {
		t.Fatalf("newOnePasswordKeyring: %v", err)
	}

	if err := ring.Set(keyring.Item{Key: "token:default:user@example.com", Data: []byte("refresh-token")}); err != nil {
		t.Fatalf("Set rejected the API Credential template: %v", err)
	}
}

func TestOnePasswordEditPreservesCompleteAPICredentialSchema(t *testing.T) {
	stateDir := t.TempDir()
	key := "token:default:user@example.com"
	fixture := `{
		"id":"fake_dG9rZW46ZGVmYXVsdDp1c2VyQGV4YW1wbGUuY29t",
		"category":"API_CREDENTIAL",
		"title":"token:default:user@example.com",
		"vault":{"id":"fakevault","name":"Private"},
		"sections":[{"id":"metadata","label":"metadata"}],
		"fields":[
			{"id":"notesPlain","label":"notesPlain","type":"STRING","value":"gog_keyring=1"},
			{"id":"username","label":"username","type":"STRING","value":""},
			{"id":"credential","label":"credential","purpose":"PASSWORD","type":"CONCEALED","value":"old-refresh-token","section":{"id":"metadata"}},
			{"id":"type","label":"type","type":"MENU","value":""}
		]
	}`
	if err := os.WriteFile(fakeOPItemPath(stateDir, key), []byte(fixture), 0o600); err != nil {
		t.Fatalf("write API Credential fixture: %v", err)
	}

	ring, err := newOnePasswordKeyring(testOPOpenOptions(t, stateDir, "validate-edit-preserves-schema", 0))
	if err != nil {
		t.Fatalf("newOnePasswordKeyring: %v", err)
	}

	if err := ring.Set(keyring.Item{Key: key, Data: []byte("rotated-refresh-token")}); err != nil {
		t.Fatalf("Set rejected schema-preserving API Credential edit: %v", err)
	}
}

func TestOnePasswordKeyringListsConfiguredVault(t *testing.T) {
	stateDir := t.TempDir()
	opts := testOPOpenOptions(t, stateDir, "none", 0)
	opts.OPVault = "OpenClaw"
	t.Setenv("GOG_FAKE_OP_REQUIRE_VAULT", "1")

	ring, err := newOnePasswordKeyring(opts)
	if err != nil {
		t.Fatalf("newOnePasswordKeyring: %v", err)
	}

	if err := ring.Set(keyring.Item{Key: "token:default:user@example.com", Data: []byte("refresh-token")}); err != nil {
		t.Fatalf("Set configured-vault item: %v", err)
	}
}

func TestOnePasswordKeyringUsesConfiguredVaultForEveryItemOperation(t *testing.T) {
	stateDir := t.TempDir()
	opts := testOPOpenOptions(t, stateDir, "none", 0)
	opts.OPVault = "OpenClaw"
	t.Setenv("GOG_FAKE_OP_REQUIRE_VAULT", "1")

	ring, err := newOnePasswordKeyring(opts)
	if err != nil {
		t.Fatalf("newOnePasswordKeyring: %v", err)
	}

	key := "token:default:user@example.com"
	if err := ring.Set(keyring.Item{Key: key, Data: []byte("initial-refresh-token")}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := ring.Get(key); err != nil {
		t.Fatalf("get: %v", err)
	}
	if err := ring.Set(keyring.Item{Key: key, Data: []byte("rotated-refresh-token")}); err != nil {
		t.Fatalf("edit: %v", err)
	}
	if err := ring.Remove(key); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestOnePasswordKeyringPersistsAcrossBackends(t *testing.T) {
	stateDir := t.TempDir()
	key := "token:work:user@example.com"
	secret := "refresh-token-b"

	first, err := newOnePasswordKeyring(testOPOpenOptions(t, stateDir, "none", 0))
	if err != nil {
		t.Fatalf("open first backend: %v", err)
	}

	if err = first.Set(keyring.Item{Key: key, Data: []byte(secret)}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// A second, independent backend instance over the same 1Password vault
	// must see the item (op items, not process state, are the source of truth).
	second, err := newOnePasswordKeyring(testOPOpenOptions(t, stateDir, "none", 0))
	if err != nil {
		t.Fatalf("open second backend: %v", err)
	}

	item, err := second.Get(key)
	if err != nil {
		t.Fatalf("Get from fresh backend: %v", err)
	}

	if string(item.Data) != secret {
		t.Fatalf("unexpected persisted data %q", item.Data)
	}

	keys, err := second.Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}

	if !slices.Contains(keys, key) {
		t.Fatalf("expected %q in %v", key, keys)
	}
}

func TestOnePasswordKeyringStoreRoundTrip(t *testing.T) {
	stateDir := t.TempDir()
	opts := testOPOpenOptions(t, stateDir, "none", 0)
	opts.Backend = KeyringBackendOnePassword

	store, err := Open(opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	tok := Token{Client: config.DefaultClientName, Email: "user@example.com", AccessToken: "at-1", RefreshToken: "rt-1"}
	if err = store.SetToken(config.DefaultClientName, "user@example.com", tok); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	got, err := store.GetToken(config.DefaultClientName, "user@example.com")
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}

	if got.AccessToken != "at-1" || got.RefreshToken != "rt-1" {
		t.Fatalf("token mismatch: %+v", got)
	}

	if err := store.DeleteToken(config.DefaultClientName, "user@example.com"); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}

	if _, err := store.GetToken(config.DefaultClientName, "user@example.com"); !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("expected not found after delete, got %v", err)
	}
}

func TestOnePasswordTokenAliasesUseOneCredentialItem(t *testing.T) {
	stateDir := t.TempDir()
	opts := testOPOpenOptions(t, stateDir, "none", 0)
	opts.Backend = KeyringBackendOnePassword
	store, err := Open(opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	tok := Token{Client: config.DefaultClientName, Email: "user@example.com", Subject: "google-subject", RefreshToken: "rt"}
	if err := store.SetToken(config.DefaultClientName, tok.Email, tok); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	keys, err := store.Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if want := []string{tokenKey(config.DefaultClientName, tok.Email)}; !slices.Equal(keys, want) {
		t.Fatalf("credential-bearing keys = %v, want %v", keys, want)
	}

	bySubject, err := store.(*KeyringStore).getTokenBySubjectNoLock(config.DefaultClientName, tok.Subject)
	if err != nil || bySubject.RefreshToken != tok.RefreshToken || bySubject.Email != tok.Email {
		t.Fatalf("subject lookup = %#v, %v", bySubject, err)
	}
}

func TestOnePasswordKeyringKeysSorted(t *testing.T) {
	stateDir := t.TempDir()

	ring, err := newOnePasswordKeyring(testOPOpenOptions(t, stateDir, "none", 0))
	if err != nil {
		t.Fatalf("newOnePasswordKeyring: %v", err)
	}

	for _, key := range []string{"z-token", "a-token", "m-token"} {
		if err = ring.Set(keyring.Item{Key: key, Data: []byte(key)}); err != nil {
			t.Fatalf("Set %q: %v", key, err)
		}
	}

	keys, err := ring.Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}

	want := []string{"a-token", "m-token", "z-token"}
	if !slices.Equal(keys, want) {
		t.Fatalf("Keys: got %v, want %v", keys, want)
	}
}

func TestOnePasswordKeyringErrorClasses(t *testing.T) {
	tests := []struct {
		name  string
		mode  string
		class opErrorClass
	}{
		{name: "locked", mode: "locked", class: opClassLocked},
		{name: "ratelimited", mode: "ratelimited", class: opClassRateLimited},
		{name: "permission", mode: "permission", class: opClassPermission},
		{name: "notsignedin", mode: "notsignedin", class: opClassNotSignedIn},
		{name: "generic", mode: "generic", class: opClassGeneric},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateDir := t.TempDir()

			ring, err := newOnePasswordKeyring(testOPOpenOptions(t, stateDir, tt.mode, 0))
			if err != nil {
				t.Fatalf("newOnePasswordKeyring: %v", err)
			}

			_, err = ring.Get("token:default:user@example.com")
			if err == nil {
				t.Fatal("expected an error from failing op, got nil")
			}

			gotClass, ok := opErrorClassOf(err)
			if !ok {
				t.Fatalf("expected *opError, got %T: %v", err, err)
			}

			if gotClass != tt.class {
				t.Fatalf("error class: got %q, want %q (%v)", gotClass, tt.class, err)
			}

			if !strings.Contains(err.Error(), "op") {
				t.Fatalf("op error should carry the op context, got %q", err.Error())
			}
		})
	}
}

func TestOnePasswordKeyringNotFound(t *testing.T) {
	stateDir := t.TempDir()

	ring, err := newOnePasswordKeyring(testOPOpenOptions(t, stateDir, "none", 0))
	if err != nil {
		t.Fatalf("newOnePasswordKeyring: %v", err)
	}

	_, err = ring.Get("token:default:missing@example.com")
	if !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("expected keyring.ErrKeyNotFound for missing key, got %v", err)
	}

	if err := ring.Remove("token:default:missing@example.com"); !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("expected keyring.ErrKeyNotFound for removing missing key, got %v", err)
	}
}

func TestOnePasswordKeyringFakeNotFoundMode(t *testing.T) {
	stateDir := t.TempDir()
	// The fake op's "notfound" mode is classification-level: Get must surface
	// it as both an opError and keyring.ErrKeyNotFound (via Unwrap).
	ring, err := newOnePasswordKeyring(testOPOpenOptions(t, stateDir, "notfound", 0))
	if err != nil {
		t.Fatalf("newOnePasswordKeyring: %v", err)
	}

	_, err = ring.Get("token:default:user@example.com")
	if !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("expected keyring.ErrKeyNotFound from notfound mode, got %v", err)
	}

	if gotClass, ok := opErrorClassOf(err); !ok || gotClass != opClassNotFound {
		t.Fatalf("expected not_found class, got %v (%q)", gotClass, err)
	}
}

func TestOnePasswordKeyringCacheServesFreshValue(t *testing.T) {
	stateDir := t.TempDir()
	key := "token:default:cached@example.com"
	secret := "cached-secret"

	ring, err := newOnePasswordKeyring(testOPOpenOptions(t, stateDir, "none", time.Hour))
	if err != nil {
		t.Fatalf("newOnePasswordKeyring: %v", err)
	}

	if err = ring.Set(keyring.Item{Key: key, Data: []byte(secret)}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Force the item out from under the backend; the bounded in-process cache
	// must serve the value without a new op call.
	if err = os.Remove(fakeOPItemPath(stateDir, key)); err != nil {
		t.Fatalf("remove backing item: %v", err)
	}

	item, err := ring.Get(key)
	if err != nil {
		t.Fatalf("Get from cache: %v", err)
	}

	if string(item.Data) != secret {
		t.Fatalf("cached data mismatch: got %q", item.Data)
	}
}

func TestOnePasswordKeyringCacheExpires(t *testing.T) {
	stateDir := t.TempDir()
	key := "token:default:expiring@example.com"

	ring, err := newOnePasswordKeyring(testOPOpenOptions(t, stateDir, "none", 50*time.Millisecond))
	if err != nil {
		t.Fatalf("newOnePasswordKeyring: %v", err)
	}

	if err := ring.Set(keyring.Item{Key: key, Data: []byte("short-lived")}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	time.Sleep(120 * time.Millisecond)

	if err := os.Remove(fakeOPItemPath(stateDir, key)); err != nil {
		t.Fatalf("remove backing item: %v", err)
	}

	if _, err := ring.Get(key); !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("expected not found after cache expiry and item removal, got %v", err)
	}
}

func TestOnePasswordBackendRejectsLegacy1PasswordSpelling(t *testing.T) {
	stateDir := t.TempDir()
	opts := testOPOpenOptions(t, stateDir, "none", 0)
	opts.Backend = "1password"

	info, err := ResolveKeyringBackendInfoWithOptions(opts)
	if err != nil {
		t.Fatalf("resolve backend: %v", err)
	}

	if info.Value != "1password" {
		t.Fatalf("expected legacy spelling to remain invalid, got %q", info.Value)
	}

	if _, err := Open(opts); err == nil {
		t.Fatal("expected Open to reject legacy spelling")
	}
}

func TestOnePasswordBackendRejectsUnknownBackend(t *testing.T) {
	opts := OpenOptions{Layout: config.Layout{
		ConfigDir: t.TempDir(),
		DataDir:   t.TempDir(),
	}}

	if _, err := Open(opts); err == nil {
		t.Fatal("expected Open to reject missing/invalid backend")
	}
}

func TestResolveOPBin(t *testing.T) {
	fake := fakeOPBinPath(t)

	if got, source, err := resolveOPBin(fake, exec.LookPath); err != nil {
		t.Fatalf("resolve absolute bin: %v", err)
	} else if got != fake || source != opBinSourceCfg {
		t.Fatalf("absolute bin: got %q (source %q)", got, source)
	}

	// A non-executable configured path must fail with a helpful op error.
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, _, err := resolveOPBin(missing, exec.LookPath); err == nil {
		t.Fatalf("expected error for missing configured bin, got nil")
	} else if got, ok := opErrorClassOf(err); !ok || got != opClassBinMissing {
		t.Fatalf("expected bin_missing class, got %q (ok=%v): %v", got, ok, err)
	}

	// Resolution via PATH when nothing is configured.
	if got, source, err := resolveOPBin("", func(name string) (string, error) {
		return "/usr/bin/" + name, nil
	}); err != nil {
		t.Fatalf("resolve via PATH: %v", err)
	} else if got != "/usr/bin/op" || source != opBinSourcePath {
		t.Fatalf("PATH bin: got %q (source %q)", got, source)
	}

	// No op anywhere → classified bin-missing error.
	if _, _, err := resolveOPBin("", func(string) (string, error) {
		return "", exec.ErrNotFound
	}); err == nil {
		t.Fatal("expected error when op is absent")
	} else if got, _ := opErrorClassOf(err); got != opClassBinMissing {
		t.Fatalf("expected bin_missing class, got %q (%v)", got, err)
	}
}

func TestTokenSourceLabelRedactsTokenFilePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service-account-token")

	got := tokenSourceLabel(path)
	if strings.Contains(got, path) {
		t.Fatalf("token source exposed token-file path: %q", got)
	}
	if got != "OP_SERVICE_ACCOUNT_TOKEN from configured token file" {
		t.Fatalf("token source = %q, want redacted configured-token description", got)
	}
}

func TestOPTokenChildEnv(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "op-token")
	if err := os.WriteFile(tokenFile, []byte("op_sa_abc123\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	env, err := opTokenChildEnv(tokenFile)
	if err != nil {
		t.Fatalf("opTokenChildEnv: %v", err)
	}

	if !slices.Contains(env, "OP_SERVICE_ACCOUNT_TOKEN=op_sa_abc123") {
		t.Fatalf("expected OP_SERVICE_ACCOUNT_TOKEN in child env, got %v", env)
	}
	for _, want := range []string{
		"OP_LOAD_DESKTOP_APP_SETTINGS=false",
		"OP_BIOMETRIC_UNLOCK_ENABLED=false",
	} {
		if !slices.Contains(env, want) {
			t.Errorf("expected service-account child environment to contain %q, got %v", want, env)
		}
	}

	emptyFile := filepath.Join(t.TempDir(), "empty-op-token")
	if err := os.WriteFile(emptyFile, nil, 0o600); err != nil {
		t.Fatalf("write empty token file: %v", err)
	}

	if _, err := opTokenChildEnv(emptyFile); err == nil {
		t.Fatal("expected error for empty token file, got nil")
	} else if got, _ := opErrorClassOf(err); got != opClassTokenMissing {
		t.Fatalf("expected token_missing class, got %q (%v)", got, err)
	}
}

func TestOPCacheBacksOpBackend(t *testing.T) {
	stateDir := t.TempDir()

	ring, err := newOnePasswordKeyring(testOPOpenOptions(t, stateDir, "none", time.Hour))
	if err != nil {
		t.Fatalf("newOnePasswordKeyring: %v", err)
	}

	opRing, ok := ring.(*onePasswordKeyring)
	if !ok {
		t.Fatalf("expected *onePasswordKeyring, got %T", ring)
	}

	if opRing.cache == nil {
		t.Fatal("expected non-nil cache")
	}

	opRing.cache.store("k", "uuid-1", "v1")

	if v, ok := opRing.cache.value("k"); !ok || v != "v1" {
		t.Fatalf("cache value: got %q, ok %v", v, ok)
	}

	opRing.cache.delete("k")

	if _, ok := opRing.cache.value("k"); ok {
		t.Fatal("expected value evicted after delete")
	}
}
