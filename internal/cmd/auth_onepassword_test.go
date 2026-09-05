package cmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/gogcli/internal/app"
	"github.com/openclaw/gogcli/internal/config"
	"github.com/openclaw/gogcli/internal/outfmt"
	"github.com/openclaw/gogcli/internal/secrets"
	"github.com/openclaw/gogcli/internal/ui"
)

// fakeOPCmdBinPath resolves the secrets testdata fake-op binary.
func fakeOPCmdBinPath(t *testing.T) string {
	t.Helper()

	_, file, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "secrets", "testdata", "op", "fake-op.sh")
}

func TestAuthKeyringSet_OnePassword(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("GOG_KEYRING_BACKEND", "")
	t.Setenv("GOG_KEYRING_PASSWORD", "")

	var stdout, stderr bytes.Buffer
	u, err := ui.New(ui.Options{Stdout: &stdout, Stderr: &stderr, Color: "never"})
	if err != nil {
		t.Fatalf("ui new: %v", err)
	}
	ctx := ui.WithUI(context.Background(), u)
	ctx = outfmt.WithMode(ctx, outfmt.Mode{})
	ctx = withTestRuntime(ctx, func(*app.Runtime) {})

	if err = runKong(t, &AuthKeyringCmd{}, []string{"onepassword"}, ctx, nil); err != nil {
		t.Fatalf("run: %v", err)
	}

	store := defaultConfigStoreForTest(t)
	cfg, err := store.Read()
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if cfg.KeyringBackend != secrets.KeyringBackendOnePassword {
		t.Fatalf("expected keyring_backend=%q, got %q", secrets.KeyringBackendOnePassword, cfg.KeyringBackend)
	}

	info, err := secrets.ResolveKeyringBackendInfoWithOptions(secrets.OpenOptions{
		Layout:  store.Layout(),
		Config:  store,
		Backend: "",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if info.Value != secrets.KeyringBackendOnePassword || info.Source != "config" {
		t.Fatalf("expected %q from config, got %q/%q", secrets.KeyringBackendOnePassword, info.Value, info.Source)
	}
}

func TestAuthKeyringSet_RejectsLegacy1PasswordSpelling(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("GOG_KEYRING_BACKEND", "")

	var stdout, stderr bytes.Buffer
	u, err := ui.New(ui.Options{Stdout: &stdout, Stderr: &stderr, Color: "never"})
	if err != nil {
		t.Fatalf("ui new: %v", err)
	}
	ctx := ui.WithUI(context.Background(), u)
	ctx = outfmt.WithMode(ctx, outfmt.Mode{})
	ctx = withTestRuntime(ctx, func(*app.Runtime) {})

	err = runKong(t, &AuthKeyringCmd{}, []string{"1password"}, ctx, nil)
	if err == nil {
		t.Fatal("expected legacy spelling to be rejected")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 2 {
		t.Fatalf("expected usage exit 2, got: %v", err)
	}
}

func TestAuthKeyringSet_RejectsUnknownBackend(t *testing.T) {
	var stdout, stderr bytes.Buffer
	u, err := ui.New(ui.Options{Stdout: &stdout, Stderr: &stderr, Color: "never"})
	if err != nil {
		t.Fatalf("ui new: %v", err)
	}
	ctx := ui.WithUI(context.Background(), u)
	ctx = outfmt.WithMode(ctx, outfmt.Mode{})

	err = runKong(t, &AuthKeyringCmd{}, []string{"gopass"}, ctx, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 2 {
		t.Fatalf("expected usage exit 2, got: %v", err)
	}
}

// opDoctorRuntime builds an app.Runtime whose keyring is the op backend
// pointed at the fake op binary with a dedicated state dir.
func opDoctorRuntime(t *testing.T, stateDir string, mode string) *app.Runtime {
	t.Helper()

	t.Setenv("GOG_FAKE_OP_STATE_DIR", stateDir)
	t.Setenv("GOG_FAKE_OP_MODE", mode)

	layout := config.Layout{
		ConfigDir: t.TempDir(),
		DataDir:   t.TempDir(),
	}
	opts := secrets.OpenOptions{
		Layout:     layout,
		Config:     config.NewConfigStore(layout),
		Backend:    secrets.KeyringBackendOnePassword,
		OPBin:      fakeOPCmdBinPath(t),
		OPCacheTTL: time.Hour,
		OPTimeout:  5 * time.Second,
		GOOS:       goruntime.GOOS,
	}

	return &app.Runtime{
		Layout:         layout,
		Config:         config.NewConfigStore(layout),
		KeyringOptions: &opts,
		Auth: app.AuthOperations{
			OpenSecretsStore: func() (secrets.Store, error) {
				return secrets.Open(opts)
			},
			OpenSecretStore: func() (secrets.SecretStore, error) {
				return secrets.Open(opts)
			},
		},
	}
}

func runAuthDoctorOP(t *testing.T, runtime *app.Runtime) string {
	t.Helper()

	var stdout, stderr bytes.Buffer
	u, err := ui.New(ui.Options{Stdout: &stdout, Stderr: &stderr, Color: "never"})
	if err != nil {
		t.Fatalf("ui new: %v", err)
	}
	ctx := ui.WithUI(context.Background(), u)
	ctx = outfmt.WithMode(ctx, outfmt.Mode{})
	ctx = app.WithRuntime(ctx, runtime)

	if err = runKong(t, &AuthDoctorCmd{}, nil, ctx, nil); err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	return stdout.String()
}

func TestAuthDoctorOnePasswordHealthy(t *testing.T) {
	out := runAuthDoctorOP(t, opDoctorRuntime(t, t.TempDir(), "none"))

	for _, want := range []string{
		"ok\tkeyring.backend\tonepassword",
		"ok\top.bin\t",
		"ok\top.version\top ",
		"ok\top.reachability\tvault is reachable for read access",
		"ok\top.vault\t(1Password default vault)",
		"ok\top.token_source\top's own auth",
		"ok\top.rate_limits\t",
		"warn\ttokens\tno OAuth tokens stored",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "op.signed_in") {
		t.Fatalf("doctor must not invoke or report op whoami:\n%s", out)
	}
}

func TestAuthDoctorOnePasswordLocked(t *testing.T) {
	out := runAuthDoctorOP(t, opDoctorRuntime(t, t.TempDir(), "locked"))

	if !strings.Contains(out, "error\top.reachability\t") {
		t.Fatalf("expected op.reachability error for locked vault:\n%s", out)
	}
	if !strings.Contains(out, "hint\top.reachability\t") {
		t.Fatalf("expected unlock hint:\n%s", out)
	}
	if !strings.Contains(out, "error\tkeyring.keys\t") {
		t.Fatalf("expected keyring.keys error surfaced from locked op:\n%s", out)
	}
}

func TestAuthDoctorOnePasswordPermissionDenied(t *testing.T) {
	out := runAuthDoctorOP(t, opDoctorRuntime(t, t.TempDir(), "permission"))

	if !strings.Contains(out, "error\top.reachability\t") {
		t.Fatalf("expected op.reachability error for denied vault access:\n%s", out)
	}
	if !strings.Contains(out, "WRITE permission") {
		t.Fatalf("expected permission guidance:\n%s", out)
	}
}

func TestAuthDoctorOnePasswordRateLimitedHint(t *testing.T) {
	out := runAuthDoctorOP(t, opDoctorRuntime(t, t.TempDir(), "ratelimited"))

	if !strings.Contains(out, "rate limit") {
		t.Fatalf("expected rate-limit guidance in doctor output:\n%s", out)
	}
}
