//go:build integration

package integration

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/gogcli/internal/config"
	"github.com/openclaw/gogcli/internal/secrets"
	"github.com/openclaw/gogcli/internal/termutil"
)

// TestOnePasswordLiveRoundTrip is the live proof for the 1Password backend
// (gogcli-aja.8). It runs against a REAL 1Password vault, so it is opt-in:
//
//	GOG_OP_IT_BIN=op GOG_OP_IT_VAULT=<vault> \
//	  go test -tags integration ./internal/integration -run TestOnePasswordLive
//
// The service account (or signed-in account) backing op must have WRITE
// permission to GOG_OP_IT_VAULT. The test writes one throwaway item under the
// `it-onepassword-live:` prefix and removes it afterwards, so it is
// CI-serializable — it never touches real tokens.
func TestOnePasswordLiveRoundTrip(t *testing.T) {
	bin := strings.TrimSpace(os.Getenv("GOG_OP_IT_BIN"))
	if bin == "" {
		bin = "op"
	}
	vault := strings.TrimSpace(os.Getenv("GOG_OP_IT_VAULT"))
	if vault == "" {
		t.Skip("set GOG_OP_IT_BIN and GOG_OP_IT_VAULT to run the live 1Password proof")
	}

	layout, err := config.NewSystemResolver("").Resolve(config.PathKindConfig, config.PathKindData)
	if err != nil {
		t.Fatalf("resolve layout: %v", err)
	}

	store, err := secrets.Open(secrets.OpenOptions{
		Layout:      layout,
		Config:      config.NewConfigStore(layout),
		Backend:     secrets.KeyringBackendOnePassword,
		OPBin:       bin,
		OPVault:     vault,
		IsTTY:       termutil.IsTerminal(os.Stdin),
		GOOS:        runtime.GOOS,
		LockTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Skipf("open 1Password live secrets repository: %v", err)
	}

	key := "it-onepassword-live:" + time.Now().UTC().Format("20060102T150405.000000000Z")
	secret := []byte("live-proof-value")

	if err := store.SetSecret(key, secret); err != nil {
		if strings.Contains(err.Error(), "vault is locked") {
			t.Skipf("1Password vault is locked; unlock it to run the live proof: %v", err)
		}
		t.Fatalf("SetSecret: %v", err)
	}

	got, err := store.GetSecret(key)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatalf("secret mismatch: got %q, want %q", got, secret)
	}

	keys, err := store.Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	found := false
	for _, k := range keys {
		if k == key {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected %q in listed keys", key)
	}

	if err := store.DeleteSecret(key); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, err := store.GetSecret(key); err == nil {
		t.Fatalf("expected not-found after DeleteSecret")
	}
}
