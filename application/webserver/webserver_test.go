package gatesentryWebserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// freshAuth returns an http.Handler protected by authenticationMiddleware along
// with a *string that the inner handler fills with whatever username it
// observed in the context. The HMAC secret is generated into a t.TempDir() so
// each test starts with a clean state.
func freshAuth(t *testing.T) (http.Handler, *string) {
	t.Helper()
	if err := InitJWTSecret(t.TempDir()); err != nil {
		t.Fatalf("InitJWTSecret: %v", err)
	}
	var observed string
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, ok := r.Context().Value("username").(string); ok {
			observed = u
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return authenticationMiddleware(protected), &observed
}

func do(t *testing.T, h http.Handler, method, authHeader string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, "/protected", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	// Recover is a safety net — the test must not panic, but if a future
	// refactor reintroduces one, surface it as a failure rather than crashing
	// the whole test binary.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handler panicked: %v", r)
		}
	}()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

// Regression test for the nil-pointer panic in authenticationMiddleware
// reported via a real stack trace. Each of these inputs used to panic with
// "invalid memory address or nil pointer dereference" at token.Claims access.
func TestAuthenticationMiddleware_MalformedBearerDoesNotPanic(t *testing.T) {
	cases := []struct {
		name        string
		authHeader  string
		wantStatus  int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"bearer prefix only", "Bearer", http.StatusUnauthorized},
		{"bearer empty value", "Bearer ", http.StatusUnauthorized},
		{"bearer word garbage", "Bearer foo", http.StatusUnauthorized},
		{"bearer null literal", "Bearer null", http.StatusUnauthorized},
		{"bearer undefined literal", "Bearer undefined", http.StatusUnauthorized},
		{"bearer truncated jwt", "Bearer eyJhbGciOiJIUzI1NiJ9", http.StatusUnauthorized},
		{"bearer alg=none token", "Bearer eyJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6ImFkbWluIn0.", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, observed := freshAuth(t)
			res := do(t, h, "GET", tc.authHeader)
			defer res.Body.Close()
			if res.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", res.StatusCode, tc.wantStatus)
			}
			if *observed != "" {
				t.Fatalf("downstream handler should not run; observed=%q", *observed)
			}
		})
	}
}

func TestAuthenticationMiddleware_ValidTokenPasses(t *testing.T) {
	h, observed := freshAuth(t)
	tok, err := CreateToken("admin")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	res := do(t, h, "GET", "Bearer "+tok)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if *observed != "admin" {
		t.Fatalf("username in context = %q, want %q", *observed, "admin")
	}
}

func TestAuthenticationMiddleware_TokenWithoutUsernameClaim(t *testing.T) {
	h, observed := freshAuth(t)
	// Sign a token with the current secret but no username claim. This used
	// to panic at `claims["username"].(string)` on a nil interface value.
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"foo": "bar",
	})
	signed, err := tok.SignedString(getJWTSecret())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	res := do(t, h, "GET", "Bearer "+signed)
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
	if *observed != "" {
		t.Fatalf("downstream should not run; observed=%q", *observed)
	}
}

func TestAuthenticationMiddleware_TokenSignedWithForeignSecret(t *testing.T) {
	h, observed := freshAuth(t)
	foreign := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "attacker",
	})
	signed, err := foreign.SignedString([]byte("some-other-secret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	res := do(t, h, "GET", "Bearer "+signed)
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
	if *observed != "" {
		t.Fatalf("downstream must not run on forged token; observed=%q", *observed)
	}
}

func TestInitJWTSecret_PersistsAndReuses(t *testing.T) {
	dir := t.TempDir()
	if err := InitJWTSecret(dir); err != nil {
		t.Fatalf("first InitJWTSecret: %v", err)
	}
	first := append([]byte(nil), hmacSecret...)
	if len(first) < 32 {
		t.Fatalf("secret too short: %d bytes", len(first))
	}
	if _, err := os.Stat(filepath.Join(dir, jwtSecretFileName)); err != nil {
		t.Fatalf("secret file should exist: %v", err)
	}

	// Reset in-memory state and call again — it must load the persisted file.
	hmacSecret = nil
	if err := InitJWTSecret(dir); err != nil {
		t.Fatalf("second InitJWTSecret: %v", err)
	}
	if string(hmacSecret) != string(first) {
		t.Fatalf("persisted secret should match in-memory secret")
	}
}

func TestInitJWTSecret_PermissionIs0600(t *testing.T) {
	dir := t.TempDir()
	if err := InitJWTSecret(dir); err != nil {
		t.Fatalf("InitJWTSecret: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, jwtSecretFileName))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Fatalf("jwt.secret mode = %o, want 0600", mode)
	}
}

func TestInitJWTSecret_RegeneratesWhenFileIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, jwtSecretFileName)
	if err := os.WriteFile(path, []byte("not-a-valid-hex-string"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	if err := InitJWTSecret(dir); err != nil {
		t.Fatalf("InitJWTSecret on corrupt file: %v", err)
	}
	if len(hmacSecret) < 32 {
		t.Fatalf("expected regenerated secret, got %d bytes", len(hmacSecret))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if strings.TrimSpace(string(data)) == "not-a-valid-hex-string" {
		t.Fatalf("corrupt secret was not replaced")
	}
}

func TestGetJWTSecret_PanicsWhenUninitialized(t *testing.T) {
	prev := hmacSecret
	defer func() { hmacSecret = prev }()
	hmacSecret = nil
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("getJWTSecret should panic when hmacSecret is nil")
		}
	}()
	_ = getJWTSecret()
}
