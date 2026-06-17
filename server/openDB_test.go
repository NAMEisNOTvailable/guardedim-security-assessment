package server

import (
	"net/url"
	"path/filepath"
	"testing"
)

func TestCraftDBAccessURLUsesTLSCertificatePaths(t *testing.T) {
	got := CraftDBAccessURL("db.example.test", 26257, "guardedim_user", "", "db_certs")

	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse database URL: %v", err)
	}
	if parsed.Scheme != "postgresql" {
		t.Fatalf("scheme = %q, want postgresql", parsed.Scheme)
	}
	if parsed.User.Username() != "guardedim_user" {
		t.Fatalf("username = %q, want guardedim_user", parsed.User.Username())
	}
	if parsed.Host != "db.example.test:26257" {
		t.Fatalf("host = %q, want db.example.test:26257", parsed.Host)
	}
	if parsed.Path != "/defaultdb" {
		t.Fatalf("path = %q, want /defaultdb", parsed.Path)
	}

	query := parsed.Query()
	if query.Get("sslmode") != "verify-full" {
		t.Fatalf("sslmode = %q, want verify-full", query.Get("sslmode"))
	}
	if query.Get("sslrootcert") != filepath.Join("db_certs", "ca.crt") {
		t.Fatalf("sslrootcert = %q", query.Get("sslrootcert"))
	}
	if query.Get("sslcert") != filepath.Join("db_certs", "client.guardedim_user.crt") {
		t.Fatalf("sslcert = %q", query.Get("sslcert"))
	}
	if query.Get("sslkey") != filepath.Join("db_certs", "client.guardedim_user.key") {
		t.Fatalf("sslkey = %q", query.Get("sslkey"))
	}
}
