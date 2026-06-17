package server

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func testWGKey(t *testing.T) string {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate WireGuard key: %v", err)
	}
	return key.String()
}

func TestAddServerRejectsInvalidInputsBeforeDatabase(t *testing.T) {
	pubKey := testWGKey(t)
	psk := testWGKey(t)

	tests := []struct {
		name string
		args []any
		code int64
	}{
		{
			name: "invalid public key",
			args: []any{"relay-a", "203.0.113.10", uint16(51820), "10.0.0.2", "not-a-key", psk},
			code: -1,
		},
		{
			name: "invalid preshared key",
			args: []any{"relay-a", "203.0.113.10", uint16(51820), "10.0.0.2", pubKey, "not-a-key"},
			code: -2,
		},
		{
			name: "server name too long",
			args: []any{strings.Repeat("a", 65), "203.0.113.10", uint16(51820), "10.0.0.2", pubKey, psk},
			code: -3,
		},
		{
			name: "invalid public ip",
			args: []any{"relay-a", "not-an-ip", uint16(51820), "10.0.0.2", pubKey, psk},
			code: -4,
		},
		{
			name: "invalid private ip",
			args: []any{"relay-a", "203.0.113.10", uint16(51820), "not-an-ip", pubKey, psk},
			code: -5,
		},
		{
			name: "private ip outside lab subnet",
			args: []any{"relay-a", "203.0.113.10", uint16(51820), "192.168.1.2", pubKey, psk},
			code: -6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AddServer(nil,
				tt.args[0].(string),
				tt.args[1].(string),
				tt.args[2].(uint16),
				tt.args[3].(string),
				tt.args[4].(string),
				tt.args[5].(string),
			)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if got != tt.code {
				t.Fatalf("AddServer returned code %d, want %d", got, tt.code)
			}
		})
	}
}
