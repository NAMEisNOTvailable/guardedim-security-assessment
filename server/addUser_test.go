package server

import "testing"

func TestAddUserRejectsInvalidInputsBeforeDatabase(t *testing.T) {
	pubKey := testWGKey(t)

	tests := []struct {
		name        string
		username    string
		displayName string
		pubKey      string
		code        int64
	}{
		{
			name:        "invalid public key",
			username:    "alice",
			displayName: "Alice",
			pubKey:      "not-a-key",
			code:        -1,
		},
		{
			name:        "empty username",
			username:    "",
			displayName: "Alice",
			pubKey:      pubKey,
			code:        -2,
		},
		{
			name:        "non-ascii username",
			username:    "alíce",
			displayName: "Alice",
			pubKey:      pubKey,
			code:        -3,
		},
		{
			name:        "invalid utf8 display name",
			username:    "alice",
			displayName: string([]byte{0xff}),
			pubKey:      pubKey,
			code:        -4,
		},
		{
			name:        "empty display name",
			username:    "alice",
			displayName: "",
			pubKey:      pubKey,
			code:        -5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AddUser(nil, tt.username, tt.displayName, tt.pubKey, "10.0.0.2")
			if err == nil {
				t.Fatal("expected validation error")
			}
			if got != tt.code {
				t.Fatalf("AddUser returned code %d, want %d", got, tt.code)
			}
		})
	}
}
