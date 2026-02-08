package gigahost

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	ghprovider "github.com/fredrik-lindseth/caddy-dns-gigahost/provider"
)

func TestCaddyModule(t *testing.T) {
	p := Provider{}
	info := p.CaddyModule()

	if got := string(info.ID); got != "dns.providers.gigahost" {
		t.Errorf("Module ID = %q, want %q", got, "dns.providers.gigahost")
	}

	instance := info.New()
	pp, ok := instance.(*Provider)
	if !ok {
		t.Fatal("New() should return a *Provider instance")
	}
	if pp.Provider == nil {
		t.Error("New() should initialise the embedded Provider")
	}
}

func TestProvision(t *testing.T) {
	t.Run("replaces environment placeholders", func(t *testing.T) {
		t.Setenv("GH_TEST_USERNAME", "actual_user")
		t.Setenv("GH_TEST_PASSWORD", "actual_pass")
		t.Setenv("GH_TEST_TOTP", "123456")

		p := &Provider{Provider: &ghprovider.Provider{
			Username: "{env.GH_TEST_USERNAME}",
			Password: "{env.GH_TEST_PASSWORD}",
			TOTPCode: "{env.GH_TEST_TOTP}",
		}}

		// caddy.Context{} zero value is sufficient for Provision since
		// it only uses caddy.NewReplacer() which is context-independent.
		err := p.Provision(caddy.Context{})
		if err != nil {
			t.Fatalf("Provision returned unexpected error: %v", err)
		}
		if p.Provider.Username != "actual_user" {
			t.Errorf("Username = %q, want %q", p.Provider.Username, "actual_user")
		}
		if p.Provider.Password != "actual_pass" {
			t.Errorf("Password = %q, want %q", p.Provider.Password, "actual_pass")
		}
		if p.Provider.TOTPCode != "123456" {
			t.Errorf("TOTPCode = %q, want %q", p.Provider.TOTPCode, "123456")
		}
	})

	t.Run("leaves direct values unchanged", func(t *testing.T) {
		p := &Provider{Provider: &ghprovider.Provider{
			Username: "direct_user",
			Password: "direct_pass",
			TOTPCode: "654321",
		}}

		err := p.Provision(caddy.Context{})
		if err != nil {
			t.Fatalf("Provision returned unexpected error: %v", err)
		}
		if p.Provider.Username != "direct_user" {
			t.Errorf("Username = %q, want %q", p.Provider.Username, "direct_user")
		}
		if p.Provider.Password != "direct_pass" {
			t.Errorf("Password = %q, want %q", p.Provider.Password, "direct_pass")
		}
		if p.Provider.TOTPCode != "654321" {
			t.Errorf("TOTPCode = %q, want %q", p.Provider.TOTPCode, "654321")
		}
	})

	t.Run("unset env placeholder resolves to empty", func(t *testing.T) {
		p := &Provider{Provider: &ghprovider.Provider{
			Username: "{env.GH_NONEXISTENT_VAR}",
			Password: "pass",
		}}

		err := p.Provision(caddy.Context{})
		if err != nil {
			t.Fatalf("Provision returned unexpected error: %v", err)
		}
		if p.Provider.Username != "" {
			t.Errorf("Username = %q, want empty string for unset env var", p.Provider.Username)
		}
	})
}

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectedErr      string
		expectedUsername string
		expectedPassword string
		expectedTOTP     string
	}{
		{
			name:             "valid full config",
			input:            "gigahost {\n username myuser\n password mypass\n}",
			expectedUsername: "myuser",
			expectedPassword: "mypass",
		},
		{
			name:             "valid with totp_code",
			input:            "gigahost {\n username myuser\n password mypass\n totp_code 123456\n}",
			expectedUsername: "myuser",
			expectedPassword: "mypass",
			expectedTOTP:     "123456",
		},
		{
			name:             "valid with env placeholders",
			input:            "gigahost {\n username {env.USER}\n password {env.PASS}\n totp_code {env.TOTP}\n}",
			expectedUsername: "{env.USER}",
			expectedPassword: "{env.PASS}",
			expectedTOTP:     "{env.TOTP}",
		},
		{
			name:        "missing username",
			input:       "gigahost {\n password mypass\n}",
			expectedErr: "missing username",
		},
		{
			name:        "missing password",
			input:       "gigahost {\n username myuser\n}",
			expectedErr: "missing password",
		},
		{
			name:        "empty block",
			input:       "gigahost {\n}",
			expectedErr: "missing username",
		},
		{
			name:        "no block",
			input:       "gigahost",
			expectedErr: "missing username",
		},
		{
			name:        "duplicate username",
			input:       "gigahost {\n username myuser\n username another\n}",
			expectedErr: "username already set",
		},
		{
			name:        "duplicate password",
			input:       "gigahost {\n username myuser\n password mypass\n password another\n}",
			expectedErr: "password already set",
		},
		{
			name:        "duplicate totp_code",
			input:       "gigahost {\n username myuser\n password mypass\n totp_code 111\n totp_code 222\n}",
			expectedErr: "TOTP code already set",
		},
		{
			name:        "unrecognized subdirective",
			input:       "gigahost {\n username myuser\n password mypass\n unknown value\n}",
			expectedErr: "unrecognized subdirective 'unknown'",
		},
		{
			name:        "inline argument not supported",
			input:       "gigahost somearg",
			expectedErr: "wrong argument count",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &Provider{Provider: new(ghprovider.Provider)}
			d := caddyfile.NewTestDispenser(tc.input)
			err := p.UnmarshalCaddyfile(d)

			if tc.expectedErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, but got nil", tc.expectedErr)
				}
				if !strings.Contains(err.Error(), tc.expectedErr) {
					t.Errorf("error = %q, want it to contain %q", err.Error(), tc.expectedErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.Provider.Username != tc.expectedUsername {
				t.Errorf("Username = %q, want %q", p.Provider.Username, tc.expectedUsername)
			}
			if p.Provider.Password != tc.expectedPassword {
				t.Errorf("Password = %q, want %q", p.Provider.Password, tc.expectedPassword)
			}
			if p.Provider.TOTPCode != tc.expectedTOTP {
				t.Errorf("TOTPCode = %q, want %q", p.Provider.TOTPCode, tc.expectedTOTP)
			}
		})
	}
}
