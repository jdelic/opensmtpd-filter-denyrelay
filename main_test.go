package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRules(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "denylist.txt")
	content := "\n# example denylist\nnorelay@example.com\nrelayonlyto@example.com=other@example.com\nrelayoptions@example.com=one@example.com\nrelayoptions@example.com=two@example.com\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write denylist: %v", err)
	}

	rules, err := loadRules(path)
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}

	if !rules.hasRule("norelay@example.com") {
		t.Fatal("expected norelay@example.com rule")
	}
	if rules.allows("norelay@example.com", "anyone@example.com") {
		t.Fatal("expected norelay@example.com to be blocked for all recipients")
	}
	if !rules.allows("relayonlyto@example.com", "other@example.com") {
		t.Fatal("expected relayonlyto@example.com to be allowed for other@example.com")
	}
	if rules.allows("relayonlyto@example.com", "else@example.com") {
		t.Fatal("expected relayonlyto@example.com to be blocked for else@example.com")
	}
	if !rules.allows("relayoptions@example.com", "one@example.com") {
		t.Fatal("expected relayoptions@example.com to be allowed for one@example.com")
	}
	if !rules.allows("relayoptions@example.com", "two@example.com") {
		t.Fatal("expected relayoptions@example.com to be allowed for two@example.com")
	}
	if rules.allows("relayoptions@example.com", "three@example.com") {
		t.Fatal("expected relayoptions@example.com to be blocked for three@example.com")
	}
	if !rules.allows("notlisted@example.com", "anyone@example.com") {
		t.Fatal("expected users not on the denylist to be unaffected")
	}
	if rules.allows("norelay+ext@example.com", "anyone@example.com") {
		t.Fatal("expected norelay+ext@example.com to match norelay@example.com")
	}
	if rules.allows("norelay-ext@example.com", "anyone@example.com") {
		t.Fatal("expected norelay-ext@example.com to match norelay@example.com")
	}
	if !rules.allows("relayonlyto+ext@example.com", "other@example.com") {
		t.Fatal("expected relayonlyto+ext@example.com to inherit relayonlyto@example.com allowlist")
	}
	if rules.allows("relayonlyto-ext@example.com", "else@example.com") {
		t.Fatal("expected relayonlyto-ext@example.com to inherit relayonlyto@example.com denylist")
	}
}

func TestLoadRulesDenyAllOverridesRecipientEntries(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "denylist.txt")
	content := "relay@example.com=other@example.com\nrelay@example.com\nrelay@example.com=someone@example.com\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write denylist: %v", err)
	}

	rules, err := loadRules(path)
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}

	if rules.allows("relay@example.com", "other@example.com") {
		t.Fatal("expected deny-all entry to override allowed recipients")
	}
}

func TestLoadRulesRejectsInvalidEntries(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "denylist.txt")
	content := "broken@example.com=\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write denylist: %v", err)
	}

	if _, err := loadRules(path); err == nil {
		t.Fatal("expected invalid denylist to fail")
	}
}

func TestNormalizeAddress(t *testing.T) {
	t.Parallel()

	if got := normalizeAddress(" <User@Example.com> "); got != "user@example.com" {
		t.Fatalf("unexpected normalized address %q", got)
	}
}

func TestRuleLookupKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		user string
		want []string
	}{
		{
			name: "exact only",
			user: "relay@example.com",
			want: []string{"relay@example.com"},
		},
		{
			name: "plus extension",
			user: "relay+tag@example.com",
			want: []string{"relay+tag@example.com", "relay@example.com"},
		},
		{
			name: "dash extension",
			user: "relay-tag@example.com",
			want: []string{"relay-tag@example.com", "relay@example.com"},
		},
		{
			name: "plus and dash extension",
			user: "relay-tag+detail@example.com",
			want: []string{"relay-tag+detail@example.com", "relay-tag@example.com", "relay@example.com"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ruleLookupKeys(tt.user)
			if len(got) != len(tt.want) {
				t.Fatalf("unexpected key count %d, want %d (%v)", len(got), len(tt.want), got)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("unexpected lookup keys %v, want %v", got, tt.want)
				}
			}

			func TestExtractAgentEmailAuthToken(t *testing.T) {
				t.Parallel()

				tests := []struct {
					name        string
					message     []string
					wantMessage []string
					wantToken   string
					wantFound   bool
				}{
					{
						name: "removes token line and following empty line",
						message: []string{
							"From: sender@example.com",
							"To: recipient@example.com",
							"",
							"X-Agent-Email-Auth: deadbeef",
							"",
							"Hello world",
						},
						wantMessage: []string{
							"From: sender@example.com",
							"To: recipient@example.com",
							"",
							"Hello world",
						},
						wantToken: "deadbeef",
						wantFound: true,
					},
					{
						name: "removes token line without extra empty line",
						message: []string{
							"Subject: test",
							"",
							"X-Agent-Email-Auth: cafebabe",
							"Body line",
						},
						wantMessage: []string{
							"Subject: test",
							"",
							"Body line",
						},
						wantToken: "cafebabe",
						wantFound: true,
					},
					{
						name: "ignores non-token first body line",
						message: []string{
							"Subject: test",
							"",
							"Hello world",
						},
						wantMessage: []string{
							"Subject: test",
							"",
							"Hello world",
						},
					},
					{
						name: "returns empty token when line is present but blank",
						message: []string{
							"Subject: test",
							"",
							"X-Agent-Email-Auth:   ",
							"Hello world",
						},
						wantMessage: []string{
							"Subject: test",
							"",
							"Hello world",
						},
						wantFound: true,
					},
				}

				for _, tt := range tests {
					tt := tt
					t.Run(tt.name, func(t *testing.T) {
						t.Parallel()

						gotMessage, gotToken, gotFound := extractAgentEmailAuthToken(tt.message)
						if gotFound != tt.wantFound {
							t.Fatalf("unexpected found value %v, want %v", gotFound, tt.wantFound)
						}
						if gotToken != tt.wantToken {
							t.Fatalf("unexpected token %q, want %q", gotToken, tt.wantToken)
						}
						if len(gotMessage) != len(tt.wantMessage) {
							t.Fatalf("unexpected message length %d, want %d (%v)", len(gotMessage), len(tt.wantMessage), gotMessage)
						}
						for i := range tt.wantMessage {
							if gotMessage[i] != tt.wantMessage[i] {
								t.Fatalf("unexpected message %v, want %v", gotMessage, tt.wantMessage)
							}
						}
					})
				}
			}

			func TestValidateAgentEmailAuthToken(t *testing.T) {
				t.Parallel()

				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/email-agent-auth-tokens/validate/" {
						t.Fatalf("unexpected path %q", r.URL.Path)
					}
					if r.Method != http.MethodPost {
						t.Fatalf("unexpected method %q", r.Method)
					}

					switch r.Header.Get("Content-Type") {
					case "application/json":
					default:
						t.Fatalf("unexpected content type %q", r.Header.Get("Content-Type"))
					}

					token := make([]byte, r.ContentLength)
					if _, err := r.Body.Read(token); err != nil && err.Error() != "EOF" {
						t.Fatalf("read request body: %v", err)
					}
					body := string(token)
					switch body {
					case `{"token":"valid-token"}`:
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(`{"valid":true,"token_hint":"valid-token","creator":{"identifier":"agent-user","uuid":"1234","primary_email":"agent@example.com"}}`))
					case `{"token":"invalid-token"}`:
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusUnauthorized)
						_, _ = w.Write([]byte(`{"valid":false}`))
					default:
						w.WriteHeader(http.StatusInternalServerError)
					}
				}))
				defer server.Close()

				filter := &DenyRelayFilter{
					agentEmailAuthValidationURL: server.URL + "/email-agent-auth-tokens/validate/",
					agentEmailAuthHTTPClient:    server.Client(),
				}

				valid, response, err := filter.validateAgentEmailAuthToken("valid-token")
				if err != nil {
					t.Fatalf("validateAgentEmailAuthToken(valid-token): %v", err)
				}
				if !valid {
					t.Fatal("expected valid-token to validate")
				}
				if response.Creator.Identifier != "agent-user" {
					t.Fatalf("unexpected creator identifier %q", response.Creator.Identifier)
				}

				valid, _, err = filter.validateAgentEmailAuthToken("invalid-token")
				if err != nil {
					t.Fatalf("validateAgentEmailAuthToken(invalid-token): %v", err)
				}
				if valid {
					t.Fatal("expected invalid-token to fail validation")
				}

				if _, _, err = filter.validateAgentEmailAuthToken("temporary-failure"); err == nil {
					t.Fatal("expected temporary-failure to return an error")
				}
			}

			func TestNormalizeAgentEmailAuthValidationURL(t *testing.T) {
				t.Parallel()

				got, err := normalizeAgentEmailAuthValidationURL(" https://auth.example.com/email-agent-auth-tokens/validate/ ")
				if err != nil {
					t.Fatalf("normalizeAgentEmailAuthValidationURL: %v", err)
				}
				if got != "https://auth.example.com/email-agent-auth-tokens/validate/" {
					t.Fatalf("unexpected normalized URL %q", got)
				}

				if _, err := normalizeAgentEmailAuthValidationURL("http://auth.example.com/email-agent-auth-tokens/validate/"); err == nil {
					t.Fatal("expected http URL to be rejected")
				}
			}
		})
	}
}
