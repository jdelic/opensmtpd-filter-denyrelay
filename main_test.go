package main

import (
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
