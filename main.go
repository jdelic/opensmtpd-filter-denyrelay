package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	opensmtpd "github.com/jdelic/opensmtpd-filters-go"
)

type relayPolicy struct {
	denyAll bool
	allowed map[string]struct{}
}

func (p relayPolicy) allows(recipient string) bool {
	if p.denyAll {
		return false
	}

	_, ok := p.allowed[normalizeAddress(recipient)]
	return ok
}

type denyRules map[string]relayPolicy

func (r denyRules) allows(userName, recipient string) bool {
	policy, ok := r[normalizeAddress(userName)]
	if !ok {
		return true
	}

	return policy.allows(recipient)
}

func (r denyRules) hasRule(userName string) bool {
	_, ok := r[normalizeAddress(userName)]
	return ok
}

type DenyRelayFilter struct {
	opensmtpd.SessionTrackingMixin
	rules denyRules
}

func (f *DenyRelayFilter) GetName() string {
	return "Authenticated denyrelay filter"
}

func (f *DenyRelayFilter) RcptTo(_ opensmtpd.FilterWrapper, event opensmtpd.FilterEvent) {
	session := f.GetSession(event.GetSessionId())
	if session == nil || normalizeAddress(session.UserName) == "" {
		event.Responder().Proceed()
		return
	}

	if !f.rules.hasRule(session.UserName) {
		event.Responder().Proceed()
		return
	}

	recipient, err := recipientFromEvent(event)
	if err != nil {
		debug("unable to determine rcpt-to recipient for session %s: %v", event.GetSessionId(), err)
		event.Responder().SoftReject("Temporary failure while checking relay policy")
		return
	}

	if f.rules.allows(session.UserName, recipient) {
		event.Responder().Proceed()
		return
	}

	message := fmt.Sprintf("Authenticated user %s is not permitted to relay to %s", session.UserName, recipient)
	debug("rejecting rcpt-to for session %s: %s", event.GetSessionId(), message)
	event.Responder().HardReject(message)
}

func recipientFromEvent(event opensmtpd.FilterEvent) (string, error) {
	params := event.GetParams()
	if len(params) == 0 {
		return "", errors.New("missing rcpt-to parameters")
	}

	if len(params) > 1 && params[0] == event.GetToken() {
		params = params[1:]
	}
	if len(params) == 0 {
		return "", errors.New("missing rcpt-to recipient")
	}

	recipient := normalizeAddress(params[0])
	if recipient == "" {
		return "", errors.New("empty rcpt-to recipient")
	}

	return recipient, nil
}

func loadRules(path string) (denyRules, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	rules := make(denyRules)
	scanner := bufio.NewScanner(file)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, recipient, err := parseRuleLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}

		policy := rules[entry]
		if recipient == "" {
			policy.denyAll = true
			policy.allowed = nil
			rules[entry] = policy
			continue
		}

		if policy.denyAll {
			continue
		}
		if policy.allowed == nil {
			policy.allowed = make(map[string]struct{})
		}
		policy.allowed[recipient] = struct{}{}
		rules[entry] = policy
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return rules, nil
}

func parseRuleLine(line string) (string, string, error) {
	if strings.Count(line, "=") > 1 {
		return "", "", fmt.Errorf("invalid denylist entry %q", line)
	}

	entry, recipient, hasRecipient := strings.Cut(line, "=")
	entry = normalizeAddress(entry)
	if entry == "" {
		return "", "", fmt.Errorf("invalid denylist entry %q", line)
	}

	if !hasRecipient {
		return entry, "", nil
	}

	recipient = normalizeAddress(recipient)
	if recipient == "" {
		return "", "", fmt.Errorf("invalid denylist entry %q", line)
	}

	return entry, recipient, nil
}

func normalizeAddress(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "<")
	value = strings.TrimSuffix(value, ">")
	return strings.TrimSpace(value)
}

func debug(format string, args ...interface{}) {
	if debugOutput != nil && *debugOutput {
		log.Printf(format, args...)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] denylist\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(1)
}

var debugOutput *bool

func main() {
	log.SetOutput(os.Stderr)
	debugOutput = flag.Bool("debug", false, "Enable debug logging")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
	}

	rules, err := loadRules(flag.Arg(0))
	if err != nil {
		log.Fatalf("unable to load denylist: %v", err)
	}

	denyRelay := opensmtpd.NewFilter(&DenyRelayFilter{rules: rules})
	opensmtpd.Run(denyRelay)
}
