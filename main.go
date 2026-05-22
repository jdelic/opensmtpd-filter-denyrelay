package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	opensmtpd "github.com/jdelic/opensmtpd-filters-go"
)

const agentEmailAuthLineName = "X-Agent-Email-Auth"

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
	policy, ok := r.policyFor(userName)
	if !ok {
		return true
	}

	return policy.allows(recipient)
}

func (r denyRules) hasRule(userName string) bool {
	_, ok := r.policyFor(userName)
	return ok
}

func (r denyRules) policyFor(userName string) (relayPolicy, bool) {
	for _, key := range ruleLookupKeys(userName) {
		policy, ok := r[key]
		if ok {
			return policy, true
		}
	}

	return relayPolicy{}, false
}

type DenyRelayFilter struct {
	opensmtpd.SessionTrackingMixin
	rules                       denyRules
	agentEmailAuthValidationURL string
	agentEmailAuthHTTPClient    *http.Client
	stateMu                     sync.Mutex
	sessionStates               map[string]messageAuthState
}

type messageAuthState struct {
	tokenRequired bool
	processed     bool
	allow         bool
	temporary     bool
	rejectMessage string
}

type emailAgentAuthValidationResponse struct {
	Valid     bool   `json:"valid"`
	TokenHint string `json:"token_hint"`
	Creator   struct {
		Identifier   string  `json:"identifier"`
		UUID         string  `json:"uuid"`
		PrimaryEmail *string `json:"primary_email"`
	} `json:"creator"`
}

func (f *DenyRelayFilter) GetName() string {
	return "Authenticated denyrelay filter"
}

func (f *DenyRelayFilter) RcptTo(_ opensmtpd.FilterWrapper, event opensmtpd.FilterEvent) {
	session := f.GetSession(event.GetSessionId())
	if session == nil || normalizeAddress(session.UserName) == "" {
		debug("No authentication. Proceed.")
		event.Responder().Proceed()
		return
	}

	if !f.rules.hasRule(session.UserName) {
		debug("no rule for %s, so we proceed", session.UserName)
		event.Responder().Proceed()
		return
	}

	sessionID := event.GetSessionId()
	userName := session.UserName
	token := event.GetToken()
	params := append([]string(nil), event.GetParams()...)
	responder := event.Responder()
	debug("sessionID: %s, token: %s, params: %v", sessionID, token, params)

	go func() {
		recipient, err := recipientFromParams(token, params)
		if err != nil {
			debug("unable to determine rcpt-to recipient for session %s: %v", sessionID, err)
			responder.SoftReject("Temporary failure while checking relay policy")
			return
		}

		if f.rules.allows(userName, recipient) {
			debug("allowing %s to %s", userName, recipient)
			responder.Proceed()
			return
		}

		if f.agentEmailAuthEnabled() {
			debug("deferring relay decision for session %s until email auth token validation", sessionID)
			f.requireToken(sessionID)
			responder.Proceed()
			return
		}

		message := fmt.Sprintf("Authenticated user %s is not permitted to relay to %s", userName, recipient)
		debug("rejecting rcpt-to for session %s: %s", sessionID, message)
		responder.HardReject(message)
	}()
}

func (f *DenyRelayFilter) TxReset(fw opensmtpd.FilterWrapper, event opensmtpd.FilterEvent) {
	f.clearSessionState(event.GetSessionId())
	f.SessionTrackingMixin.TxReset(fw, event)
}

func (f *DenyRelayFilter) LinkDisconnect(fw opensmtpd.FilterWrapper, event opensmtpd.FilterEvent) {
	f.clearSessionState(event.GetSessionId())
	f.SessionTrackingMixin.LinkDisconnect(fw, event)
}

func (f *DenyRelayFilter) MessageComplete(event *opensmtpd.FilterEvent, session *opensmtpd.SMTPSession) {
	ev := *event
	responder := ev.Responder()
	state := f.getSessionState(session.Id)

	message, token, found := extractAgentEmailAuthToken(session.Message)
	if found {
		session.Message = message
	}

	switch {
	case !f.agentEmailAuthEnabled():
		f.finishSessionState(session.Id, true, false, "")
	case found:
		valid, response, err := f.validateAgentEmailAuthToken(token)
		if err != nil {
			debug("temporary email auth validation failure for session %s: %v", session.Id, err)
			f.finishSessionState(session.Id, false, true, "Temporary failure while validating email auth token")
			break
		}
		if !valid {
			debug("invalid email auth token for session %s", session.Id)
			f.finishSessionState(session.Id, false, false, "Invalid email auth token")
			break
		}
		debug("validated email auth token for session %s (creator=%s hint=%s)", session.Id, response.Creator.Identifier, response.TokenHint)
		f.finishSessionState(session.Id, true, false, "")
	case state.tokenRequired:
		debug("missing required email auth token for session %s", session.Id)
		f.finishSessionState(session.Id, false, false, "Valid email auth token required for relay")
	default:
		f.finishSessionState(session.Id, true, false, "")
	}

	responder.FlushMessage(session)
}

func (f *DenyRelayFilter) Commit(_ opensmtpd.FilterWrapper, event opensmtpd.FilterEvent) {
	state := f.getSessionState(event.GetSessionId())
	defer f.clearSessionState(event.GetSessionId())

	if !state.processed {
		debug("message auth decision missing for session %s", event.GetSessionId())
		event.Responder().SoftReject("Temporary failure while validating email auth token")
		return
	}
	if state.allow {
		event.Responder().Proceed()
		return
	}
	if state.temporary {
		event.Responder().SoftReject(state.rejectMessage)
		return
	}
	event.Responder().HardReject(state.rejectMessage)
}

func (f *DenyRelayFilter) agentEmailAuthEnabled() bool {
	return strings.TrimSpace(f.agentEmailAuthValidationURL) != ""
}

func (f *DenyRelayFilter) requireToken(sessionID string) {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()

	if f.sessionStates == nil {
		f.sessionStates = make(map[string]messageAuthState)
	}

	state := f.sessionStates[sessionID]
	state.tokenRequired = true
	f.sessionStates[sessionID] = state
}

func (f *DenyRelayFilter) finishSessionState(sessionID string, allow, temporary bool, rejectMessage string) {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()

	if f.sessionStates == nil {
		f.sessionStates = make(map[string]messageAuthState)
	}

	state := f.sessionStates[sessionID]
	state.processed = true
	state.allow = allow
	state.temporary = temporary
	state.rejectMessage = rejectMessage
	f.sessionStates[sessionID] = state
}

func (f *DenyRelayFilter) getSessionState(sessionID string) messageAuthState {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()

	if f.sessionStates == nil {
		return messageAuthState{}
	}

	return f.sessionStates[sessionID]
}

func (f *DenyRelayFilter) clearSessionState(sessionID string) {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()

	if f.sessionStates == nil {
		return
	}

	delete(f.sessionStates, sessionID)
}

func (f *DenyRelayFilter) validateAgentEmailAuthToken(token string) (bool, emailAgentAuthValidationResponse, error) {
	var response emailAgentAuthValidationResponse

	body, err := json.Marshal(map[string]string{
		"token": strings.TrimSpace(token),
	})
	if err != nil {
		return false, response, err
	}

	client := f.agentEmailAuthHTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.agentEmailAuthValidationURL, bytes.NewReader(body))
	if err != nil {
		return false, response, err
	}
	req.Header.Set("Content-Type", "application/json")

	httpResponse, err := client.Do(req)
	if err != nil {
		return false, response, err
	}
	defer httpResponse.Body.Close()

	switch httpResponse.StatusCode {
	case http.StatusOK:
		if err := json.NewDecoder(httpResponse.Body).Decode(&response); err != nil {
			return false, response, err
		}
		return response.Valid, response, nil
	case http.StatusUnauthorized:
		return false, response, nil
	default:
		responseBody, _ := io.ReadAll(io.LimitReader(httpResponse.Body, 1024))
		return false, response, fmt.Errorf("unexpected authserver status %d: %s", httpResponse.StatusCode, strings.TrimSpace(string(responseBody)))
	}
}

func recipientFromParams(token string, params []string) (string, error) {
	if len(params) == 0 {
		return "", errors.New("missing rcpt-to parameters")
	}

	if len(params) > 1 && params[0] == token {
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

func extractAgentEmailAuthToken(message []string) ([]string, string, bool) {
	bodyStart := -1
	for i, line := range message {
		if line == "" {
			bodyStart = i + 1
			break
		}
	}

	if bodyStart < 0 || bodyStart >= len(message) {
		return message, "", false
	}

	name, value, ok := strings.Cut(message[bodyStart], ":")
	if !ok || !strings.EqualFold(strings.TrimSpace(name), agentEmailAuthLineName) {
		return message, "", false
	}

	skip := 1
	if bodyStart+1 < len(message) && message[bodyStart+1] == "" {
		skip++
	}

	sanitized := append([]string(nil), message[:bodyStart]...)
	sanitized = append(sanitized, message[bodyStart+skip:]...)
	return sanitized, strings.TrimSpace(value), true
}

func normalizeAgentEmailAuthValidationURL(rawURL string) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", nil
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return "", fmt.Errorf("must be an absolute https URL")
	}

	return parsed.String(), nil
}

func ruleLookupKeys(userName string) []string {
	normalized := normalizeAddress(userName)
	if normalized == "" {
		return nil
	}

	keys := []string{normalized}
	localPart, domain, ok := strings.Cut(normalized, "@")
	if !ok || localPart == "" || domain == "" {
		return keys
	}

	addKey := func(separator string) {
		idx := strings.Index(localPart, separator)
		if idx <= 0 {
			return
		}

		key := localPart[:idx] + "@" + domain
		for _, existing := range keys {
			if existing == key {
				return
			}
		}
		keys = append(keys, key)
	}

	addKey("+")
	addKey("-")

	return keys
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
	agentEmailAuthValidationURLFlag := flag.String("agent-email-auth-validation-url", "", "HTTPS authserver validation URL for X-Agent-Email-Auth tokens")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
	}

	agentEmailAuthValidationURL, err := normalizeAgentEmailAuthValidationURL(*agentEmailAuthValidationURLFlag)
	if err != nil {
		log.Fatalf("invalid -agent-email-auth-validation-url: %v", err)
	}

	rules, err := loadRules(flag.Arg(0))
	if err != nil {
		log.Fatalf("unable to load denylist: %v", err)
	}
	debug("Loaded %d rules", len(rules))

	denyRelay := opensmtpd.NewFilter(&DenyRelayFilter{
		rules:                       rules,
		agentEmailAuthValidationURL: agentEmailAuthValidationURL,
		agentEmailAuthHTTPClient:    &http.Client{Timeout: 10 * time.Second},
	})
	opensmtpd.Run(denyRelay)
}
