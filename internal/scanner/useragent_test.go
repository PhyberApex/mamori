package scanner_test

import (
	"net/http"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func TestUserAgentTransportSetsDefaultWhenAbsent(t *testing.T) {
	base := &recordingTransport{}
	rt := scanner.NewUserAgentTransport(base, "1.2.3")

	roundTrip(t, rt, newRequest(t, "http://a.example/"))

	got := base.lastUserAgent()
	want := "mamori/1.2.3 (+https://github.com/PhyberApex/mamori)"
	if got != want {
		t.Errorf("User-Agent = %q, want %q", got, want)
	}
}

func TestUserAgentTransportReportsDevVersion(t *testing.T) {
	base := &recordingTransport{}
	rt := scanner.NewUserAgentTransport(base, "dev")

	roundTrip(t, rt, newRequest(t, "http://a.example/"))

	got := base.lastUserAgent()
	want := "mamori/dev (+https://github.com/PhyberApex/mamori)"
	if got != want {
		t.Errorf("User-Agent = %q, want %q", got, want)
	}
}

func TestUserAgentTransportLeavesExistingHeaderUntouched(t *testing.T) {
	base := &recordingTransport{}
	rt := scanner.NewUserAgentTransport(base, "1.2.3")

	req := newRequest(t, "http://a.example/")
	req.Header.Set("User-Agent", "custom-agent/1.0")
	roundTrip(t, rt, req)

	got := base.lastUserAgent()
	want := "custom-agent/1.0"
	if got != want {
		t.Errorf("User-Agent = %q, want %q (an existing header must win over the default)", got, want)
	}
}

func TestUserAgentTransportDoesNotMutateCallersRequest(t *testing.T) {
	base := &recordingTransport{}
	rt := scanner.NewUserAgentTransport(base, "1.2.3")

	req := newRequest(t, "http://a.example/")
	roundTrip(t, rt, req)

	if got := req.Header.Get("User-Agent"); got != "" {
		t.Errorf("caller's original request Header mutated: User-Agent = %q, want unset (RoundTripper contract forbids modifying the request passed in)", got)
	}
}

func TestUserAgentTransportNilBaseUsesDefaultTransport(t *testing.T) {
	rt := scanner.NewUserAgentTransport(nil, "1.2.3")
	if rt.Base != http.DefaultTransport {
		t.Errorf("Base = %v, want http.DefaultTransport", rt.Base)
	}
}
