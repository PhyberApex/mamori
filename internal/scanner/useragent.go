package scanner

import (
	"fmt"
	"net/http"
)

// UserAgentTransport wraps another http.RoundTripper so that every request
// it sends carries a default User-Agent identifying mamori and its version,
// unless the request already has one set — e.g. via a -H 'User-Agent: ...'
// override, applied to req.Header before RoundTrip ever sees it, which
// always wins.
type UserAgentTransport struct {
	Base      http.RoundTripper
	UserAgent string
}

// NewUserAgentTransport returns a UserAgentTransport whose default
// User-Agent identifies mamori and version, the same build-version string
// -version prints ("dev" for a plain go build/go run, the release tag for a
// goreleaser build). base is the RoundTripper that actually sends a request
// once the default has been applied; nil selects http.DefaultTransport, the
// same zero-value behavior http.Client.Transport itself has.
func NewUserAgentTransport(base http.RoundTripper, version string) *UserAgentTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &UserAgentTransport{
		Base:      base,
		UserAgent: fmt.Sprintf("mamori/%s (+https://github.com/PhyberApex/mamori)", version),
	}
}

// RoundTrip clones req before setting the default User-Agent, rather than
// mutating req.Header directly, since a RoundTripper must not modify the
// request it was handed.
func (t *UserAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(req.Header.Values("User-Agent")) == 0 {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", t.UserAgent)
	}
	return t.Base.RoundTrip(req)
}
