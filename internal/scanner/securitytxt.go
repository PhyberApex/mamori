package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

const securityTxtReference = "https://www.rfc-editor.org/rfc/rfc9116"

// SecurityTxtChecker probes RFC 9116's well-known security.txt path as a
// request separate from the main target scan: unlike the header checkers, it
// needs its own round trip rather than inspecting the response already
// fetched for the target URL. This is a well-known, publicly-intended
// discovery path (unlike arbitrary file probing), so it runs unconditionally
// alongside the header checkers rather than needing an opt-in flag.
type SecurityTxtChecker struct{}

func (SecurityTxtChecker) Check(ctx context.Context, client *http.Client, target string) []Finding {
	probeURL, err := securityTxtURL(target)
	if err != nil {
		return []Finding{{Status: StatusError, Message: err.Error()}}
	}

	_, status, err := doRequest(ctx, client, http.MethodGet, probeURL)
	if err != nil {
		return []Finding{{Status: StatusError, Message: err.Error()}}
	}

	finding := Finding{
		Header:    "/.well-known/security.txt",
		Severity:  SeverityLow,
		Reference: securityTxtReference,
	}
	if status < 200 || status > 299 {
		finding.Status = StatusMissing
	} else {
		finding.Status = StatusPass
	}
	return []Finding{finding}
}

// securityTxtURL resolves RFC 9116's fixed well-known path against target's
// host, discarding any path/query/fragment target itself carries: the
// well-known path is always root-relative, regardless of what path the user
// asked to scan. The scheme is forced to https regardless of target's own
// scheme: RFC 9116 section 3 requires "the file access MUST use the
// 'https' scheme".
func securityTxtURL(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parsing target %q: %w", target, err)
	}
	u.Scheme = "https"
	u.Path = "/.well-known/security.txt"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
