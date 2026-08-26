package scanner

import (
	"fmt"
	"net/http"
)

// PathChecker is a checker category parallel to Checker (headers) and
// BodyChecker (body): it declares a path to probe at a target's origin and
// judges the response's status code, rather than headers or a body already
// fetched for the plain scan request. Scan issues one dedicated request per
// configured PathChecker per target — see scanExposurePaths — and only pays
// for those extra requests when at least one PathChecker is configured,
// mirroring how BodyChecker's extra body fetch is opt-in.
type PathChecker interface {
	// Path is root-relative (no leading slash), resolved against the
	// target's scheme+host regardless of any path component in the target
	// URL itself.
	Path() string
	// Check judges the probe response's status code, returning no Finding
	// for anything that isn't a confirmed hit.
	Check(statusCode int) []Finding
}

// exposureReference is shared by every ExposureChecker Finding rather than a
// citation per path: they're all instances of the same underlying testing
// concern (exposed backup/config/sensitive files), not distinct
// vulnerability classes.
const exposureReference = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Test_for_Backup_and_Unreferenced_Files_or_Applications"

// ExposureChecker is a PathChecker that flags a well-known sensitive path
// (e.g. .git/config, .env) as exposed when it's reachable at a target's
// origin. severity is fixed per instance, matching how severity is already
// fixed per checker instance elsewhere in this package rather than computed
// per Finding.
type ExposureChecker struct {
	path     string
	severity Severity
}

// NewExposureChecker builds an ExposureChecker for path at the given
// severity — the constructor exists because path/severity are unexported, so
// ExposureChecker's zero value alone can't be configured into a usable
// checker from outside the package.
func NewExposureChecker(path string, severity Severity) ExposureChecker {
	return ExposureChecker{path: path, severity: severity}
}

func (c ExposureChecker) Path() string { return c.path }

// Check treats 200/206 as a full-severity hit: the path is directly
// readable. 403 is still a hit — the server recognized and blocked this
// specific path rather than treating it like every other nonexistent one, so
// its existence is confirmed — but one severity step down from 200/206,
// since access is at least blocked. Any other status, in particular 404, is
// clean and produces no Finding: Scan's baseline probe (see
// scanExposurePaths) is what makes a non-404 status here trustworthy rather
// than a false positive from a soft-404/catch-all server.
func (c ExposureChecker) Check(statusCode int) []Finding {
	switch statusCode {
	case http.StatusOK, http.StatusPartialContent:
		return []Finding{c.finding(c.severity, fmt.Sprintf("responded %d: the path is directly readable", statusCode))}
	case http.StatusForbidden:
		return []Finding{c.finding(lowerSeverity(c.severity), "responded 403: the path exists (the server treated it differently from an unrecognized path) but direct access is blocked")}
	default:
		return nil
	}
}

func (c ExposureChecker) finding(severity Severity, message string) Finding {
	return Finding{
		Header:    c.path,
		Status:    StatusExposed,
		Severity:  severity,
		Reference: exposureReference,
		Message:   message,
	}
}

// lowerSeverity steps a severity down one level, floored at low, for
// ExposureChecker's 403 case: the path's existence is confirmed but access
// is blocked, so it's never a full-severity hit but also never disappears
// entirely at the bottom of the scale.
func lowerSeverity(s Severity) Severity {
	switch s {
	case SeverityHigh:
		return SeverityMedium
	case SeverityMedium:
		return SeverityLow
	default:
		return SeverityLow
	}
}

// extraExposurePathSeverity is the fixed severity assigned to a
// user-supplied extra path (see PathCheckersFor): there's no way to infer
// how sensitive an arbitrary user-supplied path is from its name alone, so
// it gets a fixed middle-of-the-road severity rather than guessing.
const extraExposurePathSeverity = SeverityMedium

// DefaultExposurePaths lists the well-known sensitive paths ExposureChecker
// probes for when the category is enabled: version control metadata,
// environment files, credential stores, and common backup-file patterns.
// User configuration can only extend this list (see PathCheckersFor), never
// replace or disable any of its entries.
func DefaultExposurePaths() []PathChecker {
	return []PathChecker{
		NewExposureChecker(".git/config", SeverityHigh),
		NewExposureChecker(".git/HEAD", SeverityHigh),
		NewExposureChecker(".env", SeverityHigh),
		NewExposureChecker(".DS_Store", SeverityLow),
		// .htpasswd holds credential hashes and web.config can hold
		// connection strings/secrets, so both get the same high severity as
		// .git/* and .env rather than the DefaultExposurePaths doc
		// comment's other two categories (low/medium), neither of which
		// fits a credentials or secrets file.
		NewExposureChecker(".htpasswd", SeverityHigh),
		NewExposureChecker("web.config", SeverityHigh),
		NewExposureChecker("wp-config.php.bak", SeverityMedium),
		NewExposureChecker("config.php.bak", SeverityMedium),
		NewExposureChecker("backup.zip", SeverityMedium),
		NewExposureChecker("backup.tar.gz", SeverityMedium),
	}
}

// PathCheckersFor builds the effective PathChecker set for a scan from the
// resolved config: enabled turns on DefaultExposurePaths, and extra adds to
// it — supplying at least one extra path enables the category on its own,
// even when enabled is false, since adding a path can't be a silent no-op.
// A nil/empty result (both enabled is false and extra is empty) tells Scan
// the category is off entirely, so it skips the extra probe requests. An
// extra path already in the default list is probed once, not twice.
func PathCheckersFor(enabled bool, extra []string) []PathChecker {
	if !enabled && len(extra) == 0 {
		return nil
	}
	checkers := DefaultExposurePaths()
	seen := make(map[string]bool, len(checkers))
	for _, c := range checkers {
		seen[c.Path()] = true
	}
	for _, path := range extra {
		if seen[path] {
			continue
		}
		seen[path] = true
		checkers = append(checkers, NewExposureChecker(path, extraExposurePathSeverity))
	}
	return checkers
}
