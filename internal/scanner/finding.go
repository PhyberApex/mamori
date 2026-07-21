package scanner

type Status string

const (
	StatusPass    Status = "pass"
	StatusMissing Status = "missing"
	StatusError   Status = "error"
)

type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

type Finding struct {
	URL       string
	Header    string
	Status    Status
	Severity  Severity
	Reference string
	Message   string
}
