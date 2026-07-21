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

// The json struct tags pin the wire names independently of the Go field
// names, so renaming a field during a refactor can never silently break
// downstream jq pipelines. Without a tag, encoding/json would emit the
// exported (capitalized) field name instead.
type Finding struct {
	URL       string   `json:"url"`
	Header    string   `json:"header"`
	Status    Status   `json:"status"`
	Severity  Severity `json:"severity"`
	Reference string   `json:"reference"`
	Message   string   `json:"message"`
}
