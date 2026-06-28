## Go learning mode

This project is being used to learn Go. During all implementation work:

1. **Explain as you go** — when using a Go-specific concept (interfaces, goroutines, channels, defer, error wrapping, struct embedding, etc.), add a short "why we do it this way in Go" note inline. Skip basic syntax; focus on idiomatic choices and Go-specific patterns that would surprise someone coming from another language.

2. **Quiz after each implementation** — end every implementation response with 2–3 quiz questions under a `## Quiz ✦` heading. Questions must:
   - Require looking something up (`go doc`, the Go spec, or the Go blog) to answer confidently — not answerable from memory alone
   - Test understanding of what was just built, not generic trivia
   - Have **no answers given** — the user researches and can share answers back for feedback

## Agent skills

### Issue tracker

Issues live in GitHub Issues for PhyberApex/mamori. See `docs/agents/issue-tracker.md`.

### Triage labels

Default label vocabulary (needs-triage, needs-info, ready-for-agent, ready-for-human, wontfix). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout — one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
