package checks

import (
	"github.com/portcullis/mailctl/internal/bootstrap"
	"github.com/portcullis/mailctl/internal/spamrules"
	"github.com/portcullis/mailctl/internal/state"
)

// spamRulesCheck: the vendored spam rules imported and verified in
// Stalwart (bootstrap.EnsureSpamRules). Until they are, the spam filter
// runs without its rule set (no GTUBE, no scores): a Problem. Mail keeps
// flowing meanwhile (degraded, not closed).
func spamRulesCheck(p state.Persistent) Check {
	s := bootstrap.ReadSpamRules(p)
	if s.Imported == spamrules.SHA256 {
		return Check{ID: "spam_rules", Severity: OK, Detail: "the spam filter's rules are in place (spam-filter " + spamrules.Version + ")"}
	}
	detail := "Stalwart has no spam rules: the import hasn't run yet (mailctl retries every minute; the spam filter scores nothing meanwhile)"
	if s.Error != "" {
		detail += ": " + s.Error
	}
	return Check{ID: "spam_rules", Severity: Problem, Detail: detail,
		Steps: []string{"Check mailctl's log (docker compose logs mailctl) for \"spam rules\"; ./portcullis up restarts mailctl, which asks for the import again."}}
}
