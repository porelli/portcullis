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

// lookupsCheck: the spam rules' external lookups found on and not turned
// off (bootstrap.SpamRulesPass) is a Problem: surprise egress.
func lookupsCheck(p state.Persistent) Check {
	s := bootstrap.ReadLookups(p)
	switch {
	case s.CheckedAt == nil:
		return Check{ID: "external_lookups", Severity: Info, Detail: "the spam rules' external lookups haven't been checked yet"}
	case s.Error != "":
		return Check{ID: "external_lookups", Severity: Problem,
			Detail: "the spam rules' external lookups may be on and couldn't be turned off (the spam filter may contact outside feeds): " + s.Error,
			Steps:  []string{"Check mailctl's log (docker compose logs mailctl) for \"spam rules\"; mailctl retries every minute."}}
	}
	return Check{ID: "external_lookups", Severity: OK, Detail: "the spam rules' external lookups are off"}
}
