package main

// domains mail-tlsa status|next|switch|drop (contract §19.3): the TLSA
// rollover state mail_acme/tlsa.json (0600, the mail-cert service's own
// uid 10004), reconciled with mail-cert's keys in the same volume. Run by
// `./portcullis mail rotate` as the mail-cert one-shot (entrypoint
// domains, the volumes of mail-cert; no network needed):
//
//	status  reconcile with /acme/mail.key and /acme/mail.next.key, write
//	        tlsa.json when it changed, print
//	        {"version","current","next","both_since","phase","due","publish"}
//	next    record mail.next.key's SPKI (after mail-cert --next-key): both
//	        published from now
//	switch  exit 0 only when the switch is due (the CLI then runs
//	        mail-cert --switch-key; the next status records it)
//	drop    end the retiring phase once it is due (the old SPKI goes)

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/portcullis/domains/internal/dnsplan"
)

type mailTLSAOutput struct {
	dnsplan.TLSAState
	Phase   string   `json:"phase"`
	Due     *string  `json:"due"`
	Publish []string `json:"publish"`
}

// tlsaNow is the clock (tests set it).
var tlsaNow = time.Now

func runMailTLSA(args []string, e toolEnv) int {
	if len(args) != 1 || (args[0] != "status" && args[0] != "next" && args[0] != "switch" && args[0] != "drop") {
		fmt.Fprintln(e.stderr, "usage: domains mail-tlsa status|next|switch|drop")
		return exitUsage
	}
	cmd := args[0]
	fail := func(err error) int {
		fmt.Fprintf(e.stderr, "domains mail-tlsa %s: %v\n", cmd, err)
		return exitProblem
	}
	acmeDir := orStr(e.acmeDir, mailCertAcmeDir)
	statePath := filepath.Join(acmeDir, "tlsa.json")
	key, err := readKeyFile(filepath.Join(acmeDir, "mail.key"))
	if err != nil {
		return fail(errors.New("no mail key yet (run ./portcullis mail cert first)"))
	}
	cur, next := spkiSHA256(key), ""
	if nk, err := readKeyFile(filepath.Join(acmeDir, "mail.next.key")); err == nil {
		next = spkiSHA256(nk)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	var prev *dnsplan.TLSAState
	b, err := os.ReadFile(statePath)
	switch {
	case err == nil:
		s, perr := dnsplan.ParseTLSAState(b)
		if perr != nil {
			return fail(perr)
		}
		prev = &s
	case !errors.Is(err, os.ErrNotExist):
		return fail(err)
	}
	now := tlsaNow()
	st, phase, due := dnsplan.TLSAStep(prev, cur, next, now)
	switch cmd {
	case "next":
		if next == "" {
			return fail(errors.New("no next key (run domains mail-cert --next-key first)"))
		}
		if st, err = dnsplan.TLSAStartRollover(st, next, now); err != nil {
			return fail(err)
		}
		st, phase, due = dnsplan.TLSAStep(&st, cur, next, now)
	case "switch":
		if due != dnsplan.TLSADueSwitch {
			return fail(fmt.Errorf("the key switch isn't due (phase %s)", phase))
		}
	case "drop":
		if st, err = dnsplan.TLSADrop(st, phase, due); err != nil {
			return fail(err)
		}
		st, phase, due = dnsplan.TLSAStep(&st, cur, next, now)
	}
	if prev == nil || string(prev.Marshal()) != string(st.Marshal()) {
		if err := writeAtomic(statePath, st.Marshal(), 0o600); err != nil {
			return fail(err)
		}
	}
	out := mailTLSAOutput{TLSAState: st, Phase: phase, Publish: st.Publish()}
	if due != "" {
		out.Due = &due
	}
	return printJSON(e, out, exitOK)
}
