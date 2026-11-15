package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/mailctl/internal/state"
)

// queued is one message as the checks read it.
type queued struct {
	CreatedAt  time.Time
	ReturnPath string
	Rcpts      []rcpt
}

type rcpt struct {
	Addr       string
	Status     string // Scheduled | Completed | TemporaryFailure | PermanentFailure
	ErrorType  string
	Host       string // responseHostname, else the error message
	RetryCount int
}

// queueMax bounds the messages read.
const queueMax = 1000

func readQueue(ctx context.Context, d Deps) ([]queued, error) {
	ids, err := d.C.Query(ctx, "QueuedMessage", nil)
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	if len(ids) > queueMax {
		ids = ids[:queueMax]
	}
	var ms []struct {
		CreatedAt  time.Time `json:"createdAt"`
		ReturnPath string    `json:"returnPath"`
		Recipients map[string]struct {
			RetryCount int             `json:"retryCount"`
			Status     json.RawMessage `json:"status"`
		} `json:"recipients"`
	}
	if err := d.C.Get(ctx, "QueuedMessage", ids, []string{"createdAt", "returnPath", "recipients"}, &ms); err != nil {
		return nil, err
	}
	out := make([]queued, 0, len(ms))
	for _, m := range ms {
		q := queued{CreatedAt: m.CreatedAt, ReturnPath: strings.ToLower(m.ReturnPath)}
		for addr, r := range m.Recipients {
			var st struct {
				Type      string  `json:"@type"`
				ErrorType string  `json:"errorType"`
				Host      *string `json:"responseHostname"`
				Message   *string `json:"errorMessage"`
			}
			_ = json.Unmarshal(r.Status, &st)
			h := ""
			if st.Host != nil {
				h = *st.Host
			} else if st.Message != nil {
				h = *st.Message
			}
			q.Rcpts = append(q.Rcpts, rcpt{Addr: strings.ToLower(addr), Status: st.Type, ErrorType: st.ErrorType, Host: h, RetryCount: r.RetryCount})
		}
		out = append(out, q)
	}
	return out, nil
}

func localDomain(doc *state.Doc, addr string) bool {
	_, dom, _ := strings.Cut(addr, "@")
	if dom == state.ParkingDomain {
		return true
	}
	if doc != nil {
		for _, d := range doc.Domains {
			if d.Name == dom {
				return true
			}
		}
	}
	return false
}

const extPort25 = "port25_reached_at"

// Port25Steps are the provider guidance when outbound port 25 is blocked.
var Port25Steps = []string{
	"Your hosting provider blocks outbound port 25: ask it to open the port for this server, or send through a relay (MAIL_RELAY_HOST in .env, then ./portcullis mail enable).",
	"Hetzner: request it in the Cloud Console once the first invoice is paid (Support → Limits → \"Unblock port 25\").",
	"DigitalOcean: outbound SMTP stays blocked on new accounts; ask support or use a relay.",
	"AWS EC2: submit the \"Request to remove email sending limitations\" form for the instance's Elastic IP.",
	"AWS Lightsail: submit the \"Request to remove email sending limitations\" form for the static IP.",
	"OVH: port 25 is open by default; check the server's firewall (Network → Firewall) and the anti-spam block.",
}

// port25 reads only the queue (never a probe, P3): every outbound attempt
// of the last 24 h failed to connect across ≥ 2 distinct MX hosts and none
// was delivered → Problem; no attempt known yet → Info.
func port25(d Deps, q []queued, qerr error, p state.Persistent) Check {
	c := Check{ID: "port25"}
	if qerr != nil {
		c.Severity, c.Detail = Info, "the queue couldn't be read: not known"
		return c
	}
	now := d.now()
	reached := false
	failedHosts := map[string]bool{}
	attempts := 0
	for _, m := range q {
		if now.Sub(m.CreatedAt) > 24*time.Hour {
			continue
		}
		for _, r := range m.Rcpts {
			if localDomain(p.Doc, r.Addr) {
				continue
			}
			switch {
			case r.Status == "Completed":
				reached, attempts = true, attempts+1
			case (r.Status == "TemporaryFailure" || r.Status == "PermanentFailure") && r.ErrorType == "connectionError":
				attempts++
				failedHosts[strings.ToLower(r.Host)] = true
			case r.Status == "TemporaryFailure" || r.Status == "PermanentFailure":
				// A remote server answered (or another error): port 25 works.
				if r.ErrorType != "" && r.ErrorType != "dnsError" && r.ErrorType != "rateLimited" && r.ErrorType != "concurrencyLimited" {
					reached = true
				}
				attempts++
			}
		}
	}
	if reached {
		t := now
		_ = d.Store.Update(func(s *state.Persistent) error {
			b, _ := json.Marshal(t)
			s.Ext[extPort25] = b
			return nil
		})
	}
	var seen *time.Time
	_ = json.Unmarshal(p.Ext[extPort25], &seen)
	switch {
	case !reached && len(failedHosts) >= 2:
		hosts := make([]string, 0, len(failedHosts))
		for h := range failedHosts {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		c.Severity = Problem
		c.Detail = fmt.Sprintf("every outbound delivery of the last 24 h failed to connect (%d MX hosts: %s): outbound port 25 looks blocked", len(hosts), joinMax(hosts, 3))
		c.Steps = Port25Steps
	case reached || seen != nil:
		c.Severity, c.Detail = OK, "outbound deliveries reach remote servers"
	default:
		c.Severity, c.Detail = Info, "no outbound delivery yet: not known"
		if attempts > 0 {
			c.Detail = "not enough outbound deliveries yet to tell: not known"
		}
	}
	return c
}

// rateHeld: an account's queued messages held by the outbound limit.
func rateHeld(d Deps, q []queued, qerr error, doc *state.Doc) []Check {
	if qerr != nil || doc == nil {
		return nil
	}
	owner := map[string]string{}
	for _, a := range doc.Accounts {
		for _, addr := range a.Addresses {
			owner[strings.ToLower(addr)] = a.Username
		}
		owner[strings.ToLower(a.Username+"@"+doc.PrimaryDomain)] = a.Username
	}
	for _, al := range doc.Aliases {
		owner[strings.ToLower(al.Address)] = al.Username
	}
	held := map[string]int{}
	for _, m := range q {
		u := owner[m.ReturnPath]
		if u == "" {
			continue
		}
		for _, r := range m.Rcpts {
			if r.Status == "TemporaryFailure" && r.ErrorType == "rateLimited" {
				held[u]++
				break
			}
		}
	}
	users := make([]string, 0, len(held))
	for u := range held {
		users = append(users, u)
	}
	sort.Strings(users)
	var out []Check
	for _, u := range users {
		out = append(out, Check{ID: "rate_held:" + u, Severity: Warning,
			Detail: fmt.Sprintf("%d of %s's queued messages are held by the outbound limit (%d recipients per hour, %d per day)", held[u], u, doc.Limits.RecipientsPerHour, doc.Limits.RecipientsPerDay),
			Steps: []string{"If this isn't expected, the account's password may be stolen: revoke its mail passwords in Settings → Mail.",
				"Otherwise raise the limits in Settings → Mail; held messages go out as the limit allows."}})
	}
	return out
}
