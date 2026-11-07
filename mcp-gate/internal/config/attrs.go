package config

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
)

// user-attributes.json v2 (contract §4.1), read with group-gate's rules
// (group-gate.py parse_user_attributes / user_attribute_headers): a
// missing or malformed file means no attribute headers, never a deny.

const (
	attrPrefix   = "X-Forwarded-Attr-"
	attrValueMax = 1024
)

var (
	attrFieldR  = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)
	attrHeaderR = regexp.MustCompile(`^[A-Za-z0-9]+(-[A-Za-z0-9]+){0,30}$`)
	attrCtrlR   = regexp.MustCompile(`[\x00-\x1f\x7f]`)
)

// Header is one attribute header.
type Header struct{ Name, Value string }

// Attributes are the parsed user-attributes.json.
type Attributes struct {
	users    map[string][]Header
	hosts    map[string]map[string][]Header
	declared map[string]map[string]bool // host → lowercase full header names it declares
}

// Headers group-gate would send for the lowercase user on the normalised
// host: the field headers (minus those the host declares), then the
// host's headers. Nil-safe.
func (a *Attributes) Headers(host, user string) []Header {
	if a == nil {
		return nil
	}
	var out []Header
	for _, h := range a.users[user] {
		if !a.declared[host][strings.ToLower(h.Name)] {
			out = append(out, h)
		}
	}
	return append(out, a.hosts[host][user]...)
}

func attrClean(v string) string {
	v = attrCtrlR.ReplaceAllString(v, "")
	if len(v) > attrValueMax {
		return "" // dropped, never truncated
	}
	return v
}

func attrEncode(v string) string {
	return strings.ReplaceAll(strings.ReplaceAll(v, "%", "%25"), ",", "%2C")
}

// ParseAttributes parses a version 2 document.
func ParseAttributes(b []byte) (*Attributes, error) {
	var doc struct {
		Version *int                                    `json:"version"`
		Fields  map[string]string                       `json:"fields"`
		Users   map[string]map[string][]string          `json:"users"`
		Hosts   map[string]map[string]map[string]string `json:"hosts"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("malformed")
	}
	if doc.Version == nil || *doc.Version != 2 {
		return nil, fmt.Errorf("not a version 2 document")
	}
	fields := map[string]string{}
	byHeader := map[string]string{}
	for name, header := range doc.Fields {
		if len(name) > 31 || !attrFieldR.MatchString(name) || !attrHeaderR.MatchString(header) {
			log.Printf("user-attributes.json: skipping an invalid field")
			continue
		}
		if other, ok := byHeader[strings.ToLower(header)]; ok && other != name {
			return nil, fmt.Errorf("two fields on one header")
		}
		byHeader[strings.ToLower(header)] = name
		fields[name] = header
	}
	a := &Attributes{users: map[string][]Header{}, hosts: map[string]map[string][]Header{}, declared: map[string]map[string]bool{}}
	for user, values := range doc.Users {
		var hs []Header
		for name, vals := range values {
			header, ok := fields[name]
			if !ok {
				continue
			}
			var kept []string
			for _, v := range vals {
				if v = attrClean(v); v != "" {
					kept = append(kept, attrEncode(v))
				}
			}
			if len(kept) > 0 {
				hs = append(hs, Header{attrPrefix + header, strings.Join(kept, ", ")})
			}
		}
		if len(hs) > 0 {
			sort.Slice(hs, func(i, j int) bool { return hs[i].Name < hs[j].Name })
			a.users[strings.ToLower(strings.TrimSpace(user))] = hs
		}
	}
	for host, byHdr := range doc.Hosts {
		if !ValidHostname(host) {
			log.Printf("user-attributes.json: skipping a host that isn't a lowercase valid hostname")
			continue
		}
		seen := map[string]bool{}
		perUser := map[string][]Header{}
		for header, byUser := range byHdr {
			if !attrHeaderR.MatchString(header) {
				log.Printf("user-attributes.json: skipping an invalid header")
				continue
			}
			if seen[strings.ToLower(header)] {
				return nil, fmt.Errorf("a host declares one header twice")
			}
			seen[strings.ToLower(header)] = true
			if a.declared[host] == nil {
				a.declared[host] = map[string]bool{}
			}
			a.declared[host][strings.ToLower(attrPrefix+header)] = true
			users := map[string]bool{}
			for user, v := range byUser {
				folded := strings.ToLower(strings.TrimSpace(user))
				if users[folded] {
					return nil, fmt.Errorf("a host header lists one user twice")
				}
				users[folded] = true
				if v = attrClean(v); v != "" {
					perUser[folded] = append(perUser[folded], Header{attrPrefix + header, v})
				}
			}
		}
		for u := range perUser {
			sort.Slice(perUser[u], func(i, j int) bool { return perUser[u][i].Name < perUser[u][j].Name })
		}
		if len(perUser) > 0 {
			a.hosts[host] = perUser
		}
	}
	return a, nil
}
