// Package wellknown serves the mail domains' well-known files behind
// Traefik (contract §19.7): the MTA-STS policy, Thunderbird autoconfig and
// Outlook autodiscover. Exact paths only, the Host checked against the mail
// domains; anything else is 404.
package wellknown

import (
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"strings"
)

// Source is what the handler serves.
type Source interface {
	// MailDomain reports a domain mail is on (or draining) for.
	MailDomain(domain string) bool
	// Policy is the domain's MTA-STS policy text ("" = none).
	Policy(domain string) string
	// Hostname is MAIL_HOSTNAME.
	Hostname() string
}

func host(r *http.Request) string {
	h := strings.ToLower(r.Host)
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.TrimSuffix(h, ".")
}

// Handler serves the files.
func Handler(src Source) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := host(r)
		label, domain, _ := strings.Cut(h, ".")
		if domain == "" || !src.MailDomain(domain) {
			http.NotFound(w, r)
			return
		}
		switch {
		case label == "mta-sts" && r.URL.Path == "/.well-known/mta-sts.txt" && r.Method == http.MethodGet:
			p := src.Policy(domain)
			if p == "" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Cache-Control", "max-age=300")
			io.WriteString(w, p)
		case label == "autoconfig" && r.Method == http.MethodGet &&
			(r.URL.Path == "/mail/config-v1.1.xml" || r.URL.Path == "/.well-known/autoconfig/mail/config-v1.1.xml"):
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("Cache-Control", "max-age=300")
			io.WriteString(w, autoconfig(domain, src.Hostname()))
		case label == "autodiscover" && r.Method == http.MethodPost && strings.EqualFold(r.URL.Path, "/autodiscover/autodiscover.xml"):
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("Cache-Control", "no-store")
			io.WriteString(w, autodiscover(requestedAddress(r, src), src.Hostname()))
		default:
			http.NotFound(w, r)
		}
	})
}

func esc(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func autoconfig(domain, mx string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="` + esc(domain) + `">
    <domain>` + esc(domain) + `</domain>
    <displayName>` + esc(domain) + `</displayName>
    <incomingServer type="imap">
      <hostname>` + esc(mx) + `</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>` + esc(mx) + `</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>
`
}

// requestedAddress is the request's EMailAddress when it parses and is on
// a mail domain ("" otherwise).
func requestedAddress(r *http.Request, src Source) string {
	var req struct {
		Request struct {
			EMailAddress string `xml:"EMailAddress"`
		} `xml:"Request"`
	}
	if err := xml.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		return ""
	}
	a := strings.ToLower(strings.TrimSpace(req.Request.EMailAddress))
	local, dom, ok := strings.Cut(a, "@")
	if !ok || local == "" || strings.ContainsAny(local, " <>\"&'\\") || !src.MailDomain(dom) {
		return ""
	}
	return a
}

func autodiscover(addr, mx string) string {
	login := ""
	if addr != "" {
		login = "\n        <LoginName>" + esc(addr) + "</LoginName>"
	}
	return `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>` + esc(mx) + `</Server>
        <Port>993</Port>
        <SSL>on</SSL>
        <SPA>off</SPA>
        <AuthRequired>on</AuthRequired>` + login + `
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>` + esc(mx) + `</Server>
        <Port>465</Port>
        <SSL>on</SSL>
        <SPA>off</SPA>
        <AuthRequired>on</AuthRequired>` + login + `
      </Protocol>
    </Account>
  </Response>
</Autodiscover>
`
}
