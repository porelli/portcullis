// Package fake is an in-memory Stalwart management API for mailctl's tests:
// x:<Object>/get|query|set and x:Action with the semantics mailctl relies
// on (Task 2's fixtures): AppPasswords and ApiKeys per `accountId`, unique
// account and list addresses, set-shaped values as JSON maps, an RCPT
// lookup over accounts, aliases and lists, and failure injection.
package fake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"time"
)

// Server is the fake. Lock-free accessors take the lock themselves.
type Server struct {
	mu      sync.Mutex
	objs    map[string]map[string]map[string]any // store → id → fields
	next    int
	Calls   []string // "x:Account/set create", "x:Action/set InvalidateCaches", …
	fail    map[string]int
	refuse  map[string]string
	Now     func() time.Time
	HTTP    *httptest.Server
	secrets int
}

// New starts the fake on a loopback port.
func New() *Server {
	s := &Server{objs: map[string]map[string]map[string]any{}, fail: map[string]int{}, refuse: map[string]string{}, Now: time.Now}
	s.HTTP = httptest.NewServer(s)
	return s
}

// URL is the management listener's base URL.
func (s *Server) URL() string { return s.HTTP.URL }

// Close stops the server.
func (s *Server) Close() { s.HTTP.Close() }

// Fail makes the next n calls whose "method[ verb]" starts with prefix
// answer HTTP 500 (e.g. "x:Account/set").
func (s *Server) Fail(prefix string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail[prefix] = n
}

// Refuse makes every create of obj fail with SetError forbidden.
func (s *Server) Refuse(obj, why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuse[obj] = why
}

func store(obj, acct string) string {
	if obj == "AppPassword" || obj == "ApiKey" {
		return obj + "@" + acct
	}
	return obj
}

func normalize(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// Put stores an object directly; returns its id.
func (s *Server) Put(obj, acct string, fields map[string]any) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putLocked(store(obj, acct), fields)
}

func (s *Server) putLocked(st string, fields map[string]any) string {
	if s.objs[st] == nil {
		s.objs[st] = map[string]map[string]any{}
	}
	s.next++
	id := fmt.Sprintf("i%d", s.next)
	s.objs[st][id] = normalize(fields)
	return id
}

// Objects returns copies of every object of a type (AppPassword: of one
// account), each with its "id".
func (s *Server) Objects(obj, acct string) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	ids := make([]string, 0)
	for id := range s.objs[store(obj, acct)] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		c := normalize(s.objs[store(obj, acct)][id])
		c["id"] = id
		out = append(out, c)
	}
	return out
}

// Get returns one object (nil when missing).
func (s *Server) Get(obj, acct, id string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objs[store(obj, acct)][id]
	if !ok {
		return nil
	}
	c := normalize(o)
	c["id"] = id
	return c
}

// Count of calls whose text starts with prefix.
func (s *Server) Count(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.Calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// ResetCalls clears the call log.
func (s *Server) ResetCalls() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Calls = nil
}

func (s *Server) domainName(id string) string {
	if d, ok := s.objs["Domain"][id]; ok {
		n, _ := d["name"].(string)
		return n
	}
	return ""
}

// Resolve is the RCPT lookup: "account <id>" for a login or an alias,
// "list <id>" for a list address, "" when the address doesn't exist.
func (s *Server) Resolve(addr string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, a := range s.objs["Account"] {
		if fmt.Sprintf("%v@%s", a["name"], s.domainName(fmt.Sprint(a["domainId"]))) == addr {
			return "account " + id
		}
		if al, ok := a["aliases"].(map[string]any); ok {
			for _, x := range al {
				m, _ := x.(map[string]any)
				if fmt.Sprintf("%v@%s", m["name"], s.domainName(fmt.Sprint(m["domainId"]))) == addr {
					return "account " + id
				}
			}
		}
	}
	for id, l := range s.objs["MailingList"] {
		if fmt.Sprintf("%v@%s", l["name"], s.domainName(fmt.Sprint(l["domainId"]))) == addr {
			return "list " + id
		}
	}
	return ""
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MethodCalls [][3]json.RawMessage `json:"methodCalls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.MethodCalls) != 1 {
		w.WriteHeader(400)
		return
	}
	var method string
	json.Unmarshal(req.MethodCalls[0][0], &method)
	var args map[string]json.RawMessage
	json.Unmarshal(req.MethodCalls[0][1], &args)
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, n := range s.fail {
		if n > 0 && strings.HasPrefix(method, p) {
			s.fail[p] = n - 1
			w.WriteHeader(500)
			return
		}
	}
	parts := strings.SplitN(strings.TrimPrefix(method, "x:"), "/", 2)
	obj, verb := parts[0], parts[1]
	var acct string
	json.Unmarshal(args["accountId"], &acct)
	st := store(obj, acct)
	var out any
	switch verb {
	case "query":
		var filter map[string]any
		json.Unmarshal(args["filter"], &filter)
		var pos int
		json.Unmarshal(args["position"], &pos)
		ids := []string{}
		if pos == 0 {
			for id, o := range s.objs[st] {
				ok := true
				for k, v := range filter {
					if fmt.Sprint(o[k]) != fmt.Sprint(v) {
						ok = false
					}
				}
				if ok {
					ids = append(ids, id)
				}
			}
			sort.Strings(ids)
		}
		s.Calls = append(s.Calls, method)
		out = map[string]any{"ids": ids}
	case "get":
		var ids []string
		json.Unmarshal(args["ids"], &ids)
		if ids == nil {
			for id := range s.objs[st] {
				ids = append(ids, id)
			}
			sort.Strings(ids)
		}
		list := []any{}
		for _, id := range ids {
			if o, ok := s.objs[st][id]; ok {
				c := normalize(o)
				c["id"] = id
				if obj == "AppPassword" || obj == "ApiKey" {
					c["secret"] = "****"
				}
				list = append(list, c)
			}
		}
		s.Calls = append(s.Calls, method)
		out = map[string]any{"list": list}
	case "set":
		out = s.setLocked(method, obj, st, args)
	}
	json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{method, out, "0"}}})
}

func (s *Server) setLocked(method, obj, st string, args map[string]json.RawMessage) map[string]any {
	var create map[string]map[string]any
	var update map[string]map[string]any
	var destroy []string
	json.Unmarshal(args["create"], &create)
	json.Unmarshal(args["update"], &update)
	json.Unmarshal(args["destroy"], &destroy)
	res := map[string]any{}
	// Destroys first, then creates, then updates (deterministic for tests).
	if len(destroy) > 0 {
		s.Calls = append(s.Calls, method+" destroy "+strings.Join(destroy, ","))
		done := []string{}
		for _, id := range destroy {
			if _, ok := s.objs[st][id]; ok {
				delete(s.objs[st], id)
				done = append(done, id)
			}
		}
		res["destroyed"] = done
	}
	if len(create) > 0 {
		cids := make([]string, 0, len(create))
		for cid := range create {
			cids = append(cids, cid)
		}
		sort.Strings(cids)
		created, notCreated := map[string]any{}, map[string]any{}
		for _, cid := range cids {
			o := create[cid]
			if obj == "Action" {
				s.Calls = append(s.Calls, method+" "+fmt.Sprint(o["@type"]))
				s.next++
				created[cid] = map[string]any{"id": fmt.Sprintf("a%d", s.next)}
				continue
			}
			s.Calls = append(s.Calls, method+" create")
			if why := s.refuse[obj]; why != "" {
				notCreated[cid] = map[string]any{"type": "forbidden", "description": why}
				continue
			}
			if obj == "Account" || obj == "MailingList" {
				if s.nameTakenLocked(fmt.Sprint(o["name"]), fmt.Sprint(o["domainId"]), "") {
					notCreated[cid] = map[string]any{"type": "alreadyExists", "description": "name taken"}
					continue
				}
			}
			if obj == "AppPassword" {
				if ips, ok := o["allowedIps"].(map[string]any); ok {
					for ip := range ips {
						if strings.HasSuffix(ip, "/0") {
							notCreated[cid] = map[string]any{"type": "invalidPatch", "properties": []string{"allowedIps"}}
						}
					}
					if _, bad := notCreated[cid]; bad {
						continue
					}
				}
			}
			if obj == "AppPassword" || obj == "ApiKey" || obj == "Account" {
				o["createdAt"] = s.Now().UTC().Format(time.RFC3339)
			}
			id := s.putLocked(st, o)
			c := map[string]any{"id": id}
			if obj == "AppPassword" || obj == "ApiKey" {
				s.secrets++
				prefix := "app_"
				if obj == "ApiKey" {
					prefix = "API_"
				}
				c["secret"] = fmt.Sprintf("%s%036d", prefix, s.secrets)
			}
			created[cid] = c
		}
		res["created"], res["notCreated"] = created, notCreated
	}
	if len(update) > 0 {
		updated, notUpdated := map[string]any{}, map[string]any{}
		for id, p := range update {
			s.Calls = append(s.Calls, method+" update")
			if st != obj && s.objs[st][id] == nil && id != "singleton" {
				notUpdated[id] = map[string]any{"type": "notFound"}
				continue
			}
			if s.objs[st] == nil {
				s.objs[st] = map[string]map[string]any{}
			}
			cur := s.objs[st][id]
			if cur == nil {
				if id != "singleton" {
					notUpdated[id] = map[string]any{"type": "notFound"}
					continue
				}
				cur = map[string]any{}
				s.objs[st][id] = cur
			}
			if obj == "Account" || obj == "MailingList" {
				n, d := cur["name"], cur["domainId"]
				if v, ok := p["name"]; ok {
					n = v
				}
				if v, ok := p["domainId"]; ok {
					d = v
				}
				if s.nameTakenLocked(fmt.Sprint(n), fmt.Sprint(d), id) {
					notUpdated[id] = map[string]any{"type": "alreadyExists"}
					continue
				}
			}
			for k, v := range normalize(p) {
				cur[k] = v
			}
			updated[id] = nil
		}
		res["updated"], res["notUpdated"] = updated, notUpdated
	}
	return res
}

func (s *Server) nameTakenLocked(name, domainID, except string) bool {
	for _, kind := range []string{"Account", "MailingList"} {
		for id, o := range s.objs[kind] {
			if id != except && fmt.Sprint(o["name"]) == name && fmt.Sprint(o["domainId"]) == domainID {
				return true
			}
		}
	}
	return false
}
