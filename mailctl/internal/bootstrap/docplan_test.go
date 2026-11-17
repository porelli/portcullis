package bootstrap

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/stalwart/fake"
	"github.com/portcullis/mailctl/internal/state"
)

// MailState v2 carries the relay, the host name and the client address
// mode: the adapter converges them from the document, idempotently.
func TestApplyDocFollowsDocument(t *testing.T) {
	f := fake.New()
	t.Cleanup(f.Close)
	c := stalwart.New(f.URL(), stalwart.Bearer("API_k"))
	b, _ := os.ReadFile("../state/testdata/mailstate_v2.json")
	doc, err := state.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if ch, err := ApplyDoc(context.Background(), c, doc); err != nil || !ch {
		t.Fatalf("first: %v %v", ch, err)
	}
	routes := func() string {
		var n []string
		for _, r := range f.Objects("MtaRoute", "") {
			n = append(n, r["name"].(string))
		}
		return strings.Join(n, ",")
	}
	if !strings.Contains(routes(), "relay") {
		t.Fatalf("no relay route: %s", routes())
	}
	ss, _ := json.Marshal(f.Get("SystemSettings", "", "singleton"))
	ob, _ := json.Marshal(f.Get("MtaOutboundStrategy", "", "singleton"))
	if !strings.Contains(string(ss), `"defaultHostname":"mail.example.com"`) || !strings.Contains(string(ob), `'relay'`) {
		t.Fatalf("%s %s", ss, ob)
	}
	f.ResetCalls()
	if ch, err := ApplyDoc(context.Background(), c, doc); err != nil || ch || f.Count("x:Action") != 0 {
		t.Fatalf("second pass wrote: %v %v %v", ch, err, f.Calls)
	}
	doc.Relay = nil
	doc.ClientIP = state.ClientIPRewritten
	if _, err := ApplyDoc(context.Background(), c, doc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(routes(), "relay") {
		t.Fatalf("relay route kept: %s", routes())
	}
	sa, _ := json.Marshal(f.Get("SenderAuth", "", "singleton"))
	if !strings.Contains(string(sa), `"spfFromVerify":{"else":"disable"`) {
		t.Fatalf("degraded sender auth %s", sa)
	}
}
