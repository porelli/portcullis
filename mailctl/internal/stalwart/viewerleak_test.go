package stalwart

import "testing"

// ViewerSecretLeaks judges masking per object and field from the schema
// (R2-M1), never by a property name: "key" is plain on MtaOutboundThrottle
// though secret elsewhere, a credential's sibling fields stay plain, an
// unknown field is plain, a patch key is resolved segment by segment.
func TestViewerSecretLeaks(t *testing.T) {
	ty, err := ParseTypes(loadSnapshotRaw(t))
	if err != nil {
		t.Fatal(err)
	}
	const s = "sentinel-0123456789"
	for name, c := range map[string]struct {
		obj  string
		v    map[string]any
		want int
	}{
		"plain description":                   {"Domain", map[string]any{"description": "x" + s}, 1},
		"key is plain on MtaOutboundThrottle": {"MtaOutboundThrottle", map[string]any{"key": map[string]any{s: true}}, 1},
		"key as a throttle value":             {"MtaOutboundThrottle", map[string]any{"key": map[string]any{"rcpt": true}, "description": s}, 1},
		"DKIM private key masked":             {"DkimSignature", map[string]any{"@type": "Dkim1Ed25519Sha256", "privateKey": map[string]any{"@type": "Text", "secret": s}}, 0},
		"password credential masked":          {"Account", map[string]any{"@type": "User", "credentials": map[string]any{"0": map[string]any{"@type": "Password", "secret": s}}}, 0},
		"a credential's plain sibling":        {"Account", map[string]any{"@type": "User", "credentials": map[string]any{"0": map[string]any{"@type": "AppPassword", "secret": "x", "description": s}}}, 1},
		"masked pointer patch":                {"Account", map[string]any{"credentials/0/secret": s}, 0},
		"plain pointer patch":                 {"Account", map[string]any{"credentials/0/description": s}, 1},
		"unknown field is plain":              {"Domain", map[string]any{"notAField": s}, 1},
		"expression literal":                  {"MtaStageData", map[string]any{"addReceivedHeader": map[string]any{"else": "'" + s + "'"}}, 1},
		"denied object":                       {"SpamDnsblServer", map[string]any{"zone": map[string]any{"else": s}}, 0},
		"denied queue":                        {"QueuedMessage", map[string]any{"x": s}, 0},
	} {
		if got := ViewerSecretLeaks(ty, c.obj, c.v, s); len(got) != c.want {
			t.Errorf("%s: %v, want %d leak(s)", name, got, c.want)
		}
	}
}
