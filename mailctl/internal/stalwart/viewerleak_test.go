package stalwart

import "testing"

func TestViewerSecretLeaks(t *testing.T) {
	sf, err := SecretFieldNames(loadSnapshotRaw(t))
	if err != nil || !sf["secret"] || !sf["privateKey"] || sf["zone"] {
		t.Fatalf("secret fields %v %v", len(sf), err)
	}
	const s = "sentinel-0123456789"
	if l := ViewerSecretLeaks("Domain", map[string]any{"description": "x" + s}, s, sf); len(l) != 1 {
		t.Fatalf("plain field not flagged: %v", l)
	}
	if l := ViewerSecretLeaks("DkimSignature", map[string]any{"privateKey": map[string]any{"@type": "Text", "secret": s}}, s, sf); len(l) != 0 {
		t.Fatalf("masked field flagged: %v", l)
	}
	if l := ViewerSecretLeaks("Account", map[string]any{"credentials/0/secret": s}, s, sf); len(l) != 0 {
		t.Fatalf("masked pointer patch flagged: %v", l)
	}
	if l := ViewerSecretLeaks("SpamDnsblServer", map[string]any{"zone": s}, s, sf); len(l) != 0 {
		t.Fatalf("denied object flagged: %v", l)
	}
}
