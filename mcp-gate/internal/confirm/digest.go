package confirm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

// maxPreview bounds args_preview (§15.7).
const maxPreview = 4 << 10

// canonical is the RFC 8785 canonical JSON of tools/call arguments;
// absent or null arguments are {} (§15.6).
func canonical(args json.RawMessage) ([]byte, error) {
	t := bytes.TrimSpace(args)
	if len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return []byte("{}"), nil
	}
	c, err := jcs.Transform(t)
	if err != nil {
		return nil, fmt.Errorf("arguments are not canonicalisable JSON")
	}
	return c, nil
}

// ArgsDigest is args_sha256: the lowercase hex SHA-256 of the arguments'
// RFC 8785 canonical JSON (gowebpki/jcs); absent / null = "{}".
func ArgsDigest(args json.RawMessage) (string, error) {
	c, err := canonical(args)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// Preview is args_preview: the canonical JSON clipped to 4 KiB on a rune
// boundary. It goes only to the Hub (which shows it on the confirmation
// page, escaped); never to a log.
func Preview(args json.RawMessage) (string, error) {
	c, err := canonical(args)
	if err != nil {
		return "", err
	}
	if len(c) > maxPreview {
		c = c[:maxPreview]
		for len(c) > 0 && !utf8.Valid(c) {
			c = c[:len(c)-1]
		}
	}
	return string(c), nil
}
