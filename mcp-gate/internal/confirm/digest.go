package confirm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/portcullis/mcp-gate/internal/canon"
)

// maxPreview bounds args_preview (§15.7). Longer arguments are never
// confirmed: a truncated preview would hide what the person approves.
const maxPreview = 4 << 10

// ErrTooLong: the canonical arguments don't fit the preview.
var ErrTooLong = errors.New("these arguments are too long to confirm safely")

// ArgsDigest is args_sha256: the lowercase hex SHA-256 of the arguments'
// RFC 8785 canonical JSON (canon.Arguments — the same bytes the bridge
// forwards); absent / null = "{}". Arguments that can't round-trip are an
// error.
func ArgsDigest(args json.RawMessage) (string, error) {
	c, err := canon.Arguments(args)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// Preview is args_preview: the whole canonical JSON (≤ 4 KiB), else
// ErrTooLong — never clipped. It goes only to the Hub (which shows it on
// the confirmation page, escaped); never to a log.
func Preview(args json.RawMessage) (string, error) {
	c, err := canon.Arguments(args)
	if err != nil {
		return "", err
	}
	if len(c) > maxPreview {
		return "", ErrTooLong
	}
	return string(c), nil
}
