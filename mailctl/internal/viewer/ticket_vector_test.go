package viewer

import (
	"strings"
	"testing"
	"time"
)

// TicketVector is the ticket format's shared vector: the Hub's
// MailAdminTicket test holds the same string.
const TicketVector = "v1.eyJ1Ijoicm9vdCIsIm4iOiJub25jZS0xIiwiZSI6MTgwMDAwMDA2MH0.h2gtGNmy3A1GfbF6Moa38GqR-VZE79oSyYECzGzrUCs"

func TestTicketVector(t *testing.T) {
	got := MintTicket(TicketKey([]byte(strings.Repeat("k", 40))), "root", "nonce-1", time.Unix(1800000060, 0))
	if got != TicketVector {
		t.Fatalf("ticket\n got %s\nwant %s", got, TicketVector)
	}
}
