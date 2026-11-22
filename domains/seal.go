package main

// `domains seal <age recipient>` / `domains unseal` (Task 29 fix round 1,
// I2): the front door's two Secrets in a core backup, age-encrypted to the
// domains service's own key (secrets/domains/age.key) like
// domains_data/store.age. seal: the plaintext on stdin (≤ 1 MiB), the
// armored age file on stdout. unseal: stdin = the identity file (its
// lines, comments allowed) then the armored file; the plaintext on stdout.
// Nothing on argv but the public recipient; nothing logged.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const sealMax = 1 << 20

func runSeal(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 1 || !strings.HasPrefix(args[0], "age1") {
		fmt.Fprintln(stderr, "usage: domains seal <age1… recipient>  (plaintext on stdin)")
		return exitUsage
	}
	r, err := age.ParseX25519Recipient(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "domains seal: the recipient: %v\n", err)
		return exitUsage
	}
	plain, err := io.ReadAll(io.LimitReader(stdin, sealMax+1))
	if err != nil || len(plain) > sealMax || len(plain) == 0 {
		fmt.Fprintln(stderr, "domains seal: stdin must hold 1 byte to 1 MiB")
		return exitUsage
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, r)
	if err == nil {
		_, err = w.Write(plain)
	}
	if err == nil {
		err = w.Close()
	}
	if err == nil {
		err = aw.Close()
	}
	if err != nil {
		fmt.Fprintf(stderr, "domains seal: %v\n", err)
		return exitFailure
	}
	_, _ = stdout.Write(buf.Bytes())
	return exitOK
}

func runUnseal(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: domains unseal  (stdin: the age identity file, then the armored file)")
		return exitUsage
	}
	in := bufio.NewReader(io.LimitReader(stdin, 4*sealMax))
	var idText strings.Builder
	var rest bytes.Buffer
	for {
		line, err := in.ReadString('\n')
		// (an identity file without a final newline puts the header on
		// its last line: split there)
		if i := strings.Index(line, armor.Header); i >= 0 {
			idText.WriteString(line[:i] + "\n")
			rest.WriteString(line[i:])
			_, _ = io.Copy(&rest, in)
			break
		}
		idText.WriteString(line)
		if err != nil {
			break
		}
	}
	ids, err := age.ParseIdentities(strings.NewReader(idText.String()))
	if err != nil || rest.Len() == 0 {
		fmt.Fprintln(stderr, "domains unseal: stdin must be the age identity file, then the armored file")
		return exitUsage
	}
	r, err := age.Decrypt(armor.NewReader(&rest), ids...)
	if err != nil {
		fmt.Fprintf(stderr, "domains unseal: decrypt (another secrets/domains/age.key?): %v\n", err)
		return exitProblem
	}
	plain, err := io.ReadAll(io.LimitReader(r, sealMax+1))
	if err != nil || len(plain) > sealMax {
		fmt.Fprintln(stderr, "domains unseal: unreadable or over 1 MiB")
		return exitProblem
	}
	_, _ = stdout.Write(plain)
	return exitOK
}
