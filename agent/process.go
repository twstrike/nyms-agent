package agent

import (
	"mime"
	"strings"

	"github.com/twstrike/pgpmail"
)

func isEncrypted(m *pgpmail.Message) bool {
	return getContentType(m) == "multipart/encrypted" || isInlineEncrypted(m)
}

func isSigned(m *pgpmail.Message) bool {
	return getContentType(m) == "multipart/signed" || isInlineSigned(m)
}

func isInlineEncrypted(m *pgpmail.Message) bool {
	return strings.Contains(m.Body, "-----BEGIN PGP MESSAGE-----")
}

func isInlineSigned(m *pgpmail.Message) bool {
	return strings.Contains(m.Body, "-----BEGIN PGP SIGNED MESSAGE-----")
}

func getContentType(m *pgpmail.Message) string {
	ct := m.GetHeaderValue("Content-Type")
	if ct == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return ""
	}
	return strings.ToLower(mt)
}
