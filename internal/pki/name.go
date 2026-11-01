package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strings"
)

// attributes are the distinguished-name attributes a subject is written with, by the short
// names OpenSSL and RFC 4514 use.
var attributes = map[string]asn1.ObjectIdentifier{
	"CN":           {2, 5, 4, 3},
	"SERIALNUMBER": {2, 5, 4, 5},
	"C":            {2, 5, 4, 6},
	"L":            {2, 5, 4, 7},
	"ST":           {2, 5, 4, 8},
	"STREET":       {2, 5, 4, 9},
	"O":            {2, 5, 4, 10},
	"OU":           {2, 5, 4, 11},
	"POSTALCODE":   {2, 5, 4, 17},
	"DC":           {0, 9, 2342, 19200300, 100, 1, 25},
	"UID":          {0, 9, 2342, 19200300, 100, 1, 1},
	"EMAILADDRESS": {1, 2, 840, 113549, 1, 9, 1},
}

// ParseName reads a distinguished name in either of the two ways people write one: OpenSSL's
// "/C=AU/O=Example/CN=host", most general first, or RFC 4514's "CN=host,O=Example,C=AU",
// most specific first. Either way the attributes are encoded in the order that puts the most
// general first, as both forms mean. A comma, slash, plus, equals or backslash in a value is
// written after a backslash.
func ParseName(s string) (pkix.Name, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return pkix.Name{}, errors.New("an empty subject: give one, such as \"CN=host.example\"")
	}

	sep, reversed := ',', true
	if strings.HasPrefix(s, "/") {
		sep, reversed, s = '/', false, s[1:]
	}

	parts, err := splitEscaped(s, sep)
	if err != nil {
		return pkix.Name{}, err
	}

	var atvs []pkix.AttributeTypeAndValue

	for _, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return pkix.Name{}, fmt.Errorf("%q in the subject is not KEY=VALUE", p)
		}

		k, v = strings.ToUpper(strings.TrimSpace(k)), strings.TrimSpace(v)
		if k == "EMAIL" || k == "E" {
			k = "EMAILADDRESS"
		}

		oid, ok := attributes[k]
		if !ok {
			return pkix.Name{}, fmt.Errorf("%q is not a subject attribute this writes: CN, O, OU, C, ST, L, STREET, "+
				"POSTALCODE, SERIALNUMBER, DC, UID, emailAddress", k)
		}

		if v == "" {
			return pkix.Name{}, fmt.Errorf("the subject's %s is empty", k)
		}

		if k == "C" && (len(v) != 2 || strings.ToUpper(v) != v) {
			return pkix.Name{}, fmt.Errorf("the subject's C is a two-letter country code in capitals (ISO 3166), not %q", v)
		}

		atvs = append(atvs, pkix.AttributeTypeAndValue{Type: oid, Value: v})
	}

	if reversed {
		for i, j := 0, len(atvs)-1; i < j; i, j = i+1, j-1 {
			atvs[i], atvs[j] = atvs[j], atvs[i]
		}
	}

	// ExtraNames alone, so the order given is the order written: pkix.Name's own fields
	// would be put in its fixed order instead.
	return pkix.Name{ExtraNames: atvs}, nil
}

// splitEscaped splits s at each sep not after a backslash, and unescapes what it keeps.
func splitEscaped(s string, sep rune) ([]string, error) {
	var (
		out []string
		cur strings.Builder
		esc bool
	)

	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)

			esc = false
		case r == '\\':
			esc = true
		case r == sep:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}

	if esc {
		return nil, errors.New("the subject ends in a backslash with nothing after it")
	}

	return append(out, cur.String()), nil
}

// CommonName is a name's CN, wherever in it the CN is.
func CommonName(n pkix.Name) string {
	if n.CommonName != "" {
		return n.CommonName
	}

	for _, a := range n.ExtraNames {
		if a.Type.Equal(attributes["CN"]) {
			if s, ok := a.Value.(string); ok {
				return s
			}
		}
	}

	return ""
}

// SANs are a certificate's or request's subject alternative names.
type SANs struct {
	DNS   []string
	IP    []net.IP
	Email []string
	URI   []*url.URL
}

// Empty reports whether there are none.
func (s SANs) Empty() bool {
	return len(s.DNS)+len(s.IP)+len(s.Email)+len(s.URI) == 0
}

// AddSAN reads one name: TYPE:VALUE, TYPE being DNS, IP, EMAIL or URI, or a bare value whose
// type is taken from its shape -- an address, something with an @, something with ://, or
// else a DNS name.
func (s *SANs) AddSAN(v string) error {
	kind, value, typed := strings.Cut(v, ":")
	kind = strings.ToUpper(kind)

	switch {
	case typed && kind == "DNS":
	case typed && kind == "IP":
	case typed && (kind == "EMAIL" || kind == "RFC822"):
		kind = "EMAIL"
	case typed && kind == "URI":
	case net.ParseIP(v) != nil:
		kind, value = "IP", v
	case strings.Contains(v, "://"):
		kind, value = "URI", v
	case strings.Contains(v, "@"):
		kind, value = "EMAIL", v
	default:
		kind, value = "DNS", v
	}

	switch kind {
	case "DNS":
		if err := checkDNSName(value); err != nil {
			return err
		}

		s.DNS = append(s.DNS, strings.ToLower(value))
	case "IP":
		ip := net.ParseIP(value)
		if ip == nil {
			return fmt.Errorf("%q is not an IP address", value)
		}

		s.IP = append(s.IP, ip)
	case "EMAIL":
		if _, err := mail.ParseAddress(value); err != nil || strings.ContainsAny(value, "<> ") {
			return fmt.Errorf("%q is not an email address", value)
		}

		s.Email = append(s.Email, value)
	case "URI":
		u, err := url.Parse(value)
		if err != nil || u.Scheme == "" {
			return fmt.Errorf("%q is not a URI with a scheme", value)
		}

		s.URI = append(s.URI, u)
	}

	return nil
}

// checkDNSName accepts a host name, its leftmost label alone allowed to be a wildcard.
func checkDNSName(name string) error {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if name == "" || len(name) > 253 {
		return fmt.Errorf("%q is not a DNS name", name)
	}

	for i, l := range labels {
		if i == 0 && l == "*" && len(labels) > 2 {
			continue
		}

		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%q is not a DNS name", name)
		}

		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("%q is not a DNS name: %q is not a letter, digit or hyphen", name, r)
			}
		}
	}

	return nil
}
