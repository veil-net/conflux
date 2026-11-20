package httpsonly

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestOnlyHTTPSIsAccepted(t *testing.T) {
	t.Setenv(InsecureEnv, "")

	if err := Check("ftp://example.com", ""); err == nil {
		t.Error("Check accepted ftp")
	}
}

// TestTheRedirectPolicy: a redirect is followed over https alone, giving the caller's why;
// to another host only where the policy allows it, and a cross-host one is refused as that
// whatever its scheme; and never past max requests.
func TestTheRedirectPolicy(t *testing.T) {
	t.Setenv(InsecureEnv, "")

	first := httptest.NewRequest(http.MethodGet, "https://api.example/a", nil)

	for _, c := range []struct {
		to       string
		via      int
		sameHost bool
		refusal  string // "" for followed
	}{
		{"https://api.example/b", 1, true, ""},
		{"https://api.example/b", 2, true, ""},
		{"https://api.example/b", 3, true, "stopped after 3 requests"},
		{"http://api.example/b", 1, true, "plain http; the reason"},
		{"https://storage.example/b", 1, true, "refusing a redirect from api.example to storage.example"},
		{"http://storage.example/b", 1, true, "refusing a redirect from api.example to storage.example"},
		{"https://storage.example/b", 1, false, ""},
		{"http://storage.example/b", 1, false, "plain http; the reason"},
		{"https://storage.example/b", 3, false, "stopped after 3 requests"},
	} {
		via := slices.Repeat([]*http.Request{first}, c.via)

		err := Redirects(3, c.sameHost, "the reason")(httptest.NewRequest(http.MethodGet, c.to, nil), via)

		switch {
		case c.refusal == "" && err != nil:
			t.Errorf("same host %v, a redirect to %s after %d requests: %v, want it followed", c.sameHost, c.to, c.via, err)
		case c.refusal != "" && (err == nil || !strings.Contains(err.Error(), c.refusal)):
			t.Errorf("same host %v, a redirect to %s after %d requests: %v, want %q", c.sameHost, c.to, c.via, err, c.refusal)
		}
	}
}
