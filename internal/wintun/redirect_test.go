package wintun

import (
	"net/http"
	"slices"
	"testing"

	_ "github.com/veil-net/conflux/internal/apitest" // the default API answers nothing
	"github.com/veil-net/conflux/internal/httpsonly"
)

// TestARedirectStaysOnHTTPS: the archive's digest is checked whatever brought it, but the
// download is held to https as every client conflux has is, so a redirect off it is refused,
// as one to another host or past the tenth request is; one on the same host over https is
// followed, up to the tenth.
func TestARedirectStaysOnHTTPS(t *testing.T) {
	t.Setenv(httpsonly.InsecureEnv, "")

	first, err := http.NewRequest(http.MethodGet, ZipURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		to      string
		via     int
		refused bool
	}{
		{"https://www.wintun.net/builds/mirror/wintun-" + Version + ".zip", 1, false},
		{"http://www.wintun.net/builds/wintun-" + Version + ".zip", 1, true},
		{"https://example.com/wintun-" + Version + ".zip", 1, true},
		{"https://www.wintun.net/builds/again.zip", 9, false},
		{"https://www.wintun.net/builds/again.zip", 10, true},
	} {
		next, err := http.NewRequest(http.MethodGet, c.to, nil)
		if err != nil {
			t.Fatal(err)
		}

		via := slices.Repeat([]*http.Request{first}, c.via)

		if err := checkRedirect(next, via); (err != nil) != c.refused {
			t.Errorf("a redirect to %s after %d requests: %v, want refused %v", c.to, c.via, err, c.refused)
		}
	}
}
