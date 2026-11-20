package wintun

import (
	"fmt"
	"net/http"

	"github.com/veil-net/conflux/internal/httpsonly"
)

// checkRedirect is the download's redirect policy: over https alone (httpsonly), on wintun.net's
// own host, and no more than 10 requests in all. Untagged, so it is tested on every machine that builds conflux
// rather than only on Windows. Replacing net/http's own policy replaces its limit too, which a
// same-host loop would otherwise run into only at the download's timeout.
func checkRedirect(r *http.Request, via []*http.Request) error {
	if err := httpsonly.Check(r.URL.String(), ""); err != nil {
		return err
	}

	if r.URL.Host != via[0].URL.Host {
		return fmt.Errorf("refusing a redirect from %s to %s", via[0].URL.Host, r.URL.Host)
	}

	if len(via) >= 10 {
		return fmt.Errorf("stopped after %d redirects", len(via))
	}

	return nil
}
