package wintun

import "github.com/veil-net/conflux/internal/httpsonly"

// checkRedirect is the download's redirect policy: on wintun.net's own host, over https
// alone, and no more than 10 requests in all. Untagged, so it is tested on every machine that
// builds conflux rather than only on Windows.
var checkRedirect = httpsonly.Redirects(10, true, "")
