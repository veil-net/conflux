package ghrelease

import (
	"net/http"
	"testing"
)

func TestOnlyHTTPSIsAccepted(t *testing.T) {
	t.Setenv(InsecureEnv, "")

	if err := CheckScheme("ftp://example.com", ""); err == nil {
		t.Error("CheckScheme accepted ftp")
	}
}

// TestARedirectToPlainHTTPIsRefused: the hop to storage is followed, but not one that
// would hand the binary to anyone on the path.
func TestARedirectToPlainHTTPIsRefused(t *testing.T) {
	t.Setenv(InsecureEnv, "")

	req, _ := http.NewRequest(http.MethodGet, "http://objects.example.com/conflux", nil)
	if err := Client.CheckRedirect(req, nil); err == nil {
		t.Error("a redirect to plain http was followed")
	}
}
