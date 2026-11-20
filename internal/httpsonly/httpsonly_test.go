package httpsonly

import "testing"

func TestOnlyHTTPSIsAccepted(t *testing.T) {
	t.Setenv(InsecureEnv, "")

	if err := Check("ftp://example.com", ""); err == nil {
		t.Error("Check accepted ftp")
	}
}
