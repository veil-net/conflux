package paths

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// TestServiceSID: the SID Windows gives a service, against one everybody knows, and the same
// whatever the name's case.
func TestServiceSID(t *testing.T) {
	sid, err := serviceSID("TrustedInstaller")
	if err != nil {
		t.Fatal(err)
	}

	if got, want := sid.String(), "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"; got != want {
		t.Errorf("serviceSID(TrustedInstaller) = %s, want %s", got, want)
	}

	lower, err := serviceSID("conflux")
	if err != nil {
		t.Fatal(err)
	}

	upper, err := serviceSID("CONFLUX")
	if err != nil {
		t.Fatal(err)
	}

	if !lower.Equals(upper) {
		t.Error("a service's SID does not depend on how its name is cased")
	}
}

// TestAServiceSIDNotGivenIsNotKept: a service SID Windows did not give is asked again the next
// time rather than kept as a failure for the life of the process, and one it gave is kept.
func TestAServiceSIDNotGivenIsNotKept(t *testing.T) {
	ask := askServiceSID

	t.Cleanup(func() {
		askServiceSID = ask
		serviceSIDKept.Store(nil)
	})

	serviceSIDKept.Store(nil)

	askServiceSID = func() (*windows.SID, error) { return nil, errors.New("RtlCreateServiceSid: STATUS_NO_MEMORY") }

	if _, err := ServiceSID(); err == nil {
		t.Fatal("ServiceSID gave a SID Windows did not")
	}

	askServiceSID = ask

	sid, err := ServiceSID()
	if err != nil {
		t.Fatalf("the service SID was not asked again once Windows gives it: %v", err)
	}

	askServiceSID = func() (*windows.SID, error) { return nil, errors.New("asked again") }

	if again, err := ServiceSID(); err != nil || !again.Equals(sid) {
		t.Errorf("ServiceSID = %v, %v once given; want the SID it was given, kept", again, err)
	}
}
