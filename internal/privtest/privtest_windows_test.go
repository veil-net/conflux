package privtest

import (
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestGiveAgainWritesOnlyWhatDiffers: every test binary gives conflux-tests its owner and DACL again
// as it starts, side by side with the others, and a DACL written by name is passed on to every folder
// below that does not protect its own, other binaries' TempDirs among them. So giveAgain writes
// nothing where the folder holds what it gives already -- a folder below, whose DACL holds no entry
// passed on to it, keeps it so -- and writes where it differs, passing the new DACL on. Windows-only,
// so it runs in CI's platforms job alone.
func TestGiveAgainWritesOnlyWhatDiffers(t *testing.T) {
	const protected = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

	parent := filepath.Join(t.TempDir(), "p")

	sd := descriptor(t, protected)

	if err := windows.CreateDirectory(utf16(t, parent), &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}); err != nil {
		t.Fatal(err)
	}

	child := filepath.Join(parent, "c")
	if err := windows.CreateDirectory(utf16(t, child), nil); err != nil {
		t.Fatal(err)
	}

	// The child's DACL set through a handle, which passes nothing on and takes nothing from the parent:
	// one entry of its own, and none of what the parent passes on.
	h, err := windows.CreateFile(utf16(t, child), windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}

	err = windows.SetKernelObjectSecurity(h, windows.DACL_SECURITY_INFORMATION, descriptor(t, "D:(A;;FA;;;BA)"))
	windows.CloseHandle(h)

	if err != nil {
		t.Fatal(err)
	}

	if n := len(ReadSecurity(t, child).Entries); n != 1 {
		t.Fatalf("the child's DACL holds %d entries, want its own one", n)
	}

	if err := giveAgain(parent, sd); err != nil {
		t.Fatalf("giveAgain(a folder holding what it gives) = %v", err)
	}

	if n := len(ReadSecurity(t, child).Entries); n != 1 {
		t.Errorf("giveAgain wrote a folder holding what it gives: the folder below holds %d entries, passed on to "+
			"it, want its own one", n)
	}

	wider := descriptor(t, protected+"(A;OICI;FR;;;BU)")
	if err := giveAgain(parent, wider); err != nil {
		t.Fatalf("giveAgain(a folder holding another DACL) = %v", err)
	}

	if n := len(ReadSecurity(t, parent).Entries); n != 3 {
		t.Errorf("giveAgain left a folder holding another DACL with %d entries, want the 3 it gives", n)
	}

	if n := len(ReadSecurity(t, child).Entries); n == 1 {
		t.Error("giveAgain's new DACL was not passed on to the folder below")
	}
}

// descriptor is the security descriptor sddl holds.
func descriptor(t *testing.T, sddl string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}

	return sd
}

// utf16 is s as Windows's calls take a name.
func utf16(t *testing.T, s string) *uint16 {
	t.Helper()

	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		t.Fatal(err)
	}

	return p
}
