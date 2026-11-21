package paths

import "golang.org/x/sys/windows"

// JudgeAsTheService is secure's judgement of the root dir as the boot service makes it at every
// start, running as SYSTEM, which trusts no other account: for the tests of package paths_test,
// which make a root through the packages that make one.
func JudgeAsTheService(dir string) error {
	was := currentUser
	defer func() { currentUser = was }()

	currentUser = func() *windows.SID { return sidSystem }

	return secure(dir)
}
