//go:build !(linux && amd64) && !(linux && arm64) && !(darwin && arm64) && !(freebsd && amd64) && !(openbsd && amd64) && !(windows && amd64) && !(windows && arm64)

package anchor

// This build carries no anchor pair. It exists so that `go build ./...` and
// `go vet ./...` succeed for an architecture we do not ship on an operating system we
// do -- darwin/amd64, say -- rather than failing at the //go:embed of a file that was
// never built for it. An operating system conflux does not support at all does not
// build: the platform packages have nothing for it.

var anchord, anchorctl []byte
