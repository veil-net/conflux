//go:build !(linux && amd64) && !(linux && arm64) && !(darwin && amd64) && !(darwin && arm64) && !(freebsd && amd64) && !(openbsd && amd64) && !(windows && amd64) && !(windows && arm64)

package anchor

// This build carries no anchor pair. It exists so that `go build ./...` and
// `go vet ./...` succeed for a GOOS/GOARCH we do not ship, rather than failing
// at the //go:embed of a file that was never built for it.

var anchord, anchorctl []byte

const supported = false
