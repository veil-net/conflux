//go:build freebsd && amd64

package anchor

import _ "embed"

//go:embed bin/anchord-freebsd-amd64
var anchord []byte

//go:embed bin/anchorctl-freebsd-amd64
var anchorctl []byte

const supported = true
