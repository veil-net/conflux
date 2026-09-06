//go:build openbsd && amd64

package anchor

import _ "embed"

//go:embed bin/anchord-openbsd-amd64
var anchord []byte

//go:embed bin/anchorctl-openbsd-amd64
var anchorctl []byte

const supported = true
