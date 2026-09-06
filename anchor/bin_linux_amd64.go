//go:build linux && amd64

package anchor

import _ "embed"

//go:embed bin/anchord-linux-amd64
var anchord []byte

//go:embed bin/anchorctl-linux-amd64
var anchorctl []byte

const supported = true
