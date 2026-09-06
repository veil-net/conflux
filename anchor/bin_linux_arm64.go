//go:build linux && arm64

package anchor

import _ "embed"

//go:embed bin/anchord-linux-arm64
var anchord []byte

//go:embed bin/anchorctl-linux-arm64
var anchorctl []byte

const supported = true
