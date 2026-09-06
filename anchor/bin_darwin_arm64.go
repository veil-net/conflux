//go:build darwin && arm64

package anchor

import _ "embed"

//go:embed bin/anchord-darwin-arm64
var anchord []byte

//go:embed bin/anchorctl-darwin-arm64
var anchorctl []byte

const supported = true
