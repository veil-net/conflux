//go:build darwin && amd64

package anchor

import _ "embed"

//go:embed bin/anchord-darwin-amd64
var anchord []byte

//go:embed bin/anchorctl-darwin-amd64
var anchorctl []byte

const supported = true
