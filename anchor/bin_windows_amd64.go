//go:build windows && amd64

package anchor

import _ "embed"

//go:embed bin/anchord-windows-amd64.exe
var anchord []byte

//go:embed bin/anchorctl-windows-amd64.exe
var anchorctl []byte

const supported = true
