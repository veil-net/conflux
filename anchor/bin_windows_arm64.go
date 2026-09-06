//go:build windows && arm64

package anchor

import _ "embed"

//go:embed bin/anchord-windows-arm64.exe
var anchord []byte

//go:embed bin/anchorctl-windows-arm64.exe
var anchorctl []byte

const supported = true
