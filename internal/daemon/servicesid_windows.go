package daemon

import "github.com/veil-net/conflux/internal/paths"

// ourServiceSID is this installation's service SID (paths.ServiceSID), which the token, anchord's
// directory, the -config's grant and the check that a directory is the account's are given: a
// variable, so a test can be a host whose answer fails.
var ourServiceSID = paths.ServiceSID
