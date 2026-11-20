// Package apitest is for tests, and only for tests: imported, it points conflux's default API
// at an address nothing answers on, for the whole test binary.
//
// A configuration or a client that names no API enrols and renews at config.DefaultAPIBaseURL,
// which is production's. Under test that would be a real enrolment the moment a test went
// further than it meant to, so every package whose tests link config imports this, and
// TestEveryTestBinaryLinkingConfigImportsIt holds them to it. A test that wants a server names
// one, an httptest server's URL, as it always must.
package apitest

import "github.com/veil-net/conflux/internal/config"

// Nowhere is an API nothing answers on: a port on loopback nothing listens on, so a dial is
// refused at once.
const Nowhere = "https://127.0.0.1:1"

func init() { config.DefaultAPIBaseURL = Nowhere }
