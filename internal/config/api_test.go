package config_test

// The default API answers nothing under test (internal/apitest), which can be imported only from
// config's external test package: it imports config.
import _ "github.com/veil-net/conflux/internal/apitest"
