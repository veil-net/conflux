package daemon

// noCoreDumps has nothing to set on Windows, where a crash dump is Windows Error Reporting's
// to write and its settings the machine's; docs/ephemeral.md says so.
func noCoreDumps() {}
