package daemon

// restoreModes is nothing here: the root's DACL, which paths.EnsureAll holds to SYSTEM and
// the Administrators, is what everything in it inherits.
func (s *Supervisor) restoreModes() error { return nil }
