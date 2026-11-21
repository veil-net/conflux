package paths

// MountAllowsExec is true, and reads nothing at dir: Windows mounts nothing noexec. A lookup there
// would follow whatever is at the name by then, a link to a share another user made in C:\ among
// it, which following signs this machine in to, and Ephemeral asks this of a candidate whose way
// Foreign found missing.
func MountAllowsExec(string) (bool, error) { return true, nil }
