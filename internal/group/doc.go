// Package group answers who a Unix group lets in, from the system's own databases: getent,
// or /etc/group and /etc/passwd where there is no getent, or macOS's directory service.
// account asks it before adopting a group of its account's name (Users, read afresh), and
// paths before taking a directory that group may write for one nobody else may (a Lookup, read
// once for each judgement).
package group
