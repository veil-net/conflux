// Package group answers who a Unix group lets in, from the system's own databases: getent,
// or /etc/group and /etc/passwd where there is no getent, or macOS's directory service, through a
// Lookup. account asks it before adopting a group of its account's name (a new Lookup each time,
// read afresh, since a supervisor asks at every start), and paths before taking a directory that
// group may write for one nobody else may (one Lookup for the process, read once).
package group
