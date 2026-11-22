// Package group answers who a Unix group lets in, from the system's own databases: getent, or
// /etc/group and /etc/passwd where there is no getent, or macOS's directory service. account asks it
// before adopting a group of its account's name, read afresh at every question, since a supervisor asks
// at every start.
package group
