package logfile

import "os"

// standardStreams does nothing: a Windows service has no standard streams to place it over.
func standardStreams(*os.File) {}
