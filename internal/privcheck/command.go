package privcheck

import (
	"runtime"
	"strings"
)

// Command is argv as somebody would type it again, for a message that says what to run:
// each word quoted where the shell it is pasted into would otherwise read it, PowerShell
// on Windows, where an Administrator retries, and a POSIX shell elsewhere.
func Command(argv ...string) string {
	words := make([]string, len(argv))
	for i, w := range argv {
		words[i] = word(w)
	}

	return strings.Join(words, " ")
}

// word quotes w when it holds anything but the characters every shell reads literally.
func word(w string) string {
	if w != "" && strings.Trim(w, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_%+=:./-") == "" {
		return w
	}

	// PowerShell doubles a quote; a POSIX shell closes the quoting around one.
	if runtime.GOOS == "windows" {
		return "'" + strings.ReplaceAll(w, "'", "''") + "'"
	}

	return "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
}
