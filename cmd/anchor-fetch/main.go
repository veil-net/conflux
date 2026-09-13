// Command anchor-fetch populates anchor/bin from the published release manifest.
//
// Invoked by scripts/anchor-bins.sh when no local anchor checkout is available, which
// is the state CI is in and the state a fresh clone starts in.
//
// Go rather than shell, and a program rather than curl piped into a JSON parser,
// because docs/build.md promises "Go 1.27.1 or newer, and nothing else" and a fresh
// clone should not need python or jq to become buildable. It also puts the digest
// check, the redirect refusal and the atomic write somewhere they can be tested.
//
// Deliberately imports no package that embeds anything. `go run ./cmd/anchor-fetch`
// has to work when anchor/bin is empty -- that is the only moment it is ever wanted --
// so a dependency on the anchor package would make this unable to run in exactly the
// case it exists for.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/veil-net/conflux/internal/shelf"
)

func main() {
	url := flag.String("url", shelf.DefaultURL, "the release manifest to fetch from")
	dest := flag.String("dest", "anchor/bin", "where to write the binaries")
	want := flag.String("want", "", "comma-separated file names to fetch (required)")

	flag.Parse()

	names := strings.FieldsFunc(*want, func(r rune) bool { return r == ',' })
	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "anchor-fetch: -want is required and names the files to fetch")
		os.Exit(2)
	}

	// Interruptible, because this moves a couple of hundred megabytes and the first
	// thing anybody does to a fetch that is taking too long is press ^C.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	log := func(format string, a ...any) { fmt.Fprintf(os.Stderr, "anchor-fetch: "+format+"\n", a...) }

	if err := shelf.Fetch(ctx, *url, names, *dest, log); err != nil {
		fmt.Fprintf(os.Stderr, "anchor-fetch: %v\n", err)
		os.Exit(1)
	}

	log("%d/%d fetched, digests verified", len(names), len(names))
}
