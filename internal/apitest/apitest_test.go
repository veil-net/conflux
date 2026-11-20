package apitest

import (
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/config"
)

const module = "github.com/veil-net/conflux"

// TestEveryTestBinaryLinkingConfigImportsIt: a package whose test binary links config -- its
// tests build a configuration, a manifest or a client, or use something that does -- imports
// this package in a test file, so its default API is Nowhere. Read from the source, every file
// whatever its build constraints, so a package added later is held to it too.
func TestEveryTestBinaryLinkingConfigImportsIt(t *testing.T) {
	if config.DefaultAPIBaseURL != Nowhere {
		t.Fatalf("the default API is %s under test, want %s", config.DefaultAPIBaseURL, Nowhere)
	}

	root := filepath.Join("..", "..")
	imports := map[string]map[string]bool{}     // a package's own imports, of this module's
	testImports := map[string]map[string]bool{} // its test files', in either package

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if name := d.Name(); p != root && (strings.HasPrefix(name, ".") || name == "testdata") {
				return filepath.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(p, ".go") {
			return nil
		}

		rel, err := filepath.Rel(root, filepath.Dir(p))
		if err != nil {
			return err
		}

		pkg := path.Join(module, filepath.ToSlash(rel))

		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}

		into := imports
		if strings.HasSuffix(p, "_test.go") {
			into = testImports
		}

		if into[pkg] == nil {
			into[pkg] = map[string]bool{}
		}

		for _, spec := range f.Imports {
			if ip, _ := strconv.Unquote(spec.Path.Value); strings.HasPrefix(ip, module+"/") {
				into[pkg][ip] = true
			}
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg, self := module+"/internal/config", module+"/internal/apitest"

	// links says whether anything in from, or anything it imports, is config.
	seen := map[string]bool{}

	var links func(from map[string]bool) bool

	links = func(from map[string]bool) bool {
		for ip := range from {
			if ip == cfg {
				return true
			}

			if !seen[ip] {
				seen[ip] = true

				if links(imports[ip]) {
					return true
				}
			}
		}

		return false
	}

	var held []string

	for _, pkg := range slices.Sorted(maps.Keys(testImports)) {
		tests := testImports[pkg]

		clear(seen)

		if pkg == self || pkg != cfg && !links(imports[pkg]) && !links(tests) {
			continue
		}

		held = append(held, strings.TrimPrefix(pkg, module+"/"))

		if !tests[self] {
			t.Errorf("%s's tests link config and do not import %s, so a configuration naming no API enrols at production's", pkg, self)
		}
	}

	// A scan that found nothing would pass: it found the packages it is about.
	for _, pkg := range []string{"internal/cli", "internal/config", "internal/daemon", "internal/enrol"} {
		if !slices.Contains(held, pkg) {
			t.Errorf("the scan did not find %s's tests linking config; it found %v", pkg, held)
		}
	}
}
