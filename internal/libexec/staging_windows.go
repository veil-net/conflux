package libexec

import (
	"errors"
	"io/fs"
	"math/rand/v2"
	"path/filepath"
	"strconv"

	"github.com/veil-net/conflux/internal/paths"
)

// makeStaging makes the directory a set is written in before it takes its name, in root under a
// name drawn as os.MkdirTemp draws one, with Restrict's ownership and DACL set as it is created
// (paths.MakeRestricted): SYSTEM's and the Administrators', never for an instant what root passes
// on. A name taken is drawn again, as often as os.MkdirTemp would.
func makeStaging(root string) (string, error) {
	for try := 0; ; try++ {
		dir := filepath.Join(root, ".staging-"+strconv.FormatUint(uint64(rand.Uint32()), 10))

		if err := paths.MakeRestricted(dir); !errors.Is(err, fs.ErrExist) || try == 9999 {
			return dir, err
		}
	}
}
