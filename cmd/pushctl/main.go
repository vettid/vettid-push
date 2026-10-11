// Command pushctl prepares the push gateway's blob-keys secret
// (PUSH-GATEWAY §4, §10.2).
//
//	pushctl blob-keys new            print a first secret with one random key
//	pushctl blob-keys rotate < old   print old with a new current key added; the
//	                                 retired keys stay and still open blobs
//	pushctl blob-keys drop <key_id> < old
//	                                 print old without a retired key (after its
//	                                 400 days; its blobs then answer blob_invalid)
//	pushctl blob-keys list < secret  print the key ids and the current one (no keys)
//
// The output of new, rotate and drop IS THE SECRET: pipe it straight into
// the secret store (aws secretsmanager put-secret-value --secret-string
// file:///dev/stdin), never into a file or a terminal log.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/vettid/vettid-push/internal/blob"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pushctl blob-keys new | rotate | drop <key_id> | list   (secret on stdin for rotate, drop, list)")
	os.Exit(2)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "pushctl:", err)
	os.Exit(1)
}

func stdin() []byte {
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
	if err != nil {
		die(err)
	}
	return b
}

func main() {
	if len(os.Args) < 3 || os.Args[1] != "blob-keys" {
		usage()
	}
	var out []byte
	var err error
	switch os.Args[2] {
	case "new":
		out, err = blob.NewSecret()
	case "rotate":
		out, err = blob.RotateSecret(stdin())
	case "drop":
		if len(os.Args) != 4 {
			usage()
		}
		out, err = blob.DropKey(stdin(), os.Args[3])
	case "list":
		k, e := blob.NewKeyring("list", stdin())
		if e != nil {
			die(e)
		}
		ids, cur := k.KeyIDs()
		out, err = json.Marshal(map[string]any{"current": cur, "key_ids": ids})
	default:
		usage()
	}
	if err != nil {
		die(err)
	}
	fmt.Println(string(out))
}
