package mitm

import (
	"bufio"
	_ "unsafe"

	"github.com/metacubex/http"
)

//go:linkname readRequest github.com/metacubex/http.readRequest
func readRequest(b *bufio.Reader) (*http.Request, error)
