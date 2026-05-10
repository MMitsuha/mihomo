package mitm_test

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/mitm"
	"github.com/metacubex/mihomo/rewrite"

	"github.com/metacubex/http"
)

type fakeTunnel struct {
	t *testing.T
}

func (f fakeTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()

	if metadata.Type != C.MITM {
		f.t.Errorf("expected MITM metadata type, got %s", metadata.Type.String())
		return
	}

	request, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		f.t.Errorf("read upstream request: %v", err)
		return
	}
	if request.Body != nil {
		_, _ = io.Copy(io.Discard, request.Body)
		_ = request.Body.Close()
	}

	body := `{"score":1}`
	response := &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Proto:         request.Proto,
		ProtoMajor:    request.ProtoMajor,
		ProtoMinor:    request.ProtoMinor,
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
		Request:       request,
	}
	response.Header.Set("Content-Type", "application/json")
	response.Header.Set("Content-Length", "11")
	if err = response.Write(conn); err != nil {
		f.t.Errorf("write upstream response: %v", err)
	}
}

func (fakeTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata) {}

func (fakeTunnel) NatTable() C.NatTable { return nil }

func TestHandlePlainHTTPResponseBodyRewrite(t *testing.T) {
	old := `"score":\d+`
	rule, err := rewrite.ParseRewrite(rewrite.RawMitmRule{
		Url:    `^http://example\.com/score$`,
		Action: C.MitmResponseBody,
		Old:    &old,
		New:    `"score":999`,
	})
	if err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	defer client.Close()

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.HTTP,
		Host:    "example.com",
		DstPort: 80,
		SrcIP:   netip.MustParseAddr("127.0.0.1"),
		SrcPort: 12345,
	}

	go mitm.HandleConn(server, metadata, fakeTunnel{t: t}, &mitm.Option{
		Handler: rewrite.NewHandler(rewrite.NewRewriteRules(nil, []C.Rewrite{rule})),
	})

	if _, err = io.WriteString(client, "GET /score HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), `{"score":999}`; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
