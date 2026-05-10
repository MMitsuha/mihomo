package mitm_test

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/mitm"
	"github.com/metacubex/mihomo/rewrite"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
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

type fakeTLSTunnel struct {
	t         *testing.T
	authority *ca.MitmAuthority
	h2Seen    chan bool
}

func (f fakeTLSTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()

	if metadata.Type != C.MITM {
		f.t.Errorf("expected MITM metadata type, got %s", metadata.Type.String())
		return
	}

	tlsConn := tls.Server(conn, f.authority.NewTLSConfigForHost("example.com"))
	if err := tlsConn.Handshake(); err != nil {
		f.t.Errorf("upstream TLS handshake: %v", err)
		return
	}

	negotiatedH2 := tlsConn.ConnectionState().NegotiatedProtocol == http.Http2NextProtoTLS
	select {
	case f.h2Seen <- negotiatedH2:
	default:
	}
	if !negotiatedH2 {
		f.t.Errorf("expected upstream HTTP/2, got %q", tlsConn.ConnectionState().NegotiatedProtocol)
		return
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.ProtoMajor != 2 {
				f.t.Errorf("expected upstream HTTP/2 request, got %s", request.Proto)
			}
			body := `{"score":1}`
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = io.WriteString(w, body)
		}),
	}
	h2Server := &http.Http2Server{}
	_ = http.Http2ConfigureServer(server, h2Server)
	h2Server.ServeConn(tlsConn, &http.Http2ServeConnOpts{BaseConfig: server})
}

func (fakeTLSTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata) {}

func (fakeTLSTunnel) NatTable() C.NatTable { return nil }

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

func TestHandlePlainHTTP2DirectResponse(t *testing.T) {
	rule, err := rewrite.ParseRewrite(rewrite.RawMitmRule{
		Url:    `^http://example\.com/blocked$`,
		Action: C.MitmRejectDict,
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
		Handler: rewrite.NewHandler(rewrite.NewRewriteRules([]C.Rewrite{rule}, nil)),
	})

	h2Transport := &http.Http2Transport{}
	h2Conn, err := h2Transport.NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	defer h2Conn.Close()

	request, err := http.NewRequest(http.MethodGet, "http://example.com/blocked", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := h2Conn.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2 response, got %s", response.Proto)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, response.StatusCode)
	}
	if got, want := string(body), `{}`; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestHandleHTTPSHTTP2ResponseBodyRewrite(t *testing.T) {
	old := `"score":\d+`
	rule, err := rewrite.ParseRewrite(rewrite.RawMitmRule{
		Url:    `^https://example\.com/score$`,
		Action: C.MitmResponseBody,
		Old:    &old,
		New:    `"score":999`,
	})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "mitm_ca.crt")
	keyPath := filepath.Join(dir, "mitm_ca.key")
	if err = ca.GenerateAndSaveMitmCA(caPath, keyPath); err != nil {
		t.Fatal(err)
	}
	rootCA, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = ca.AddCertificate(string(rootCA)); err != nil {
		t.Fatal(err)
	}
	defer ca.ResetCertificate()

	authority, err := ca.LoadMitmAuthority(caPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	h2Seen := make(chan bool, 1)

	client, server := net.Pipe()
	defer client.Close()

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.HTTP,
		Host:    "example.com",
		DstPort: 443,
		SrcIP:   netip.MustParseAddr("127.0.0.1"),
		SrcPort: 12345,
	}

	go mitm.HandleConn(server, metadata, fakeTLSTunnel{t: t, authority: authority, h2Seen: h2Seen}, &mitm.Option{
		Authority: authority,
		Handler:   rewrite.NewHandler(rewrite.NewRewriteRules(nil, []C.Rewrite{rule})),
	})

	tlsConn := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
		NextProtos:         []string{http.Http2NextProtoTLS},
	})
	if err = tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if got, want := tlsConn.ConnectionState().NegotiatedProtocol, http.Http2NextProtoTLS; got != want {
		t.Fatalf("expected negotiated protocol %q, got %q", want, got)
	}

	h2Transport := &http.Http2Transport{}
	h2Conn, err := h2Transport.NewClientConn(tlsConn)
	if err != nil {
		t.Fatal(err)
	}
	defer h2Conn.Close()

	request, err := http.NewRequest(http.MethodGet, "https://example.com/score", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := h2Conn.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err = h2Conn.Close(); err != nil {
		t.Fatal(err)
	}

	if response.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2 response, got %s", response.Proto)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, response.StatusCode)
	}
	if got, want := string(body), `{"score":999}`; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}

	select {
	case ok := <-h2Seen:
		if !ok {
			t.Fatal("expected upstream HTTP/2")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for upstream HTTP/2 request")
	}
}
