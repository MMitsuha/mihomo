package tunnel

import (
	"context"
	"net"
	"testing"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/tls"
)

func TestGetMitmConfigMatchesHTTPHostDomainFilter(t *testing.T) {
	defer restoreMitmConfigForTest(setMitmConfigForTest(&C.MitmConfig{
		Enable:         true,
		Ports:          []uint16{80},
		DomainMatchers: testMitmDomainMatchers(t, "example.com"),
	}))(t)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: ads.example.com\r\n\r\n"))
	}()

	metadata := &C.Metadata{NetWork: C.TCP, Type: C.HTTP, DstPort: 80}
	cfg, decision := getMitmConfig(N.NewBufferedConn(server), metadata)
	if cfg == nil || decision != mitmDecisionHandle {
		t.Fatalf("expected MITM handle decision, got cfg=%v decision=%d", cfg, decision)
	}
	if metadata.SniffHost != "ads.example.com" {
		t.Fatalf("expected sniffed host to be recorded, got %q", metadata.SniffHost)
	}
}

func TestGetMitmConfigSkipsHTTPHostOutsideDomainFilter(t *testing.T) {
	defer restoreMitmConfigForTest(setMitmConfigForTest(&C.MitmConfig{
		Enable:         true,
		Ports:          []uint16{80},
		DomainMatchers: testMitmDomainMatchers(t, "example.com"),
	}))(t)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"))
	}()

	metadata := &C.Metadata{NetWork: C.TCP, Type: C.HTTP, DstPort: 80}
	cfg, decision := getMitmConfig(N.NewBufferedConn(server), metadata)
	if cfg != nil || decision != mitmDecisionSkip {
		t.Fatalf("expected MITM skip decision, got cfg=%v decision=%d", cfg, decision)
	}
}

func TestGetMitmConfigMatchesTLSSNIDomainFilter(t *testing.T) {
	defer restoreMitmConfigForTest(setMitmConfigForTest(&C.MitmConfig{
		Enable:         true,
		Ports:          []uint16{443},
		DomainMatchers: testMitmDomainMatchers(t, "example.com"),
	}))(t)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		tlsConn := tls.Client(client, &tls.Config{
			ServerName:         "ads.example.com",
			InsecureSkipVerify: true,
		})
		_ = tlsConn.HandshakeContext(context.Background())
	}()

	metadata := &C.Metadata{NetWork: C.TCP, Type: C.HTTP, DstPort: 443}
	cfg, decision := getMitmConfig(N.NewBufferedConn(server), metadata)
	if cfg == nil || decision != mitmDecisionHandle {
		t.Fatalf("expected MITM handle decision, got cfg=%v decision=%d", cfg, decision)
	}
	if metadata.SniffHost != "ads.example.com" {
		t.Fatalf("expected sniffed host to be recorded, got %q", metadata.SniffHost)
	}
}

func setMitmConfigForTest(cfg *C.MitmConfig) *C.MitmConfig {
	configMux.Lock()
	defer configMux.Unlock()
	old := mitmConfig
	mitmConfig = cfg
	return old
}

func restoreMitmConfigForTest(old *C.MitmConfig) func(*testing.T) {
	return func(t *testing.T) {
		t.Helper()
		configMux.Lock()
		defer configMux.Unlock()
		mitmConfig = old
	}
}

func testMitmDomainMatchers(t *testing.T, domains ...string) []C.DomainMatcher {
	t.Helper()
	tree := trie.New[struct{}]()
	for _, domain := range domains {
		if err := tree.Insert("+."+domain, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	return []C.DomainMatcher{tree.NewDomainSet()}
}
