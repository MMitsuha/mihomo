package cert

import (
	"sync"

	"github.com/metacubex/mihomo/component/trie"

	"github.com/metacubex/tls"
)

// CertsStorage caches generated leaf certificates.
type CertsStorage interface {
	Get(key string) (*tls.Certificate, bool)
	Set(key string, cert *tls.Certificate)
}

// DomainTrieCertsStorage stores certs in a domain trie so wildcard entries
// (key="+.example.com") match every subdomain.
type DomainTrieCertsStorage struct {
	mu    sync.RWMutex
	cache *trie.DomainTrie[*tls.Certificate]
}

func NewDomainTrieCertsStorage() *DomainTrieCertsStorage {
	return &DomainTrieCertsStorage{cache: trie.New[*tls.Certificate]()}
}

func (s *DomainTrieCertsStorage) Get(key string) (*tls.Certificate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	node := s.cache.Search(key)
	if node == nil {
		return nil, false
	}
	return node.Data(), true
}

func (s *DomainTrieCertsStorage) Set(key string, cert *tls.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.cache.Insert(key, cert)
}
